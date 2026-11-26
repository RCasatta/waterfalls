//! Limits applied to every connection of the public listener: the write stall timeout and the
//! maximum number of connections.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio::time::{Instant, Sleep};

use crate::inc_connection_error_counter;

/// The limits of the connections of the public listener
pub(crate) struct ConnectionLimits {
    pub header_read_timeout: Duration,
    /// See [`crate::server::Arguments::write_stall_timeout_seconds`]
    pub write_stall_timeout: Duration,
    /// One permit per connection, see [`crate::server::Arguments::max_connections`]
    pub permits: Arc<Semaphore>,
    /// One permit per connection being answered 503 because `permits` are exhausted
    pub reject_permits: Arc<Semaphore>,
}

/// Marks, in its extensions, a response streaming a subscription.
///
/// Its connection gives back its permit: it lives as long as the subscription and is bounded by
/// `--max-active-subscriptions` instead. The response must close the connection once sent, so
/// that it doesn't serve other requests without a permit.
#[derive(Clone, Copy)]
pub(crate) struct SubscriptionStream;

/// Serves the HTTP connection `io` with the limits of the public listener.
///
/// The connection holds a permit of [`ConnectionLimits::permits`] for its whole life, sending
/// the responses included, and serves its requests with `route`. When no permit is left, it
/// answers its request with `reject`, a 503, and closes: clients retry 503 with backoff, while
/// leaving them in the TCP backlog would make their requests hang without any status.
///
/// A rejected connection holds a permit of [`ConnectionLimits::reject_permits`] until closed,
/// at most the header read timeout plus the write stall timeout, so that slow clients cannot
/// keep an unbounded number of them open. When none is left either, the connection is closed
/// without reading the request.
pub(crate) async fn serve_connection<T, F, Fut, R, B>(
    io: T,
    limits: &ConnectionLimits,
    route: F,
    reject: R,
) -> Result<(), hyper::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: Fn(Request<Incoming>) -> Fut,
    Fut: Future<Output = Result<Response<B>, hyper::Error>>,
    R: Fn() -> Response<B>,
    B: Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let io = TokioIo::new(StallTimeoutIo::new(io, limits.write_stall_timeout));
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);

    let Ok(permit) = limits.permits.clone().try_acquire_owned() else {
        let Ok(_reject_permit) = limits.reject_permits.clone().try_acquire_owned() else {
            inc_connection_error_counter("max_connections_closed");
            return Ok(());
        };
        inc_connection_error_counter("max_connections");
        let service = service_fn(|_req| {
            let response = reject();
            async move { Ok::<_, hyper::Error>(response) }
        });
        return builder
            .keep_alive(false)
            .serve_connection(io, service)
            .await;
    };

    let permit = std::sync::Mutex::new(Some(permit));
    let permit = &permit;
    let service = service_fn(|req| {
        let response = route(req);
        async move {
            let response = response.await?;
            if response.extensions().get::<SubscriptionStream>().is_some() {
                if let Ok(mut permit) = permit.lock() {
                    permit.take();
                }
            }
            Ok::<_, hyper::Error>(response)
        }
    });
    builder.serve_connection(io, service).await
}

/// Fails a write making no progress for `timeout`, see [`crate::server::Arguments::write_stall_timeout_seconds`].
///
/// hyper doesn't poll the response body while its write buffer is full, it waits for the socket
/// to accept the buffered bytes: a client that stops reading is only noticed here. The error
/// makes hyper drop the connection, which closes the socket and frees the response.
///
/// The timer is reset by every write making progress: a slow but steady client is not cut off.
pub(crate) struct StallTimeoutIo<T> {
    inner: T,
    timeout: Duration,
    sleep: Pin<Box<Sleep>>,
    /// Whether a write is pending since the last progress, `sleep` is then its deadline
    armed: bool,
}

/// The error of a write that made no progress for the stall timeout
#[derive(Debug)]
pub(crate) struct WriteStalled;

impl std::fmt::Display for WriteStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "write stalled")
    }
}

impl std::error::Error for WriteStalled {}

/// Whether the connection was closed by [`StallTimeoutIo`]
pub(crate) fn is_write_stall(err: &hyper::Error) -> bool {
    let mut source = std::error::Error::source(err);
    while let Some(e) = source {
        if e.downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .is_some_and(|inner| inner.is::<WriteStalled>())
        {
            return true;
        }
        source = e.source();
    }
    false
}

impl<T> StallTimeoutIo<T> {
    pub(crate) fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
            armed: false,
        }
    }

    /// Disarms the timer when a write operation is ready, arms it when the operation is pending
    /// and none was pending already, and fails the operation once the deadline is reached.
    fn track<R>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<R>>) -> Poll<io::Result<R>> {
        match poll {
            Poll::Ready(result) => {
                self.armed = false;
                Poll::Ready(result)
            }
            Poll::Pending => {
                if !self.armed {
                    self.armed = true;
                    self.sleep.as_mut().reset(Instant::now() + self.timeout);
                }
                match self.sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, WriteStalled)))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for StallTimeoutIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for StallTimeoutIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.track(cx, poll)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.track(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_flush(cx);
        self.track(cx, poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.track(cx, poll)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::Response;
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    type TestBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

    /// Answers "ok", or a subscription stream that never ends on `/subscribe`
    async fn test_route(req: Request<Incoming>) -> Result<Response<TestBody>, hyper::Error> {
        use futures_util::StreamExt;
        use http_body_util::{BodyExt, StreamBody};
        use hyper::body::Frame;

        if req.uri().path() == "/subscribe" {
            let events = futures_util::stream::once(async {
                Ok(Frame::data(Bytes::from_static(b": ready\n\n")))
            })
            .chain(futures_util::stream::pending());
            let response = Response::builder()
                .header(hyper::header::CONNECTION, "close")
                .extension(SubscriptionStream)
                .body(BodyExt::boxed(StreamBody::new(events)))
                .unwrap();
            return Ok(response);
        }
        Ok(Response::new(Full::new(Bytes::from_static(b"ok")).boxed()))
    }

    fn test_reject() -> Response<TestBody> {
        use http_body_util::BodyExt;

        let mut response = Response::new(Full::new(Bytes::new()).boxed());
        *response.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
        response
    }

    /// Opens a connection served by `serve_connection` with `limits`
    fn connect(
        limits: &Arc<ConnectionLimits>,
    ) -> (
        DuplexStream,
        tokio::task::JoinHandle<Result<(), hyper::Error>>,
    ) {
        let (client, server) = tokio::io::duplex(PIPE_CAPACITY);
        let limits = limits.clone();
        let handle = tokio::spawn(async move {
            serve_connection(server, &limits, test_route, test_reject).await
        });
        (client, handle)
    }

    /// Sends a request for `path` and returns the response head, with what follows it in the
    /// same read
    async fn get(client: &mut DuplexStream, path: &str) -> String {
        let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        while !response.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
                .await
                .expect("no response")
                .unwrap();
            assert_ne!(n, 0, "connection closed before the response head");
            response.extend_from_slice(&buf[..n]);
        }
        String::from_utf8(response).unwrap().to_lowercase()
    }

    /// A connection over the limit is answered 503 and closed, a connection is served again
    /// once a slot frees up, and a subscription doesn't hold a slot.
    #[tokio::test]
    async fn connections_are_capped() {
        let limits = Arc::new(ConnectionLimits {
            header_read_timeout: Duration::from_secs(5),
            write_stall_timeout: Duration::from_secs(5),
            permits: Arc::new(Semaphore::new(1)),
            reject_permits: Arc::new(Semaphore::new(1)),
        });

        // the first connection takes the slot and keeps it while kept alive
        let (mut first, first_handle) = connect(&limits);
        assert!(get(&mut first, "/").await.starts_with("http/1.1 200"));
        assert!(get(&mut first, "/").await.starts_with("http/1.1 200"));

        // the second is answered 503 and closed, while it is being answered a third one is
        // closed without a response
        let (mut second, second_handle) = connect(&limits);
        while limits.reject_permits.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        let (mut third, third_handle) = connect(&limits);
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), third.read_to_end(&mut rest))
            .await
            .expect("the connection was not closed")
            .unwrap();
        assert!(rest.is_empty());
        assert!(third_handle.await.unwrap().is_ok());

        let response = get(&mut second, "/").await;
        assert!(response.starts_with("http/1.1 503"), "{response}");
        second.read_to_end(&mut rest).await.unwrap();
        assert!(second_handle.await.unwrap().is_ok());
        assert_eq!(limits.reject_permits.available_permits(), 1);

        // closing the first frees the slot
        drop(first);
        assert!(first_handle.await.unwrap().is_ok());
        assert_eq!(limits.permits.available_permits(), 1);
        let (mut fourth, _fourth_handle) = connect(&limits);
        assert!(get(&mut fourth, "/").await.starts_with("http/1.1 200"));

        // a subscription gives back its slot while streaming, and closes once done
        let response = get(&mut fourth, "/subscribe").await;
        assert!(response.starts_with("http/1.1 200"), "{response}");
        assert!(response.contains("connection: close"), "{response}");
        assert_eq!(limits.permits.available_permits(), 1);
        let (mut fifth, _fifth_handle) = connect(&limits);
        assert!(get(&mut fifth, "/").await.starts_with("http/1.1 200"));
        drop(fourth);
    }

    /// Capacity of the pipe between client and server: writes beyond it wait for the client
    const PIPE_CAPACITY: usize = 64 * 1024;
    const BODY_LEN: usize = 1024 * 1024;
    const TIMEOUT: Duration = Duration::from_millis(200);

    /// Serves a connection answering every request with a body of `BODY_LEN` bytes, sends it a
    /// request and returns the client end and the result of serving the connection.
    async fn request_large_body() -> (
        DuplexStream,
        tokio::task::JoinHandle<Result<(), hyper::Error>>,
    ) {
        let (mut client, server) = tokio::io::duplex(PIPE_CAPACITY);
        let handle = tokio::spawn(async move {
            let service = service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(vec![
                    b'x';
                    BODY_LEN
                ]))))
            });
            http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(TokioIo::new(StallTimeoutIo::new(server, TIMEOUT)), service)
                .await
        });
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        (client, handle)
    }

    /// A client reading the response head and then nothing else is disconnected after the
    /// stall timeout.
    #[tokio::test]
    async fn stalled_client_is_disconnected() {
        let (mut client, handle) = request_large_body().await;
        let mut head = [0u8; 1024];
        let n = client.read(&mut head).await.unwrap();
        assert!(head[..n].starts_with(b"HTTP/1.1 200 OK"));

        let start = std::time::Instant::now();
        let err = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the server did not close the connection")
            .unwrap()
            .unwrap_err();
        assert!(is_write_stall(&err), "{err:?}");
        assert!(start.elapsed() >= TIMEOUT / 2);

        // the connection is closed: reading drains what was buffered, then ends
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.len() < BODY_LEN);
    }

    /// A client reading slowly, but making progress more often than the stall timeout, receives
    /// the whole response.
    #[tokio::test]
    async fn slow_steady_client_is_served() {
        let (mut client, handle) = request_large_body().await;

        let start = std::time::Instant::now();
        let mut buf = vec![0u8; 32 * 1024];
        let n = client.read(&mut buf).await.unwrap();
        let head_len = buf[..n]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("the head fits in the first read")
            + 4;
        let mut body_len = n - head_len;
        while body_len < BODY_LEN {
            // a pause shorter than the timeout between reads
            tokio::time::sleep(TIMEOUT / 4).await;
            match client.read(&mut buf).await.unwrap() {
                0 => break,
                n => body_len += n,
            }
        }
        assert_eq!(body_len, BODY_LEN);
        // the response took longer than the stall timeout overall
        assert!(start.elapsed() > TIMEOUT * 4);
        drop(client);
        assert!(handle.await.unwrap().is_ok());
    }
}

//! Limits applied to every connection of the public listener, below the HTTP layer.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

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

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_memory() {
    let test_env = launch_memory();
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
async fn integration_db() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let path = tempdir.path().to_path_buf();
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    let test_env = waterfall::test_env::launch(exe, Some(path));
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
fn launch_memory() -> waterfall::test_env::TestEnv {
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    waterfall::test_env::launch(exe, None)
}

#[cfg(all(feature = "test_env", not(feature = "db")))]
fn launch_memory() -> waterfall::test_env::TestEnv {
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    waterfall::test_env::launch(exe)
}

#[cfg(feature = "test_env")]
async fn do_test(test_env: waterfall::test_env::TestEnv) {
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    test_env.shutdown().await;
    assert!(true);
}

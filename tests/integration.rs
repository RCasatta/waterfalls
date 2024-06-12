//! # Integration testing
//!
//! This is not going to depend on LWK because we want to use this lib in LWK testing
//! Thus following tests aren't a proper wallet scan but they checks memory/db backend and also
//! mempool/confirmation result in receiving a payment

use waterfall::route::Output;

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_memory() {
    let test_env = launch_memory().await;
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
async fn integration_db() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let path = tempdir.path().to_path_buf();
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    let test_env = waterfall::test_env::launch(exe, Some(path)).await;
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
async fn launch_memory() -> waterfall::test_env::TestEnv {
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    waterfall::test_env::launch(exe, None).await
}

#[cfg(all(feature = "test_env", not(feature = "db")))]
async fn launch_memory() -> waterfall::test_env::TestEnv {
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    waterfall::test_env::launch(exe).await
}

#[cfg(feature = "test_env")]
async fn do_test(test_env: waterfall::test_env::TestEnv) {
    use elements::{bitcoin::secp256k1, AddressParams};
    use elements_miniscript::{ConfidentialDescriptor, DescriptorPublicKey};
    use std::str::FromStr;
    let secp = secp256k1::Secp256k1::new();

    let bitcoin_desc = "elwpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";
    let single_bitcoin_desc = bitcoin_desc.replace("<0;1>", "0");
    let blinding = "slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023)";
    let desc_str = format!("ct({blinding},{single_bitcoin_desc})#qwqap8xk"); // we use a non-multipath to generate addresses
    let base_url = test_env.base_url();
    let client = reqwest::Client::new();
    let result = make_waterfall_req(&client, &base_url, &bitcoin_desc).await;

    let desc = ConfidentialDescriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();
    let addr = desc
        .at_derivation_index(0)
        .unwrap()
        .address(&secp, &AddressParams::ELEMENTS)
        .unwrap();

    test_env.send_to(&addr, 10_000);

    tokio::time::sleep(std::time::Duration::from_secs(1)).await; // give some time to start the server

    let result = make_waterfall_req(&client, &base_url, &bitcoin_desc).await;

    test_env.shutdown().await;
    assert!(true);
}

async fn make_waterfall_req(client: &reqwest::Client, base_url: &str, desc: &str) -> Output {
    let descriptor_url = format!("{}/v1/waterfall", base_url);

    let response = client
        .get(&descriptor_url)
        .query(&[("descriptor", desc)])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
    let body = response.text().await.unwrap();
    println!("{body}");
    serde_json::from_str(&body).unwrap()
}

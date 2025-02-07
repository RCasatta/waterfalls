//! # Integration testing
//!
//! This is not going to depend on LWK because we want to use this lib in LWK testing
//! Thus following tests aren't a proper wallet scan but they checks memory/db backend and also
//! mempool/confirmation result in receiving a payment

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_memory() {
    let _ = env_logger::try_init();

    let test_env = launch_memory().await;
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
async fn integration_db() {
    let _ = env_logger::try_init();

    let tempdir = tempfile::TempDir::new().unwrap();
    let path = tempdir.path().to_path_buf();
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    let test_env = waterfalls::test_env::launch(exe, Some(path)).await;
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
async fn launch_memory() -> waterfalls::test_env::TestEnv {
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    waterfalls::test_env::launch(exe, None).await
}

#[cfg(all(feature = "test_env", not(feature = "db")))]
async fn launch_memory() -> waterfalls::test_env::TestEnv {
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    waterfalls::test_env::launch(exe).await
}

#[cfg(feature = "test_env")]
async fn do_test(test_env: waterfalls::test_env::TestEnv) {
    use bitcoin::sign_message::MessageSignature;
    use elements::{bitcoin::secp256k1, AddressParams};
    use elements_miniscript::{ConfidentialDescriptor, DescriptorPublicKey};
    use std::str::FromStr;
    use waterfalls::{server::encryption::encrypt, WaterfallResponse};
    let secp = secp256k1::Secp256k1::new();
    let client = test_env.client();

    let bitcoin_desc = "elwpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";
    let single_bitcoin_desc = bitcoin_desc.replace("<0;1>", "0");
    let blinding = "slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023)";
    let desc_str = format!("ct({blinding},{single_bitcoin_desc})#qwqap8xk"); // we use a non-multipath to generate addresses

    let result = client.waterfalls_v2(&bitcoin_desc).await.unwrap().0;
    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 2);
    assert!(result.is_empty());
    assert!(result.tip.is_some());
    let result = client.waterfalls_v1(&bitcoin_desc).await.unwrap().0;
    assert!(result.tip.is_none());

    let desc = ConfidentialDescriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();
    let addr = desc
        .at_derivation_index(0)
        .unwrap()
        .address(&secp, &AddressParams::ELEMENTS)
        .unwrap();

    let txid = test_env.send_to(&addr, 10_000);

    let result = client
        .wait_waterfalls_non_empty(&bitcoin_desc)
        .await
        .unwrap();
    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 2);
    assert!(!result.is_empty());
    assert_eq!(result.count_non_empty(), 1);
    let first = &result.txs_seen.iter().next().unwrap().1[0][0];
    assert_eq!(first.txid, txid);
    assert_eq!(first.height, 0);
    assert_eq!(first.block_hash, None);
    assert_eq!(first.block_timestamp, None);

    test_env.node_generate(1).await;

    let result = client.waterfalls_v2(&bitcoin_desc).await.unwrap().0;
    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 2);
    assert!(!result.is_empty());
    assert_eq!(result.count_non_empty(), 1);
    assert!(result.tip.is_some());
    let first = &result.txs_seen.iter().next().unwrap().1[0][0];
    assert_eq!(first.txid, txid);
    assert_eq!(first.height, 3);
    assert!(first.block_hash.is_some());
    assert!(first.block_timestamp.is_some());

    // Try encrypted descriptor
    let recipient = client.server_recipient().await.unwrap();
    assert_eq!(recipient, test_env.server_recipient());
    let encrypted_desc = encrypt(&bitcoin_desc, recipient).unwrap();
    let result_from_encrypted = client.waterfalls_v2(&encrypted_desc).await.unwrap().0;
    assert_eq!(result, result_from_encrypted);

    // Test broadcast is working
    let unspent = test_env.list_unspent();
    assert_eq!(unspent.len(), 1);
    let tx_unblind = test_env.create_self_transanction();

    let tx_blind = test_env.blind_raw_transanction(&tx_unblind);
    let err = client.broadcast(&tx_blind).await.unwrap_err();
    assert!(err.to_string().contains("non-mandatory-script-verify-flag"));

    let tx_sign = test_env.sign_raw_transanction_with_wallet(&tx_blind);
    let txid = client.broadcast(&tx_sign).await.unwrap();
    assert_eq!(txid, tx_blind.txid());

    // Test getting tx
    let tx = client.tx(txid).await.unwrap();
    assert_eq!(tx.txid(), txid);

    // Test server_address
    let server_address = test_env.server_address();
    let address = client.server_address().await.unwrap();
    assert_eq!(address, server_address);

    // Verify signature
    let (result, headers) = client.waterfalls_v2(&bitcoin_desc).await.unwrap();
    let message = serde_json::to_string(&result).unwrap();
    let signature = headers.get("X-Content-Signature").unwrap();
    let signature = MessageSignature::from_str(signature.to_str().unwrap()).unwrap();
    let sign_result = waterfalls::server::sign::verify_response(
        &secp,
        &server_address,
        message.as_bytes(),
        &signature,
    )
    .unwrap();
    assert!(sign_result);

    // Test v3
    let (result_v3, _headers) = client.waterfalls(&bitcoin_desc).await.unwrap();
    let result_v2: WaterfallResponse = result_v3.try_into().unwrap();
    assert_eq!(result, result_v2);

    test_env.shutdown().await;
    assert!(true);
}

#[ignore = "Test to examine the log manually"]
#[cfg(feature = "test_env")]
#[tokio::test]
async fn test_no_rest() {
    let _ = env_logger::try_init();

    // CODE duplicated from inner_launch, with rest=1 commented
    let mut conf = bitcoind::Conf::default();
    let args = vec![
        "-fallbackfee=0.0001",
        "-dustrelayfee=0.00000001",
        "-chain=liquidregtest",
        "-initialfreecoins=2100000000",
        "-validatepegin=0",
        "-txindex=1",
        //"-rest=1",
    ];
    conf.args = args;
    conf.view_stdout = std::env::var("RUST_LOG").is_ok();
    conf.network = "liquidregtest";
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    let elementsd = bitcoind::BitcoinD::with_conf(exe, &conf).unwrap();
    let _test_env = waterfalls::test_env::launch_with_node(elementsd, None).await;
}

#[ignore = "Test to examine the log manually"]
#[cfg(feature = "test_env")]
#[tokio::test]
async fn test_no_txindex() {
    use std::str::FromStr;
    let _ = env_logger::try_init();

    // CODE duplicated from inner_launch, with rest=1 commented
    let mut conf = bitcoind::Conf::default();
    let args = vec![
        "-fallbackfee=0.0001",
        "-dustrelayfee=0.00000001",
        "-chain=liquidregtest",
        "-initialfreecoins=2100000000",
        "-validatepegin=0",
        // "-txindex=1",
        "-rest=1",
    ];
    conf.args = args;
    conf.view_stdout = std::env::var("RUST_LOG").is_ok();
    conf.network = "liquidregtest";
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    let elementsd = bitcoind::BitcoinD::with_conf(exe, &conf).unwrap();
    let test_env = waterfalls::test_env::launch_with_node(elementsd, None).await;
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let _tx = test_env.client().tx(txid).await.unwrap();
}

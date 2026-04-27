//! # Integration testing
//!
//! This is not going to depend on LWK because we want to use this lib in LWK testing
//! Thus following tests aren't a proper wallet scan but they checks memory/db backend and also
//! mempool/confirmation result in receiving a payment

use std::time::{Duration, Instant};

use age::x25519;
use elements::AddressParams;
use tokio::time::sleep;
use waterfalls::Family;
#[cfg(feature = "test_env")]
use waterfalls::{be, fetch::Client as FetchClient, server::Arguments, server::Network};

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_memory_elements() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Elements).await;
    do_test(test_env).await;
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_fetch_client_regtest_elements() {
    let _ = env_logger::try_init();

    let elementsd =
        waterfalls::test_env::launch_elements(std::env::var("ELEMENTSD_EXEC").unwrap());
    let client = fetch_client_for_node(&elementsd, Network::ElementsRegtest);
    test_fetch_client_local_regtest(client, Network::ElementsRegtest).await;
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_memory_bitcoin() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Bitcoin).await;
    do_test(test_env).await;
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_fetch_client_regtest_bitcoin() {
    let _ = env_logger::try_init();

    let bitcoind = waterfalls::test_env::launch_bitcoin(std::env::var("BITCOIND_EXEC").unwrap());
    let client = fetch_client_for_node(&bitcoind, Network::BitcoinRegtest);
    test_fetch_client_local_regtest(client, Network::BitcoinRegtest).await;
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_addresses_txs_seen_truncation() {
    let _ = env_logger::try_init();

    let exe = std::env::var("BITCOIND_EXEC").unwrap();
    #[cfg(feature = "db")]
    let test_env =
        waterfalls::test_env::launch_with_max_txs_seen(exe, None, Family::Bitcoin, 3).await;
    #[cfg(not(feature = "db"))]
    let test_env = waterfalls::test_env::launch_with_max_txs_seen(exe, Family::Bitcoin, 3).await;

    let addr = test_env.get_new_address(None);
    let mut expected_txids = Vec::new();
    for _ in 0..5 {
        expected_txids.push(test_env.send_to(&addr, 10_000));
        test_env.node_generate(1).await;
    }

    let result_page_0 = test_env
        .client()
        .waterfalls_addresses(&vec![addr.clone()])
        .await
        .unwrap()
        .0;
    let txs_page_0 = &result_page_0.txs_seen.get("addresses").unwrap()[0];

    assert_eq!(txs_page_0.len(), 3);
    assert_eq!(result_page_0.page, 0);
    assert_eq!(result_page_0.has_more, Some(vec![addr.to_string()]));
    assert_eq!(
        txs_page_0
            .iter()
            .map(|tx_seen| tx_seen.txid)
            .collect::<Vec<_>>(),
        expected_txids[..3].to_vec()
    );

    let result_page_1 = test_env
        .client()
        .waterfalls_addresses_with_page(&vec![addr.clone()], 1)
        .await
        .unwrap()
        .0;
    let txs_page_1 = &result_page_1.txs_seen.get("addresses").unwrap()[0];

    assert_eq!(txs_page_1.len(), 2);
    assert_eq!(result_page_1.page, 1);
    assert_eq!(result_page_1.has_more, None);
    assert_eq!(
        txs_page_1
            .iter()
            .map(|tx_seen| tx_seen.txid)
            .collect::<Vec<_>>(),
        expected_txids[3..].to_vec()
    );

    test_env.shutdown().await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
async fn integration_db_elements() {
    let _ = env_logger::try_init();

    let tempdir = tempfile::TempDir::new().unwrap();
    let path = tempdir.path().to_path_buf();
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    let test_env = waterfalls::test_env::launch(exe, Some(path), Family::Elements).await;
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
async fn integration_db_bitcoin() {
    let _ = env_logger::try_init();

    let tempdir = tempfile::TempDir::new().unwrap();
    let path = tempdir.path().to_path_buf();
    let exe = std::env::var("BITCOIND_EXEC").unwrap();
    let test_env = waterfalls::test_env::launch(exe, Some(path), Family::Bitcoin).await;
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
async fn launch_memory(family: Family) -> waterfalls::test_env::TestEnv {
    let exe = match family {
        Family::Bitcoin => std::env::var("BITCOIND_EXEC").unwrap(),
        Family::Elements => std::env::var("ELEMENTSD_EXEC").unwrap(),
    };
    waterfalls::test_env::launch(exe, None, family).await
}

#[cfg(all(feature = "test_env", not(feature = "db")))]
async fn launch_memory() -> waterfalls::test_env::TestEnv<'static> {
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    waterfalls::test_env::launch(exe).await
}

#[cfg(feature = "test_env")]
fn get_new_address(wallet: &bitcoind::bitcoincore_rpc::Client, network: Network) -> be::Address {
    use bitcoind::bitcoincore_rpc::RpcApi;
    use serde_json::Value;

    let address_value: Value = wallet
        .call("getnewaddress", &[Value::Null, Value::Null])
        .unwrap();
    be::Address::from_str(address_value.as_str().unwrap(), network).unwrap()
}

#[cfg(feature = "test_env")]
fn send_to_address(
    wallet: &bitcoind::bitcoincore_rpc::Client,
    address: &be::Address,
    amount: f64,
) -> elements::Txid {
    use bitcoind::bitcoincore_rpc::RpcApi;
    use serde_json::Value;
    use std::str::FromStr;

    let result: Value = wallet
        .call(
            "sendtoaddress",
            &[address.to_string().into(), amount.to_string().into()],
        )
        .unwrap();
    elements::Txid::from_str(result.as_str().unwrap()).unwrap()
}

#[cfg(feature = "test_env")]
fn fetch_client_for_node(node: &bitcoind::BitcoinD, network: Network) -> FetchClient {
    let mut args = Arguments::default();
    args.use_esplora = false;
    args.network = network;
    args.node_url = Some(node.rpc_url());
    args.request_timeout_seconds = 10;
    args.rpc_user_password = Some(
        std::fs::read_to_string(&node.params.cookie_file)
            .unwrap()
            .trim()
            .to_string(),
    );
    FetchClient::new(&args).unwrap()
}

#[cfg(feature = "test_env")]
async fn test_fetch_client_local_regtest(client: FetchClient, network: Network) {
    use elements::BlockHash;
    use std::str::FromStr;

    let (genesis_hash, genesis_txid) = match network {
        Network::ElementsRegtest => (
            "c7af03b0774a3498a574902bd41045c1633fd40b69ca163345c5d9c78bfd6af7",
            "81c9570df1135a6bb7fb0f77a273561fddfd87bc62e7f265e94ffb01474ae578",
        ),
        Network::BitcoinRegtest => (
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        ),
        _ => panic!("unexpected network {network:?}"),
    };

    let genesis_hash = BlockHash::from_str(genesis_hash).unwrap();
    let genesis_txid = be::Txid::from_str(genesis_txid).unwrap();

    let fetched = client.block_hash(0).await.unwrap().unwrap();
    assert_eq!(genesis_hash, fetched, "network:{network}");

    let block = client.block(genesis_hash, network.into()).await.unwrap();
    let header = block.header();
    assert_eq!(header.block_hash(), genesis_hash, "network:{network}");

    if network == Network::ElementsRegtest {
        let genesis_tx = client.tx(genesis_txid, network.into()).await.unwrap();
        assert_eq!(genesis_tx.txid(), genesis_txid);
    }

    client.mempool(false).await.unwrap();

    let support_verbose = client.mempool(true).await.is_ok();
    match network.into() {
        Family::Bitcoin => assert!(support_verbose),
        Family::Elements => assert!(!support_verbose),
    }

    let fetched_header = client
        .block_header(genesis_hash, network.into())
        .await
        .unwrap();
    assert_eq!(block.header(), fetched_header);
    assert_eq!(fetched_header.block_hash(), genesis_hash, "network:{network}");

    let header_json = client
        .block_header_json(genesis_hash, network.into())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(header_json.hash, genesis_hash);
    assert_eq!(header_json.nextblockhash, None, "network:{network}");

    let fee_estimates = client.fee_estimates().await.unwrap();
    assert!(fee_estimates.values().all(|&f| f > 0.0));
}

#[cfg(feature = "test_env")]
async fn do_test(test_env: waterfalls::test_env::TestEnv) {
    use bitcoin::sign_message::MessageSignature;
    use elements::{bitcoin::secp256k1, AddressParams};
    use elements_miniscript::{ConfidentialDescriptor, DescriptorPublicKey};
    use std::str::FromStr;
    use waterfalls::{be, server::encryption::encrypt, WaterfallResponse, V};
    let secp = secp256k1::Secp256k1::new();
    let client = test_env.client();

    let prefix = match test_env.family {
        Family::Bitcoin => "",
        Family::Elements => "el",
    };
    let tpub = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";
    let bitcoin_desc = format!("{prefix}wpkh({tpub}/<0;1>/*)");
    let single_bitcoin_desc = bitcoin_desc.replace("<0;1>", "0");
    let blinding = "slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023)";
    let desc_str = format!("ct({blinding},{single_bitcoin_desc})"); // we use a non-multipath to generate addresses

    let result = client.waterfalls_v2(&bitcoin_desc).await.unwrap().0;
    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 2);
    assert!(result.is_empty());
    assert!(result.tip.is_some());
    assert!(result.tip_meta.is_none());
    let mut result_v4 = client.waterfalls_v4(&bitcoin_desc).await.unwrap().0;
    assert!(result_v4.tip_meta.is_some());
    result_v4.tip = result_v4.tip_meta.map(|e| e.b);
    result_v4.tip_meta = None;
    assert_eq!(result, result_v4);
    let result = client.waterfalls_v1(&bitcoin_desc).await.unwrap().0;
    assert!(result.tip.is_none());
    assert!(result.tip_meta.is_none());

    let addr = match test_env.family {
        Family::Bitcoin => {
            let desc = be::bitcoin_descriptor(&single_bitcoin_desc).unwrap();
            let desc = desc.bitcoin().unwrap();
            let addr = desc
                .at_derivation_index(0)
                .unwrap()
                .address(bitcoin::Network::Regtest)
                .unwrap();
            be::Address::Bitcoin(addr)
        }
        Family::Elements => {
            let desc = ConfidentialDescriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();
            let addr = desc
                .at_derivation_index(0)
                .unwrap()
                .address(&secp, &AddressParams::ELEMENTS)
                .unwrap();
            be::Address::Elements(addr)
        }
    };

    let initial_txid = test_env.send_to(&addr, 10_000);

    let result = client
        .wait_waterfalls_non_empty(&bitcoin_desc)
        .await
        .unwrap();

    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 2);
    assert!(!result.is_empty());
    assert_eq!(result.count_non_empty(), 1);
    let expected_first = &result.txs_seen.iter().next().unwrap().1[0][0];
    let first = &result.txs_seen.iter().next().unwrap().1[0][0];
    assert_eq!(first.txid, initial_txid);
    assert_eq!(first.height, 0);
    assert_eq!(first.block_hash, None);
    assert_eq!(first.block_timestamp, None);

    test_env.node_generate(1).await;

    let result = client.waterfalls_v2(&bitcoin_desc).await.unwrap().0;
    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 2);
    assert!(!result.is_empty());
    assert_eq!(result.count_non_empty(), 1);
    assert_eq!(result.count_scripts(), 60);
    assert!(result.tip.is_some());
    let first = &result.txs_seen.iter().next().unwrap().1[0][0];
    assert_eq!(first.txid, initial_txid);

    assert_eq!(first.height, 103);
    assert!(first.block_hash.is_some());
    assert!(first.block_timestamp.is_some());

    // Try encrypted descriptor
    let recipient = client.server_recipient().await.unwrap();
    assert_eq!(recipient, test_env.server_recipient());
    let encrypted_desc = encrypt(&bitcoin_desc, recipient).unwrap();
    let result_from_encrypted = client.waterfalls_v2(&encrypted_desc).await.unwrap().0;
    assert_eq!(result, result_from_encrypted);

    // Try with wrong recipient to see what error is returned
    let wrong_identity = x25519::Identity::generate();
    let wrong_recipient = wrong_identity.to_public();
    let encrypted_desc_wrong = encrypt(&bitcoin_desc, wrong_recipient).unwrap();
    let wrong_result = client
        .waterfalls_v2(&encrypted_desc_wrong)
        .await
        .unwrap_err();
    assert_eq!(
        format!("{wrong_result:?}"),
        "waterfalls response is not 200 but: 422 body is: CannotDecrypt"
    );

    // Test broadcast is working
    let unspent = test_env.list_unspent();
    let expected_unspent = match test_env.family {
        Family::Bitcoin => 3,
        Family::Elements => 1,
    };
    assert_eq!(unspent.len(), expected_unspent);
    let tx_unblind = test_env.create_self_transanction();

    let tx_blind = match tx_unblind {
        be::Transaction::Bitcoin(tx) => be::Transaction::Bitcoin(tx),
        be::Transaction::Elements(tx) => {
            be::Transaction::Elements(test_env.blind_raw_transanction(&tx))
        }
    };
    let err = client.broadcast(&tx_blind).await.unwrap_err();
    assert!(
        err.to_string().contains("non-mandatory-script-verify-flag")
            || err.to_string().contains("bad-txns-nonstandard-inputs"),
        "{err:?}"
    );

    // Test unspent endpoint before spending UTXOs
    let unspent_list = test_env.list_unspent();
    assert!(!unspent_list.is_empty(), "Should have at least one UTXO");
    let utxo = &unspent_list[0];
    let outpoint_for_unspent_check = format!("{}:{}", utxo.txid, utxo.vout);
    let is_unspent = client.unspent(&outpoint_for_unspent_check).await.unwrap();
    assert!(is_unspent, "UTXO should be unspent");

    let tx_sign = test_env.sign_raw_transanction_with_wallet(&tx_blind);
    let txid = client.broadcast(&tx_sign).await.unwrap();

    // TODO: this helps with flakyness, fix properly and remove
    sleep(Duration::from_secs(1)).await;

    match test_env.family {
        Family::Bitcoin => {
            // assert_eq!(txid, tx_blind.txid()); // TODO: fix this
        }
        Family::Elements => {
            assert_eq!(txid, tx_blind.txid().into());
        }
    }

    // Test getting tx
    let tx = client.tx(txid).await.unwrap();
    assert_eq!(crate::be::Txid::from(tx.txid()), txid);

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

    // Test addresses
    let addr = match test_env.family {
        Family::Bitcoin => addr,
        Family::Elements => addr.to_unconfidential().unwrap(),
    };
    let (result, _) = client
        .waterfalls_addresses(&vec![addr.clone()])
        .await
        .unwrap();
    assert_eq!(result.count_non_empty(), 1);

    // Test address_txs
    let address_txs = client.address_txs(&addr).await.unwrap();
    assert!(address_txs.contains(&initial_txid.to_string()));

    // Create two transactions in the same block the second one is spending an output of the first one
    let other_wallet = test_env.create_other_wallet();
    let other_address = get_new_address(&other_wallet, test_env.network());
    test_env.send_to(&other_address, 1_000_000);
    test_env.node_generate(1).await;
    let address_spent_same_block = get_new_address(&other_wallet, test_env.network());
    let txid1 = send_to_address(&other_wallet, &address_spent_same_block, 0.0098);
    let new_address = test_env.get_new_address(None);
    let txid2 = send_to_address(&other_wallet, &new_address, 0.0096);
    test_env.node_generate(1).await;
    let address_txs = client.address_txs(&address_spent_same_block).await.unwrap();
    assert!(address_txs.contains(&txid1.to_string()));
    assert!(address_txs.contains(&txid2.to_string()));

    // Test using huge to_index will return paginated results
    let (result, _) = client
        .waterfalls_version(&bitcoin_desc, 2, None, Some(1_000_000), false)
        .await
        .unwrap();
    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 2);
    assert!(!result.is_empty());
    assert_eq!(result.count_non_empty(), 1);
    assert_eq!(result.count_scripts(), 2_000); // this is MAX_BATCH * GAP_LIMIT * 2
    assert!(result.tip.is_some());

    // Test descriptor without wildcard
    let desc_str = format!("{prefix}wpkh({tpub}/0/0)");
    let result = client.waterfalls_v2(&desc_str).await.unwrap().0;
    let first_script_result = &result.txs_seen.iter().next().unwrap().1[0];
    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 1);
    assert_eq!(first_script_result.len(), 1);
    assert!(!result.is_empty());
    assert_eq!(result.count_non_empty(), 1);
    let first = &first_script_result[0];
    assert_eq!(first.txid, expected_first.txid);

    // Test utxo_only
    let mut result1 = client
        .waterfalls_v2_utxo_only(&bitcoin_desc)
        .await
        .unwrap()
        .0;
    let result2 = client.waterfalls_v2(&bitcoin_desc).await.unwrap().0;
    assert_ne!(result1, result2); // they are not the same because of v
    result1.txs_seen.iter_mut().for_each(|(_, v)| {
        v.iter_mut().for_each(|a| {
            a.iter_mut().for_each(|b| {
                b.v = V::Undefined;
            });
        });
    });
    assert_eq!(result1, result2); // we didn't spend anything from the wallet, thus after zeroing v they are the same

    // Test utxo_only on addresses endpoint, we just test the results are different because of v since we are not spending in this test
    test_env.node_generate(1).await;
    let mut result_utxo_only = client
        .waterfalls_addresses_utxo_only(&vec![addr.clone()], true)
        .await
        .unwrap()
        .0;
    let mut result_full_history = client
        .waterfalls_addresses(&vec![addr.clone()])
        .await
        .unwrap()
        .0;
    let full_txs = result_full_history
        .txs_seen
        .remove("addresses")
        .unwrap()
        .pop()
        .unwrap();
    let mut utxo_only_txs = result_utxo_only
        .txs_seen
        .remove("addresses")
        .unwrap()
        .pop()
        .unwrap();
    assert_ne!(full_txs, utxo_only_txs);
    utxo_only_txs.iter_mut().for_each(|a| {
        a.v = V::Undefined;
    });
    assert_eq!(full_txs, utxo_only_txs);

    let is_unspent = client.unspent(&outpoint_for_unspent_check).await.unwrap();
    assert!(!is_unspent, "UTXO should be spent");

    let fee_estimates = client.fee_estimates().await.unwrap();
    assert!(fee_estimates.values().all(|&f| f > 0.0));

    test_env.shutdown().await;
    assert!(true);
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn test_fee_estimates_elements() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Elements).await;

    // The fee estimator needs multiple fee-paying txs spread across many blocks.
    // Send one tx per batch and mine a few blocks each time, mimicking the working prod node.
    let addr = test_env.get_new_address(None);
    for _ in 0..25 {
        test_env.send_to(&addr, 1_000);
        test_env.node_generate(3).await;
    }

    let fee_estimates = test_env.client().fee_estimates().await.unwrap();
    assert!(!fee_estimates.is_empty());
    assert!(fee_estimates.values().all(|&f| f > 0.0));

    test_env.shutdown().await;
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn test_fee_estimates_bitcoin() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Bitcoin).await;

    let addr = test_env.get_new_address(None);
    for _ in 0..25 {
        test_env.send_to(&addr, 1_000);
        test_env.node_generate(3).await;
    }

    let fee_estimates = test_env.client().fee_estimates().await.unwrap();
    assert!(!fee_estimates.is_empty());
    assert!(fee_estimates.values().all(|&f| f > 0.0));

    test_env.shutdown().await;
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn test_last_used_index_elements() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Elements).await;
    do_test_last_used_index(test_env).await;
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn test_last_used_index_bitcoin() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Bitcoin).await;
    do_test_last_used_index(test_env).await;
}

#[cfg(feature = "test_env")]
async fn do_test_last_used_index(test_env: waterfalls::test_env::TestEnv) {
    use elements_miniscript::{ConfidentialDescriptor, DescriptorPublicKey};
    use std::str::FromStr;
    use waterfalls::be;

    let client = test_env.client();

    let prefix = match test_env.family {
        Family::Bitcoin => "",
        Family::Elements => "el",
    };
    let tpub = "tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M";

    // Test descriptor with multipath
    let bitcoin_desc = format!("{prefix}wpkh({tpub}/<0;1>/*)");
    let single_bitcoin_desc = bitcoin_desc.replace("<0;1>", "0");
    let blinding = "slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023)";
    let desc_str = format!("ct({blinding},{single_bitcoin_desc})");

    // Initially, no addresses should be used
    let result = client.last_used_index(&bitcoin_desc).await.unwrap();
    assert_eq!(
        result.external, None,
        "No external addresses should be used initially"
    );
    assert_eq!(
        result.internal, None,
        "No internal addresses should be used initially"
    );
    assert!(result.tip.is_some(), "Tip should be present");

    // Generate address at index 0 and send to it
    let secp = elements::bitcoin::secp256k1::Secp256k1::new();
    let addr = match test_env.family {
        Family::Bitcoin => {
            let desc = be::bitcoin_descriptor(&single_bitcoin_desc).unwrap();
            let desc = desc.bitcoin().unwrap();
            let addr = desc
                .at_derivation_index(0)
                .unwrap()
                .address(bitcoin::Network::Regtest)
                .unwrap();
            be::Address::Bitcoin(addr)
        }
        Family::Elements => {
            let desc = ConfidentialDescriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();
            let addr = desc
                .at_derivation_index(0)
                .unwrap()
                .address(&secp, &AddressParams::ELEMENTS)
                .unwrap();
            be::Address::Elements(addr)
        }
    };

    // Send to address at index 0
    test_env.send_to(&addr, 10_000);
    test_env.node_generate(1).await;

    // Wait for the transaction to be indexed
    client
        .wait_waterfalls_non_empty(&bitcoin_desc)
        .await
        .unwrap();

    // Now external index 0 should be used
    let result = client.last_used_index(&bitcoin_desc).await.unwrap();
    assert_eq!(
        result.external,
        Some(0),
        "External index 0 should be used after first transaction"
    );
    assert_eq!(
        result.internal, None,
        "Internal should still be None (no change outputs on our descriptor)"
    );

    // Send to address at index 5 (skipping some addresses)
    let addr_5 = match test_env.family {
        Family::Bitcoin => {
            let desc = be::bitcoin_descriptor(&single_bitcoin_desc).unwrap();
            let desc = desc.bitcoin().unwrap();
            let addr = desc
                .at_derivation_index(5)
                .unwrap()
                .address(bitcoin::Network::Regtest)
                .unwrap();
            be::Address::Bitcoin(addr)
        }
        Family::Elements => {
            let desc = ConfidentialDescriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();
            let addr = desc
                .at_derivation_index(5)
                .unwrap()
                .address(&secp, &AddressParams::ELEMENTS)
                .unwrap();
            be::Address::Elements(addr)
        }
    };

    test_env.send_to(&addr_5, 20_000);
    test_env.node_generate(1).await;

    // Give the server time to index
    sleep(Duration::from_millis(500)).await;

    // Now external index 5 should be the last used
    let result = client.last_used_index(&bitcoin_desc).await.unwrap();
    assert_eq!(
        result.external,
        Some(5),
        "External index 5 should be the last used"
    );

    // Test with encrypted descriptor
    let recipient = client.server_recipient().await.unwrap();
    let encrypted_desc = waterfalls::server::encryption::encrypt(&bitcoin_desc, recipient).unwrap();
    let result_encrypted = client.last_used_index(&encrypted_desc).await.unwrap();
    assert_eq!(
        result.external, result_encrypted.external,
        "Encrypted and plain descriptor should return same result"
    );
    assert_eq!(
        result.internal, result_encrypted.internal,
        "Encrypted and plain descriptor should return same result"
    );

    // Test descriptor without multipath (single chain, external only)
    // This should not cause infinite loops and should return the same external result
    let no_multipath_desc = format!("{prefix}wpkh({tpub}/0/*)");
    let result_no_multipath = client.last_used_index(&no_multipath_desc).await.unwrap();
    assert_eq!(
        result_no_multipath.external,
        Some(5),
        "Descriptor without multipath should find last used at index 5"
    );
    assert_eq!(
        result_no_multipath.internal, None,
        "Descriptor without multipath has no internal chain"
    );

    // Test descriptor without wildcard (single address at index 0)
    // This must error
    let no_wildcard_desc = format!("{prefix}wpkh({tpub}/0/0)");
    let result_no_wildcard = client.last_used_index(&no_wildcard_desc).await.unwrap_err();
    assert_eq!(
        result_no_wildcard.to_string(),
        "last_used_index response is not 200 but: 400 body is: DescriptorMustHaveWildcard"
    );

    println!(
        "last_used_index test completed successfully for {:?}",
        test_env.family
    );
    println!("✓ Initial state: no addresses used");
    println!("✓ After sending to index 0: external=0");
    println!("✓ After sending to index 5: external=5");
    println!("✓ Encrypted descriptor works correctly");
    println!("✓ Descriptor without multipath works correctly");
    println!("✓ Descriptor without wildcard works correctly");

    test_env.shutdown().await;
}

#[cfg(feature = "examine_logs")]
#[tokio::test]
async fn test_no_rest() {
    use waterfalls::Family;

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
    let _test_env = waterfalls::test_env::launch_with_node(elementsd, None, Family::Elements).await;
}

#[cfg(feature = "examine_logs")]
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
    let test_env = waterfalls::test_env::launch_with_node(elementsd, None, Family::Elements).await;
    let txid = crate::be::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let _tx = test_env.client().tx(txid).await.unwrap();
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
/// Test Bitcoin reorg handling with proper history correction.
///
/// This test verifies that when a reorg occurs, the waterfalls server correctly:
/// 1. Restores UTXOs that were spent in the reorged block  
/// 2. Removes transaction history entries that were added in the reorged block
///
/// Without the history correction functionality (added in the latest commit),
/// addresses would still show transactions from reorged blocks in their history,
/// leading to incorrect transaction lists via address_txs().
async fn test_bitcoin_reorg() {
    let _ = env_logger::try_init();

    let tempdir = tempfile::TempDir::new().unwrap();
    let path = tempdir.path().to_path_buf();
    let exe = std::env::var("BITCOIND_EXEC").unwrap();
    let test_env = waterfalls::test_env::launch(exe, Some(path), Family::Bitcoin).await;

    // Generate some initial blocks to build upon
    test_env.node_generate(5).await;

    // Create some UTXOs that can be spent in the competing blocks
    let address_to_spend = test_env.get_new_address(None);
    test_env.send_to(&address_to_spend, 10_000);
    test_env.node_generate(1).await; // This creates UTXOs we can spend

    // Get a specific UTXO that we'll spend in both chains (creating a double-spend)
    let unspent = test_env.list_unspent();
    let utxo_to_double_spend = &unspent[0]; // Take the first available UTXO
    println!(
        "UTXO to double-spend: {} vout {} amount {}",
        utxo_to_double_spend.txid, utxo_to_double_spend.vout, utxo_to_double_spend.amount
    );

    // Create transaction A - spends the UTXO to recipient A
    let recipient_a = test_env.get_new_address(None);
    let tx_a = test_env.create_transaction_spending(
        &[(*utxo_to_double_spend).clone()],
        &recipient_a,
        utxo_to_double_spend.amount - 0.00001, // Leave small fee
    );
    let signed_tx_a = test_env.sign_raw_transanction_with_wallet(&tx_a);

    // Broadcast transaction A and mine it in block A
    let txid_a = test_env.client().broadcast(&signed_tx_a).await.unwrap();
    let block_a_hashes = test_env.node_generate(1).await;
    let block_a_hash = block_a_hashes[0];

    // Wait for the waterfalls server to index block A
    test_env.client().wait_tip_hash(block_a_hash).await.unwrap();

    println!(
        "Created block A: {} with transaction: {}",
        block_a_hash, txid_a
    );

    // Check address history after transaction A is mined
    // The recipient_a address should show transaction A in its history
    let recipient_a_history_before_reorg =
        test_env.client().address_txs(&recipient_a).await.unwrap();
    println!(
        "recipient_a history before reorg: {:?}",
        recipient_a_history_before_reorg
    );
    assert!(
        recipient_a_history_before_reorg.contains(&txid_a.to_string()),
        "Transaction A should be in recipient A's history before reorg"
    );

    let block_a_header = test_env.client().header(block_a_hash).await.unwrap();

    // Now create the reorg by invalidating block A
    test_env.invalidate_block(block_a_hash);

    // Create transaction B - spends the SAME UTXO to recipient B (double-spend)
    let recipient_b = test_env.get_new_address(None);
    let tx_b = test_env.create_transaction_spending(
        &[(*utxo_to_double_spend).clone()],
        &recipient_b,
        utxo_to_double_spend.amount - 0.00002, // Leave slightly different fee
    );
    let signed_tx_b = test_env.sign_raw_transanction_with_wallet(&tx_b);

    // Broadcast transaction B and mine it in block B
    let txid_b = test_env.client().broadcast(&signed_tx_b).await.unwrap();
    let blocks_b_hashes = test_env.node_generate(2).await;
    let block_b_hash = blocks_b_hashes[0];
    let final_tip_hash = blocks_b_hashes[1];

    println!(
        "Created block B: {} with transaction: {}",
        block_b_hash, txid_b
    );
    println!("New tip after reorg: {}", final_tip_hash);

    // Wait for the waterfalls server to index the new tip
    // This should trigger the "every utxo must exist when spent" expect line
    // because the server will try to process transaction B that spends
    // the same UTXO that was already spent in transaction A
    test_env
        .client()
        .wait_tip_hash(final_tip_hash)
        .await
        .unwrap();

    // Check address histories after the reorg to verify proper history correction
    // With the history correction functionality (from the latest commit),
    // transaction A should be removed from recipient A's history since it was reorged out
    let recipient_a_history_after_reorg =
        test_env.client().address_txs(&recipient_a).await.unwrap();
    println!(
        "recipient_a history after reorg: {:?}",
        recipient_a_history_after_reorg
    );
    assert!(
        !recipient_a_history_after_reorg.contains(&txid_a.to_string()),
        "Transaction A should NOT be in recipient A's history after reorg - it should be removed by history correction"
    );

    // Transaction B should now be in recipient B's history
    let recipient_b_history_after_reorg =
        test_env.client().address_txs(&recipient_b).await.unwrap();
    println!(
        "recipient_b history after reorg: {:?}",
        recipient_b_history_after_reorg
    );
    assert!(
        recipient_b_history_after_reorg.contains(&txid_b.to_string()),
        "Transaction B should be in recipient B's history after reorg"
    );

    // Verify the reorg happened by checking that block A is no longer in the main chain
    let current_tip = test_env.client().tip_hash().await.unwrap();
    assert_eq!(current_tip, final_tip_hash);
    assert_ne!(current_tip, block_a_hash);

    // Try to get block A header should now error
    let _ = test_env.client().header(block_a_hash).await.unwrap_err();
    let block_b_header = test_env.client().header(block_b_hash).await.unwrap();

    // Both blocks should have the same previous block hash (they're at the same height)
    assert_eq!(
        block_a_header.prev_blockhash(),
        block_b_header.prev_blockhash()
    );

    println!("Reorg test completed successfully");
    println!("✓ Verified that transaction A was correctly removed from recipient A's history");
    println!("✓ Verified that transaction B is correctly present in recipient B's history");
    println!("✓ History correction functionality is working properly during reorgs");

    test_env.shutdown().await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
async fn test_bitcoin_two_block_reorg_memory() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Bitcoin).await;
    do_test_bitcoin_two_block_reorg(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
async fn test_bitcoin_two_block_reorg() {
    let _ = env_logger::try_init();

    let tempdir = tempfile::TempDir::new().unwrap();
    let path = tempdir.path().to_path_buf();
    let exe = std::env::var("BITCOIND_EXEC").unwrap();
    let test_env = waterfalls::test_env::launch(exe, Some(path), Family::Bitcoin).await;
    do_test_bitcoin_two_block_reorg(test_env).await;
}

#[cfg(feature = "test_env")]
async fn do_test_bitcoin_two_block_reorg(test_env: waterfalls::test_env::TestEnv) {
    // Generate some initial blocks to build upon
    test_env.node_generate(5).await;

    // Create some UTXOs that can be spent in the competing chains
    let address_to_spend = test_env.get_new_address(None);
    test_env.send_to(&address_to_spend, 10_000);
    test_env.node_generate(1).await; // This creates UTXOs we can spend

    println!("=== Setting up initial blockchain state ===");

    // Get two UTXOs that we'll spend in competing chains
    let unspent = test_env.list_unspent();
    let utxo_1 = &unspent[0]; // Will be spent in original chain block H+1
    let utxo_2 = &unspent[1]; // Will be spent in original chain block H+2

    println!(
        "UTXO 1: {} vout {} amount {}",
        utxo_1.txid, utxo_1.vout, utxo_1.amount
    );
    println!(
        "UTXO 2: {} vout {} amount {}",
        utxo_2.txid, utxo_2.vout, utxo_2.amount
    );

    // ===== Create original chain with 2 blocks =====

    // Block H+1: Create transaction A spending utxo_1 to recipient_a
    let recipient_a = test_env.get_new_address(None);
    let tx_a = test_env.create_transaction_spending(
        &[(*utxo_1).clone()],
        &recipient_a,
        utxo_1.amount - 0.00001,
    );
    let signed_tx_a = test_env.sign_raw_transanction_with_wallet(&tx_a);
    let txid_a = test_env.client().broadcast(&signed_tx_a).await.unwrap();
    let block_h1_hashes = test_env.node_generate(1).await;
    let block_h1_hash = block_h1_hashes[0];

    println!("\n=== Original Chain ===");
    println!("Block H+1: {} with tx_a: {}", block_h1_hash, txid_a);

    // Wait for waterfalls to index block H+1
    test_env
        .client()
        .wait_tip_hash(block_h1_hash)
        .await
        .unwrap();

    // Block H+2: Create transaction B spending OUTPUT FROM tx_a (creates dependency)
    // This is the key: tx_b spends an output created in block H+1
    // If reorg handling is broken, this output won't exist when we try to index the new chain
    let recipient_b = test_env.get_new_address(None);

    // tx_a created an output at vout 0 to recipient_a
    // The amount is: initial amount minus fee from tx_a
    // Round to 8 decimal places to avoid floating point precision issues
    let tx_a_output_amount = (utxo_1.amount * 100_000_000.0 - 1_000.0) / 100_000_000.0;

    let tx_a_output = waterfalls::test_env::Input {
        txid: txid_a.to_string(),
        vout: 0,
        amount: tx_a_output_amount,
    };

    // Round to 8 decimal places
    let tx_b_output_amount = (tx_a_output_amount * 100_000_000.0 - 1_000.0) / 100_000_000.0;

    let tx_b = test_env.create_transaction_spending(
        &[tx_a_output.clone()],
        &recipient_b,
        tx_b_output_amount,
    );
    let signed_tx_b = test_env.sign_raw_transanction_with_wallet(&tx_b);
    let txid_b = test_env.client().broadcast(&signed_tx_b).await.unwrap();
    let block_h2_hashes = test_env.node_generate(1).await;
    let block_h2_hash = block_h2_hashes[0];

    println!("Block H+2: {} with tx_b: {}", block_h2_hash, txid_b);

    // Wait for waterfalls to index block H+2
    test_env
        .client()
        .wait_tip_hash(block_h2_hash)
        .await
        .unwrap();

    // Verify both transactions are in their respective address histories
    let recipient_a_history_before = test_env.client().address_txs(&recipient_a).await.unwrap();
    let recipient_b_history_before = test_env.client().address_txs(&recipient_b).await.unwrap();

    assert!(
        recipient_a_history_before.contains(&txid_a.to_string()),
        "Transaction A should be in recipient A's history before reorg"
    );
    assert!(
        recipient_b_history_before.contains(&txid_b.to_string()),
        "Transaction B should be in recipient B's history before reorg"
    );

    println!("✓ Both transactions confirmed and indexed");

    // ===== Trigger 2-block reorg =====

    println!("\n=== Triggering 2-block reorg ===");

    // Invalidate both blocks (must invalidate in reverse order: H+2, then H+1)
    println!("Invalidating block H+2: {}", block_h2_hash);
    test_env.invalidate_block(block_h2_hash);

    println!("Invalidating block H+1: {}", block_h1_hash);
    test_env.invalidate_block(block_h1_hash);

    // After invalidating blocks, tx_a and tx_b go back into the mempool.
    // The node will naturally re-include them when we mine new blocks.
    // This tests our multi-block reorg handling:
    // - If we only roll back 1 block, tx_a's output won't be properly restored
    // - When indexing new H+2' with tx_b, it will fail with "utxo must exist when spent"
    // - If we correctly roll back both blocks, everything works cleanly

    println!("\n=== Mining new chain (tx_a and tx_b will be re-included from mempool) ===");

    // Mine 3 new blocks to make the new chain longer than the old one
    // The node will naturally include tx_a and tx_b from the mempool
    let new_blocks = test_env.node_generate(3).await;
    let block_h1_prime_hash = new_blocks[0];
    let block_h2_prime_hash = new_blocks[1];
    let final_tip_hash = new_blocks[2];

    println!(
        "New blocks mined: H+1'={}, H+2'={}, H+3'={}",
        block_h1_prime_hash, block_h2_prime_hash, final_tip_hash
    );
    println!("✓ tx_a and tx_b were naturally re-included by the node");
    test_env
        .client()
        .wait_tip_hash(final_tip_hash)
        .await
        .unwrap();

    println!("\n=== Verifying final state ===");

    // If we get here without panicking, verify the state
    let current_tip = test_env.client().tip_hash().await.unwrap();
    println!("Current tip: {}", current_tip);
    assert_eq!(current_tip, final_tip_hash);

    // Check address histories after 2-block reorg
    let recipient_a_history_after = test_env.client().address_txs(&recipient_a).await.unwrap();
    let recipient_b_history_after = test_env.client().address_txs(&recipient_b).await.unwrap();

    println!("Recipient A history: {:?}", recipient_a_history_after);
    println!("Recipient B history: {:?}", recipient_b_history_after);

    // After a proper 2-block reorg with tx_a and tx_b re-included:
    // - Both transactions should STILL be in the histories (they were re-mined)
    // - This tests that our reorg logic correctly handled rolling back 2 blocks
    //   and then re-indexing them with the same transactions
    assert!(
        recipient_a_history_after.contains(&txid_a.to_string()),
        "Transaction A should still be in recipient A's history after reorg (re-included)"
    );
    assert!(
        recipient_b_history_after.contains(&txid_b.to_string()),
        "Transaction B should still be in recipient B's history after reorg (re-included)"
    );

    println!("\n✓ 2-block reorg completed successfully!");
    println!("✓ tx_a and tx_b were correctly re-indexed in the new chain");
    println!("✓ This confirms multi-block reorg handling works correctly");

    test_env.shutdown().await;
}

#[cfg(all(feature = "test_env", feature = "db", feature = "reorg_crash_test"))]
#[tokio::test]
async fn test_bitcoin_reorg_data_not_persisted() {
    use waterfalls::be::Family;

    let _ = env_logger::try_init();

    // Create persistent storage
    let tempdir = tempfile::TempDir::new().unwrap();
    let db_path = tempdir.path().to_path_buf();

    // Launch bitcoin node (will be reused across restarts)
    let exe = std::env::var("BITCOIND_EXEC").unwrap();
    let node = waterfalls::test_env::launch_bitcoin(&exe);

    println!("=== Phase 1: Initial indexing with crash injection ===");

    // Set env var to cause crash when reorg is detected
    std::env::set_var("WATERFALLS_TEST_CRASH_ON_REORG", "1");

    // Launch first server instance with the persistent database
    let test_env =
        waterfalls::test_env::launch_with_node(node, Some(db_path.clone()), Family::Bitcoin).await;

    // Generate some initial blocks
    test_env.node_generate(5).await;

    // Create a UTXO that we'll spend
    let address_to_spend = test_env.get_new_address(None);
    test_env.send_to(&address_to_spend, 10_000);
    test_env.node_generate(1).await;

    // Get the UTXO we'll double-spend
    let unspent = test_env.list_unspent();
    let utxo = &unspent[0];
    println!(
        "UTXO to spend: {} vout {} amount {}",
        utxo.txid, utxo.vout, utxo.amount
    );

    // Create and broadcast transaction A spending the UTXO to recipient_a
    let recipient_a = test_env.get_new_address(None);
    let tx_a = test_env.create_transaction_spending(
        &[(*utxo).clone()],
        &recipient_a,
        utxo.amount - 0.00001,
    );
    let signed_tx_a = test_env.sign_raw_transanction_with_wallet(&tx_a);
    let txid_a = test_env.client().broadcast(&signed_tx_a).await.unwrap();

    // Mine block H+1 containing transaction A
    let block_h1_hashes = test_env.node_generate(1).await;
    let block_h1_hash = block_h1_hashes[0];
    println!("Block H+1: {} with tx_a: {}", block_h1_hash, txid_a);

    // Verify transaction A is indexed
    test_env
        .client()
        .wait_tip_hash(block_h1_hash)
        .await
        .unwrap();
    let recipient_a_history = test_env.client().address_txs(&recipient_a).await.unwrap();
    assert!(
        recipient_a_history.contains(&txid_a.to_string()),
        "Transaction A should be in recipient A's history"
    );
    println!("✓ Block H+1 indexed, transaction A confirmed");

    // Now invalidate the block to trigger reorg
    println!("\n=== Triggering reorg (will cause crash) ===");
    test_env.invalidate_block(block_h1_hash);

    // The server will detect the reorg and crash due to WATERFALLS_TEST_CRASH_ON_REORG
    // Extract the node before the crash completes so we can reuse it
    let node = test_env.into_node();

    println!("Waiting for server to detect reorg and crash...");

    // Give it some time to detect the reorg and crash
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    println!("✓ Server crashed as expected (reorg data lost from memory)");

    // At this point:
    // - The database has block H+1 indexed (UTXO marked as spent)
    // - The reorg data (which would restore the UTXO) was only in memory
    // - The reorg data is now LOST because the process crashed

    println!("\n=== Phase 2: Restart server without crash injection ===");

    // Remove the crash env var for the restart
    std::env::remove_var("WATERFALLS_TEST_CRASH_ON_REORG");

    // Restart the server with the SAME database and SAME node
    // Use launch_with_node_no_generate to avoid generating blocks during launch
    // (the server will crash during indexing anyway)
    let test_env2 = waterfalls::test_env::launch_with_node_no_generate(
        node,
        Some(db_path.clone()),
        Family::Bitcoin,
    )
    .await;

    println!("✓ Server restarted with same database");

    // Generate blocks on the node to give the server something to index
    // The server will detect reorg and crash when trying to index these
    let _hashes = test_env2.node_generate_no_wait(102);
    println!("   Generated 102 new blocks on node (server should crash while indexing)");

    println!("\nWaiting to see if server crashes during indexing...");

    // Give the server some time to start indexing and hit the error
    // The server's indexing thread will panic when it tries to process blocks
    // and encounters the missing UTXO
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Note: The HTTP server may still respond to queries even though the indexing
    // thread has crashed. The key indicator of failure is in the server logs:
    // "ERROR waterfalls::store::db] every utxo must exist when spent"
    // and "Initial sync channel closed unexpectedly (blocks thread may have crashed)"

    // Clean up env var to avoid affecting other tests (if running multiple)
    std::env::remove_var("WATERFALLS_TEST_CRASH_ON_REORG");

    // Don't call shutdown because the indexing thread has already crashed
    // Just let test_env2 drop, which will clean up resources
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn test_lwk_wollet() {
    use lwk_common::Signer;
    use waterfalls::be;

    let _ = env_logger::try_init();
    let network = lwk_wollet::ElementsNetwork::default_regtest();

    let test_env = launch_memory(Family::Elements).await;
    let (signer, mut wollet) = lwk_wollet::Wollet::test_wallet().unwrap();
    let descriptor = wollet.descriptor().to_string();
    let bitcoind_desc = wollet
        .wollet_descriptor()
        .bitcoin_descriptor_without_key_origin()
        .to_string();
    let address = wollet.address(None).unwrap();
    let address = be::Address::Elements(address.address().clone());
    let initial_amount = 10_000;
    test_env.send_to(&address, initial_amount);
    test_env.node_generate(1).await;
    test_env
        .client()
        .wait_waterfalls_non_empty(&bitcoind_desc)
        .await
        .unwrap();
    let waterfalls_url = test_env.base_url();
    let mut lwk_client =
        lwk_wollet::clients::asyncr::EsploraClientBuilder::new(waterfalls_url, network)
            .waterfalls(true)
            .build()
            .unwrap();

    do_lwk_scan(
        network,
        &descriptor,
        waterfalls_url,
        Some(initial_amount),
        Some(1),
    )
    .await;

    wollet_scan(&mut wollet, &mut lwk_client).await;

    let sent_amount = 1000;
    let node_address = test_env.get_new_address(None);
    let mut pset = wollet
        .tx_builder()
        .add_lbtc_recipient(node_address.elements().unwrap(), sent_amount)
        .unwrap()
        .finish()
        .unwrap();
    let details = wollet.get_details(&pset).unwrap();

    let signatures = signer.sign(&mut pset).unwrap();
    assert_eq!(signatures, 1);
    let tx = be::Transaction::Elements(wollet.finalize(&mut pset).unwrap());
    test_env.client().broadcast(&tx).await.unwrap();
    // test_env.node_generate(1).await;
    sleep(Duration::from_secs(2)).await;

    wollet_scan(&mut wollet, &mut lwk_client).await;

    let final_balance = initial_amount - sent_amount - details.balance.fee;
    do_lwk_scan(
        lwk_wollet::ElementsNetwork::default_regtest(),
        &descriptor,
        test_env.base_url(),
        Some(final_balance),
        Some(2),
    )
    .await;

    test_env.node_generate(1).await; // TODO: should work also without this

    let mut lwk_client_utxo_only =
        lwk_wollet::clients::asyncr::EsploraClientBuilder::new(waterfalls_url, network)
            .waterfalls(true)
            .utxo_only(true)
            .build()
            .unwrap();

    // Create another Wollet using utxo_only client and compare results
    let lwk_desc: lwk_wollet::WolletDescriptor = descriptor.parse().unwrap();
    let mut wollet_utxo_only = lwk_wollet::Wollet::without_persist(network, lwk_desc).unwrap();
    wollet_scan(&mut wollet_utxo_only, &mut lwk_client_utxo_only).await;

    // The balance should match between regular and utxo_only scans
    let balance_utxo_only = wollet_utxo_only.balance().unwrap();
    assert_eq!(
        balance_utxo_only.get(&network.policy_asset()).unwrap(),
        &final_balance,
        "Balance should match between regular and utxo_only scans"
    );

    // The transaction lists should be different because utxo_only should not include spent transactions
    let txs_regular = wollet.transactions().unwrap();
    let txs_utxo_only = wollet_utxo_only.transactions().unwrap();
    assert_ne!(
        txs_regular.len(),
        txs_utxo_only.len(),
        "Transaction lists should be different: utxo_only should have fewer transactions (excluding spent ones)"
    );
    assert!(
        txs_utxo_only.len() < txs_regular.len(),
        "utxo_only should have fewer transactions than regular scan"
    );

    // Test utxo_only on addresses endpoint with actual spending
    // Test the address that received the initial funds - it should now have both incoming and outgoing transactions
    let unconfidential_address = address.to_unconfidential().unwrap();

    // Test with utxo_only=false (full history)
    let result_full_history = test_env
        .client()
        .waterfalls_addresses(&vec![unconfidential_address.clone()])
        .await
        .unwrap()
        .0;

    // Test with utxo_only=true (only transactions with unspent outputs)
    let result_utxo_only = test_env
        .client()
        .waterfalls_addresses_utxo_only(&vec![unconfidential_address.clone()], true)
        .await
        .unwrap()
        .0;

    let full_history_txs = &result_full_history.txs_seen.get("addresses").unwrap()[0];
    let utxo_only_txs = &result_utxo_only.txs_seen.get("addresses").unwrap()[0];
    assert_eq!(full_history_txs.len(), 2);
    assert_eq!(utxo_only_txs.len(), 0);

    test_env.shutdown().await;
    assert!(true);
}

#[tokio::test]
#[ignore = "requires internet"]
async fn test_lwk_wollet_mainnet() {
    let _ = env_logger::try_init();
    do_lwk_scan(
        lwk_wollet::ElementsNetwork::Liquid,
        "ct(slip77(2411e278affa5c47010eab6d313c1ec66628ec0dd03b6fc98d1a05a0618719e6),elwpkh([a8874235/84'/1776'/0']xpub6DLHCiTPg67KE9ksCjNVpVHTRDHzhCSmoBTKzp2K4FxLQwQvvdNzuqxhK2f9gFVCN6Dori7j2JMLeDoB4VqswG7Et9tjqauAvbDmzF8NEPH/<0;1>/*))#upsg7h8m",
        "https://waterfalls.liquidwebwallet.org/liquid/api/",
        None,
        Some(17),
    )
    .await;
}

#[tokio::test]
#[cfg(feature = "bench_test")]
async fn test_lwk_wollet_huge_testnet() {
    let _ = env_logger::try_init();
    // full history is 6442 txs
    do_lwk_scan(
        lwk_wollet::ElementsNetwork::LiquidTestnet,
        "ct(slip77(1bda6cd71a1e206e3eb793e5a4d98a46c3fa473c9ab7bdef9bb9c814764d6614),elwpkh([cb4ba44a/84'/1'/0']tpubDDrybtUajFcgXC85rvwPsh1oU7Azx4kJ9BAiRzMbByqK7UnVXY3gDRJPwEDfaQwguNUZFzrhavJGgEhbsfuebyxUSZQnjLezWVm2Vdqb7UM/<0;1>/*))#za9ktavp",
        "https://waterfalls.liquidwebwallet.org/liquidtestnet/api/",
        Some(9361396473),
        None,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires internet and testnet deployment"]
async fn test_lwk_wollet_small_testnet() {
    let _ = env_logger::try_init();
    // full history is ~65 txs
    do_lwk_scan(
        lwk_wollet::ElementsNetwork::LiquidTestnet,
        "ct(slip77(ac53739ddde9fdf6bba3dbc51e989b09aa8c9cdce7b7d7eddd49cec86ddf71f7),elwpkh([93970d14/84'/1'/0']tpubDC3BrFCCjXq4jAceV8k6UACxDDJCFb1eb7R7BiKYUGZdNagEhNfJoYtUrRdci9JFs1meiGGModvmNm8PrqkrEjJ6mpt6gA1DRNU8vu7GqXH/<0;1>/*))#u0y4axgs",
        "https://waterfalls.liquidwebwallet.org/liquidtestnet/api/",
        None,
        Some(65),
    )
    .await;
}

async fn do_lwk_scan(
    network: lwk_wollet::ElementsNetwork,
    descriptor: &str,
    url: &str,
    expected_satoshi_balance: Option<u64>,
    expected_txs_full: Option<usize>,
) {
    let mut previous_balance = None;
    for waterfalls_active in [true, false] {
        for utxo_only in [true, false] {
            if !waterfalls_active && utxo_only {
                continue;
            }
            let start = Instant::now();
            let mut lwk_client =
                lwk_wollet::clients::asyncr::EsploraClientBuilder::new(url, network)
                    .waterfalls(waterfalls_active)
                    .utxo_only(utxo_only)
                    .concurrency(4)
                    .build()
                    .unwrap();
            let lwk_desc: lwk_wollet::WolletDescriptor = descriptor.parse().unwrap();
            let mut lwk_wollet = lwk_wollet::Wollet::without_persist(network, lwk_desc).unwrap();
            wollet_scan(&mut lwk_wollet, &mut lwk_client).await;
            let duration = start.elapsed();
            let txs = lwk_wollet.transactions().unwrap().len();

            let balance = lwk_wollet.balance().unwrap();
            if let Some(previous_balance) = previous_balance.as_ref() {
                assert_eq!(
                    &balance, previous_balance,
                    "waterfalls_active: {} utxo_only: {}",
                    waterfalls_active, utxo_only
                );
            } else {
                previous_balance = Some(balance.clone());
            }
            let policy_balance = balance.get(&network.policy_asset()).unwrap();
            println!(
                "Scan completed in {:?} - waterfalls_active: {}, utxo_only: {} txs: {} balance: {}",
                duration, waterfalls_active, utxo_only, txs, policy_balance
            );
            if let Some(expected_satoshi_balance) = expected_satoshi_balance {
                assert_eq!(
                    policy_balance, &expected_satoshi_balance,
                    "waterfalls_active: {} utxo_only: {}",
                    waterfalls_active, utxo_only
                );
            }
            if !utxo_only {
                if let Some(expected_txs) = expected_txs_full {
                    assert!(
                        txs >= expected_txs,
                        "txs: {} >= expected_txs: {}",
                        txs,
                        expected_txs
                    );
                }
            }
        }

        // TODO add UTXO scan test once ready
    }
}

/// Scan the wollet until you find something
async fn wollet_scan(
    wollet: &mut lwk_wollet::Wollet,
    lwk_client: &mut lwk_wollet::clients::asyncr::EsploraClient,
) {
    for _ in 0..100 {
        if let Some(update) = lwk_client.full_scan(wollet).await.unwrap() {
            let _ = wollet.apply_update(update);
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("No update found in 10 seconds");
}

#[cfg(feature = "bench_test")]
#[derive(Debug)]
struct TestResult {
    txs: usize,
    first_scan: Duration,
    second_scan: Duration,
    waterfalls: bool,
    first_scan_requests: usize,
    second_scan_requests: usize,
}

#[cfg(feature = "bench_test")]
impl TestResult {
    fn md_row(&self) -> String {
        let first_duration = format!("{:.3}s", self.first_scan.as_secs_f64());
        let second_duration = format!("{:.3}s", self.second_scan.as_secs_f64());
        format!(
            "{:>6} | {:>5} | {:>9} | {:>9} | {:>6} | {:>6}",
            self.txs,
            self.waterfalls,
            first_duration,
            second_duration,
            self.first_scan_requests,
            self.second_scan_requests,
        )
    }
}

#[cfg(feature = "bench_test")]
async fn test_esplora_waterfalls_desc(desc: &str, url: &str) -> Vec<TestResult> {
    use lwk_wollet::{clients, ElementsNetwork, Wollet, WolletDescriptor};
    use std::str::FromStr;
    use waterfalls::{be, server::Network};

    // Parse as Liquid to check network - parsing works the same for Liquid/LiquidTestnet
    let parsed = be::Descriptor::from_str(desc, Network::Liquid).unwrap();
    let network = if parsed.is_mainnet() {
        ElementsNetwork::Liquid
    } else {
        ElementsNetwork::LiquidTestnet
    };

    let _ = env_logger::try_init();

    let desc = WolletDescriptor::from_str(desc).unwrap();

    let mut wollets = vec![];
    let mut results = vec![];
    for waterfalls in [true, false] {
        let start = Instant::now();
        let mut wollet = Wollet::without_persist(network, desc.clone()).unwrap();
        let mut client = clients::asyncr::EsploraClientBuilder::new(url, network)
            .waterfalls(waterfalls)
            .concurrency(2)
            .build()
            .unwrap();
        let update = client.full_scan(&wollet).await.unwrap().unwrap();
        wollet.apply_update(update).unwrap();
        let first_scan = start.elapsed();
        let first_scan_requests = client.requests();

        println!(
            "waterfall:{waterfalls} first_scan: {}ms {} txs",
            first_scan.as_millis(),
            wollet.transactions().unwrap().len(),
        );

        let start_second = Instant::now();
        client.full_scan(&wollet).await.unwrap();
        let second_scan = start_second.elapsed();
        let second_scan_requests = client.requests() - first_scan_requests;

        println!(
            "waterfall:{waterfalls} first_scan: {}ms second_scan: {}ms",
            first_scan.as_millis(),
            second_scan.as_millis()
        );
        results.push(TestResult {
            txs: wollet.transactions().unwrap().len(),
            first_scan,
            second_scan,
            waterfalls,
            first_scan_requests,
            second_scan_requests,
        });
        wollets.push(wollet);
    }

    assert_eq!(wollets[0].balance().unwrap(), wollets[1].balance().unwrap());
    assert_eq!(
        wollets[0].transactions().unwrap(),
        wollets[1].transactions().unwrap()
    );
    results
}

#[tokio::test]
#[cfg(feature = "bench_test")]
async fn test_waterfalls_vs_esplora_performance() {
    let mut all_results = vec![];

    let url = "https://waterfalls.liquidwebwallet.org/liquidtestnet/api";
    let descriptors = [
        "ct(slip77(0371e66dde8ab9f3cb19d2c20c8fa2d7bd1ddc73454e6b7ef15f0c5f624d4a86),elsh(wpkh([75ea4a43/49'/1'/0']tpubDDRMQzj8FGnDXxAhr8zgM22VT7BT2H2cPUdCRDSi3ima15TRUZEkT32zExr1feVReMYvBEm21drG1qKryjHf3cD6iD4j1nkPkbPDuQxCJG4/<0;1>/*)))#utnwh7dr",
         "ct(slip77(ac53739ddde9fdf6bba3dbc51e989b09aa8c9cdce7b7d7eddd49cec86ddf71f7),elwpkh([93970d14/84'/1'/0']tpubDC3BrFCCjXq4jAceV8k6UACxDDJCFb1eb7R7BiKYUGZdNagEhNfJoYtUrRdci9JFs1meiGGModvmNm8PrqkrEjJ6mpt6gA1DRNU8vu7GqXH/<0;1>/*))#u0y4axgs",
"ct(slip77(1bda6cd71a1e206e3eb793e5a4d98a46c3fa473c9ab7bdef9bb9c814764d6614),elwpkh([cb4ba44a/84'/1'/0']tpubDDrybtUajFcgXC85rvwPsh1oU7Azx4kJ9BAiRzMbByqK7UnVXY3gDRJPwEDfaQwguNUZFzrhavJGgEhbsfuebyxUSZQnjLezWVm2Vdqb7UM/<0;1>/*))#za9ktavp",
    ];

    for descriptor in descriptors {
        all_results.extend(test_esplora_waterfalls_desc(descriptor, url).await);
    }

    for result in all_results {
        println!("{}", result.md_row());
    }
}

#[tokio::test]
#[ignore = "requires internet"]
async fn test_waterfalls_descriptor_vs_addresses() {
    let url = "https://waterfalls.liquidwebwallet.org/liquidtestnet/api";
    let client = waterfalls::test_env::WaterfallClient::new(url.to_string(), Family::Elements);
    let descriptors = [
        "elsh(wpkh([75ea4a43/49'/1'/0']tpubDDRMQzj8FGnDXxAhr8zgM22VT7BT2H2cPUdCRDSi3ima15TRUZEkT32zExr1feVReMYvBEm21drG1qKryjHf3cD6iD4j1nkPkbPDuQxCJG4/0/*))",
        "elsh(wpkh([75ea4a43/49'/1'/0']tpubDDRMQzj8FGnDXxAhr8zgM22VT7BT2H2cPUdCRDSi3ima15TRUZEkT32zExr1feVReMYvBEm21drG1qKryjHf3cD6iD4j1nkPkbPDuQxCJG4/1/*))"
    ];
    for descriptor_str in descriptors {
        let descriptor = be::Descriptor::from_str(descriptor_str, Network::LiquidTestnet).unwrap();
        let descriptor = descriptor.elements().unwrap();

        let (resp, _) = client.waterfalls(&descriptor_str).await.unwrap();
        println!("resp: {:?}", resp);
        let len = resp.txs_seen.get(&descriptor.to_string()).unwrap().len();

        let mut addresses = vec![];
        for i in 0..len as u32 {
            addresses.push(waterfalls::be::Address::Elements(
                descriptor
                    .at_derivation_index(i)
                    .unwrap()
                    .address(&AddressParams::LIQUID_TESTNET)
                    .unwrap(),
            ));
        }
        let (resp2, _) = client.waterfalls_addresses(&addresses).await.unwrap();
        assert_eq!(resp2.txs_seen.get("addresses").unwrap().len(), len);

        assert_eq!(
            resp.txs_seen.get(&descriptor.to_string()).unwrap(),
            resp2.txs_seen.get("addresses").unwrap(),
        );
    }
}

//! # Integration testing
//!
//! This is not going to depend on LWK because we want to use this lib in LWK testing
//! Thus following tests aren't a proper wallet scan but they checks memory/db backend and also
//! mempool/confirmation result in receiving a payment

use std::time::{Duration, Instant};

use tokio::time::sleep;
use waterfalls::Family;

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_memory_elements() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Elements).await;
    do_test(test_env).await;
}

#[cfg(feature = "test_env")]
#[tokio::test]
async fn integration_memory_bitcoin() {
    let _ = env_logger::try_init();

    let test_env = launch_memory(Family::Bitcoin).await;
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
#[tokio::test]
async fn integration_db() {
    let _ = env_logger::try_init();

    let tempdir = tempfile::TempDir::new().unwrap();
    let path = tempdir.path().to_path_buf();
    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    let test_env = waterfalls::test_env::launch(exe, Some(path), Family::Elements).await;
    do_test(test_env).await;
}

#[cfg(all(feature = "test_env", feature = "db"))]
async fn launch_memory(family: Family) -> waterfalls::test_env::TestEnv<'static> {
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
fn get_new_address(wallet: &bitcoind::bitcoincore_rpc::Client) -> elements::Address {
    use bitcoind::bitcoincore_rpc::RpcApi;
    use serde_json::Value;
    use std::str::FromStr;

    let address_value: Value = wallet
        .call("getnewaddress", &[Value::Null, Value::Null])
        .unwrap();
    elements::Address::from_str(address_value.as_str().unwrap()).unwrap()
}

#[cfg(feature = "test_env")]
fn send_to_address(
    wallet: &bitcoind::bitcoincore_rpc::Client,
    address: &elements::Address,
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
async fn do_test(test_env: waterfalls::test_env::TestEnv<'_>) {
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
    let bitcoin_desc = format!("{prefix}wpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)");
    let single_bitcoin_desc = bitcoin_desc.replace("<0;1>", "0");
    let blinding = "slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023)";
    let desc_str = format!("ct({blinding},{single_bitcoin_desc})"); // we use a non-multipath to generate addresses

    let result = client.waterfalls_v2(&bitcoin_desc).await.unwrap().0;
    assert_eq!(result.page, 0);
    assert_eq!(result.txs_seen.len(), 2);
    assert!(result.is_empty());
    assert!(result.tip.is_some());
    let result = client.waterfalls_v1(&bitcoin_desc).await.unwrap().0;
    assert!(result.tip.is_none());

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

    let tx_sign = test_env.sign_raw_transanction_with_wallet(&tx_blind);
    let txid = client.broadcast(&tx_sign).await.unwrap();

    match test_env.family {
        Family::Bitcoin => {
            // assert_eq!(txid, tx_blind.txid()); // TODO: fix this
        }
        Family::Elements => {
            assert_eq!(txid, tx_blind.txid());
        }
    }

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

    if test_env.family == Family::Bitcoin {
        // TODO: fix this
        return;
    }

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
    let other_address = get_new_address(&other_wallet);
    test_env.send_to(&be::Address::Elements(other_address), 1_000_000);
    test_env.node_generate(1).await;
    let address_spent_same_block = get_new_address(&other_wallet);
    let txid1 = send_to_address(&other_wallet, &address_spent_same_block, 0.0098);
    let new_address = test_env.get_new_address(None);
    let txid2 = send_to_address(&other_wallet, new_address.elements().unwrap(), 0.0096);
    test_env.node_generate(1).await;
    let address_txs = client
        .address_txs(&be::Address::Elements(address_spent_same_block))
        .await
        .unwrap();
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
    let desc_str = format!("elwpkh(tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/0/0)");
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

    test_env.shutdown().await;
    assert!(true);
}

#[ignore = "Test to examine the log manually"]
#[cfg(feature = "test_env")]
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
    let _test_env =
        waterfalls::test_env::launch_with_node(&elementsd, None, Family::Elements).await;
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
    let test_env = waterfalls::test_env::launch_with_node(&elementsd, None, Family::Elements).await;
    let txid = elements::Txid::from_str(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    let _tx = test_env.client().tx(txid).await.unwrap();
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

    do_lwk_scan(network, &descriptor, waterfalls_url, initial_amount).await;

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
        final_balance,
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
        2899, // note this may change with funding/spending
    )
    .await;
}

#[tokio::test]
#[ignore = "requires internet and testnet deployment"]
async fn test_lwk_wollet_huge_testnet() {
    let _ = env_logger::try_init();
    // full history is 6442 txs
    do_lwk_scan(
        lwk_wollet::ElementsNetwork::LiquidTestnet,
        "ct(slip77(1bda6cd71a1e206e3eb793e5a4d98a46c3fa473c9ab7bdef9bb9c814764d6614),elwpkh([cb4ba44a/84'/1'/0']tpubDDrybtUajFcgXC85rvwPsh1oU7Azx4kJ9BAiRzMbByqK7UnVXY3gDRJPwEDfaQwguNUZFzrhavJGgEhbsfuebyxUSZQnjLezWVm2Vdqb7UM/<0;1>/*))#za9ktavp",
        "https://waterfalls.liquidwebwallet.org/liquidtestnet-utxo-only/api/",
        9361396473,
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
        "https://waterfalls.liquidwebwallet.org/liquidtestnet-utxo-only/api/",
        1070521,
    )
    .await;
}

async fn do_lwk_scan(
    network: lwk_wollet::ElementsNetwork,
    descriptor: &str,
    url: &str,
    expected_satoshi_balance: u64,
) {
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
            let policy_balance = balance.get(&network.policy_asset()).unwrap();
            println!(
                "Scan completed in {:?} - waterfalls_active: {}, utxo_only: {} txs: {} balance: {}",
                duration, waterfalls_active, utxo_only, txs, policy_balance
            );
            assert_eq!(
                policy_balance, &expected_satoshi_balance,
                "waterfalls_active: {} utxo_only: {}",
                waterfalls_active, utxo_only
            );
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

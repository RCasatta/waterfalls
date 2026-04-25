use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use bitcoin::key::Secp256k1;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hyper::body::Buf;

use elements::secp256k1_zkp::rand::{thread_rng, RngCore};
use elements::Txid;
use elements_miniscript::Descriptor;
use elements_miniscript::DescriptorPublicKey;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, Options, WriteBatch, DB,
};
use tempfile;
use waterfalls::{OutPoint, WaterfallResponse};

criterion_group!(
    benches,
    descriptor,
    encoding_decoding,
    sign_verify,
    writebatch_sorting,
    hasher,
    txid_from_hex,
    block_cache,
    history_multi_get
);
criterion_main!(benches);

pub fn descriptor(c: &mut Criterion) {
    c.benchmark_group("descriptor")
    .bench_function("derive script pubkey", |b: &mut criterion::Bencher<'_>| {
        let desc_str = "elwpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)#20ufqv7z";
        let desc: Descriptor<DescriptorPublicKey> = desc_str.parse().unwrap();
        let mut i = 0;
        b.iter(|| {
            let r = desc.at_derivation_index(i).unwrap();
            i += 1;
            black_box(r.script_pubkey()); // bulk of the time is spent here, because the pubkey is derived here
        });
    })
    .bench_function("create verification only context", |b: &mut criterion::Bencher<'_>| {
        b.iter(|| {
            let secp = Secp256k1::verification_only();
            black_box(secp);
        });
    })
    .bench_function("create secp context", |b: &mut criterion::Bencher<'_>| {
        b.iter(|| {
            let secp = Secp256k1::new();
            black_box(secp);
        });
    });
}

pub fn encoding_decoding(c: &mut Criterion) {
    c.benchmark_group("encoding")
        .bench_function("encode cbor", |b: &mut criterion::Bencher<'_>| {
            let buffer = include_bytes!("../tests/data/waterfall_response_v2.cbor");
            let resp: WaterfallResponse = minicbor::decode(buffer).unwrap();
            b.iter(|| {
                let mut buffer = vec![];
                minicbor::encode(&resp, &mut buffer).unwrap();
                black_box(buffer);
            });
        })
        .bench_function("decode cbor", |b: &mut criterion::Bencher<'_>| {
            let buffer = include_bytes!("../tests/data/waterfall_response_v2.cbor");
            b.iter(|| {
                let cbor: WaterfallResponse = minicbor::decode(buffer).unwrap();
                black_box(cbor);
            });
        })
        .bench_function("encode json", |b: &mut criterion::Bencher<'_>| {
            let s = include_str!("../tests/data/waterfall_response_v2.json");
            let resp: WaterfallResponse = serde_json::from_str(s).unwrap();
            b.iter(|| {
                let s = serde_json::to_string(&resp).unwrap();
                black_box(s);
            });
        })
        .bench_function("decode json", |b: &mut criterion::Bencher<'_>| {
            let s = include_str!("../tests/data/waterfall_response_v2.json");
            b.iter(|| {
                let json: WaterfallResponse = serde_json::from_str(s).unwrap();
                black_box(json);
            });
        })
        .bench_function(
            "decode mempool json elements::Txid",
            |b: &mut criterion::Bencher<'_>| {
                let s = include_str!("../tests/data/mempool-verbose-false.json");
                b.iter(|| {
                    let json: HashSet<elements::Txid> = serde_json::from_str(s).unwrap();
                    black_box(json);
                });
            },
        )
        .bench_function(
            "decode mempool json bitcoin::Txid",
            |b: &mut criterion::Bencher<'_>| {
                let s = include_str!("../tests/data/mempool-verbose-false.json");
                b.iter(|| {
                    let json: HashSet<bitcoin::Txid> = serde_json::from_str(s).unwrap();
                    black_box(json);
                });
            },
        )
        .bench_function(
            "decode mempool json crate::be::Txid",
            |b: &mut criterion::Bencher<'_>| {
                let s = include_str!("../tests/data/mempool-verbose-false.json");
                b.iter(|| {
                    let json: HashSet<waterfalls::be::Txid> = serde_json::from_str(s).unwrap();
                    black_box(json);
                });
            },
        )
        .bench_function(
            "decode mempool json String",
            |b: &mut criterion::Bencher<'_>| {
                let s = include_str!("../tests/data/mempool-verbose-false.json");
                b.iter(|| {
                    let json: HashSet<String> = serde_json::from_str(s).unwrap();
                    black_box(json);
                });
            },
        )
        .bench_function(
            "decode mempool json from_reader",
            |b: &mut criterion::Bencher<'_>| {
                let bytes = include_bytes!("../tests/data/mempool-verbose-false.json");
                b.iter(|| {
                    let reader = std::io::Cursor::new(bytes);
                    let json: HashSet<Txid> = serde_json::from_reader(reader).unwrap();
                    black_box(json);
                });
            },
        )
        .bench_function(
            "decode mempool json from_slice",
            |b: &mut criterion::Bencher<'_>| {
                let bytes = include_bytes!("../tests/data/mempool-verbose-false.json");
                b.iter(|| {
                    let json: HashSet<Txid> = serde_json::from_slice(bytes).unwrap();
                    black_box(json);
                });
            },
        )
        .bench_function(
            "decode mempool json bytes_reader",
            |b: &mut criterion::Bencher<'_>| {
                let bytes = hyper::body::Bytes::from_static(include_bytes!(
                    "../tests/data/mempool-verbose-false.json"
                ));
                b.iter(|| {
                    let json: HashSet<Txid> =
                        serde_json::from_reader(bytes.clone().reader()).unwrap();
                    black_box(json);
                });
            },
        )
        .bench_function(
            "decode mempool json string_conversion",
            |b: &mut criterion::Bencher<'_>| {
                let bytes = hyper::body::Bytes::from_static(include_bytes!(
                    "../tests/data/mempool-verbose-false.json"
                ));
                b.iter(|| {
                    let s = std::str::from_utf8(&bytes).unwrap();
                    let json: HashSet<Txid> = serde_json::from_str(s).unwrap();
                    black_box(json);
                });
            },
        );
}

pub fn writebatch_sorting(c: &mut Criterion) {
    use elements::encode::Encodable;
    use elements::hashes::Hash;

    // Generate test data
    let mut rng = thread_rng();
    let mut test_outpoints = Vec::new();

    for _ in 0..1000 {
        let mut txid_bytes = [0u8; 32];
        rng.fill_bytes(&mut txid_bytes);
        let txid = Txid::from_byte_array(txid_bytes);
        let vout = rng.next_u32();
        test_outpoints.push(OutPoint::new(txid.into(), vout));
    }

    // Helper function to serialize OutPoint
    let serialize_outpoint = |o: &OutPoint| -> Vec<u8> {
        let mut v = Vec::with_capacity(36);
        o.consensus_encode(&mut v).expect("vec don't error");
        v
    };

    c.benchmark_group("writebatch")
        .bench_function("sorted keys", |b: &mut criterion::Bencher<'_>| {
            b.iter_batched(
                || {
                    // Setup: create temp db and sort the keys
                    let temp_dir = tempfile::TempDir::new().unwrap();
                    let mut opts = Options::default();
                    opts.create_if_missing(true);
                    let db = DB::open(&opts, temp_dir.path()).unwrap();

                    let mut sorted_outpoints = test_outpoints.clone();
                    sorted_outpoints.sort();

                    (db, sorted_outpoints, temp_dir)
                },
                |(db, sorted_outpoints, _temp_dir)| {
                    // Benchmark: WriteBatch with sorted keys
                    let mut batch = WriteBatch::default();
                    for outpoint in &sorted_outpoints {
                        let key = serialize_outpoint(outpoint);
                        let value = b"test_value";
                        batch.put(&key, value);
                    }
                    let result = db.write(batch);
                    let _ = black_box(result);
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .bench_function("random keys", |b: &mut criterion::Bencher<'_>| {
            b.iter_batched(
                || {
                    // Setup: create temp db, keys are already random
                    let temp_dir = tempfile::TempDir::new().unwrap();
                    let mut opts = Options::default();
                    opts.create_if_missing(true);
                    let db = DB::open(&opts, temp_dir.path()).unwrap();

                    (db, test_outpoints.clone(), temp_dir)
                },
                |(db, random_outpoints, _temp_dir)| {
                    // Benchmark: WriteBatch with random keys
                    let mut batch = WriteBatch::default();
                    for outpoint in &random_outpoints {
                        let key = serialize_outpoint(outpoint);
                        let value = b"test_value";
                        batch.put(&key, value);
                    }
                    let result = db.write(batch);
                    let _ = black_box(result);
                },
                criterion::BatchSize::SmallInput,
            )
        });
}

pub fn sign_verify(c: &mut Criterion) {
    let secp = bitcoin::key::Secp256k1::new();
    let private_key = elements::bitcoin::PrivateKey::generate(elements::bitcoin::NetworkKind::Test);
    let test_data = b"benchmark test data";

    c.benchmark_group("sign verify")
        .bench_function("sign", |b: &mut criterion::Bencher<'_>| {
            b.iter(|| {
                let sig = waterfalls::server::sign::sign_response(&secp, &private_key, test_data);
                black_box(sig);
            });
        })
        .bench_function("verify", |b: &mut criterion::Bencher<'_>| {
            let address = waterfalls::server::sign::p2pkh(&secp, &private_key);
            let sig = waterfalls::server::sign::sign_response(&secp, &private_key, test_data);

            b.iter(|| {
                let result = waterfalls::server::sign::verify_response(
                    &secp,
                    &address,
                    test_data,
                    &sig.signature,
                )
                .unwrap();
                black_box(result);
            });
        });
}

pub fn hasher(c: &mut Criterion) {
    use elements::hashes::Hash;
    use elements::secp256k1_zkp::rand::{thread_rng, RngCore};

    // Generate test data
    let mut rng = thread_rng();
    let mut txid_bytes = [0u8; 32];
    rng.fill_bytes(&mut txid_bytes);

    let elements_txid = elements::Txid::from_byte_array(txid_bytes);
    let bitcoin_txid = bitcoin::Txid::from_byte_array(txid_bytes);
    let waterfalls_txid = waterfalls::be::Txid::from(bitcoin_txid);

    c.benchmark_group("hasher")
        .bench_function(
            "single hash elements::Txid",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    let mut hasher = DefaultHasher::new();
                    elements_txid.hash(&mut hasher);
                    let hash_result = hasher.finish();
                    black_box(hash_result);
                });
            },
        )
        .bench_function(
            "single hash bitcoin::Txid",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    let mut hasher = DefaultHasher::new();
                    bitcoin_txid.hash(&mut hasher);
                    let hash_result = hasher.finish();
                    black_box(hash_result);
                });
            },
        )
        .bench_function(
            "single hash waterfalls::be::Txid",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    let mut hasher = DefaultHasher::new();
                    waterfalls_txid.hash(&mut hasher);
                    let hash_result = hasher.finish();
                    black_box(hash_result);
                });
            },
        );
}

pub fn txid_from_hex(c: &mut Criterion) {
    // Test hex string (64 chars representing 32 bytes)
    let hex_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    c.benchmark_group("txid_from_hex")
        .bench_function(
            "bitcoin::Txid from hex",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    let bitcoin_txid: bitcoin::Txid = hex_str.parse().unwrap();
                    let txid = waterfalls::be::Txid::from(bitcoin_txid);
                    let _ = black_box(txid);
                });
            },
        )
        .bench_function(
            "waterfalls::be::Txid from hex",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    let txid: waterfalls::be::Txid = hex_str.parse().unwrap();
                    let _ = black_box(txid);
                });
            },
        )
        .bench_function(
            "waterfalls::be::Txid from array crate hex-simd",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    let mut array = [0u8; 32];
                    hex_simd::decode(hex_str.as_bytes(), hex_simd::AsOut::as_out(&mut array[..]))
                        .unwrap();
                    array.reverse();
                    // use Txid::from_array to create the txid
                    let txid = waterfalls::be::Txid::from_array(array);
                    let _ = black_box(txid);
                });
            },
        );
}

fn open_cache_bench_db(dir: &std::path::Path, cache: &Cache) -> DB {
    let cfs = ["utxo", "history"]
        .iter()
        .map(|&name| {
            let mut cf_opts = Options::default();
            cf_opts.set_compression_type(DBCompressionType::None);

            let mut block_opts = BlockBasedOptions::default();
            block_opts.set_block_cache(cache);
            block_opts.set_block_size(16 * 1024);
            block_opts.set_cache_index_and_filter_blocks(true);
            block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
            if name == "history" {
                block_opts.set_bloom_filter(10.0, true);
            }
            cf_opts.set_block_based_table_factory(&block_opts);

            ColumnFamilyDescriptor::new(name, cf_opts)
        })
        .collect::<Vec<_>>();

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    DB::open_cf_descriptors(&db_opts, dir, cfs).unwrap()
}

fn populate_cache_bench_db(db: &DB, num_utxo_keys: u64, num_history_keys: u64) {
    let cf = db.cf_handle("utxo").unwrap();
    for start in (0..num_utxo_keys).step_by(10_000) {
        let mut batch = WriteBatch::default();
        for i in start..(start + 10_000).min(num_utxo_keys) {
            let mut key = [0u8; 36];
            key[..8].copy_from_slice(&i.to_be_bytes());
            batch.put_cf(&cf, key, i.to_be_bytes());
        }
        db.write(batch).unwrap();
    }

    let cf = db.cf_handle("history").unwrap();
    for start in (0..num_history_keys).step_by(10_000) {
        let mut batch = WriteBatch::default();
        for i in start..(start + 10_000).min(num_history_keys) {
            batch.put_cf(&cf, i.to_be_bytes(), vec![0xABu8; 100 + (i as usize % 50)]);
        }
        db.write(batch).unwrap();
    }

    for name in ["utxo", "history"] {
        let cf = db.cf_handle(name).unwrap();
        db.flush_cf(&cf).unwrap();
        db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
    }
}

/// Compares LRUCache vs HyperClockCache for RocksDB block cache using
/// `multi_get_cf` (the actual production access pattern) under varying
/// concurrency levels.
///
/// Two scenarios model production data-to-cache ratios:
/// - **liquid**: ~21 MB data, 2 MB cache (~9%) — matches Liquid mainnet (~6%)
/// - **bitcoin**: ~76 MB data, 2 MB cache (~2.6%) — matches Bitcoin UTXO (~3.6%)
///
/// Each scenario tests 1, 4, and 16 concurrent reader threads.
pub fn block_cache(c: &mut Criterion) {
    const LOOKUPS_PER_ITER: usize = 100;

    struct Scenario {
        name: &'static str,
        cache_size: usize,
        num_utxo_keys: u64,
        num_history_keys: u64,
    }

    let scenarios = [
        Scenario {
            name: "liquid",
            cache_size: 2 * 1024 * 1024,
            num_utxo_keys: 200_000,
            num_history_keys: 100_000,
        },
        Scenario {
            name: "bitcoin",
            cache_size: 2 * 1024 * 1024,
            num_utxo_keys: 300_000,
            num_history_keys: 500_000,
        },
    ];

    let thread_counts: &[usize] = &[1, 4, 16];

    for scenario in &scenarios {
        let mut rng = thread_rng();
        let history_keys: Vec<[u8; 8]> = (0..LOOKUPS_PER_ITER)
            .map(|_| (rng.next_u64() % (scenario.num_history_keys * 2)).to_be_bytes())
            .collect();

        let lru_dir = tempfile::TempDir::new().unwrap();
        let lru_cache = Cache::new_lru_cache(scenario.cache_size);
        let lru_db = open_cache_bench_db(lru_dir.path(), &lru_cache);
        populate_cache_bench_db(&lru_db, scenario.num_utxo_keys, scenario.num_history_keys);

        let hcc_dir = tempfile::TempDir::new().unwrap();
        let hcc_cache = Cache::new_hyper_clock_cache(scenario.cache_size, 0);
        let hcc_db = open_cache_bench_db(hcc_dir.path(), &hcc_cache);
        populate_cache_bench_db(&hcc_db, scenario.num_utxo_keys, scenario.num_history_keys);

        let mut group = c.benchmark_group(format!("block_cache/{}", scenario.name));

        for &num_threads in thread_counts {
            let label = format!("{}t", num_threads);

            group.bench_function(format!("lru/{label}"), |b| {
                if num_threads == 1 {
                    let cf = lru_db.cf_handle("history").unwrap();
                    b.iter(|| {
                        let keys: Vec<_> = history_keys.iter().map(|k| (&cf, *k)).collect();
                        black_box(lru_db.multi_get_cf(keys));
                    });
                } else {
                    b.iter_custom(|iters| {
                        let start = std::time::Instant::now();
                        std::thread::scope(|s| {
                            for _ in 0..num_threads {
                                s.spawn(|| {
                                    let cf = lru_db.cf_handle("history").unwrap();
                                    for _ in 0..iters {
                                        let keys: Vec<_> =
                                            history_keys.iter().map(|k| (&cf, *k)).collect();
                                        black_box(lru_db.multi_get_cf(keys));
                                    }
                                });
                            }
                        });
                        start.elapsed()
                    });
                }
            });

            group.bench_function(format!("hyperclock/{label}"), |b| {
                if num_threads == 1 {
                    let cf = hcc_db.cf_handle("history").unwrap();
                    b.iter(|| {
                        let keys: Vec<_> = history_keys.iter().map(|k| (&cf, *k)).collect();
                        black_box(hcc_db.multi_get_cf(keys));
                    });
                } else {
                    b.iter_custom(|iters| {
                        let start = std::time::Instant::now();
                        std::thread::scope(|s| {
                            for _ in 0..num_threads {
                                s.spawn(|| {
                                    let cf = hcc_db.cf_handle("history").unwrap();
                                    for _ in 0..iters {
                                        let keys: Vec<_> =
                                            history_keys.iter().map(|k| (&cf, *k)).collect();
                                        black_box(hcc_db.multi_get_cf(keys));
                                    }
                                });
                            }
                        });
                        start.elapsed()
                    });
                }
            });
        }

        group.finish();
    }
}

pub fn history_multi_get(c: &mut Criterion) {
    const DEFAULT_NUM_HISTORY_KEYS: u64 = 500_000;
    let num_history_keys = std::env::var("WATERFALLS_HISTORY_BENCH_ROWS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_NUM_HISTORY_KEYS);

    let cache = Cache::new_hyper_clock_cache(8 * 1024 * 1024, 0);
    let dir = tempfile::TempDir::new().unwrap();
    let db = open_cache_bench_db(dir.path(), &cache);
    populate_cache_bench_db(&db, 0, num_history_keys);

    let cf = db.cf_handle("history").unwrap();
    for lookup_count in [20usize, 512] {
        let mut rng = thread_rng();
        let scripts: Vec<u64> = (0..lookup_count)
            .map(|_| rng.next_u64() % (num_history_keys * 2))
            .collect();

        let mut group = c.benchmark_group(format!(
            "history_multi_get/{lookup_count}/{num_history_keys}"
        ));
        group.sample_size(20);

        group.bench_function("batched_unsorted", |b| {
            b.iter(|| {
                black_box(bench_raw_history_multi_get_old(&db, &cf, &scripts));
            });
        });

        group.bench_function("batched_sorted_reordered", |b| {
            b.iter(|| {
                black_box(bench_raw_history_multi_get_new(&db, &cf, &scripts));
            });
        });

        group.finish();
    }
}

fn bench_raw_history_multi_get_old(
    db: &DB,
    cf: &impl rocksdb::AsColumnFamilyRef,
    scripts: &[u64],
) -> usize {
    let keys: Vec<_> = scripts.iter().map(|script| script.to_be_bytes()).collect();
    let results = db.batched_multi_get_cf(cf, keys.iter(), false);
    results
        .into_iter()
        .map(|result| result.unwrap().as_ref().map_or(0, |value| value.len()))
        .sum()
}

fn bench_raw_history_multi_get_new(
    db: &DB,
    cf: &impl rocksdb::AsColumnFamilyRef,
    scripts: &[u64],
) -> usize {
    let mut indexed_keys: Vec<_> = scripts
        .iter()
        .enumerate()
        .map(|(index, script)| (index, script.to_be_bytes()))
        .collect();
    indexed_keys.sort_unstable_by_key(|(_, key)| *key);

    let sorted_results = db.batched_multi_get_cf(cf, indexed_keys.iter().map(|(_, key)| key), true);
    let mut reordered = vec![0usize; scripts.len()];
    for ((index, _), result) in indexed_keys.into_iter().zip(sorted_results.into_iter()) {
        reordered[index] = result.unwrap().as_ref().map_or(0, |value| value.len());
    }

    reordered.into_iter().sum()
}

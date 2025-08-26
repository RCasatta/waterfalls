use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use bitcoin::key::Secp256k1;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hyper::body::Buf;

use elements::secp256k1_zkp::rand::{thread_rng, RngCore};
use elements::{OutPoint, Txid};
use elements_miniscript::Descriptor;
use elements_miniscript::DescriptorPublicKey;
use rocksdb::{Options, WriteBatch, DB};
use tempfile;
use waterfalls::WaterfallResponse;
use waterfalls::WaterfallResponseV3;

criterion_group!(
    benches,
    descriptor,
    encoding_decoding,
    conversion,
    sign_verify,
    writebatch_sorting,
    hasher,
    txid_from_hex
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
            let buffer = include_bytes!("../tests/data/waterfall_response_v3.cbor");
            let resp: WaterfallResponseV3 = minicbor::decode(buffer).unwrap();
            b.iter(|| {
                let mut buffer = vec![];
                minicbor::encode(&resp, &mut buffer).unwrap();
                black_box(buffer);
            });
        })
        .bench_function("decode cbor", |b: &mut criterion::Bencher<'_>| {
            let buffer = include_bytes!("../tests/data/waterfall_response_v3.cbor");
            b.iter(|| {
                let cbor: WaterfallResponseV3 = minicbor::decode(buffer).unwrap();
                black_box(cbor);
            });
        })
        .bench_function("encode json", |b: &mut criterion::Bencher<'_>| {
            let s = include_str!("../tests/data/waterfall_response_v3.json");
            let resp: WaterfallResponseV3 = serde_json::from_str(s).unwrap();
            b.iter(|| {
                let s = serde_json::to_string(&resp).unwrap();
                black_box(s);
            });
        })
        .bench_function("decode json", |b: &mut criterion::Bencher<'_>| {
            let s = include_str!("../tests/data/waterfall_response_v3.json");
            b.iter(|| {
                let json: WaterfallResponseV3 = serde_json::from_str(s).unwrap();
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

pub fn conversion(c: &mut Criterion) {
    c.benchmark_group("conversion")
        .bench_function("v3 -> v2 ", |b: &mut criterion::Bencher<'_>| {
            let buffer = include_bytes!("../tests/data/waterfall_response_v3.cbor");
            let resp: WaterfallResponseV3 = minicbor::decode(buffer).unwrap();
            b.iter(|| {
                let resp_v2: WaterfallResponse = resp.clone().into();
                black_box(resp_v2);
            });
        })
        .bench_function("v2 -> v3 ", |b: &mut criterion::Bencher<'_>| {
            let buffer = include_bytes!("../tests/data/waterfall_response_v2.cbor");
            let resp: WaterfallResponse = minicbor::decode(buffer).unwrap();
            b.iter(|| {
                let resp_v3: WaterfallResponseV3 = resp.clone().try_into().unwrap();
                black_box(resp_v3);
            });
        });
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
        test_outpoints.push(OutPoint { txid, vout });
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
                    black_box(result);
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
                    black_box(result);
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
            "waterfalls::be::Txid from hex",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    let bitcoin_txid: bitcoin::Txid = hex_str.parse().unwrap();
                    let txid = waterfalls::be::Txid::from(bitcoin_txid);
                    black_box(txid);
                });
            },
        )
        .bench_function(
            "waterfalls::be::Txid from array",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    // use hex library to decode directly into a byte array [u8; 32]
                    let mut array = [0u8; 32];
                    hex::decode_to_slice(hex_str, &mut array).unwrap();
                    // use Txid::from_array to create the txid
                    let txid = waterfalls::be::Txid::from_array(array);
                    black_box(txid);
                });
            },
        )
        .bench_function(
            "waterfalls::be::Txid from array hex-simd",
            |b: &mut criterion::Bencher<'_>| {
                b.iter(|| {
                    // use hex-simd library to decode directly into a byte array [u8; 32]
                    let mut array = [0u8; 32];
                    hex_simd::decode(hex_str.as_bytes(), hex_simd::AsOut::as_out(&mut array[..]))
                        .unwrap();
                    // use Txid::from_array to create the txid
                    let txid = waterfalls::be::Txid::from_array(array);
                    black_box(txid);
                });
            },
        );
}

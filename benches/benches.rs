use criterion::{black_box, criterion_group, criterion_main, Criterion};

use elements_miniscript::Descriptor;
use elements_miniscript::DescriptorPublicKey;
use waterfalls::WaterfallResponse;
use waterfalls::WaterfallResponseV3;

criterion_group!(benches, descriptor, encoding_decoding, conversion);
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
            black_box(r.script_pubkey());
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
        });
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

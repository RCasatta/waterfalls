#![feature(test)]

extern crate test;

#[cfg(test)]
mod tests {

    use elements_miniscript::Descriptor;
    use elements_miniscript::DescriptorPublicKey;
    use std::hint::black_box;
    pub fn test_desc(bh: &mut test::Bencher) {
        let desc_str = "elwpkh([a12b02f4/44'/0'/0']xpub6BzhLAQUDcBUfHRQHZxDF2AbcJqp4Kaeq6bzJpXrjrWuK26ymTFwkEFbxPra2bJ7yeZKbDjfDeFwxe93JMqpo5SsPJH6dZdvV9kMzJkAZ69/0/*)#20ufqv7z";
        let desc: Descriptor<DescriptorPublicKey> = desc_str.parse().unwrap();
        let mut i = 0;
        bh.iter(|| {
            let r = desc.at_derivation_index(i).unwrap();
            i += 1;
            black_box(r.script_pubkey());
        });
    }
}

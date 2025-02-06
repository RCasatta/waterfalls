#[cfg(test)]
mod tests {
    use minicbor::{Decode, Encode};

    #[derive(Encode, Decode)]
    struct Test {
        #[cbor(n(0))]
        a: u8,
    }

    #[test]
    fn test_encode() {
        let test = Test { a: 1 };
        let mut buffer = vec![];
        minicbor::encode(&test, &mut buffer).unwrap();
        println!("{:?}", buffer);
    }
}

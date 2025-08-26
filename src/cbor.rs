pub(crate) mod cbor_block_hash {

    use bitcoin::hashes::Hash;
    use elements::BlockHash;
    use minicbor::{bytes::ByteArray, Decoder, Encoder};

    pub(crate) fn decode<Ctx>(
        d: &mut Decoder<'_>,
        _ctx: &mut Ctx,
    ) -> Result<BlockHash, minicbor::decode::Error> {
        let bytes = d.decode::<ByteArray<32>>()?;
        // TODO use array
        Ok(BlockHash::from_slice(bytes.as_slice()).expect("every 32 bytes is a valid block hash"))
    }

    pub(crate) fn encode<Ctx, W: minicbor::encode::Write>(
        v: &BlockHash,
        e: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(v.as_ref())?;
        Ok(())
    }
}

pub(crate) mod cbor_opt_block_hash {

    use bitcoin::hashes::Hash;
    use elements::BlockHash;
    use minicbor::{bytes::ByteArray, Decoder, Encoder};

    pub(crate) fn decode<Ctx>(
        d: &mut Decoder<'_>,
        _ctx: &mut Ctx,
    ) -> Result<Option<BlockHash>, minicbor::decode::Error> {
        let bytes = d.decode::<ByteArray<32>>()?;
        if bytes.as_slice() == [0u8; 32] {
            Ok(None)
        } else {
            Ok(Some(
                BlockHash::from_slice(bytes.as_slice())
                    .expect("every 32 bytes is a valid block hash"),
            ))
        }
    }

    pub(crate) fn encode<Ctx, W: minicbor::encode::Write>(
        v: &Option<BlockHash>,
        e: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match v {
            Some(block_hash) => e.bytes(block_hash.as_ref())?,
            None => e.bytes(&[0u8; 32])?,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use elements::{hex::ToHex, BlockHash};
    use minicbor::{Decode, Encode};

    use crate::BlockMeta;
    use crate::WaterfallResponse;

    #[test]
    fn test_encode_cbor() {
        let block_meta = BlockMeta {
            b: BlockHash::from_str(
                "759333440d911fbfab40c4f6d572635873bf4cbc9ffd8efaf014b762e733d30b",
            )
            .unwrap(),
            t: 1234567890,
            h: 654321,
        };
        let mut buffer = vec![];
        minicbor::encode(&block_meta, &mut buffer).unwrap();
        assert_eq!(buffer.len(), 45);
        assert_eq!("8358200bd333e762b714f0fa8efd9fbc4cbf73586372d5f6c440abbf1f910d443393751a499602d21a0009fbf1", buffer.to_hex());
        let block_meta_decoded: BlockMeta = minicbor::decode(&buffer).unwrap();
        assert_eq!(block_meta_decoded, block_meta);
        let x = r#"{"b":"759333440d911fbfab40c4f6d572635873bf4cbc9ffd8efaf014b762e733d30b","t":1234567890,"h":654321}"#;
        assert_eq!(x.len(), 98);

        #[derive(Encode, Decode, Debug, PartialEq, Eq)]
        struct Test {
            #[cbor(n(0))]
            a: Vec<crate::be::Txid>,
        }
        // Test Vec<Txid> roundtrip
        let txids = vec![
            crate::be::Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            crate::be::Txid::from_str(
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
        ];
        let test = Test { a: txids };
        let mut buffer = vec![];
        minicbor::encode(&test, &mut buffer).unwrap();
        assert_eq!("81825820111111111111111111111111111111111111111111111111111111111111111158202222222222222222222222222222222222222222222222222222222222222222", buffer.to_hex());
        assert_eq!(buffer.len(), 70);
        let test_decoded: Test = minicbor::decode(&buffer).unwrap();
        assert_eq!(test_decoded, test);

        let s = include_str!("../tests/data/waterfall_response_v2.json");
        assert_eq!(s.len(), 8065);
        let resp: WaterfallResponse = serde_json::from_str(&s).unwrap();
        let mut buffer = vec![];
        minicbor::encode(&resp, &mut buffer).unwrap();
        assert_eq!(buffer.len(), 3349);
        let resp_decoded: WaterfallResponse = minicbor::decode(&buffer).unwrap();
        assert_eq!(resp_decoded, resp);
    }
}

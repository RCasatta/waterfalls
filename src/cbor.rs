pub(crate) mod cbor_block_hash {

    use bitcoin::hashes::Hash;
    use elements::BlockHash;
    use minicbor::{bytes::ByteArray, Decoder, Encoder};

    pub(crate) fn decode<'b, Ctx>(
        d: &mut Decoder<'b>,
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use elements::{hex::ToHex, BlockHash};

    use crate::BlockMeta;

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
        //println!("{}", buffer.to_hex());
        let block_meta_decoded: BlockMeta = minicbor::decode(&buffer).unwrap();
        assert_eq!(block_meta_decoded, block_meta);
        let x = r#"{"b":"759333440d911fbfab40c4f6d572635873bf4cbc9ffd8efaf014b762e733d30b","t":1234567890,"h":654321}"#;
        assert_eq!(x.len(), 98);
    }
}

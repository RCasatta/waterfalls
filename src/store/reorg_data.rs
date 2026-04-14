use anyhow::Result;
use std::collections::BTreeMap;

use crate::{store::TxSeen, OutPoint, ScriptHash};

use super::db::{vec_tx_seen_from_be_bytes, vec_tx_seen_to_be_bytes};

/// Data for handling reorgs up to 1 block.
/// If the process halts right before a reorg, this will be lost and a reindex must happen.
#[derive(Debug, Default)]
pub(super) struct ReorgData {
    /// Input spent in the last block. These are usually deleted from the db when a block is found.
    /// When there is a reorg we reinsert them in the db.
    pub(super) spent: Vec<(OutPoint, ScriptHash)>,

    /// History changes from the last block. Contains the script hashes and their corresponding
    /// TxSeen entries that were added in the last block. When there is a reorg we remove
    /// these entries from the history.
    pub(super) history: BTreeMap<ScriptHash, Vec<TxSeen>>,

    /// UTXOs created in the last block. When there is a reorg we remove these UTXOs
    /// from the database.
    pub(super) utxos_created: BTreeMap<OutPoint, ScriptHash>,
}

impl ReorgData {
    /// Serialize ReorgData to bytes using consensus encoding.
    ///
    /// Format:
    /// - Version (u8): 1
    /// - Spent count (u32)
    /// - For each spent: OutPoint (36 bytes) + ScriptHash (8 bytes)
    /// - History count (u32)
    /// - For each history entry: ScriptHash (8 bytes) + Vec<TxSeen> length (u32) + serialized TxSeen data
    /// - UTXOs created count (u32)
    /// - For each utxo_created: OutPoint (36 bytes) + ScriptHash (8 bytes)
    pub(super) fn to_bytes(&self) -> Result<Vec<u8>> {
        use elements::encode::Encodable;

        let mut bytes = Vec::new();

        // Version byte for future compatibility
        bytes.push(1u8);

        // Serialize spent
        (self.spent.len() as u32).consensus_encode(&mut bytes)?;
        for (outpoint, script_hash) in &self.spent {
            outpoint.consensus_encode(&mut bytes)?;
            script_hash.consensus_encode(&mut bytes)?;
        }

        // Serialize history
        (self.history.len() as u32).consensus_encode(&mut bytes)?;
        for (script_hash, tx_seen_vec) in &self.history {
            script_hash.consensus_encode(&mut bytes)?;
            let tx_seen_bytes = vec_tx_seen_to_be_bytes(tx_seen_vec);
            (tx_seen_bytes.len() as u32).consensus_encode(&mut bytes)?;
            bytes.extend_from_slice(&tx_seen_bytes);
        }

        // Serialize utxos_created
        (self.utxos_created.len() as u32).consensus_encode(&mut bytes)?;
        for (outpoint, script_hash) in &self.utxos_created {
            outpoint.consensus_encode(&mut bytes)?;
            script_hash.consensus_encode(&mut bytes)?;
        }

        Ok(bytes)
    }

    /// Deserialize ReorgData from bytes.
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use elements::encode::Decodable;

        if bytes.is_empty() {
            return Ok(Self::default());
        }

        let mut cursor = std::io::Cursor::new(bytes);

        // Read and verify version
        let version = u8::consensus_decode(&mut cursor)?;
        if version != 1 {
            anyhow::bail!("Unknown ReorgData version: {}", version);
        }

        // Deserialize spent
        let spent_count = u32::consensus_decode(&mut cursor)? as usize;
        let mut spent = Vec::with_capacity(spent_count);
        for _ in 0..spent_count {
            let outpoint = OutPoint::consensus_decode(&mut cursor)?;
            let script_hash = u64::consensus_decode(&mut cursor)?;
            spent.push((outpoint, script_hash));
        }

        // Deserialize history
        let history_count = u32::consensus_decode(&mut cursor)? as usize;
        let mut history = BTreeMap::new();
        for _ in 0..history_count {
            let script_hash = u64::consensus_decode(&mut cursor)?;
            let tx_seen_len = u32::consensus_decode(&mut cursor)? as usize;
            let pos = cursor.position() as usize;
            let tx_seen_bytes = &bytes[pos..pos + tx_seen_len];
            let tx_seen_vec = vec_tx_seen_from_be_bytes(tx_seen_bytes)?;
            cursor.set_position((pos + tx_seen_len) as u64);
            history.insert(script_hash, tx_seen_vec);
        }

        // Deserialize utxos_created
        let utxos_created_count = u32::consensus_decode(&mut cursor)? as usize;
        let mut utxos_created = BTreeMap::new();
        for _ in 0..utxos_created_count {
            let outpoint = OutPoint::consensus_decode(&mut cursor)?;
            let script_hash = u64::consensus_decode(&mut cursor)?;
            utxos_created.insert(outpoint, script_hash);
        }

        Ok(Self {
            spent,
            history,
            utxos_created,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::V;

    #[test]
    fn test_reorg_data_roundtrip() {
        // Create a ReorgData with all fields populated
        let mut reorg_data = ReorgData::default();

        // Add some spent UTXOs
        let txid1 = crate::be::Txid::from_slice(&[1u8; 32]).unwrap();
        let txid2 = crate::be::Txid::from_slice(&[2u8; 32]).unwrap();
        let outpoint1 = OutPoint::new(txid1, 0);
        let outpoint2 = OutPoint::new(txid2, 1);
        reorg_data.spent.push((outpoint1, 123456789u64));
        reorg_data.spent.push((outpoint2, 987654321u64));

        // Add some history entries
        let script_hash1 = 111111u64;
        let script_hash2 = 222222u64;

        let tx_seen1 = TxSeen::new(
            crate::be::Txid::from_slice(&[3u8; 32]).unwrap(),
            100,
            V::Vout(0),
        );
        let tx_seen2 = TxSeen::new(
            crate::be::Txid::from_slice(&[4u8; 32]).unwrap(),
            101,
            V::Vin(1),
        );

        reorg_data
            .history
            .insert(script_hash1, vec![tx_seen1.clone()]);
        reorg_data
            .history
            .insert(script_hash2, vec![tx_seen1.clone(), tx_seen2.clone()]);

        // Add some created UTXOs
        let txid3 = crate::be::Txid::from_slice(&[5u8; 32]).unwrap();
        let txid4 = crate::be::Txid::from_slice(&[6u8; 32]).unwrap();
        let outpoint3 = OutPoint::new(txid3, 2);
        let outpoint4 = OutPoint::new(txid4, 3);
        reorg_data.utxos_created.insert(outpoint3, 333333u64);
        reorg_data.utxos_created.insert(outpoint4, 444444u64);

        // Serialize to bytes
        let bytes = reorg_data.to_bytes().expect("serialization should succeed");

        assert!(!bytes.is_empty(), "Serialized data should not be empty");
        assert_eq!(bytes.len(), 315);

        // Deserialize from bytes
        let deserialized = ReorgData::from_bytes(&bytes).expect("deserialization should succeed");

        // Verify spent
        assert_eq!(reorg_data.spent.len(), deserialized.spent.len());
        for (original, deserialized) in reorg_data.spent.iter().zip(deserialized.spent.iter()) {
            assert_eq!(original.0, deserialized.0,);
            assert_eq!(original.1, deserialized.1,);
        }

        // Verify history
        assert_eq!(reorg_data.history.len(), deserialized.history.len());
        for (script_hash, tx_seen_vec) in &reorg_data.history {
            let deserialized_vec = deserialized
                .history
                .get(script_hash)
                .expect("ScriptHash should exist in deserialized history");
            assert_eq!(tx_seen_vec.len(), deserialized_vec.len(),);
            for (original_tx_seen, deserialized_tx_seen) in
                tx_seen_vec.iter().zip(deserialized_vec.iter())
            {
                assert_eq!(original_tx_seen.txid, deserialized_tx_seen.txid);
                assert_eq!(original_tx_seen.height, deserialized_tx_seen.height);
                assert_eq!(original_tx_seen.v, deserialized_tx_seen.v);
            }
        }

        // Verify utxos_created
        assert_eq!(
            reorg_data.utxos_created.len(),
            deserialized.utxos_created.len()
        );
        for (outpoint, script_hash) in &reorg_data.utxos_created {
            let deserialized_script_hash = deserialized
                .utxos_created
                .get(outpoint)
                .expect("OutPoint should exist in deserialized utxos_created");
            assert_eq!(script_hash, deserialized_script_hash,);
        }
    }

    #[test]
    fn test_reorg_data_empty() {
        // Test empty ReorgData
        let empty = ReorgData::default();
        let bytes = empty.to_bytes().expect("serialization should succeed");

        // Should have version byte + 3 zero counts (spent, history, utxos_created)
        assert_eq!(
            bytes.len(),
            1 + 4 + 4 + 4,
            "Empty ReorgData should be 13 bytes"
        );

        let deserialized = ReorgData::from_bytes(&bytes).expect("deserialization should succeed");
        assert!(deserialized.spent.is_empty());
        assert!(deserialized.history.is_empty());
        assert!(deserialized.utxos_created.is_empty());

        // Test from empty slice
        let from_empty = ReorgData::from_bytes(&[]).expect("should handle empty slice");
        assert!(from_empty.spent.is_empty());
        assert!(from_empty.history.is_empty());
        assert!(from_empty.utxos_created.is_empty());
    }
}

use elements::hex::FromHex;

use crate::{be, Family};

#[derive(Debug)]
pub enum Transaction {
    Bitcoin(bitcoin::Transaction),
    Elements(elements::Transaction),
}

pub enum Output {
    Bitcoin(Box<bitcoin::TxOut>),
    Elements(Box<elements::TxOut>),
}

pub enum Input {
    Bitcoin(Box<bitcoin::TxIn>),
    Elements(Box<elements::TxIn>),
}

fn elements_txid(txid: bitcoin::Txid) -> elements::Txid {
    elements::Txid::from_raw_hash(txid.to_raw_hash())
}

impl Transaction {
    // We are using elements::Txid also for bitcoin txid which is ugly but less impactfull for now (they serialize to the same 32 bytes)
    pub fn txid(&self) -> elements::Txid {
        match self {
            Transaction::Bitcoin(tx) => elements_txid(tx.compute_txid()),
            Transaction::Elements(tx) => tx.txid(),
        }
    }

    pub(crate) fn is_coinbase(&self) -> bool {
        match self {
            Transaction::Bitcoin(tx) => tx.is_coinbase(),
            Transaction::Elements(tx) => tx.is_coinbase(),
        }
    }

    pub(crate) fn outputs(&self) -> Vec<be::Output> {
        match self {
            Transaction::Bitcoin(tx) => tx
                .output
                .iter()
                .cloned()
                .map(|output| be::Output::Bitcoin(Box::new(output)))
                .collect(),
            Transaction::Elements(tx) => tx
                .output
                .iter()
                .cloned()
                .map(|output| be::Output::Elements(Box::new(output)))
                .collect(),
        }
    }

    pub(crate) fn inputs(&self) -> Vec<be::Input> {
        match self {
            Transaction::Bitcoin(tx) => tx
                .input
                .iter()
                .cloned()
                .map(|input| be::Input::Bitcoin(Box::new(input)))
                .collect(),
            Transaction::Elements(tx) => tx
                .input
                .iter()
                .cloned()
                .map(|input| be::Input::Elements(Box::new(input)))
                .collect(),
        }
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        match self {
            Transaction::Bitcoin(tx) => bitcoin::consensus::serialize(tx),
            Transaction::Elements(tx) => elements::encode::serialize(tx),
        }
    }

    pub(crate) fn serialize_hex(&self) -> String {
        match self {
            Transaction::Bitcoin(tx) => bitcoin::consensus::encode::serialize_hex(tx),
            Transaction::Elements(tx) => elements::encode::serialize_hex(tx),
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8], family: be::Family) -> Result<Self, anyhow::Error> {
        Ok(match family {
            Family::Bitcoin => {
                let bitcoin_tx =
                    <bitcoin::Transaction as bitcoin::consensus::Decodable>::consensus_decode(
                        &mut &bytes[..],
                    )?;
                be::Transaction::Bitcoin(bitcoin_tx)
            }
            Family::Elements => {
                let elements_tx =
                    <elements::Transaction as elements::encode::Decodable>::consensus_decode(
                        bytes,
                    )?;
                be::Transaction::Elements(elements_tx)
            }
        })
    }

    pub(crate) fn from_str(tx_hex: &str, family: be::Family) -> Result<Self, anyhow::Error> {
        let bytes = Vec::<u8>::from_hex(tx_hex).unwrap();
        Self::from_bytes(&bytes, family)
    }
}

impl Output {
    pub(crate) fn skip_indexing(&self) -> bool {
        match self {
            Output::Bitcoin(output) => {
                output.script_pubkey.is_empty() || output.script_pubkey.is_op_return()
            }
            Output::Elements(output) => {
                output.is_null_data() || output.is_fee() || output.script_pubkey.is_empty()
            }
        }
    }

    pub(crate) fn script_pubkey_bytes(&self) -> &[u8] {
        match self {
            Output::Bitcoin(output) => output.script_pubkey.as_bytes(),
            Output::Elements(output) => output.script_pubkey.as_bytes(),
        }
    }
}

impl Input {
    pub(crate) fn skip_indexing(&self) -> bool {
        match self {
            Input::Bitcoin(_) => false,
            Input::Elements(input) => input.is_pegin(),
        }
    }

    pub(crate) fn previous_output(&self) -> elements::OutPoint {
        match self {
            Input::Bitcoin(input) => elements::OutPoint::new(
                elements_txid(input.previous_output.txid),
                input.previous_output.vout,
            ),
            Input::Elements(input) => input.previous_output,
        }
    }
}

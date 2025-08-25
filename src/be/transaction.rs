use elements::hex::FromHex;

use crate::{be, Family};

#[derive(Debug)]
pub enum Transaction {
    Bitcoin(bitcoin::Transaction),
    Elements(elements::Transaction),
}

#[derive(Debug)]
pub enum TransactionRef<'a> {
    Bitcoin(&'a bitcoin::Transaction),
    Elements(&'a elements::Transaction),
}

pub enum Output {
    Bitcoin(Box<bitcoin::TxOut>),
    Elements(Box<elements::TxOut>),
}

pub enum OutputRef<'a> {
    Bitcoin(&'a bitcoin::TxOut),
    Elements(&'a elements::TxOut),
}

pub enum Input {
    Bitcoin(Box<bitcoin::TxIn>),
    Elements(Box<elements::TxIn>),
}

pub enum InputRef<'a> {
    Bitcoin(&'a bitcoin::TxIn),
    Elements(&'a elements::TxIn),
}

impl Transaction {
    // We are using elements::Txid also for bitcoin txid which is ugly but less impactfull for now (they serialize to the same 32 bytes)
    pub fn txid(&self) -> crate::be::Txid {
        match self {
            Transaction::Bitcoin(tx) => tx.compute_txid().into(),
            Transaction::Elements(tx) => tx.txid().into(),
        }
    }

    /// Iterator over outputs without cloning - more efficient for indexing
    pub(crate) fn outputs_iter(&self) -> impl Iterator<Item = be::OutputRef> {
        match self {
            Transaction::Bitcoin(tx) => OutputIterator::Bitcoin(tx.output.iter()),
            Transaction::Elements(tx) => OutputIterator::Elements(tx.output.iter()),
        }
    }

    /// Iterator over inputs without cloning - more efficient for indexing
    pub(crate) fn inputs_iter(&self) -> impl Iterator<Item = be::InputRef> {
        match self {
            Transaction::Bitcoin(tx) => InputIterator::Bitcoin(tx.input.iter()),
            Transaction::Elements(tx) => InputIterator::Elements(tx.input.iter()),
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

impl<'a> TransactionRef<'a> {
    pub fn txid(&self) -> crate::be::Txid {
        match self {
            TransactionRef::Bitcoin(tx) => tx.compute_txid().into(),
            TransactionRef::Elements(tx) => tx.txid().into(),
        }
    }

    pub(crate) fn is_coinbase(&self) -> bool {
        match self {
            TransactionRef::Bitcoin(tx) => tx.is_coinbase(),
            TransactionRef::Elements(tx) => tx.is_coinbase(),
        }
    }

    /// Iterator over outputs without cloning - more efficient for indexing
    pub(crate) fn outputs_iter(&self) -> impl Iterator<Item = be::OutputRef> {
        match self {
            TransactionRef::Bitcoin(tx) => OutputIterator::Bitcoin(tx.output.iter()),
            TransactionRef::Elements(tx) => OutputIterator::Elements(tx.output.iter()),
        }
    }

    /// Iterator over inputs without cloning - more efficient for indexing
    pub(crate) fn inputs_iter(&self) -> impl Iterator<Item = be::InputRef> {
        match self {
            TransactionRef::Bitcoin(tx) => InputIterator::Bitcoin(tx.input.iter()),
            TransactionRef::Elements(tx) => InputIterator::Elements(tx.input.iter()),
        }
    }
}

pub(crate) enum OutputIterator<'a> {
    Bitcoin(std::slice::Iter<'a, bitcoin::TxOut>),
    Elements(std::slice::Iter<'a, elements::TxOut>),
}

impl<'a> Iterator for OutputIterator<'a> {
    type Item = be::OutputRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            OutputIterator::Bitcoin(iter) => iter.next().map(be::OutputRef::Bitcoin),
            OutputIterator::Elements(iter) => iter.next().map(be::OutputRef::Elements),
        }
    }
}

pub(crate) enum InputIterator<'a> {
    Bitcoin(std::slice::Iter<'a, bitcoin::TxIn>),
    Elements(std::slice::Iter<'a, elements::TxIn>),
}

impl<'a> Iterator for InputIterator<'a> {
    type Item = be::InputRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            InputIterator::Bitcoin(iter) => iter.next().map(be::InputRef::Bitcoin),
            InputIterator::Elements(iter) => iter.next().map(be::InputRef::Elements),
        }
    }
}

impl<'a> OutputRef<'a> {
    pub(crate) fn skip_utxo(&self) -> bool {
        match self {
            OutputRef::Bitcoin(output) => output.script_pubkey.is_op_return(),
            OutputRef::Elements(output) => output.is_null_data() || output.is_fee(),
        }
    }

    pub(crate) fn skip_indexing(&self) -> bool {
        match self {
            OutputRef::Bitcoin(output) => {
                output.script_pubkey.is_empty()
                    || output.script_pubkey.is_op_return()
                    || bitcoin::Address::from_script(
                        &output.script_pubkey,
                        bitcoin::Network::Regtest,
                    )
                    .is_err()
            }
            OutputRef::Elements(output) => {
                output.is_null_data()
                    || output.is_fee()
                    || output.script_pubkey.is_empty()
                    || elements::Address::from_script(
                        &output.script_pubkey,
                        None,
                        &elements::AddressParams::ELEMENTS,
                    )
                    .is_none()
            }
        }
    }

    pub(crate) fn script_pubkey_bytes(&self) -> &[u8] {
        match self {
            OutputRef::Bitcoin(output) => output.script_pubkey.as_bytes(),
            OutputRef::Elements(output) => output.script_pubkey.as_bytes(),
        }
    }
}

impl<'a> InputRef<'a> {
    pub(crate) fn skip_indexing(&self) -> bool {
        match self {
            InputRef::Bitcoin(_) => false,
            InputRef::Elements(input) => input.is_pegin(),
        }
    }

    pub(crate) fn previous_output(&self) -> elements::OutPoint {
        match self {
            InputRef::Bitcoin(input) => elements::OutPoint::new(
                crate::be::Txid::from(input.previous_output.txid).elements(),
                input.previous_output.vout,
            ),
            InputRef::Elements(input) => input.previous_output,
        }
    }
}

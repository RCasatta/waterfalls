use crate::be;

pub enum Transaction {
    Bitcoin(bitcoin::Transaction),
    Elements(elements::Transaction),
}

pub enum Output {
    Bitcoin(bitcoin::TxOut),
    Elements(elements::TxOut),
}

pub enum Input {
    Bitcoin(bitcoin::TxIn),
    Elements(elements::TxIn),
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
                .map(|output| be::Output::Bitcoin(output))
                .collect(),
            Transaction::Elements(tx) => tx
                .output
                .iter()
                .cloned()
                .map(|output| be::Output::Elements(output))
                .collect(),
        }
    }

    pub(crate) fn inputs(&self) -> Vec<be::Input> {
        match self {
            Transaction::Bitcoin(tx) => tx
                .input
                .iter()
                .cloned()
                .map(|input| be::Input::Bitcoin(input))
                .collect(),
            Transaction::Elements(tx) => tx
                .input
                .iter()
                .cloned()
                .map(|input| be::Input::Elements(input))
                .collect(),
        }
    }
}

impl Output {
    pub(crate) fn skip_indexing(&self) -> bool {
        match self {
            Output::Bitcoin(_) => todo!(),
            Output::Elements(output) => {
                output.is_null_data() || output.is_fee() || output.script_pubkey.is_empty()
            }
        }
    }

    // We are using elements::Script also for bitcoin script which is ugly but less impactfull for now
    pub(crate) fn script_pubkey(&self) -> elements::Script {
        match self {
            Output::Bitcoin(output) => output.script_pubkey.to_bytes().into(),
            Output::Elements(output) => output.script_pubkey.clone(),
        }
    }
}

impl Input {
    pub(crate) fn skip_indexing(&self) -> bool {
        match self {
            Input::Bitcoin(_) => todo!(),
            Input::Elements(input) => input.is_pegin(),
        }
    }

    pub(crate) fn previous_output(&self) -> elements::OutPoint {
        match self {
            Input::Bitcoin(input) => elements::OutPoint::new(
                elements_txid(input.previous_output.txid),
                input.previous_output.vout,
            ),
            Input::Elements(input) => input.previous_output.clone(),
        }
    }
}

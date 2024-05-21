use serde::{Serialize, Serializer};

#[derive(Debug, Serialize)]
pub struct Input {
    pub txid: String,
    pub output_index: u32,
    pub script: String,
    pub sequence: u32,
}

#[derive(Debug)]
pub struct Amount(u64);

pub trait BitcoinValue {
    fn to_btc(&self) -> f64;
}

impl BitcoinValue for Amount {
    fn to_btc(&self) -> f64 {
        self.0 as f64 / 100_000_000.0
    }
}

impl Amount {
    pub fn from_sat(sats: u64) -> Amount {
        Amount(sats)
    }
}

fn as_btc<T: BitcoinValue, S: Serializer>(t: &T, s: S) -> Result<S::Ok, S::Error> {
    let btc = t.to_btc();
    s.serialize_f64(btc)
}

#[derive(Debug, Serialize)]
pub struct Output {
    #[serde(serialize_with = "as_btc")]
    pub amount: Amount,
    pub script_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

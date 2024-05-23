use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Error as IOError, ErrorKind};
use std::io::{Read, Write};

#[derive(fmt::Debug)]
pub enum Error {
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl std::error::Error for Error {}

#[derive(fmt::Debug)]
pub struct Transaction {
    pub version: Version,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn txid(&self) -> Txid {
        let mut txid_data = Vec::new();
        self.version.consensus_encode(&mut txid_data).unwrap();
        self.inputs.consensus_encode(&mut txid_data).unwrap();
        self.outputs.consensus_encode(&mut txid_data).unwrap();
        self.lock_time.consensus_encode(&mut txid_data).unwrap();
        Txid::new(txid_data)
    }
}

pub trait Encodable {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error>;
}

impl Encodable for Version {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let len = self.0.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for u8 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let len = writer.write([*self].as_slice()).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for u16 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        let len = writer.write(bytes.as_slice()).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for u32 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        let len = writer.write(bytes.as_slice()).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for u64 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        let len = writer.write(bytes.as_slice()).map_err(Error::Io)?;
        Ok(len)
    }
}

impl Encodable for Vec<TxIn> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += CompactSize(self.len() as u64).consensus_encode(writer)?;
        for input in self.iter() {
            len += input.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl Encodable for TxIn {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.previous_txid.consensus_encode(writer)?;
        len += self.previous_vout.consensus_encode(writer)?;
        len += self.script_sig.consensus_encode(writer)?;
        len += self.sequence.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for Txid {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let buff = self.0.as_slice();
        Ok(writer.write(buff).map_err(Error::Io)?)
    }
}

impl Encodable for String {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let b = hex::decode(self).expect("should be a valid hex string");
        let compact_size_len = CompactSize(b.len() as u64).consensus_encode(writer)?;
        let b_len = writer.write(&b).map_err(Error::Io)?;
        Ok(compact_size_len + b_len)
    }
}

impl Encodable for Vec<TxOut> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += CompactSize(self.len() as u64).consensus_encode(writer)?;
        for input in self.iter() {
            len += input.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl Encodable for TxOut {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut len = 0;
        len += self.amount.consensus_encode(writer)?;
        len += self.script_pubkey.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Encodable for Amount {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        Ok(self.0.consensus_encode(writer)?)
    }
}

impl Encodable for CompactSize {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let val = self.0;
        match val {
            0..=0xFC => {
                (val as u8).consensus_encode(writer)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                writer.write([0xFD].as_slice()).map_err(Error::Io)?;
                (val as u16).consensus_encode(writer)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                writer.write([0xFE].as_slice()).map_err(Error::Io)?;
                (val as u32).consensus_encode(writer)?;
                Ok(5)
            }
            _ => {
                writer.write([0xFF].as_slice()).map_err(Error::Io)?;
                val.consensus_encode(writer)?;
                Ok(9)
            }
        }
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tx = serializer.serialize_struct("Transaction", 5)?;
        tx.serialize_field("transaction_id", &self.txid())?;
        tx.serialize_field("version", &self.version)?;
        tx.serialize_field("inputs", &self.inputs)?;
        tx.serialize_field("outputs", &self.outputs)?;
        tx.serialize_field("locktime", &self.lock_time)?;
        tx.end()
    }
}

impl Decodable for Transaction {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(Transaction {
            version: Version::consensus_decode(reader)?,
            inputs: Vec::<TxIn>::consensus_decode(reader)?,
            outputs: Vec::<TxOut>::consensus_decode(reader)?,
            lock_time: u32::consensus_decode(reader)?,
        })
    }
}

#[derive(fmt::Debug)]
pub struct Txid([u8; 32]);

impl Txid {
    fn new(data: Vec<u8>) -> Txid {
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash1 = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(hash1);
        let hash2 = hasher.finalize();

        Txid(hash2.into())
    }
}

impl Serialize for Txid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut bytes = self.0.clone();
        bytes.reverse();
        s.serialize_str(&hex::encode(bytes))
    }
}

impl Decodable for Txid {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 32];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(Txid(buffer))
    }
}

#[derive(Debug, Serialize)]
pub struct Version(pub u32);

#[derive(fmt::Debug, Serialize)]
pub struct TxIn {
    pub previous_txid: Txid,
    pub previous_vout: u32,
    pub script_sig: String,
    pub sequence: u32,
}

impl Decodable for Vec<TxIn> {
    fn consensus_decode<R: Read>(r: &mut R) -> Result<Self, Error> {
        let len = CompactSize::consensus_decode(r)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(TxIn::consensus_decode(r)?);
        }
        Ok(ret)
    }
}

impl Decodable for TxIn {
    fn consensus_decode<R: Read>(r: &mut R) -> Result<Self, Error> {
        Ok(TxIn {
            previous_txid: Txid::consensus_decode(r)?,
            previous_vout: u32::consensus_decode(r)?,
            script_sig: String::consensus_decode(r)?,
            sequence: u32::consensus_decode(r)?,
        })
    }
}

impl Decodable for String {
    fn consensus_decode<R: Read>(r: &mut R) -> Result<Self, Error> {
        let script_size = CompactSize::consensus_decode(r)?.0;
        let mut buffer = vec![0; script_size as usize];
        r.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(hex::encode(buffer))
    }
}

#[derive(fmt::Debug, Serialize)]
pub struct TxOut {
    #[serde(serialize_with = "as_btc")]
    pub amount: Amount,
    pub script_pubkey: String,
}

impl Decodable for Vec<TxOut> {
    fn consensus_decode<R: Read>(r: &mut R) -> Result<Self, Error> {
        let len = CompactSize::consensus_decode(r)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(TxOut::consensus_decode(r)?);
        }
        Ok(ret)
    }
}

impl Decodable for TxOut {
    fn consensus_decode<R: Read>(r: &mut R) -> Result<Self, Error> {
        Ok(TxOut {
            amount: Amount::from_sat(u64::consensus_decode(r)?),
            script_pubkey: String::consensus_decode(r)?,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct CompactSize(pub u64);

pub trait Decodable: Sized {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error>;
}

impl Decodable for u8 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 1];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(buffer[0]) // endian-ness doesn't matter for 1 byte
    }
}

impl Decodable for u16 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 2];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(u16::from_le_bytes(buffer))
    }
}

impl Decodable for u32 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 4];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(u32::from_le_bytes(buffer))
    }
}

impl Decodable for u64 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buffer = [0; 8];
        reader.read_exact(&mut buffer).map_err(Error::Io)?;
        Ok(u64::from_le_bytes(buffer))
    }
}

impl Decodable for Version {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(Version(u32::consensus_decode(reader)?))
    }
}

impl Decodable for CompactSize {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut n = u8::consensus_decode(reader)?;

        match n {
            (1..=252) => Ok(CompactSize(n as u64)),
            253 => {
                let x = u16::consensus_decode(reader)?;
                Ok(CompactSize(x as u64))
            }
            254 => {
                let x = u32::consensus_decode(reader)?;
                Ok(CompactSize(x as u64))
            }
            255 => {
                let x = u64::consensus_decode(reader)?;
                Ok(CompactSize(x))
            }
            _ => Err(Error::Io(IOError::new(
                ErrorKind::InvalidInput,
                "Compact size error: invalid compact size",
            ))),
        }
    }
}

#[derive(fmt::Debug)]
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

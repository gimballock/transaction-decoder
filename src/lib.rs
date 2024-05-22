mod transaction;

use std::error::Error;
use std::io::Read;
use std::io::{Error as IOError, ErrorKind};

use clap::{arg, value_parser, Command};
use sha2::{Digest, Sha256};

use transaction::{Amount, Input, Output, Transaction};

use crate::transaction::Txid;

pub fn get_arg() -> String {
    let matches = Command::new("Bitcoin Transaction Decoder")
        .version("1.0")
        .about("Decodes a raw transaction")
        .arg(
            arg!([RAW_TRANSACTION])
                .value_parser(value_parser!(String))
                .required(true),
        )
        .get_matches();

    matches
        .get_one::<String>("RAW_TRANSACTION")
        .cloned()
        .expect("raw transaction is required")
}

fn read_u32(transaction_bytes: &mut &[u8]) -> Result<u32, IOError> {
    let mut buffer = [0; 4];
    transaction_bytes.read(&mut buffer)?;

    Ok(u32::from_le_bytes(buffer))
}

fn read_compact_size(transaction_bytes: &mut &[u8]) -> Result<u64, IOError> {
    let mut compact_size = [0; 1];
    transaction_bytes.read(&mut compact_size)?;

    let first_byte = compact_size[0];
    match first_byte {
        (1..=252) => Ok(compact_size[0] as u64),
        253 => {
            let mut buffer = [0; 2];
            transaction_bytes.read(&mut buffer)?;
            Ok(u16::from_le_bytes(buffer) as u64)
        }
        254 => {
            let mut buffer = [0; 4];
            transaction_bytes.read(&mut buffer)?;
            Ok(u32::from_le_bytes(buffer) as u64)
        }
        255 => {
            let mut buffer = [0; 8];
            transaction_bytes.read(&mut buffer)?;
            Ok(u64::from_le_bytes(buffer) as u64)
        }
        _ => Err(IOError::new(ErrorKind::InvalidData, "invalid compact size")),
    }
}

fn read_txid(transaction_bytes: &mut &[u8]) -> Result<Txid, IOError> {
    let mut buffer = [0; 32];
    transaction_bytes.read(&mut buffer)?;
    Ok(Txid::from_bytes(buffer))
}

fn read_script(transaction_bytes: &mut &[u8]) -> Result<String, IOError> {
    let script_size = read_compact_size(transaction_bytes)? as usize;
    let mut buffer = vec![0; script_size];
    transaction_bytes.read(&mut buffer)?;
    Ok(hex::encode(buffer))
}

fn read_amount(transaction_bytes: &mut &[u8]) -> Result<Amount, IOError> {
    let mut buffer = [0; 8];
    transaction_bytes.read(&mut buffer)?;

    Ok(Amount::from_sat(u64::from_le_bytes(buffer)))
}

fn hash_transaction(raw_transaction: &[u8]) -> Txid {
    // create a sha256 object
    let mut hasher = Sha256::new();

    // write the input message
    hasher.update(&raw_transaction);

    // read digest, consumer hasher
    let hash1 = hasher.finalize();

    // hash1 becomes our new input to be hashed again
    // prepare a new hasher object
    let mut hasher = Sha256::new();
    hasher.update(hash1);
    let hash2 = hasher.finalize();

    // hash is of the type GenericArray<u8, Self::OutputSize>
    // convert to [u8; 32]
    Txid::from_bytes(hash2.into())
}

pub fn run(raw_transaction_hex: String) -> Result<String, Box<dyn Error>> {
    let transaction_bytes =
        hex::decode(raw_transaction_hex).map_err(|e| format!("Hex decoding error: {}", e))?;
    let mut bytes_slice = transaction_bytes.as_slice();
    let version = read_u32(&mut bytes_slice)?;

    //Read inputs
    let input_length = read_compact_size(&mut bytes_slice)?;
    let mut inputs = vec![];

    for _ in 0..input_length {
        let txid = read_txid(&mut bytes_slice)?;
        let output_index = read_u32(&mut bytes_slice)?;
        let script = read_script(&mut bytes_slice)?;
        let sequence = read_u32(&mut bytes_slice)?;

        inputs.push(Input {
            previous_txid: txid,
            previous_vout: output_index,
            script_sig: script,
            sequence,
        });
    }

    // Read outputs
    let output_length = read_compact_size(&mut bytes_slice)?;

    let mut outputs = vec![];
    for _ in 0..output_length {
        let amount = read_amount(&mut bytes_slice)?;
        let script_pubkey = read_script(&mut bytes_slice)?;

        outputs.push(Output {
            amount,
            script_pubkey,
        });
    }

    let lock_time = read_u32(&mut bytes_slice)?;

    let transaction_id = hash_transaction(&transaction_bytes);

    let txn = Transaction {
        version,
        inputs,
        outputs,
        locktime: lock_time,
        transaction_id,
    };

    let json = serde_json::to_string_pretty(&txn)?;

    Ok(json)
}

#[cfg(test)]
mod unit_tests {
    use super::read_compact_size;

    #[test]
    fn test_read_compact_size() {
        let mut bytes = [1_u8].as_slice();
        let length = read_compact_size(&mut bytes).unwrap();
        assert_eq!(length, 1_u64);

        let mut bytes = [253_u8, 0, 1].as_slice();
        let length = read_compact_size(&mut bytes).unwrap();
        assert_eq!(length, 256_u64);

        let mut bytes = [254_u8, 0, 0, 0, 1].as_slice();
        let length = read_compact_size(&mut bytes).unwrap();
        assert_eq!(length, 256_u64.pow(3));

        let mut bytes = [255_u8, 0, 0, 0, 0, 0, 0, 0, 1].as_slice();
        let length = read_compact_size(&mut bytes).unwrap();
        assert_eq!(length, 256_u64.pow(7));

        // https://mempool.space/tx/52539a56b1eb890504b775171923430f0355eb836a57134ba598170a2f8980c1
        // fd is 253
        // transaction has 20,000 empty inputs
        let hex = "fd204e";
        let decoded = hex::decode(hex).unwrap();
        let mut bytes = decoded.as_slice();
        let length = read_compact_size(&mut bytes).unwrap();
        let expected_length = 20_000_u64;
        assert_eq!(length, expected_length);

        let result = std::panic::catch_unwind(|| {
            let mut bytes = [0_u8].as_slice();
            read_compact_size(&mut bytes).unwrap();
        });
        assert!(result.is_err());
    }
}

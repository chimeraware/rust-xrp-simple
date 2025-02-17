// First, declare the xrp_transaction module
use bs58::{decode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256,Sha512};
use std::error::Error;
use secp256k1::{Message, PublicKey as Secp256k1PublicKey, SecretKey, Secp256k1};
use xrpl_rs::{
    transports::HTTP,
    types::{
        account::AccountInfoRequest,
        fee::FeeRequest,
        ledger::LedgerRequest,
        submit::SubmitRequest,
        CurrencyAmount,
        BigInt,
    },
    XRPL,
    transaction::types::Payment,
};

static FAMILY_SEED: u8 = 0x21;
const XRPL_TESTNET_URL: &str = "https://s.altnet.rippletest.net:51234/";
static DEFAULT_MAX_FEE: i64 = 100;
static DEFAULT_LEDGER_OFFSET: u32 = 20;

#[derive(Debug)]
pub enum TransactionType {
    EscrowFinish,
    AccountDelete,
    Other,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WalletInfo {
    pub seed: String,
    pub secret_key: String,
    pub public_key: String,
    pub address: String,
}

pub struct TransactionFee {
    pub tx_type: TransactionType,
    pub fulfillment: Option<String>,
}

#[derive(Debug)]
pub struct XrpTransaction {
    pub account: [u8; 20],
    pub destination: [u8; 20],
    pub amount: u64,
    pub fee: u64,
    pub sequence: u32,
    pub destination_tag: Option<u32>,
}

pub fn calculate_fee(max_fee: i64, tx_type: TransactionType, signers_count: u32) -> i64 {
    let net_fee: i64 = 10;
    let mut base_fee = net_fee;

    match tx_type {
        TransactionType::EscrowFinish => {
            let fulfillment_bytes = ("Escrow".len() as f64 / 2.0).ceil() as i64;
            base_fee = (net_fee as f64 * (33.0 + fulfillment_bytes as f64 / 16.0)).ceil() as i64;
        }
        TransactionType::AccountDelete => {
            base_fee = 2_000_000;
        }
        TransactionType::Other => {}
    }

    if signers_count > 0 {
        base_fee += net_fee * (1 + signers_count as i64);
    }

    match tx_type {
        TransactionType::AccountDelete => base_fee,
        _ => base_fee.min(max_fee),
    }
}

pub fn generate_wallet() -> WalletInfo {
    let secret = "SECRET".to_string();
    let wallet = xrpl_rs::wallet::Wallet::from_secret(&secret).unwrap();

    WalletInfo {
        seed: secret,
        secret_key: wallet.private_key().to_string(),
        public_key: wallet.public_key().to_string(),
        address: wallet.address().to_string(),
    }
}

pub fn decode_xrp_address(address: &str) -> Result<[u8; 20], String> {
    let alphabet = bs58::alphabet::Alphabet::RIPPLE;
    let decoded = decode(address)
        .with_alphabet(alphabet)
        .into_vec()
        .map_err(|e| e.to_string())?;

    if decoded.len() != 25 {
        return Err("Invalid address length - must decode to 25 bytes".into());
    }

    let (version_payload, checksum) = decoded.split_at(21);
    let computed_checksum = double_sha256(version_payload);

    if computed_checksum[..4] != *checksum {
        return Err("Checksum verification failed".into());
    }

    version_payload[1..21]
        .try_into()
        .map_err(|_| "Failed to convert payload to 20-byte array".into())
}

fn double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let first_hash = hasher.finalize_reset();
    hasher.update(first_hash);
    hasher.finalize().into()
}

pub struct TransactionBuilder {
    pub xrpl: XRPL<HTTP>,
    pub account_address: String,
    pub destination_address: String,
    pub amount: u64,
    pub secret_key: SecretKey,
}

impl TransactionBuilder {
    pub fn new(account_address: String, destination_address: String, amount: u64, secret_key: SecretKey) -> Result<Self, Box<dyn Error>> {
        let xrpl = XRPL::new(
            HTTP::builder()
                .with_endpoint(XRPL_TESTNET_URL).unwrap()
                .build().unwrap()
        );

        Ok(Self {
            xrpl,
            account_address,
            destination_address,
            amount,
            secret_key,
        })
    }

    pub async fn create_payment(&self) -> Result<Payment, Box<dyn Error>> {
        let mut payment = Payment::default();
        payment.amount = CurrencyAmount::xrp(self.amount);
        payment.destination = self.destination_address.clone();
        Ok(payment)
    }

    pub async fn prepare_transaction(&self, payment: Payment) -> Result<xrpl_rs::transaction::types::Transaction, Box<dyn Error>> {
        // Get account info
        let mut req = AccountInfoRequest::default();
        req.account = self.account_address.clone();
        let account_info = self.xrpl.account_info(req).await.unwrap();

        // Create and prepare transaction
        let mut tx = payment.into_transaction();
        tx.flags = Some(2147483648u32); // tfFullyCanonicalSig
        tx.account = account_info.account_data.account;
        tx.sequence = account_info.account_data.sequence;

        // Set fee
        self.set_transaction_fee(&mut tx).await?;
        
        // Set last ledger sequence
        self.set_last_ledger_sequence(&mut tx).await?;

        Ok(tx)
    }

    async fn set_transaction_fee(&self, tx: &mut xrpl_rs::transaction::types::Transaction) -> Result<(), Box<dyn Error>> {
        let fee_req = FeeRequest::default();
        let fee = self.xrpl.fee(fee_req).await.unwrap();
        
        if let CurrencyAmount::XRP(drops) = fee.drops.open_ledger_fee {
            tx.fee = drops;
        }

        if tx.fee > BigInt(DEFAULT_MAX_FEE as u64) {
            tx.fee = BigInt(calculate_fee(
                DEFAULT_MAX_FEE,
                TransactionType::Other,
                1
            ) as u64);
        }

        Ok(())
    }

    async fn set_last_ledger_sequence(&self, tx: &mut xrpl_rs::transaction::types::Transaction) -> Result<(), Box<dyn Error>> {
        let ledger_req = LedgerRequest::default();
        let ledger = self.xrpl.ledger(ledger_req).await.unwrap();
        tx.last_ledger_sequence = ledger
            .ledger
            .ledger_info
            .ledger_index
            .ok_or("Failed to get ledger index")?
            .0 + DEFAULT_LEDGER_OFFSET;
        Ok(())
    }

    pub fn sign_transaction(&self, tx: &mut xrpl_rs::transaction::types::Transaction) -> Result<(), Box<dyn Error>> {
        let secp = Secp256k1::new();
        tx.signing_pub_key = Secp256k1PublicKey::from_secret_key(&secp, &self.secret_key).to_string();

        let tx_blob_for_signing = serde_xrpl::ser::to_bytes_for_signing(&serde_json::to_value(&*tx)?)?;
        let mut hasher = Sha512::new();
        hasher.update(&tx_blob_for_signing);
        let hash = hasher.finalize()[..32].to_vec();
        
        let message = Message::from_slice(&hash)?;
        let signature = secp.sign_ecdsa(&message, &self.secret_key);
        tx.txn_signature = Some(signature.to_string().to_uppercase());

        Ok(())
    }
    
    pub fn serialize_transaction(&self, tx: &xrpl_rs::transaction::types::Transaction) -> Result<String, Box<dyn Error>> {
        let tx_blob = serde_xrpl::ser::to_bytes(&serde_json::to_value(tx)?)?;
        Ok(hex::encode(tx_blob).to_uppercase())
    }

    pub async fn submit_transaction(&self, tx_blob: String) -> Result<String, Box<dyn Error>> {
        let mut submit_req = SubmitRequest::default();
        submit_req.tx_blob = tx_blob;

        let submit_res = self.xrpl.submit(submit_req).await.unwrap();
        Ok(format!("{:?}", submit_res))
    }
}

// Keep all the existing functions (generate_wallet, decode_xrp_address, etc.)...
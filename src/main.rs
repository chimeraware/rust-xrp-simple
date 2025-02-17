use secp256k1::SecretKey;
mod xrp_transactions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate wallet
    let wallet = xrp_transactions::generate_wallet();
    println!("Secret Key: {}", wallet.secret_key);
    println!("Public Key: {}", wallet.public_key);
    println!("XRP Address: {}", wallet.address);

    // Setup transaction parameters
    let secret_key = SecretKey::from_slice(&hex::decode(wallet.secret_key).unwrap())?;
    let destination_address = "DESTINATION";
    let amount = 10000; // 10,000 drops

    // Create transaction builder
    let builder = xrp_transactions::TransactionBuilder::new(
        wallet.address,
        destination_address.to_string(),
        amount,
        secret_key,
    )?;

    // Create and prepare transaction
    let payment = builder.create_payment().await?;
    let mut tx = builder.prepare_transaction(payment).await?;

    // Sign the transaction
    builder.sign_transaction(&mut tx)?;

    // Serialize the transaction
    let tx_blob = builder.serialize_transaction(&tx)?;

    // Submit the transaction
    let result = builder.submit_transaction(tx_blob).await?;
    println!("Transaction submission response: {}", result);

    Ok(())
}
use bitcoincore_rpc::RpcApi;
use cat_scripts::{create_cat_address, spend_cat};
use config::NetworkConfig;

use rpc_helper::{get_vout_after_confirmation, send_funding_transaction};

use bitcoin::{
    absolute,
    consensus::encode::serialize_hex,
    transaction::{self},
    Address, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut,
};

use tracing::info;

mod cat_scripts;
mod config;
mod rpc_helper;
mod sigops;

//the amount you want to spend in the cat transaction
const CAT_SPEND_AMOUNT: Amount = Amount::from_sat(10000);
//this is the min dust amount required to anchor the transaction
const FEE_AMOUNT: Amount = Amount::from_sat(1000);

fn main() {
    tracing_subscriber::fmt().with_target(false).init();

    let config = NetworkConfig::new();
    let rpc = config.bitcoin_rpc();

    let cat_spend_to_address = rpc
        .get_new_address(None, None)
        .unwrap()
        .require_network(config.network)
        .unwrap();

    info!("cat target address: {}", cat_spend_to_address);

    let cat_tx_out = TxOut {
        value: CAT_SPEND_AMOUNT - FEE_AMOUNT,
        script_pubkey: cat_spend_to_address.script_pubkey(),
    };

    // create cat contract address
    let cat_tr_spend_info = create_cat_address(cat_tx_out.clone()).unwrap();
    let cat_contract_address =
        Address::p2tr_tweaked(cat_tr_spend_info.output_key(), config.network);
    info!("cat contract address: {}", cat_contract_address);

    #[cfg(feature = "regtest")]
    if rpc.get_balance(None, None).unwrap() < CAT_SPEND_AMOUNT + FEE_AMOUNT {
        let _ = rpc.generate_to_address(101, &cat_spend_to_address);
    }

    info!("Funding cat contract address...");
    let cat_funding_txid = send_funding_transaction(&rpc, &cat_contract_address, CAT_SPEND_AMOUNT);

    #[cfg(feature = "regtest")]
    let _ = rpc.generate_to_address(1, &cat_spend_to_address);

    //we have to wait for the funding transaction to be confirmed to pay to anchor
    let cat_vout = get_vout_after_confirmation(&rpc, cat_funding_txid, CAT_SPEND_AMOUNT);

    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: cat_funding_txid,
            vout: cat_vout,
        },
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    }];

    let unsigned_tx = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: vec![cat_tx_out.clone()],
    };

    let parent_tx = spend_cat(unsigned_tx, cat_tr_spend_info, cat_tx_out);

    let parent_serialized_tx = serialize_hex(&parent_tx);
    info!("\nSpending cat transaction...");
    info!("\nParent tx: {}", parent_serialized_tx);

    let parent_txid = rpc.send_raw_transaction(parent_serialized_tx).unwrap();

    info!("\nParent txid: {}", parent_txid);

    #[cfg(feature = "regtest")]
    let _ = rpc.generate_to_address(1, &cat_spend_to_address);
}

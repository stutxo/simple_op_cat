use bitcoin::{
    consensus::Encodable,
    hashes::{sha256, Hash},
    hex::{Case, DisplayHex},
    io::Error,
    key::{Keypair, Secp256k1},
    opcodes::all::{
        OP_CAT, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_ROT, OP_SHA256, OP_SWAP,
        OP_TOALTSTACK,
    },
    script::Builder,
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    ScriptBuf, TapLeafHash, Transaction, TxOut, XOnlyPublicKey,
};

use lazy_static::lazy_static;
use schnorr_fun::fun::G;
use tracing::info;

lazy_static! {
    pub(crate) static ref G_X: [u8; 32] = G.into_point_with_even_y().0.to_xonly_bytes();
    pub(crate) static ref TAPSIGHASH_TAG: [u8; 10] = {
        let mut tag = [0u8; 10];
        let val = "TapSighash".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
    pub(crate) static ref BIP0340_CHALLENGE_TAG: [u8; 17] = {
        let mut tag = [0u8; 17];
        let val = "BIP0340/challenge".as_bytes();
        tag.copy_from_slice(val);
        tag
    };
}

use crate::sigops::{
    compute_signature_from_components, get_sigmsg_components, grind_transaction, GrindField,
};

pub fn create_cat_address(tx_outs: Vec<TxOut>) -> Result<TaprootSpendInfo, Error> {
    let secp = Secp256k1::new();

    let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
    // Random unspendable XOnlyPublicKey provided for internal key
    let (unspendable_pubkey, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let cat_script = cat_script(tx_outs);
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, cat_script)
        .unwrap()
        .finalize(&secp, unspendable_pubkey)
        .unwrap();

    Ok(taproot_spend_info)
}

pub fn spend_cat(
    unsigned_tx: Transaction,
    taproot_spend_info: TaprootSpendInfo,
    prev_output: TxOut,
) -> Transaction {
    let mut txin = unsigned_tx.input[0].clone();

    let cat_script = cat_script(unsigned_tx.output.clone());

    let leaf_hash = TapLeafHash::from_script(&cat_script, LeafVersion::TapScript);

    let contract_components = grind_transaction(
        unsigned_tx.clone(),
        GrindField::LockTime,
        &[prev_output.clone()],
        leaf_hash,
    )
    .unwrap();

    let mut txn = contract_components.transaction;

    let witness_components =
        get_sigmsg_components(&txn, 0, &[prev_output.clone()], None, leaf_hash, true).unwrap();

    for component in witness_components.iter() {
        info!(
            "pushing component <0x{}> into the witness",
            hex::encode(component)
        );

        txin.witness.push(component.as_slice());
    }

    let computed_signature =
        compute_signature_from_components(&contract_components.signature_components).unwrap();

    let mangled_signature: [u8; 63] = computed_signature[0..63].try_into().unwrap(); // chop off the last byte, so we can provide the 0x00 and 0x01 bytes on the stack
    txin.witness.push(mangled_signature);

    txin.witness.push([computed_signature[63]]); // push the last byte of the signature
    txin.witness.push([computed_signature[63] + 1]);

    txin.witness.push(cat_script.clone().to_bytes());

    txin.witness.push(
        taproot_spend_info
            .control_block(&(cat_script, LeafVersion::TapScript))
            .unwrap()
            .serialize(),
    );

    txn.input.first_mut().unwrap().witness = txin.witness.clone();

    txn
}

pub fn cat_script(tx_outs: Vec<TxOut>) -> ScriptBuf {
    let outputs_hash = compute_bip341_hash_outputs(&tx_outs);
    info!(
        "outputs hash: {:?}",
        outputs_hash.as_byte_array().to_hex_string(Case::Lower)
    );

    Builder::new()
        .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
        .push_opcode(OP_TOALTSTACK) // move last byte to alt stack
        .push_opcode(OP_TOALTSTACK) // move last byte to alt stack
        // start with encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // input index
        .push_opcode(OP_CAT) // spend type
        // .push_slice(outputs_hash.as_byte_array()) // outputs hash
        .push_opcode(OP_CAT) // outputs hash
        .push_opcode(OP_CAT) // prev sequences
        .push_opcode(OP_CAT) // prev scriptpubkeys
        .push_opcode(OP_CAT) // prev amounts
        .push_opcode(OP_CAT) // prevouts
        .push_opcode(OP_CAT) // lock time
        .push_opcode(OP_CAT) // version
        .push_opcode(OP_CAT) // control (sighash type)
        .push_opcode(OP_CAT) // epoch
        //sighash stuff
        .push_slice(*TAPSIGHASH_TAG) // push tag
        .push_opcode(OP_SHA256) // hash tag
        .push_opcode(OP_DUP) // dup hash
        .push_opcode(OP_ROT) // move the sighash to the top of the stack
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_SHA256) // tagged hash of the sighash
        .push_slice(*BIP0340_CHALLENGE_TAG) // push tag
        .push_opcode(OP_SHA256)
        .push_opcode(OP_DUP)
        .push_opcode(OP_ROT) // bring challenge to the top of the stack
        .push_slice(*G_X) // G is used for the pubkey and K
        .push_opcode(OP_DUP)
        .push_opcode(OP_DUP)
        .push_opcode(OP_TOALTSTACK) // we'll need a copy of G later to be our R value in the signature
        .push_opcode(OP_ROT) // bring the challenge to the top of the stack
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT) // cat the two tags, R, P, and M values together
        .push_opcode(OP_SHA256) // hash the whole thing to get the s value for the signature
        .push_opcode(OP_FROMALTSTACK) // bring G back from the alt stack to use as the R value in the signature
        .push_opcode(OP_SWAP)
        .push_opcode(OP_CAT) // cat the R value with the s value for a complete signature
        .push_opcode(OP_FROMALTSTACK) // grab the pre-computed signature minus the last byte from the alt stack
        .push_opcode(OP_DUP) // we'll need a second copy later to do the actual signature verification
        .push_slice([0x00u8]) // add the last byte of the signature, which should match what we computed. NOTE ⚠️: push_int(0) will not work here because it will push OP_FALSE, but we want an actual 0 byte
        .push_opcode(OP_CAT)
        .push_opcode(OP_ROT) // bring the script-computed signature to the top of the stack
        .push_opcode(OP_EQUALVERIFY) // check that the script-computed and pre-computed signatures match
        .push_int(0x01) // we need the last byte of the signature to be 0x01 because our k value is 1 (because K is G)
        .push_opcode(OP_CAT)
        .push_slice(*G_X) // push G again. TODO: DUP this from before and stick it in the alt stack or something
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn compute_bip341_hash_outputs(txouts: &[TxOut]) -> sha256::Hash {
    let mut engine = sha256::HashEngine::default();

    for txout in txouts {
        // Encode the TxOut in BIP-0341 style (value + scriptPubKey)
        txout
            .consensus_encode(&mut engine)
            .expect("Writing to HashEngine should never fail");
    }

    sha256::Hash::from_engine(engine)
}

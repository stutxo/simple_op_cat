use bitcoin::{
    io::Error,
    key::{Keypair, Secp256k1},
    opcodes::all::{
        OP_CAT, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_FROMALTSTACK, OP_ROT, OP_SHA256, OP_SWAP,
        OP_TOALTSTACK,
    },
    script::{Builder, PushBytesBuf},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    ScriptBuf, Transaction, TxOut, XOnlyPublicKey,
};
use schnorr_fun::fun::G;

pub fn create_cat_address(cat_txout: TxOut) -> Result<TaprootSpendInfo, Error> {
    let secp = Secp256k1::new();

    let key_pair = Keypair::new(&secp, &mut rand::thread_rng());
    // Random unspendable XOnlyPublicKey provided for internal key
    let (unspendable_pubkey, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let cat_script = cat_script(cat_txout);

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, cat_script)
        .unwrap()
        .finalize(&secp, unspendable_pubkey)
        .unwrap();

    Ok(taproot_spend_info)
}

pub fn spend_cat(
    mut unsigned_tx: Transaction,
    taproot_spend_info: TaprootSpendInfo,
    cat_txout: TxOut,
) -> Transaction {
    let ctv_script = cat_script(cat_txout);

    for input in unsigned_tx.input.iter_mut() {
        let script_ver = (ctv_script.clone(), LeafVersion::TapScript);
        let ctrl_block = taproot_spend_info.control_block(&script_ver).unwrap();

        input.witness.push(script_ver.0.into_bytes());
        input.witness.push(ctrl_block.serialize());
    }
    unsigned_tx
}

pub fn cat_script(tx_out: TxOut) -> ScriptBuf {
    let script_pubkey: PushBytesBuf = tx_out
        .script_pubkey
        .clone()
        .into_bytes()
        .try_into()
        .unwrap();
    let g_x = G.into_point_with_even_y().0.to_xonly_bytes();
    let tap_sighash_tag: [u8; 10] = *b"TapSighash";
    let bip304_tag: [u8; 17] = *b"BIP0340/challenge";

    Builder::new()
        .push_opcode(OP_TOALTSTACK) // move pre-computed signature minus last byte to alt stack
        .push_opcode(OP_TOALTSTACK) // push the first copy of the vault scriptpubkey to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the first copy of the vault amount to the alt stack
        .push_slice(script_pubkey) // push the payout scriptpubkey
        .push_slice(&tx_out.value.to_sat().to_le_bytes()) // push the payout amount
        .push_opcode(OP_TOALTSTACK) // push the second copy of the vault scriptpubkey to the alt stack
        .push_opcode(OP_TOALTSTACK) // push the second copy of the vault amount to the alt stack
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // encoded leaf hash
        .push_opcode(OP_CAT) // input index
        .push_opcode(OP_CAT) // spend type
        .push_opcode(OP_FROMALTSTACK) // get the output amount
        .push_opcode(OP_FROMALTSTACK) // get the second copy of the scriptpubkey
        .push_opcode(OP_CAT) // cat the output amount and the second copy of the scriptpubkey
        .push_opcode(OP_SHA256) // hash the output
        .push_opcode(OP_SWAP) // move the hashed encoded outputs below our working sigmsg
        .push_opcode(OP_CAT) // outputs
        .push_opcode(OP_CAT) // prev sequences
        .push_opcode(OP_FROMALTSTACK) // get the other copy of the vault amount
        .push_opcode(OP_FROMALTSTACK) // get the other copy of the vault scriptpubkey
        .push_opcode(OP_SWAP) // move the vault amount to the top of the stack
        .push_opcode(OP_TOALTSTACK) // move the vault amount to the alt stack
        .push_opcode(OP_SHA256) // hash the scriptpubkeys, should now be consensus encoding
        .push_opcode(OP_SWAP) // move the hashed encoded scriptpubkeys below our working sigmsg
        .push_opcode(OP_CAT) // prev scriptpubkeys
        .push_opcode(OP_FROMALTSTACK) // get the vault amount
        .push_opcode(OP_SHA256) // hash the amounts
        .push_opcode(OP_SWAP) // move the hashed encoded amounts below our working sigmsg
        .push_opcode(OP_CAT) // prev amounts
        .push_opcode(OP_CAT) // prevouts
        .push_opcode(OP_CAT) // lock time
        .push_opcode(OP_CAT) // version
        .push_opcode(OP_CAT) // control
        .push_opcode(OP_CAT) // epoch
        //sighash stuff
        .push_slice(tap_sighash_tag) // push tag
        .push_opcode(OP_SHA256) // hash tag
        .push_opcode(OP_DUP) // dup hash
        .push_opcode(OP_ROT) // move the sighash to the top of the stack
        .push_opcode(OP_CAT)
        .push_opcode(OP_CAT)
        .push_opcode(OP_SHA256) // tagged hash of the sighash
        .push_slice(bip304_tag) // push tag
        .push_opcode(OP_SHA256)
        .push_opcode(OP_DUP)
        .push_opcode(OP_ROT) // bring challenge to the top of the stack
        .push_slice(g_x) // G is used for the pubkey and K
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
        .push_slice(g_x) // push G again. TODO: DUP this from before and stick it in the alt stack or something
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

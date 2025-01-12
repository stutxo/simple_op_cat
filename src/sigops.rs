use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::sighash::{Annex, TapSighash, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{Sequence, Transaction, TxOut};

use tracing::debug;

use crate::cat_scripts::G_X;

#[derive(Debug)]
pub(crate) enum GrindField {
    LockTime,
    Sequence,
}

//https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki creating sigmsg for sighash type default (all)
pub(crate) fn get_sigmsg_components<S: Into<TapLeafHash>>(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    annex: Option<Annex>,
    leaf_hash: S,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let sigh_hash_type = TapSighashType::Default;
    let mut components = Vec::new();

    let leaf_hash_code_separator = Some((leaf_hash.into(), 0xFFFFFFFFu32));

    //epoch (1): the epoch number of the transaction.
    let mut epoch = Vec::new();
    0u8.consensus_encode(&mut epoch)?;
    debug!("epoch: {:?}", hex::encode(&epoch));
    components.push(epoch);

    //hash_type (1)
    let mut control = Vec::new();
    (sigh_hash_type as u8).consensus_encode(&mut control)?;
    debug!("control: {:?}", hex::encode(&control));
    components.push(control);

    //nVersion (4): the nVersion of the transaction.
    let mut version = Vec::new();
    tx.version.consensus_encode(&mut version)?;
    debug!("version: {:?}", hex::encode(&version));
    components.push(version);

    //nLockTime (4): the nLockTime of the transaction.
    let mut lock_time = Vec::new();
    tx.lock_time.consensus_encode(&mut lock_time)?;
    debug!("lock_time: {:?}", hex::encode(&lock_time));
    components.push(lock_time);

    let mut previousouts = Vec::new();
    let mut buffer = Vec::new();
    for previousouts in tx.input.iter() {
        previousouts
            .previous_output
            .consensus_encode(&mut buffer)
            .unwrap();
    }

    //sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
    let hash = sha256::Hash::hash(&buffer);
    hash.consensus_encode(&mut previousouts).unwrap();
    debug!("prevouts: {:?}", previousouts.to_hex_string(Case::Lower));
    components.push(previousouts);

    //sha_amounts (32): the SHA256 of the serialization of all input amounts.
    let mut prev_amounts = Vec::new();
    let mut buffer = Vec::new();
    for p in prevouts {
        p.value.consensus_encode(&mut buffer).unwrap();
    }

    let hash = sha256::Hash::hash(&buffer);
    hash.consensus_encode(&mut prev_amounts).unwrap();
    debug!(
        "prev_amounts: {:?}",
        prev_amounts.to_hex_string(Case::Lower)
    );
    components.push(prev_amounts);

    //sha_scriptpubkeys (32): the SHA256 of all spent outputs' scriptPubKeys, serialized as script inside CTxOut.
    let mut prev_sciptpubkeys = Vec::new();
    let mut buffer = Vec::new();
    for p in prevouts {
        p.script_pubkey.consensus_encode(&mut buffer).unwrap();
    }
    debug!(
        "prev_sciptpubkeys buffer: {:?}",
        buffer.to_hex_string(Case::Lower)
    );

    //sha_sequences (32): the SHA256 of the serialization of all input nSequence.
    let hash = sha256::Hash::hash(&buffer);
    hash.consensus_encode(&mut prev_sciptpubkeys).unwrap();
    debug!(
        "prev_sciptpubkeys: {:?}",
        prev_sciptpubkeys.to_hex_string(Case::Lower)
    );
    components.push(prev_sciptpubkeys);

    let mut sequences = Vec::new();
    let mut buffer = Vec::new();
    for i in tx.input.iter() {
        i.sequence.consensus_encode(&mut buffer).unwrap();
    }

    let hash = sha256::Hash::hash(&buffer);
    hash.consensus_encode(&mut sequences).unwrap();
    debug!("sequences: {:?}", sequences.to_hex_string(Case::Lower));
    components.push(sequences);

    //* sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.

    // spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0 if no annex is present,
    // or 1 otherwise (the original witness stack has two or more witness elements,
    // and the first byte of the last element is 0x50)
    let mut encoded_spend_type = Vec::new();
    let mut spend_type = 0u8;
    if annex.is_some() {
        spend_type |= 1u8;
    }
    if leaf_hash_code_separator.is_some() {
        spend_type |= 2u8;
    }
    spend_type.consensus_encode(&mut encoded_spend_type)?;
    debug!("spend_type: {:?}", hex::encode(&encoded_spend_type));
    components.push(encoded_spend_type);

    //input_index (4): index of this input in the transaction input vector. Index of the first input is 0.
    let mut input_idx = Vec::new();
    (input_index as u32).consensus_encode(&mut input_idx)?;
    debug!("input index: {:?}", input_idx.to_hex_string(Case::Lower));
    components.push(input_idx);

    //Leaf Hash	(32) The leaf hash for the chosen script you're using from the script tree.
    //Public Key Version (1) The type of public key used in the leaf script. Used to indicate different types of public keys in future upgrades. default = 0x00
    //Codeseparator Position (4) The opcode position of the last OP_CODESEPARATOR in the leaf script (if there is one). none = 0xffffffff

    #[allow(non_snake_case)]
    let KEY_VERSION_0 = 0u8;

    if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
        let mut encoded_leaf_hash = Vec::new();
        hash.as_byte_array()
            .consensus_encode(&mut encoded_leaf_hash)?;
        debug!("leaf_hash: {:?}", hex::encode(&encoded_leaf_hash));
        components.push(encoded_leaf_hash);
        let mut encoded_leaf_hash = Vec::new();
        KEY_VERSION_0.consensus_encode(&mut encoded_leaf_hash)?;
        debug!("leaf_ver: {:?}", hex::encode(&encoded_leaf_hash));
        components.push(encoded_leaf_hash);
        let mut encoded_leaf_hash = Vec::new();
        code_separator_pos.consensus_encode(&mut encoded_leaf_hash)?;
        debug!("code_separator_pos: {:?}", hex::encode(&encoded_leaf_hash));
        components.push(encoded_leaf_hash);
    }

    Ok(components)
}

// Append the sigmsg of the outcome?
pub(crate) fn compute_signature_from_components(
    components: &[Vec<u8>],
) -> anyhow::Result<[u8; 64]> {
    let sigmsg = compute_sigmsg_from_components(components)?;
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    let challenge = make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice());
    Ok(make_signature(&challenge))
}

pub(crate) fn compute_sigmsg_from_components(components: &[Vec<u8>]) -> anyhow::Result<[u8; 32]> {
    debug!("creating sigmsg from components",);
    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input("TapSighash".as_bytes());
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);

    let mut serialized_tx = sha256::Hash::engine();
    serialized_tx.input(hashed_tag.as_ref());
    serialized_tx.input(hashed_tag.as_ref());

    {
        let tapsighash_engine = TapSighash::engine();
        assert_eq!(tapsighash_engine.midstate(), serialized_tx.midstate());
    }

    for component in components.iter() {
        serialized_tx.input(component.as_slice());
    }

    let tagged_hash = sha256::Hash::from_engine(serialized_tx);
    Ok(tagged_hash.to_byte_array())
}

pub(crate) fn compute_challenge(sigmsg: &[u8; 32]) -> [u8; 32] {
    let mut buffer = Vec::new();
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut G_X.to_vec());
    buffer.append(&mut sigmsg.to_vec());
    make_tagged_hash("BIP0340/challenge".as_bytes(), buffer.as_slice())
}

fn make_signature(challenge: &[u8; 32]) -> [u8; 64] {
    let mut signature: [u8; 64] = [0; 64];
    signature[0..32].copy_from_slice(G_X.as_slice());
    signature[32..64].copy_from_slice(challenge);
    signature
}

fn make_tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    // make a hashed_tag which is sha256(tag)
    let mut hashed_tag = sha256::Hash::engine();
    hashed_tag.input(tag);
    let hashed_tag = sha256::Hash::from_engine(hashed_tag);

    // compute the message to be hashed. It is prefixed with the hashed_tag twice
    // for example, hashed_tag || hashed_tag || data
    let mut message = sha256::Hash::engine();
    message.input(hashed_tag.as_ref());
    message.input(hashed_tag.as_ref());
    message.input(data);
    let message = sha256::Hash::from_engine(message);
    message.to_byte_array()
}

pub(crate) fn grind_transaction<S>(
    initial_tx: Transaction,
    grind_field: GrindField,
    prevouts: &[TxOut],
    leaf_hash: S,
) -> anyhow::Result<ContractComponents>
where
    S: Into<TapLeafHash> + Clone,
{
    let signature_components: Vec<Vec<u8>>;
    let mut counter = 0;

    let mut spend_tx = initial_tx.clone();

    loop {
        match grind_field {
            GrindField::LockTime => spend_tx.lock_time = LockTime::from_height(counter)?,
            GrindField::Sequence => {
                // make sure counter has the 31st bit set, so that it's not used as a relative timelock
                // (BIP68 tells us that bit disables the consensus meaning of sequence numbers for RTL)
                counter |= 1 << 31;
                // set the sequence number of the last input to the counter, we'll use that to pay fees if there is more than one input
                spend_tx.input.last_mut().unwrap().sequence = Sequence::from_consensus(counter);
            }
        }
        debug!("grinding counter {}", counter);

        let components_for_signature =
            get_sigmsg_components(&spend_tx, 0, prevouts, None, leaf_hash.clone())?;
        let sigmsg = compute_sigmsg_from_components(&components_for_signature)?;
        let challenge = compute_challenge(&sigmsg);

        if challenge[31] == 0x00 {
            debug!("Found a challenge with a 0 at the end!");
            debug!("{:?} is {}", grind_field, counter);
            debug!("Here's the challenge: {}", hex::encode(challenge),);
            signature_components = components_for_signature;
            break;
        }
        counter += 1;
    }
    Ok(ContractComponents {
        transaction: spend_tx,
        signature_components,
    })
}

pub(crate) struct ContractComponents {
    pub(crate) transaction: Transaction,
    pub(crate) signature_components: Vec<Vec<u8>>,
}

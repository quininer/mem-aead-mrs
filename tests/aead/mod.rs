use mem_aead_mrs::{
    KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH,
    Mrs, Permutation
};

#[path = "blake2-p.rs"]
mod blake2_p;

pub enum Blake2P {}

impl Permutation for Blake2P {
    fn permutation(state: &mut [u64; 16]) {
        blake2_p::mro_permute(state);
    }
}

pub fn aead_encrypt<P: Permutation>(key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], aad: &[u8], m: &[u8], c: &mut [u8]) {
    assert_eq!(m.len() + TAG_LENGTH, c.len());

    let (c, tag) = c.split_at_mut(m.len());
    c.copy_from_slice(m);
    let tag = array_mut_ref!(tag, 0, TAG_LENGTH);

    Mrs::<P>::new()
        .encrypt(key, nonce, aad, c, tag);
}

pub fn aead_decrypt<P: Permutation>(key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], aad: &[u8], c: &[u8], m: &mut [u8]) -> bool {
    assert!(c.len() >= TAG_LENGTH);
    assert_eq!(m.len() + TAG_LENGTH, c.len());

    let (c, tag) = c.split_at(m.len());
    m.copy_from_slice(c);
    let tag = array_ref!(tag, 0, TAG_LENGTH);

    Mrs::<P>::new()
        .decrypt(key, nonce, aad, m, tag)
}

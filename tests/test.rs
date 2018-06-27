#[macro_use] extern crate arrayref;
extern crate rand;
extern crate mem_aead_mrs;

mod aead;

use rand::{ RngCore, thread_rng, random };
use mem_aead_mrs::{
    KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH,
    Permutation
};
use aead::{ Blake2P, aead_encrypt, aead_decrypt };


fn test_aead<P: Permutation>() {
    for i in 0..1025 {
        let mut key = [0; KEY_LENGTH];
        let mut nonce = [0; NONCE_LENGTH];
        let mut aad = vec![0; random::<usize>() % 128];
        let mut m = vec![0; i];
        let mut c = vec![0; m.len() + TAG_LENGTH];
        let mut p = vec![0; m.len()];

        thread_rng().fill_bytes(&mut key);
        thread_rng().fill_bytes(&mut nonce);
        thread_rng().fill_bytes(&mut aad);
        thread_rng().fill_bytes(&mut m);

        aead_encrypt::<P>(&key, &nonce, &aad, &m, &mut c);
        let r = aead_decrypt::<P>(&key, &nonce, &aad, &c, &mut p);
        assert!(r, "{} times", i);

        assert_eq!(p, m, "{} times", i);
    }
}

#[test]
fn test_blake2p() {
    test_aead::<Blake2P>();
}

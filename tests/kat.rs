#![cfg_attr(feature = "cargo-clippy", allow(needless_range_loop))]

#[macro_use] extern crate arrayref;
extern crate rand;
extern crate mem_aead_mrs;

#[allow(dead_code)]
mod aead;

use mem_aead_mrs::{
    KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH,
    Permutation
};
use aead::{ Blake2P, aead_encrypt };

const MAX_SIZE: usize = 768;
const KAT: [u8; 319104] = include!("kat_mrs_blake2p.txt");


fn test_aead_kat<P: Permutation>() {
    let mut w = [0; MAX_SIZE];
    let mut h = [0; MAX_SIZE];
    let mut k = [0; KEY_LENGTH];
    let mut n = [0; NONCE_LENGTH];

    for i in 0..w.len() {
        w[i] = (255 & (i * 197 + 123)) as u8;
    }
    for i in 0..h.len() {
        h[i] = (255 & (i * 193 + 123)) as u8;
    }
    for i in 0..k.len() {
        k[i] = (255 & (i * 191 + 123)) as u8;
    }
    for i in 0..n.len() {
        n[i] = (255 & (i * 181 + 123)) as u8;
    }

    let mut kat = &KAT[..];

    for i in 0..w.len() {
        let mut c = vec![0; i + TAG_LENGTH];

        aead_encrypt::<P>(&k, &n, &h[..i], &w[..i], &mut c);
        assert_eq!(c, &kat[..c.len()], "{} times", i);
        kat = &kat[c.len()..];
    }
}

#[test]
fn test_blake2p_kat() {
    test_aead_kat::<Blake2P>();
}

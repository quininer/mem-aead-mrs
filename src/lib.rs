#[macro_use] extern crate arrayref;
extern crate byteorder;

mod common;

use std::marker::PhantomData;
use std::mem;
use common::tags;


pub(crate) type U = u64;
pub(crate) const W: usize = 64;
pub(crate) const L: usize = 4;
pub(crate) const T: usize = W * 4;
pub(crate) const LENGTH: usize = 16;
pub const KEY_LENGTH: usize = mem::size_of::<U>() * 4;
pub const NONCE_LENGTH: usize = mem::size_of::<U>() * 2;
pub const TAG_LENGTH: usize = NONCE_LENGTH;
pub const STATE_LENGTH: usize = mem::size_of::<U>() * LENGTH;
pub const BLOCK_LENGTH: usize = STATE_LENGTH - mem::size_of::<U>() * 4;

pub trait Permutation {
    fn permutation(state: &mut [u64; LENGTH]);
}

pub struct Mrs<P: Permutation> {
    state: [u8; STATE_LENGTH],
    _phantom: PhantomData<P>
}

impl<P: Permutation> Mrs<P> {
    pub fn new() -> Mrs<P> {
        Mrs {
            state: [0; STATE_LENGTH],
            _phantom: PhantomData
        }
    }

    pub fn encrypt(mut self, key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], aad: &[u8], m: &mut [u8], tag: &mut [u8; TAG_LENGTH]) {
        // absorption phase
        self.init::<tags::Abs>(key, nonce);
        self.absorb(aad);
        self.absorb(m);
        self.finalise(aad.len(), m.len(), tag);

        // encryption phase
        self.init::<tags::Enc>(key, tag);
        self.encrypt_data(m);
    }

    pub fn decrypt(mut self, key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], aad: &[u8], c: &mut [u8], tag: &[u8; TAG_LENGTH]) -> bool {
        let mut tag2 = [0; TAG_LENGTH];

        // decryption phase
        self.init::<tags::Enc>(key, tag);
        self.decrypt_data(c);

        // absorption phase
        self.init::<tags::Abs>(key, nonce);
        self.absorb(aad);
        self.absorb(c);
        self.finalise(aad.len(), c.len(), &mut tag2);

        // verification phase
        unimplemented!()
    }
}
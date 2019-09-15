#![no_std]

mod common;

use core::marker::PhantomData;
use core::mem;
use arrayref::{ array_ref, array_mut_ref };
use subtle::ConstantTimeEq;
use common::{ Tag, tags, with };


pub(crate) type U = u64;
pub(crate) const W: usize = 64;
pub(crate) const L: usize = 4;
pub(crate) const T: usize = W * 4;
pub(crate) const LENGTH: usize = 16;
pub const KEY_LENGTH: usize = mem::size_of::<U>() * 4;
pub const NONCE_LENGTH: usize = mem::size_of::<U>() * 2;
pub const TAG_LENGTH: usize = KEY_LENGTH;
pub const STATE_LENGTH: usize = mem::size_of::<U>() * LENGTH;
pub const BLOCK_LENGTH: usize = STATE_LENGTH - mem::size_of::<U>() * 4;

pub trait Permutation {
    fn permutation(state: &mut [u64; LENGTH]);
}

pub struct Mrs<P: Permutation> {
    state: [U; LENGTH],
    _phantom: PhantomData<P>
}

impl<P: Permutation> Default for Mrs<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Permutation> Mrs<P> {
    pub fn new() -> Mrs<P> {
        Mrs {
            state: [0; LENGTH],
            _phantom: PhantomData
        }
    }

    pub fn encrypt(
        mut self,
        key: &[u8; KEY_LENGTH],
        nonce: &[u8; NONCE_LENGTH],
        aad: &[u8],
        m: &mut [u8],
        tag: &mut [u8; TAG_LENGTH]
    ) {
        // absorption phase
        self.init::<tags::Abs>(key, nonce);
        self.absorb(aad);
        self.absorb(m);
        self.finalise(aad.len(), m.len(), tag);

        // encryption phase
        self.init::<tags::Enc>(key, tag);
        self.encrypt_data(m);

        // TODO zero state
    }

    pub fn decrypt(
        mut self,
        key: &[u8; KEY_LENGTH],
        nonce: &[u8; NONCE_LENGTH],
        aad: &[u8],
        c: &mut [u8],
        tag: &[u8; TAG_LENGTH]
    ) -> bool {
        let mut tag2 = [0; TAG_LENGTH];

        // decryption phase
        self.init::<tags::Enc>(key, tag);
        self.decrypt_data(c);

        // absorption phase
        self.init::<tags::Abs>(key, nonce);
        self.absorb(aad);
        self.absorb(c);
        self.finalise(aad.len(), c.len(), &mut tag2);

        // TODO zero state

        // verification phase
        tag.ct_eq(&tag2).unwrap_u8() == 1
    }
}

impl<P: Permutation> Mrs<P> {
    pub(crate) fn init<T: Tag>(&mut self, key: &[u8; KEY_LENGTH], nonce: &[u8]) {
        with(&mut self.state, |state| {
            state.copy_from_slice(&[0; STATE_LENGTH]);
            state[..nonce.len()].copy_from_slice(nonce);
        });

        self.state[9] = L as U;
        self.state[10] = T as U;
        self.state[11] = T::TAG;

        with(&mut self.state, |state| {
            state[12 * mem::size_of::<U>()..].copy_from_slice(key);
        });
    }

    pub(crate) fn absorb(&mut self, aad: &[u8]) {
        #[inline]
        fn absorb_block<P: Permutation>(state: &mut [U; LENGTH], chunk: &[u8; STATE_LENGTH]) {
            P::permutation(state);

            with(state, |state| {
                for i in 0..STATE_LENGTH {
                    state[i] ^= chunk[i];
                }
            });
        }

        let mut iter = aad.chunks_exact(STATE_LENGTH);
        while let Some(chunk) = iter.next() {
            let chunk = array_ref!(chunk, 0, STATE_LENGTH);
            absorb_block::<P>(&mut self.state, chunk);
        }

        let chunk = iter.remainder();
        if !chunk.is_empty() {
            P::permutation(&mut self.state);

            with(&mut self.state, |state| {
                for i in 0..chunk.len() {
                    state[i] ^= chunk[i];
                }
            });
        }
    }

    pub(crate) fn finalise(&mut self, hlen: usize, mlen: usize, tag: &mut [u8; TAG_LENGTH]) {
        P::permutation(&mut self.state);

        self.state[0] ^= hlen as U;
        self.state[1] ^= mlen as U;

        P::permutation(&mut self.state);

        with(&mut self.state, |state| {
            tag.copy_from_slice(&state[..TAG_LENGTH]);
        });
    }

    pub(crate) fn encrypt_data(&mut self, m: &mut [u8]) {
        #[inline]
        fn encrypt_block<P: Permutation>(state: &mut [U; LENGTH], chunk: &mut [u8; BLOCK_LENGTH]) {
            P::permutation(state);

            with(state, |state| {
                for i in 0..BLOCK_LENGTH {
                    state[i] ^= chunk[i];
                    chunk[i] = state[i];
                }
            });
        }

        let mut iter = m.chunks_exact_mut(BLOCK_LENGTH);
        while let Some(chunk) = iter.next() {
            let chunk = array_mut_ref!(chunk, 0, BLOCK_LENGTH);
            encrypt_block::<P>(&mut self.state, chunk);
        }


        let chunk = iter.into_remainder();
        if !chunk.is_empty() {
            P::permutation(&mut self.state);

            with(&mut self.state, |state| {
                for i in 0..chunk.len() {
                    chunk[i] ^= state[i];
                }
            });
        }
    }

    pub(crate) fn decrypt_data(&mut self, c: &mut [u8]) {
        #[inline]
        fn decrypt_block<P: Permutation>(state: &mut [U; LENGTH], chunk: &mut [u8; BLOCK_LENGTH]) {
            P::permutation(state);

            with(state, |state| {
                for i in 0..BLOCK_LENGTH {
                    let s = mem::replace(&mut state[i], chunk[i]);
                    chunk[i] ^= s;
                }
            });
        }

        let mut iter = c.chunks_exact_mut(BLOCK_LENGTH);
        while let Some(chunk) = iter.next() {
            let chunk = array_mut_ref!(chunk, 0, BLOCK_LENGTH);
            decrypt_block::<P>(&mut self.state, chunk);
        }

        let chunk = iter.into_remainder();
        if !chunk.is_empty() {
            P::permutation(&mut self.state);

            with(&mut self.state, |state| {
                for i in 0..chunk.len() {
                    chunk[i] ^= state[i];
                }
            });
        }
    }
}

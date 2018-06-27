use std::mem;
use byteorder::{ ByteOrder, LittleEndian };
use ::{
    U, L, T, LENGTH,
    KEY_LENGTH, TAG_LENGTH,
    STATE_LENGTH, BLOCK_LENGTH,
    Permutation, Mrs
};


pub trait Tag {
    const TAG: U;
}

pub mod tags {
    use super::U;
    use super::Tag;

    macro_rules! tags {
        ( $( $( #[$attr:meta] )* $name:ident => $val:expr ),+ ) => {
            $(
                $( #[$attr] )*
                pub enum $name {}

                impl Tag for $name {
                    const TAG: U = $val;
                }
            )+
        }
    }

    tags!{
        Abs => 0x00,
        Enc => 0x01
    }
}

#[inline]
pub fn with<F>(arr: &mut [u8; STATE_LENGTH], f: F)
    where F: FnOnce(&mut [U; LENGTH])
{
    #[inline]
    fn transmute(arr: &mut [u8; STATE_LENGTH]) -> &mut [U; LENGTH] {
        unsafe { mem::transmute(arr) }
//        unsafe { &mut *(arr as *mut [u8; STATE_LENGTH] as *mut [U; LENGTH]) }
    }

    #[inline]
    fn le_from_slice(arr: &mut [U; LENGTH]) {
        LittleEndian::from_slice_u64(arr);
    }

    let arr = transmute(arr);
    le_from_slice(arr);
    f(arr);
    le_from_slice(arr);
}

impl<P: Permutation> Mrs<P> {
    pub(crate) fn init<T: Tag>(&mut self, key: &[u8; KEY_LENGTH], nonce: &[u8]) {
        self.state.copy_from_slice(&[0; STATE_LENGTH]);
        self.state[..nonce.len()].copy_from_slice(nonce);

        with(&mut self.state, |state| {
            state[9] = L as U;
            state[10] = T as U;
            state[11] = T::TAG;
        });

        self.state[12 * mem::size_of::<U>()..].copy_from_slice(key);
    }

    pub(crate) fn absorb(&mut self, aad: &[u8]) {
        #[inline]
        fn absorb_block<P: Permutation>(state: &mut [u8; STATE_LENGTH], chunk: &[u8; STATE_LENGTH]) {
            with(state, P::permutation);

            for i in 0..STATE_LENGTH {
                state[i] ^= chunk[i];
            }
        }

        let (aad, remaining) = aad.split_at(aad.len() - aad.len() % STATE_LENGTH);

        for chunk in aad.chunks(STATE_LENGTH) {
            let chunk = array_ref!(chunk, 0, STATE_LENGTH);
            absorb_block::<P>(&mut self.state, chunk);
        }

        if !remaining.is_empty() {
            with(&mut self.state, P::permutation);

            for i in 0..remaining.len() {
                self.state[i] ^= remaining[i];
            }
        }
    }

    pub(crate) fn finalise(&mut self, hlen: usize, mlen: usize, tag: &mut [u8; TAG_LENGTH]) {
        with(&mut self.state, |state| {
            P::permutation(state);

            state[0] ^= hlen as U;
            state[1] ^= mlen as U;

            P::permutation(state);
        });

        tag.copy_from_slice(&self.state[..TAG_LENGTH]);
    }

    pub(crate) fn encrypt_data(&mut self, m: &mut [u8]) {
        #[inline]
        fn encrypt_block<P: Permutation>(state: &mut [u8; STATE_LENGTH], chunk: &mut [u8; BLOCK_LENGTH]) {
            with(state, P::permutation);

            for i in 0..BLOCK_LENGTH {
                state[i] ^= chunk[i];
                chunk[i] = state[i];
            }
        }

        let mlen = m.len();
        let (m, remaining) = m.split_at_mut(mlen - mlen % BLOCK_LENGTH);

        for chunk in m.chunks_mut(BLOCK_LENGTH) {
            let chunk = array_mut_ref!(chunk, 0, BLOCK_LENGTH);
            encrypt_block::<P>(&mut self.state, chunk);
        }

        if !remaining.is_empty() {
            with(&mut self.state, P::permutation);

            for i in 0..remaining.len() {
                remaining[i] ^= self.state[i];
            }
        }
    }

    pub(crate) fn decrypt_data(&mut self, c: &mut [u8]) {
        #[inline]
        fn decrypt_block<P: Permutation>(state: &mut [u8; STATE_LENGTH], chunk: &mut [u8; BLOCK_LENGTH]) {
            with(state, P::permutation);

            for i in 0..BLOCK_LENGTH {
                let s = mem::replace(&mut state[i], chunk[i]);
                chunk[i] ^= s;
            }
        }


        let clen = c.len();
        let (c, remaining) = c.split_at_mut(clen - clen % BLOCK_LENGTH);

        for chunk in c.chunks_mut(BLOCK_LENGTH) {
            let chunk = array_mut_ref!(chunk, 0, BLOCK_LENGTH);
            decrypt_block::<P>(&mut self.state, chunk);
        }

        if !remaining.is_empty() {
            with(&mut self.state, P::permutation);

            for i in 0..remaining.len() {
                remaining[i] ^= self.state[i];
            }
        }
    }
}

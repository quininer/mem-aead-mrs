//! copy from https://github.com/MEM-AEAD/mem-aead-rust

#![allow(dead_code, unused_macros)]

use std::num::{Wrapping};

type Word = u64;

const MRO_W: usize = 64;         // word size
const MRO_L: usize = 4;          // number of rounds
const MRO_T: usize = MRO_W *  4; // tag size
//const MRO_N: usize = MRO_W *  2; // nonce size
//const MRO_K: usize = MRO_W *  4; // key size
const MRO_B: usize = MRO_W * 16; // permutation size

const R0 : u32 = 32; 
const R1 : u32 = 24; 
const R2 : u32 = 16; 
const R3 : u32 = 63; 

#[derive(PartialEq)]
enum Tag {
    HDD, // header data
    MSG  // message data
}

macro_rules! Bytes { ($x: expr) => (($x + 7) / 8;); }
macro_rules! Words { ($x: expr) => (($x + (MRO_W-1)) / MRO_W;); }

#[inline]
fn load_le(v : &[u8]) -> Word {
    let mut x : Word = 0;
    for i in 0..Bytes!(MRO_W) {
        x |= (v[i] as Word) << (8*i);
    }
    return x;
}

#[inline]
fn store_le(v : &mut[u8], x : Word) {
    for i in 0..Bytes!(MRO_W) {
        v[i] = (x >> 8*i) as u8;
    }
}

macro_rules! Add { ($x: expr, $y: expr) => ((Wrapping($x)+Wrapping($y)).0;); }

macro_rules! G { ($a:expr, $b:expr, $c:expr, $d:expr) => 
    ({
        $a = Add!($a, $b); $d ^= $a; $d = $d.rotate_right(R0); 
        $c = Add!($c, $d); $b ^= $c; $b = $b.rotate_right(R1); 
        $a = Add!($a, $b); $d ^= $a; $d = $d.rotate_right(R2); 
        $c = Add!($c, $d); $b ^= $c; $b = $b.rotate_right(R3);
    });
}

#[inline]
#[allow(non_snake_case)]
fn F(x : &mut[Word; 16]) {
    // column step
    G!(x[ 0], x[ 4], x[ 8], x[12]);
    G!(x[ 1], x[ 5], x[ 9], x[13]);
    G!(x[ 2], x[ 6], x[10], x[14]);
    G!(x[ 3], x[ 7], x[11], x[15]);
    // diagonal step
    G!(x[ 0], x[ 5], x[10], x[15]);
    G!(x[ 1], x[ 6], x[11], x[12]);
    G!(x[ 2], x[ 7], x[ 8], x[13]);
    G!(x[ 3], x[ 4], x[ 9], x[14]);
}

#[inline]
pub fn mro_permute(x : &mut[Word; 16]) {
    for _ in 0..MRO_L {
        F(x);
    }
}

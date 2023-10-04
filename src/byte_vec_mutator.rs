// https://github.com/AFLplusplus/LibAFL/blob/main/libafl/src/mutators/mutations.rs

use std::cmp::min;
use std::ops::Range;

use rand::rngs::ThreadRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::Rng;

/// The max value that will be added or subtracted during add mutations
pub const ARITH_MAX: u64 = 35;

/// Interesting 8-bit values from AFL
pub const INTERESTING_8: [i8; 9] = [-128, -1, 0, 1, 16, 32, 64, 100, 127];
/// Interesting 16-bit values from AFL
pub const INTERESTING_16: [i16; 19] = [
    -128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767,
];
/// Interesting 32-bit values from AFL
pub const INTERESTING_32: [i32; 27] = [
    -128,
    -1,
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    -32768,
    -129,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    -2147483648,
    -100663046,
    -32769,
    32768,
    65535,
    65536,
    100663045,
    2147483647,
];

/// Flips a random bit in the input vector
pub fn bit_flip_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let bit = 1 << rng.gen_range(0..8);
    let byte = buf.choose_mut(rng).unwrap();
    *byte ^= bit;
}

/// Flips a random byte in the input vector
pub fn byte_flip_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let byte = buf.choose_mut(rng).unwrap();
    *byte ^= 0xff;
}

/// Increments a random byte in the input vector by 1
pub fn byte_inc_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let byte = buf.choose_mut(rng).unwrap();
    *byte = byte.wrapping_add(1);
}

/// Decrements a random byte in the input vector by 1
pub fn byte_dec_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let byte = buf.choose_mut(rng).unwrap();
    *byte = byte.wrapping_sub(1);
}

/// Sets a random byte in the input vector to its negative value
pub fn byte_neg_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let byte = buf.choose_mut(rng).unwrap();
    *byte = (!(*byte)).wrapping_add(1);
}

/// Flips a random bit in a random byte in the input vector
pub fn byte_rand_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let byte = buf.choose_mut(rng).unwrap();
    *byte ^= rng.gen_range(1..=255);
}

/// Adds or subtracts a random value up to `ARITH_MAX` to a [`<$size>`] at a random place in the [`&mut [u8]`], in random byte order
macro_rules! add_mutator {
    ($buf:expr, $rng:expr, $size:ty) => {
        if $buf.len() < std::mem::size_of::<$size>() {
            return;
        }
        let (index, bytes) = $buf
            .windows(std::mem::size_of::<$size>())
            .enumerate()
            .choose($rng)
            .unwrap();
        let value = <$size>::from_le_bytes(bytes.try_into().unwrap());

        let num = $rng.gen_range(1..=ARITH_MAX) as $size;
        let new_val = match $rng.gen_range(0..4) {
            0 => value.wrapping_add(num),
            1 => value.wrapping_sub(num),
            2 => value.swap_bytes().wrapping_add(num).swap_bytes(),
            _ => value.swap_bytes().wrapping_sub(num).swap_bytes(),
        };
        let new_bytes = &mut $buf[index..index + std::mem::size_of::<$size>()];
        new_bytes.copy_from_slice(&new_val.to_ne_bytes());
    };
}

/// Adds a random value to a random u8 in the input vector
pub fn add_mutator_u8(buf: &mut [u8], rng: &mut ThreadRng) {
    add_mutator!(buf, rng, u8);
}

/// Adds a random value to a random u16 in the input vector
pub fn add_mutator_u16(buf: &mut [u8], rng: &mut ThreadRng) {
    add_mutator!(buf, rng, u16);
}

/// Adds a random value to a random u32 in the input vector
pub fn add_mutator_u32(buf: &mut [u8], rng: &mut ThreadRng) {
    add_mutator!(buf, rng, u32);
}

/// Adds a random value to a random u64 in the input vector
pub fn add_mutator_u64(buf: &mut [u8], rng: &mut ThreadRng) {
    add_mutator!(buf, rng, u64);
}

/// Inserts an interesting value at a random place in the input vector
macro_rules! set_mutator {
    ($buf:expr, $rng:expr, $type:ty, $interesting_value:expr) => {
        if $buf.len() < std::mem::size_of::<$type>() {
            return;
        }
        let (index, _) = $buf
            .windows(std::mem::size_of::<$type>())
            .enumerate()
            .choose($rng)
            .unwrap();

        let num = $interesting_value.choose($rng).unwrap();
        let new_bytes = &mut $buf[index..index + std::mem::size_of::<$type>()];
        new_bytes.copy_from_slice(&num.to_ne_bytes());
    };
}

/// Inserts an interesting u8 value at a random place in the input vector
pub fn interesting_set_mutator_u8(buf: &mut [u8], rng: &mut ThreadRng) {
    set_mutator!(buf, rng, u8, INTERESTING_8);
}

/// Inserts an interesting u16 value at a random place in the input vector
pub fn interesting_set_mutator_u16(buf: &mut [u8], rng: &mut ThreadRng) {
    set_mutator!(buf, rng, u16, INTERESTING_16);
}

/// Inserts an interesting u32 value at a random place in the input vector
pub fn interesting_set_mutator_u32(buf: &mut [u8], rng: &mut ThreadRng) {
    set_mutator!(buf, rng, u32, INTERESTING_32);
}

/// Generate a range of values where (upon repeated calls) each index is likely to appear in the
/// provided range as likely as any other value
fn random_range(buf: &[u8], max_len: usize, rng: &mut ThreadRng) -> Range<usize> {
    let len = rng.gen_range(1..=min(buf.len(), max_len));
    let mut index2 = rng.gen_range(1..buf.len() + len);
    let index1 = index2.saturating_sub(len);
    if index2 > buf.len() {
        index2 = buf.len();
    }
    index1..index2
}

/// Sets range of bytes in the buffer to a value already in the input vector
pub fn bytes_set_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let value = buf.choose(rng).unwrap().to_owned();
    let range = random_range(buf, 16, rng);
    let subslice = &mut buf[range];
    subslice.iter_mut().for_each(|b| *b = value);
}

/// Sets range of bytes in the input vector to a random value
pub fn bytes_random_set_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let value = rng.gen_range(0..=255);
    let range = random_range(buf, 16, rng);
    let subslice = &mut buf[range];
    subslice.iter_mut().for_each(|b| *b = value);
}

/// Overwrite a range of bytes in the input vector with a range of bytes from the input vector
pub fn bytes_copy_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let range = random_range(buf, 16, rng);
    let copy_source = buf[range].to_vec();
    let dest_start_index = rng.gen_range(0..=buf.len().saturating_sub(copy_source.len()));
    let copy_dest = &mut buf[dest_start_index..dest_start_index + copy_source.len()];
    copy_dest.copy_from_slice(&copy_source);
}

/// Swap a range of bytes in the input vector with a range of bytes from the input vector
pub fn bytes_swap_mutator(buf: &mut [u8], rng: &mut ThreadRng) {
    let range_a = random_range(buf, 16, rng);
    let mut index_b = rng.gen_range(0..=buf.len().saturating_sub(range_a.len()));
    for index_a in range_a {
        buf.swap(index_a, index_b);
        index_b += 1;
    }
}

// Future options: crossover replace / splice

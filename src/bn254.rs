//! BN254 syscall wrappers using Pinocchio
//!
//! This module provides wrapper functions around Pinocchio's raw syscalls
//! for BN254 elliptic curve operations.

use crate::errors::Groth16Error;
use alloc::vec::Vec;

// Operation codes for sol_alt_bn128_group_op
const ALT_BN128_G1_ADD: u64 = 0;
const ALT_BN128_G1_MUL: u64 = 2;
const ALT_BN128_PAIRING: u64 = 3;

// Operation codes for sol_alt_bn128_compression
const ALT_BN128_G1_COMPRESS: u64 = 0;
const ALT_BN128_G1_DECOMPRESS: u64 = 1;
const ALT_BN128_G2_COMPRESS: u64 = 2;
const ALT_BN128_G2_DECOMPRESS: u64 = 3;

// Size constants
const ALT_BN128_ADDITION_INPUT_SIZE: usize = 128;
const ALT_BN128_ADDITION_OUTPUT_SIZE: usize = 64;
const ALT_BN128_MULTIPLICATION_INPUT_SIZE: usize = 96;
const ALT_BN128_MULTIPLICATION_OUTPUT_SIZE: usize = 64;
const ALT_BN128_PAIRING_ELEMENT_SIZE: usize = 192;
const ALT_BN128_PAIRING_OUTPUT_SIZE: usize = 32;
const ALT_BN128_G1_POINT_SIZE: usize = 64;
const ALT_BN128_G1_COMPRESSED_SIZE: usize = 32;
const ALT_BN128_G2_POINT_SIZE: usize = 128;
const ALT_BN128_G2_COMPRESSED_SIZE: usize = 64;

/// Performs BN254 G1 point addition
///
/// # Arguments
/// * `input` - Concatenated G1 points (128 bytes: two 64-byte points)
///
/// # Returns
/// * `Ok(Vec<u8>)` - The resulting G1 point (64 bytes)
/// * `Err(Groth16Error)` - If the operation fails
pub fn alt_bn128_addition(input: &[u8]) -> Result<Vec<u8>, Groth16Error> {
    if input.len() > ALT_BN128_ADDITION_INPUT_SIZE {
        return Err(Groth16Error::PreparingInputsG1AdditionFailed);
    }

    let mut result = vec![0u8; ALT_BN128_ADDITION_OUTPUT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let return_code = unsafe {
            pinocchio::syscalls::sol_alt_bn128_group_op(
                ALT_BN128_G1_ADD,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };

        if return_code != 0 {
            return Err(Groth16Error::PreparingInputsG1AdditionFailed);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        // For non-Solana targets, return error as we can't perform the operation
        return Err(Groth16Error::PreparingInputsG1AdditionFailed);
    }

    Ok(result)
}

/// Performs BN254 G1 scalar multiplication
///
/// # Arguments
/// * `input` - G1 point and scalar (96 bytes: 64-byte point + 32-byte scalar)
///
/// # Returns
/// * `Ok(Vec<u8>)` - The resulting G1 point (64 bytes)
/// * `Err(Groth16Error)` - If the operation fails
pub fn alt_bn128_multiplication(input: &[u8]) -> Result<Vec<u8>, Groth16Error> {
    if input.len() > ALT_BN128_MULTIPLICATION_INPUT_SIZE {
        return Err(Groth16Error::PreparingInputsG1MulFailed);
    }

    let mut result = vec![0u8; ALT_BN128_MULTIPLICATION_OUTPUT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let return_code = unsafe {
            pinocchio::syscalls::sol_alt_bn128_group_op(
                ALT_BN128_G1_MUL,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };

        if return_code != 0 {
            return Err(Groth16Error::PreparingInputsG1MulFailed);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        return Err(Groth16Error::PreparingInputsG1MulFailed);
    }

    Ok(result)
}

/// Performs BN254 pairing operation
///
/// # Arguments
/// * `input` - Pairs of G1 and G2 points (multiple of 192 bytes)
///
/// # Returns
/// * `Ok(Vec<u8>)` - Result (32 bytes, last byte is 1 if pairing succeeds)
/// * `Err(Groth16Error)` - If the operation fails
pub fn alt_bn128_pairing(input: &[u8]) -> Result<Vec<u8>, Groth16Error> {
    if input.len() % ALT_BN128_PAIRING_ELEMENT_SIZE != 0 {
        return Err(Groth16Error::ProofVerificationFailed);
    }

    let mut result = vec![0u8; ALT_BN128_PAIRING_OUTPUT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let return_code = unsafe {
            pinocchio::syscalls::sol_alt_bn128_group_op(
                ALT_BN128_PAIRING,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };

        if return_code != 0 {
            return Err(Groth16Error::ProofVerificationFailed);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        return Err(Groth16Error::ProofVerificationFailed);
    }

    Ok(result)
}

/// Compresses a G1 point from 64 bytes to 32 bytes
///
/// # Arguments
/// * `point` - Uncompressed G1 point (64 bytes)
///
/// # Returns
/// * `Ok([u8; 32])` - Compressed G1 point
/// * `Err(Groth16Error)` - If compression fails
pub fn alt_bn128_g1_compress(point: &[u8; 64]) -> Result<[u8; 32], Groth16Error> {
    let mut result = [0u8; ALT_BN128_G1_COMPRESSED_SIZE];

    #[cfg(target_os = "solana")]
    {
        let return_code = unsafe {
            pinocchio::syscalls::sol_alt_bn128_compression(
                ALT_BN128_G1_COMPRESS,
                point.as_ptr(),
                point.len() as u64,
                result.as_mut_ptr(),
            )
        };

        if return_code != 0 {
            return Err(Groth16Error::ProofConversionError);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        return Err(Groth16Error::ProofConversionError);
    }

    Ok(result)
}

/// Decompresses a G1 point from 32 bytes to 64 bytes
///
/// # Arguments
/// * `compressed` - Compressed G1 point (32 bytes)
///
/// # Returns
/// * `Ok([u8; 64])` - Decompressed G1 point
/// * `Err(Groth16Error)` - If decompression fails
pub fn alt_bn128_g1_decompress(compressed: &[u8; 32]) -> Result<[u8; 64], Groth16Error> {
    let mut result = [0u8; ALT_BN128_G1_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let return_code = unsafe {
            pinocchio::syscalls::sol_alt_bn128_compression(
                ALT_BN128_G1_DECOMPRESS,
                compressed.as_ptr(),
                compressed.len() as u64,
                result.as_mut_ptr(),
            )
        };

        if return_code != 0 {
            return Err(Groth16Error::DecompressingG1Failed);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        return Err(Groth16Error::DecompressingG1Failed);
    }

    Ok(result)
}

/// Compresses a G2 point from 128 bytes to 64 bytes
///
/// # Arguments
/// * `point` - Uncompressed G2 point (128 bytes)
///
/// # Returns
/// * `Ok([u8; 64])` - Compressed G2 point
/// * `Err(Groth16Error)` - If compression fails
pub fn alt_bn128_g2_compress(point: &[u8; 128]) -> Result<[u8; 64], Groth16Error> {
    let mut result = [0u8; ALT_BN128_G2_COMPRESSED_SIZE];

    #[cfg(target_os = "solana")]
    {
        let return_code = unsafe {
            pinocchio::syscalls::sol_alt_bn128_compression(
                ALT_BN128_G2_COMPRESS,
                point.as_ptr(),
                point.len() as u64,
                result.as_mut_ptr(),
            )
        };

        if return_code != 0 {
            return Err(Groth16Error::ProofConversionError);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        return Err(Groth16Error::ProofConversionError);
    }

    Ok(result)
}

/// Decompresses a G2 point from 64 bytes to 128 bytes
///
/// # Arguments
/// * `compressed` - Compressed G2 point (64 bytes)
///
/// # Returns
/// * `Ok([u8; 128])` - Decompressed G2 point
/// * `Err(Groth16Error)` - If decompression fails
pub fn alt_bn128_g2_decompress(compressed: &[u8; 64]) -> Result<[u8; 128], Groth16Error> {
    let mut result = [0u8; ALT_BN128_G2_POINT_SIZE];

    #[cfg(target_os = "solana")]
    {
        let return_code = unsafe {
            pinocchio::syscalls::sol_alt_bn128_compression(
                ALT_BN128_G2_DECOMPRESS,
                compressed.as_ptr(),
                compressed.len() as u64,
                result.as_mut_ptr(),
            )
        };

        if return_code != 0 {
            return Err(Groth16Error::DecompressingG2Failed);
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        return Err(Groth16Error::DecompressingG2Failed);
    }

    Ok(result)
}

/// Converts endianness by reversing byte chunks
///
/// This generic function reverses CHUNK_SIZE-byte chunks within an ARRAY_SIZE-byte array.
/// For example, `convert_endianness::<32, 64>()` splits 64 bytes into two 32-byte chunks
/// and reverses each chunk individually.
///
/// # Type Parameters
/// * `CHUNK_SIZE` - Size of each chunk to reverse
/// * `ARRAY_SIZE` - Total size of the byte array
///
/// # Arguments
/// * `bytes` - Input byte array
///
/// # Returns
/// * Byte array with reversed chunks
pub fn convert_endianness<const CHUNK_SIZE: usize, const ARRAY_SIZE: usize>(
    bytes: &[u8; ARRAY_SIZE],
) -> [u8; ARRAY_SIZE] {
    let mut result = [0u8; ARRAY_SIZE];

    for (chunk_idx, chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
        let start = chunk_idx * CHUNK_SIZE;
        for (i, &byte) in chunk.iter().rev().enumerate() {
            result[start + i] = byte;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_endianness_32_64() {
        let input: [u8; 64] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ];

        let result = convert_endianness::<32, 64>(&input);

        // First 32 bytes should be reversed
        assert_eq!(result[0], 32);
        assert_eq!(result[31], 1);

        // Second 32 bytes should be reversed
        assert_eq!(result[32], 64);
        assert_eq!(result[63], 33);
    }

    #[test]
    fn test_convert_endianness_64_128() {
        let input: [u8; 128] = [0; 128].map(|_| {
            static mut COUNTER: u8 = 0;
            unsafe {
                COUNTER += 1;
                COUNTER
            }
        });

        let result = convert_endianness::<64, 128>(&input);

        // First 64 bytes should be reversed
        assert_eq!(result[0], 64);
        assert_eq!(result[63], 1);

        // Second 64 bytes should be reversed
        assert_eq!(result[64], 128);
        assert_eq!(result[127], 65);
    }
}

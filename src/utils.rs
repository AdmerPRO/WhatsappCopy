use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use std::{fs, io, path::Path};

// Consts

const BIT_COUNT: usize = 65_534;
const HASH_COUNT: u64 = 7;
const FILE_PATH: &str = "username.bloom";

// Hashing passwords

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).unwrap();

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

// Bloom filter

pub struct BloomFilter {
    bits: Vec<u8>,
}

impl BloomFilter {
    pub fn new() -> Self {
        Self {
            bits: vec![0; BIT_COUNT.div_ceil(8)],
        }
    }

    pub fn load() -> io::Result<Self> {
        if !Path::new(FILE_PATH).exists() {
            return Ok(Self::new());
        }

        let bits = fs::read(FILE_PATH)?;

        if bits.len() != BIT_COUNT.div_ceil(8) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Bloom Filter size",
            ));
        }

        Ok(Self { bits })
    }

    fn hash(username: &str, seed: u64) -> usize {
        let mut hash = 0xcbf29ce484222325u64 ^ seed;

        for byte in username.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }

        (hash % BIT_COUNT as u64) as usize
    }

    pub fn is_taken(&self, username: &str) -> bool {
        (0..HASH_COUNT).all(|seed| {
            let index = Self::hash(username, seed);

            let byte_index = index / 8;
            let bit_index = index % 8;

            self.bits[byte_index] & (1 << bit_index) != 0
        })
    }

    pub fn insert(&mut self, username: &str) {
        for seed in 0..HASH_COUNT {
            let index = Self::hash(username, seed);

            let byte_index = index / 8;
            let bit_index = index % 8;

            self.bits[byte_index] |= 1 << bit_index;
        }
    }

    pub fn save(&self) -> io::Result<()> {
        fs::write(FILE_PATH, &self.bits)
    }
}

#![allow(dead_code)]

use crate::symmetric::ALPHABET;
use rand;
use rand::Rng;

/*
    In this method, the secret is the same size as the plain text.
    In this implementation we have a list of random numbers in a range of 0..ALPHABET.len(),
    which will be used to swap the letters, creating a cipher text.
    Since the generated numbers are random, there is no information leaking in the cipher text, making
    One Time Pad solution  having a perfect secrecy.
*/

fn random_sequence(len: usize) -> Vec<usize> {
    let mut rng = rand::thread_rng();
    let mut result = vec![0; len];

    for i in 0..len {
        result[i] = rng.gen_range(0..ALPHABET.len());
    }

    result
}

pub fn encrypt(plain_text: &str, secret: &[usize]) -> String {
    let mut result = String::new();

    for (index, char) in plain_text.to_uppercase().chars().enumerate() {
        let char_index = ALPHABET.iter().position(|a| *a == char).unwrap_or_default();
        result.push(ALPHABET[(char_index + secret[index]) % ALPHABET.len()]);
    }

    result
}

pub fn decrypt(cipher_text: &str, secret: &[usize]) -> String {
    let mut result = String::new();

    for (index, char) in cipher_text.to_uppercase().chars().enumerate() {
        let char_index = ALPHABET.iter().position(|a| *a == char).unwrap_or_default();
        result.push(ALPHABET[(ALPHABET.len() + char_index - secret[index]) % ALPHABET.len()]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_data() {
        let message = "Hello World";
        let secret = vec![8, 0, 0, 2, 3, 8, 7, 8, 1, 1, 4];

        let encrypted = encrypt(message, &secret);
        assert_eq!(encrypted, "PELNRHCWSMH");

        let decrypted = decrypt(&encrypted, &secret);
        assert_eq!(decrypted, "HELLO WORLD");

        let secret = random_sequence(message.len());
        let encrypted = encrypt(message, &secret);
        let decrypted = decrypt(&encrypted, &secret);
        assert_eq!(decrypted, "HELLO WORLD");
    }
}

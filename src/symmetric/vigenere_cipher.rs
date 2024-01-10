/*
    Vigenere cipher utilizes a word as a secret and each letter of the secret
    has a integer representation (ascii code for example)
    and each word of the plain text will be swapped by the x + y being x and y the integer representation
    of the letters of the plain text and the secret.

    the secret will have a loop so that each letter of the plain text will have it's own 'secret' number to be swapped.
*/

use crate::symmetric::ALPHABET;

fn map_secret(secret: &str) -> Vec<usize> {
    secret
        .to_uppercase()
        .chars()
        .map(|c| ALPHABET.iter().position(|a| *a == c).unwrap_or_default())
        .collect::<Vec<usize>>()
}

pub fn encrypt(plain_text: &str, secret: &str) -> String {
    let mut result = String::new();
    let secret = map_secret(secret);
    for (index, char) in plain_text.to_uppercase().chars().enumerate() {
        let secret_value = secret[index % secret.len()];
        let plain_text_char_index = ALPHABET.iter().position(|a| *a == char).unwrap_or_default();
        let index = (plain_text_char_index + secret_value) % ALPHABET.len();
        result.push(ALPHABET[index]);
    }

    result
}

pub fn decrypt(cipher_text: &str, secret: &str) -> String {
    let mut result = String::new();
    let secret = map_secret(secret);
    for (index, char) in cipher_text.to_uppercase().chars().enumerate() {
        let secret_value = secret[index % secret.len()];
        let cipher_text_char_index = ALPHABET.iter().position(|a| *a == char).unwrap_or_default();
        let index = (ALPHABET.len() + cipher_text_char_index - secret_value) % ALPHABET.len();
        result.push(ALPHABET[index]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypt_decrypt_message() {
        let message = "Hello World";
        let secret = "secret";
        let result = encrypt(message, secret);
        assert_eq!(result, " JOCTTOTUCI");

        let decrypted = decrypt(&result, secret);
        assert_eq!(decrypted, "HELLO WORLD");
    }
}

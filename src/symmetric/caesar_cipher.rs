use crate::symmetric::ALPHABET;
use std::collections::HashMap;

/*
    Basically, this encryption method shifts letters in the alphabet a given `N` times, `N` being a secret
    used to encrypt and decrypt the method.

    In this implementation, I'm using ascii table as a reference so the character `A` is represented by
    65 in the decimal base (https://www.asciitable.com/) and using 5 as a secret, the result would be 65 + 5 = 70
    which represents F, so in a plain text phrase, an `A` would be `F`.

    Since this is a symmetric encryption method, the secret must be shared between the two parties trying to communicate
    securely.
*/

#[allow(dead_code)]
const MOST_FREQUENT_LETTERS_IN_ENGLISH_ALPHABET: [char; 12] =
    ['E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 'L', 'U'];

pub fn encrypt(plain_text: &str, secret_key: i32) -> String {
    let mut cipher_text = String::new();
    let secret = secret_key.abs() as usize % ALPHABET.len();
    for c in plain_text.to_uppercase().chars() {
        let plain_text_index = ALPHABET.iter().position(|a| *a == c).unwrap_or_default();
        let index = (plain_text_index + secret) % ALPHABET.len();
        cipher_text.push(ALPHABET[index]);
    }

    cipher_text
}

pub fn decrypt(cipher_text: &str, secret_key: i32) -> String {
    let mut plain_text = String::new();
    let secret = secret_key.abs() as usize % ALPHABET.len();
    for c in cipher_text.chars() {
        let cipher_text_char_index = ALPHABET.iter().position(|a| *a == c).unwrap_or_default();
        let index = (ALPHABET.len() + cipher_text_char_index - secret) % ALPHABET.len();
        plain_text.push(ALPHABET[index]);
    }

    plain_text
}

/*
    Two ways of breaking caesar cipher method

    Brute force attack: Since I'm using ascii code, the possible secrets are in a range between 0 and 255,
    so this method will try to use every possible secret to decrypt the message.

    Frequency analysis: It will try to get the most frequent letters in the cipher text
    and compare with the most frequent letters in the english alphabet, generating a list of
    possible secrets to try and decrypt the message;
*/

#[allow(dead_code)]
pub fn brute_force_attack(cipher_text: &str) -> Vec<String> {
    let mut result = vec![];

    for i in 0..ALPHABET.len() {
        result.push(decrypt(cipher_text, i as i32));
    }

    result
}

fn frequencies(text: &str) -> HashMap<char, i32> {
    let mut map = HashMap::new();
    for c in text.to_uppercase().chars() {
        if c != ' ' {
            *map.entry(c).or_insert(0) += 1;
        }
    }
    map
}

#[allow(dead_code)]
pub fn frequency_analysis(cipher_text: &str) -> Vec<u8> {
    let mut freq = frequencies(cipher_text)
        .into_iter()
        .collect::<Vec<(char, i32)>>();

    freq.sort_by(|a, b| b.1.cmp(&a.1));

    if let Some((most_frequent_letter, _)) = freq.get(0) {
        let mut result = vec![0u8; MOST_FREQUENT_LETTERS_IN_ENGLISH_ALPHABET.len()];
        for (i, c) in MOST_FREQUENT_LETTERS_IN_ENGLISH_ALPHABET.iter().enumerate() {
            let ascii_number = *most_frequent_letter as u8;
            result[i] = ascii_number.saturating_sub(*c as u8) % u8::MAX;
        }

        result
    } else {
        vec![]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn encrypt_decrypt_message() {
        let message = "Hello World";
        let secret = 3;
        let result = encrypt(&message, secret);
        assert_eq!(result, "KHOORCZRUOG");
        let decrypted = decrypt(&result, secret);
        assert_eq!(decrypted, "HELLO WORLD");

        // Test overflow case
        let secret = 80;
        let result = encrypt(message, secret);
        assert_eq!(result, "GDKKNZVNQKC");
        let decrypted = decrypt(&result, secret);
        assert_eq!(decrypted, "HELLO WORLD");

        let secret = 200;
        let result = encrypt(message, secret);
        assert_eq!(result, "SPWWZKGZBWO");
        let decrypted = decrypt(&result, secret);
        assert_eq!(decrypted, "HELLO WORLD");
    }

    #[test]
    fn brute_force_attack_encrypted_message() {
        let message = "KHOORCZRUOG";
        let decrypted = brute_force_attack(message);

        for i in 0..ALPHABET.len() {
            match i {
                3 => {
                    assert_eq!(decrypted[i], "HELLO WORLD");
                }
                _ => {
                    assert_ne!(decrypted[i], "HELLO WORLD");
                }
            }
        }
    }

    #[test]
    fn frequency_analysis_attack() {
        let cipher_text = "KHOORCZRUOG";
        let result = frequency_analysis(cipher_text);
        for i in 0..MOST_FREQUENT_LETTERS_IN_ENGLISH_ALPHABET.len() {
            if i == 10 {
                assert_eq!(decrypt(cipher_text, result[i] as i32), "HELLO WORLD");
            } else {
                assert_ne!(decrypt(cipher_text, result[i] as i32), "HELLO WORLD");
            }
        }

        assert_eq!(frequency_analysis(""), vec![]);
    }
}

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

const MOST_FREQUENT_LETTERS_IN_ENGLISH_ALPHABET: [char; 12] =
    ['E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 'L', 'U'];

pub fn encrypt(plain_text: &str, secret_key: u8) -> String {
    let mut cipher_text = String::new();
    for c in plain_text.to_uppercase().chars() {
        let ascii_code = (c as u8).saturating_add(secret_key) % u8::MAX;
        cipher_text.push_str(char::from(ascii_code).to_string().as_ref());
    }

    cipher_text
}

pub fn decrypt(cipher_text: &str, secret_key: u8) -> String {
    let mut plain_text = String::new();
    for c in cipher_text.to_uppercase().chars() {
        let ascii_code = (c as u8).saturating_sub(secret_key) % u8::MAX;
        plain_text.push_str(char::from(ascii_code).to_string().as_ref());
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

pub fn brute_force_attack(cipher_text: &str) -> Vec<String> {
    let mut result = vec![];

    for i in 0..u8::MAX {
        result.push(decrypt(cipher_text, i));
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

pub fn frequency_analysis(cipher_text: &str) -> Vec<u8> {
    let mut freq = frequencies(cipher_text)
        .into_iter()
        .collect::<Vec<(char, i32)>>();

    freq.sort_by(|a, b| b.1.cmp(&a.1));

    let Some((most_frequent_letter, _)) = freq.get(0) else {
        return vec![]
    };

    let mut result = vec![0u8; 12];
    for (i, c) in MOST_FREQUENT_LETTERS_IN_ENGLISH_ALPHABET.iter().enumerate() {
        let ascii_number = *most_frequent_letter as u8;
        result[i] = ascii_number.saturating_sub(*c as u8) % u8::MAX;
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn encrypt_message() {
        let message = "Hello World";
        let secret = 3;
        let result = encrypt(&message, secret);
        assert_eq!(result, "KHOOR#ZRUOG");
    }

    #[test]
    fn decrypt_message() {
        let cipher_text = "KHOOR#ZRUOG";
        let secret = 3;
        let result = decrypt(&cipher_text, secret);
        assert_eq!(result, "HELLO WORLD");
    }

    #[test]
    fn brute_force_attack_encrypted_message() {
        let message = "KHOOR#ZRUOG";
        let decrypted = brute_force_attack(message);

        for i in 0..u8::MAX {
            match i {
                3 => {
                    assert_eq!(decrypted[i as usize], "HELLO WORLD");
                }
                _ => {
                    assert_ne!(decrypted[i as usize], "HELLO WORLD");
                }
            }
        }
    }

    #[test]
    fn frequency_analysis_attack() {
        let cipher_text = "KHOOR#ZRUOG";
        let result = frequency_analysis(cipher_text);
        for i in 0..MOST_FREQUENT_LETTERS_IN_ENGLISH_ALPHABET.len() {
            if i == 10 {
                assert_eq!(decrypt(cipher_text, result[i]), "HELLO WORLD");
            } else {
                assert_ne!(decrypt(cipher_text, result[i]), "HELLO WORLD");
            }
        }

        assert_eq!(frequency_analysis(""), vec![]);
    }
}

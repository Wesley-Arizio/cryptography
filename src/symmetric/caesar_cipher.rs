use std::ops::Index;

const ALPHABET: &[char] = &['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];

pub fn encrypt(plain_text: &str, secret_key: usize) -> String {
    let mut cipher_text = String::new();
    for c in plain_text.to_uppercase().chars() {
        if let Some(index) = ALPHABET.iter().position(|v | *v == c) {
            let new_index = (index + secret_key) % ALPHABET.len();
            cipher_text.push_str(&ALPHABET[new_index].to_string());
        } else {
            cipher_text.push_str(" ");
        }
    }

    cipher_text.to_string()
}

pub fn decrypt() -> String {
    todo!()
}

#[cfg(tests)]
mod test {
    use super::*;
    #[test]
    fn encrypt_message() {
        let message = "Hello World";
        let secret  = 3;
        let result = encrypt(&message, secret);
        assert_eq!(result, "KHOOR ZRUOG");
    }

    #[test]
    fn decrypt_message() {
        assert_eq!(1 + 1, 2);
    }
}
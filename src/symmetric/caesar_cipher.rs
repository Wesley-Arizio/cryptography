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

pub fn brute_force_attack(cipher_text: &str) -> Vec<String> {
    let mut result = vec![];

    for i in 0..u8::MAX {
        result.push(decrypt(cipher_text, i));
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
}

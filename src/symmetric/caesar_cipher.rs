pub fn encrypt(plain_text: &str, secret_key: u8) -> String {
    let mut cipher_text = String::new();
    for c in plain_text.to_uppercase().chars() {
        let ascii_code = (c as u8 + secret_key) % u8::MAX;
        cipher_text.push_str(char::from(ascii_code).to_string().as_ref());
    }

    cipher_text
}

pub fn decrypt(cipher_text: &str, secret_key: u8) -> String {
    let mut plain_text = String::new();
    for c in cipher_text.to_uppercase().chars() {
        let ascii_code = (c as u8 - secret_key) % u8::MAX;
        plain_text.push_str(char::from(ascii_code).to_string().as_ref());
    }

    plain_text
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
}

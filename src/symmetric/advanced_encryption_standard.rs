/*
    AES - Advanced Encryption Standard
*/

use crypto::symmetriccipher::SymmetricCipherError;

#[derive(Debug)]
pub enum AesError {
    InvalidSecretLength,
    InvalidPadding,
    InvalidHexEncryptedData,
    InvalidDecodedValue,
}

impl From<SymmetricCipherError> for AesError {
    fn from(value: SymmetricCipherError) -> Self {
        match value {
            SymmetricCipherError::InvalidLength => Self::InvalidSecretLength,
            SymmetricCipherError::InvalidPadding => Self::InvalidPadding,
        }
    }
}

impl From<AesError> for String {
    fn from(value: AesError) -> Self {
        format!("{:?}", value)
    }
}

use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer};

// Example from https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs

// Encrypt a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<String, AesError> {
    if key.len() != 32 {
        return Err(AesError::InvalidSecretLength);
    };
    // Create an encryptor instance of the best performing
    // type available for the platform.
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    // Each encryption operation encrypts some data from
    // an input buffer into an output buffer. Those buffers
    // must be instances of RefReaderBuffer and RefWriteBuffer
    // (respectively) which keep track of how much data has been
    // read from or written to them.
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // Each encryption operation will "make progress". "Making progress"
    // is a bit loosely defined, but basically, at the end of each operation
    // either BufferUnderflow or BufferOverflow will be returned (unless
    // there was an error). If the return value is BufferUnderflow, it means
    // that the operation ended while wanting more input data. If the return
    // value is BufferOverflow, it means that the operation ended because it
    // needed more space to output data. As long as the next call to the encryption
    // operation provides the space that was requested (either more input data
    // or more output space), the operation is guaranteed to get closer to
    // completing the full operation - ie: "make progress".
    //
    // Here, we pass the data to encrypt to the enryptor along with a fixed-size
    // output buffer. The 'true' flag indicates that the end of the data that
    // is to be encrypted is included in the input buffer (which is true, since
    // the input data includes all the data to encrypt). After each call, we copy
    // any output data to our result Vec. If we get a BufferOverflow, we keep
    // going in the loop since it means that there is more work to do. We can
    // complete as soon as we get a BufferUnderflow since the encryptor is telling
    // us that it stopped processing data due to not having any more data in the
    // input buffer.
    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(hex::encode(final_result))
}

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
pub fn decrypt(encrypted_data: &str, key: &[u8], iv: &[u8]) -> Result<String, AesError> {
    let Some(encrypted_data) = hex::decode(encrypted_data).ok() else {
        return Err(AesError::InvalidHexEncryptedData)
    };
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(&encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(String::from_utf8(final_result).map_err(|_| AesError::InvalidDecodedValue)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypt_decrypt_message() {
        let message = "Hello World";
        let key = b"mysecretpasswordmysecretpassword";
        let iv = b"0000000000000000";

        // hex code from online tool https://www.javainuse.com/aesgenerator
        let encrypted_data = encrypt(message.as_bytes(), key, iv).unwrap();
        assert_eq!(encrypted_data, "9ed5a2c1484805d74255b86d8ef652b3");
        let hex = "9ed5a2c1484805d74255b86d8ef652b3".to_uppercase();
        let decrypted_data = decrypt(&hex, key, iv).unwrap();
        assert_eq!(message, decrypted_data);
    }
}

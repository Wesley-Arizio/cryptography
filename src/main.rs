use clap::{Parser, Subcommand};

mod symmetric;

const IV: &[u8; 16] = b"0000000000000000";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Encrypt {
    CaesarCipher {
        /// Data to be encrypted
        data: String,
        /// Secret number to shift in caesar cipher encryption method
        secret: i32,
    },
    VigenereCipher {
        /// Data to be encrypted
        data: String,
        /// Secret word used to shift values in data in vigenere cipher method.
        secret: String,
    },
    Aes {
        /// Data to be encrypted
        data: String,
        /// 32 bit secret used to decrypt data
        secret: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum Decrypt {
    CaesarCipher {
        /// Data to be decrypted
        data: String,
        /// Secret number to shift back in caesar cipher decryption method
        secret: i32,
    },
    VigenereCipher {
        /// Data to be decrypted
        data: String,
        /// Secret word used to shift values in data in vigenere cipher method.
        secret: String,
    },
    Aes {
        /// Data to be decrypted
        data: String,
        /// 32 bit secret used to decrypt data
        secret: String,
    },
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Encrypt data using different methodologies, use --help to see which one we support
    Encrypt {
        #[command(subcommand)]
        command: Encrypt,
    },

    /// Decrypt data using different methodologies, use --help to see which one we support
    Decrypt {
        #[command(subcommand)]
        command: Decrypt,
    },
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { command } => match command {
            Encrypt::CaesarCipher { data, secret } => {
                let encrypted = symmetric::caesar_cipher::encrypt(&data, secret);
                println!("Encrypted message: '{}'", encrypted);
            }
            Encrypt::VigenereCipher { data, secret } => {
                let encrypted = symmetric::vigenere_cipher::encrypt(&data, &secret);
                println!("Encrypted message: '{}'", encrypted);
            }
            Encrypt::Aes { data, secret } => {
                let encrypted = symmetric::advanced_encryption_standard::encrypt(
                    data.as_bytes(),
                    secret.as_bytes(),
                    IV,
                )?;
                println!("Encrypted message: '{}'", encrypted);
            }
        },
        Command::Decrypt { command } => match command {
            Decrypt::CaesarCipher { data, secret } => {
                let decrypted = symmetric::caesar_cipher::decrypt(&data, secret);
                println!("Decrypted message: '{}'", decrypted);
            }
            Decrypt::VigenereCipher { data, secret } => {
                let decrypted = symmetric::vigenere_cipher::decrypt(&data, &secret);
                println!("Decrypted message: '{}'", decrypted);
            }
            Decrypt::Aes { data, secret } => {
                let decrypted =
                    symmetric::advanced_encryption_standard::decrypt(&data, secret.as_bytes(), IV)?;
                println!("Decrypted message: '{}'", decrypted);
            }
        },
    }

    Ok(())
}

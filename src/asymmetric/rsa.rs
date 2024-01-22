#![allow(dead_code)]
/*
    Rivest, Shamir and Adleman - RSA crypto system.
    Public key crypto system, contains public and private keys.

    RSA Algorithm

    - generate two large prime numbers P and Q (use Rabin-Miller algorithm)
      integers of 1024 bits or 2048 bits/

    - calculate Euler's phi function of N = P * Q

    - Then we need to find the 'e' parameter which is the public key, we calculate 'e' such that gcd(e, φ(n)) == 1
    basically e and φ(n) are relative primes (the gcd of them is 1).

    - Then we calculate the 'd' parameter which is the private key.
    to find 'd', we need to calculate the modular inverse of 'e' that's why 'e' and φ(n) need to be coprime.
    once we satisfy the equation, we find the 'd' value d * e mod φ(n) == 1

    once we do these steps, we have the public and private key, we can use them to encrypt and decrypt.

    encryption
    ciphertext_block = plaintext_block.pow(e) mod n;
    decryption
    plaintext_block =  ciphertext_block.pow(d) mod n;

    euclidean algorithm
    Efficient algorithm to find the greatest common divisor between two numbers.

    modular inverse
    the inverse of a is a.pow(1) multiplied by a that's equal to 1

    in modular arithmetic is kinda same
    a * a.pow(-1) mod m == 1;

    only numbers coprime to m will have modular inverse.

    extended euclidean algorithm
    it yields the GCD of a and b and also two coefficients x and y.

    a * x + b * y = gcd(a, b);
*/

use num_bigint::BigUint;
use num_traits::{FromBytes, ToBytes, ToPrimitive};
use rand::Rng;

const START: i32 = 100;
const END: i32 = 1000;

fn euclidean_gcd(a: u128, b: u128) -> u128 {
    if a % b == 0 {
        return b;
    };

    euclidean_gcd(b, a % b)
}

fn modular_inverse(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    };

    let (div, x1, y1) = modular_inverse(b % a, a);

    let x = y1 - (b / a) * x1;
    let y = x1;

    (div, x, y)
}

// a is always smaller value
fn extended_gcd(a: u128, b: u128) -> (u128, u128, u128) {
    return if b == 0 {
        (a, 1, 0)
    } else {
        let (gcd, x, y) = extended_gcd(b, a % b);
        (gcd, y, x - (a / b) * y)
    };
}

fn is_prime(num: i128) -> bool {
    if num < 2 {
        return false;
    };

    if num == 2 {
        return true;
    };

    if num % 2 == 0 {
        return false;
    };

    for i in (3..=(num as f64).sqrt() as i128).step_by(2) {
        if num % i == 0 {
            return false;
        };
    }

    true
}

fn generate_large_prime_number() -> u128 {
    let mut num: u128 = 0;
    let mut rng = rand::thread_rng();
    while !is_prime(num as i128) {
        num = rng.gen_range(START..=END) as u128;
    }
    num
}

fn generate_rsa_keys() -> ((u128, u128), (u128, u128)) {
    let p = generate_large_prime_number();
    let q = generate_large_prime_number();

    // trapdoor function, calculating n is fast but the opposite (getting p an q from n) is an exponentially slow operation.
    let n = p * q;

    // Euler's phi function
    let phi = (p - 1) * (q - 1);

    let mut rng = rand::thread_rng();

    let mut public_key = rng.gen_range(1..=phi);

    // public key and phi must be coprime, which means that the gcd of both must be 1
    while euclidean_gcd(public_key, phi) != 1 {
        public_key = rng.gen_range(1..=phi);
    }

    // private key is the modular inverse of the public key
    let private_key = modular_inverse(public_key as i128, phi as i128).1 as u128;

    ((private_key, n), (public_key, n))
}

fn encrypt(public_key: (u128, u128), message: &str) -> Vec<Vec<u8>> {
    let mut result = vec![];
    let (public_key, n) = public_key;
    for &c in message.as_bytes() {
        let cipher = BigUint::from(c).modpow(&BigUint::from(public_key), &BigUint::from(n));
        result.push(cipher.to_bytes_le());
    }

    result
}

fn decrypt(private_key: (u128, u128), message: &Vec<Vec<u8>>) -> String {
    let mut result = String::new();

    let (private_key, n) = private_key;
    for num in message.iter() {
        let t = BigUint::from_bytes_le(num);
        let a = t.modpow(&BigUint::from(private_key), &BigUint::from(n));

        if let Some(v) = a.to_u128() {
            let c = char::from(v as u8);
            result.push(c);
        };
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_euclidean_gcd() {
        assert_eq!(euclidean_gcd(24, 9), 3);
        // assert_eq!(extended_gcd(15, 56), (1, 15, -4));
        //  a * x + b * y = gcd(a, b);
        // 15 * 15 + 56 * -4 - 225 + (-224) = 1
    }

    #[test]
    fn test_modular_inverse() {
        assert_eq!(modular_inverse(9, 31).1, 7);
        // (7 * 9) % 31 == 1
    }

    #[test]
    fn test_is_prime() {
        assert!(!is_prime(1));
        assert!(is_prime(2));
        assert!(!is_prime(8));
        assert!(is_prime(11));
    }

    #[test]
    fn test_generating_rsa_keys() {
        let result = generate_rsa_keys();

        let message = "Hello World";
        let cipher = encrypt(result.1, message);
        assert_eq!(cipher.len(), message.len());

        let plain_text = decrypt(result.0, &cipher);
        assert_eq!(plain_text.as_bytes(), message.as_bytes());
    }
}

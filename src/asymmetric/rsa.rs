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
*/

fn euclidean_gcd(a: i32, b: i32) -> i32 {
    if a % b == 0 {
        return b;
    };

    euclidean_gcd(b, a % b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_euclidean_gcd() {
        assert_eq!(euclidean_gcd(24, 9), 3);
    }
}

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

fn euclidean_gcd(a: i32, b: i32) -> i32 {
    if a % b == 0 {
        return b;
    };

    euclidean_gcd(b, a % b)
}
fn modular_inverse(a: u32, m: u32) -> Option<u32> {
    for i in 0..m {
        // only numbers coprime to m will have a modular inverse
        if (a * i) % m == 1 {
            return Some(i);
        };
    }

    None
}

// a is always smaller value
fn extended_gcd(a: i32, b: i32) -> (i32, i32, i32) {
    return if b == 0 {
        (a, 1, 0)
    } else {
        let (gcd, x, y) = extended_gcd(b, a % b);
        (gcd, y, x - (a / b) * y)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_euclidean_gcd() {
        assert_eq!(euclidean_gcd(24, 9), 3);
        assert_eq!(extended_gcd(15, 56), (1, 15, -4));
    }
    #[test]
    fn test_modular_inverse() {
        assert_eq!(modular_inverse(9, 31), Some(7));
        // (7 * 9) % 31 == 1
    }
}

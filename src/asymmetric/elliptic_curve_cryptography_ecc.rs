/*
    Elliptic Curve Cryptography - ECC

    cryptography relies on trapdoor function
    easy to compute, Ka or Kb using their generated random number and the generator point
    A -> B
    Ka = A * R(x1, y1)

    hard to impossible to compute
    in this case, the inverse operation is called elliptic curve discrete logarithm problem.
    A <- B
    hard to find A or B from Ka or kb

    The elliptic curve cryptography is just a secure way of key agreement between two parties.
    a secure way of generating and sharing a secret key, then they can use the secret key in an algorithm like AES
    to actually encrypt and decrypt the message.


    Elliptic curve diffie-hellman algorithm

    Alice generates a random number between 2 and length of elliptic curve
    Bob does the same.

    Alice and bob generate a public key using their random number
    Alice:  Ka = A * R(x1, y1) being R e generator point on the elliptic curve
    Bob:    Kb = B * R(x2, y2).

    Ka and Kb are their public keys.
    Now they can calculate their private keys using each other's public key.

    Alice's private key: A * Kb
    Bob's private key:   B * ka

    Their private key are the same, that's why they can use their shared private key to encrypt data using
    symmetric crypto system like AES.

    Notes
    - Elliptic curves are symmetric on the x-axis.
    - For this equation 4 * aˆ3 + 27 * bˆ2 != 0 to be true, it must be a non-singular elliptic curve (it does have 3  distinct roots)
    - A straight line meet the x-axis either at 1 or 3 points.
*/

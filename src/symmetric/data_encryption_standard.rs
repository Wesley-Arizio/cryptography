/*
    DES or Data Encryption Standard was created in early 1970s at IBM.
    It is a block cipher, the plain text is processed to the cipher text in blocks of 64 bits or 8 bytes

    The plain text is divided into groups of 64 bits, creating blocks, these block are input for the 16 rounds of encryption/decryption
    of this algorithm.

    Each round needs a sub-keys, derived from a 64 bits private key (being only 56 bits relevant).
    Every sub-key size will be 56 bits long.

    https://en.wikipedia.org/wiki/DES_supplementary_material#

    How DES algorithm works?
    - First we convert the plaintext into binary and split it into groups of 64 bits (8 bytes),
      filling the missing bits to complete last group if necessary.

    - Initial permutation of the 64 bits of the plaintext block.
      Using a table 8x8 (64) we have fixed order for the bits of the input.
      The permutation is basically get the identifier bit on the table and apply it using the plaintext block.
      ex:
      IP - initial permutation
      [58, 50, 42] -> it will use the sequence of 58th bit of the input, then the 50th, then 42th and so on.
      IP - 1 - inverse of the initial permutation
      Does the same thing but with a different table.

    - Generate sub-keys for each round from the secret key which is 64 bits,
      for that we shuffle the order of the bits and omit 8 bits, obtaining the rest 56 bits.
      The process is called permuted choice 1 (PC-1).
      After that, we apply a left circular shift which shift bits (N bits) to the left and then,
      apply a permuted choice 2 (PC-2) which makes the key of 56 bits become 48 bits.

    - The generated key and the initial plain text block are the input for the first round,
      for the remaining rounds, the input is the output of the last round and the new generated key.

    - About the rounds
      In the beginning of the round, the plaintext block is divided into two 32bits group called Left and Right
      The sub-key for the given round is split as well, into two 28 bits group called K1 K2.

      - Then we have circular left operation for K1 and K2 which basically shifts the bits of the keys to left given N times (1 or 2);
      - Then we have permuted choice 2 (PC-2) which uses two different table that permute K1 and K2, generating a 48 bits key.

      - The first step is to use a expansion function into the Right side of the plaintext block, which will make the 32 bits group turn into 48 bits,
      basically using a pre-defined table, we will use the bits of the input and repeat a few of them.
      - After that we do a XOR operation between the Right side of the plaintext block with the permuted choice 2 key output.

      - Then we have a S-BOX operation or Substitution boxes
        For this operation, the input is 48 bits and the output is 32 bits.
        It basically splits the 48 bits into 8 groups of 6 bits (like a box) which then, uses lookup tables
        that transform those 6 bits into 4 bits, hence 48 bits -> 32 bits.

        In the box, with the 6 bits, the first and last digit defines the row, the four bits in the middle defines the column,
        that's how it transforms 6 bits into 4 bits.

        reference to the lookup table for s-box operation https://en.wikipedia.org/wiki/DES_supplementary_material#Substitution_boxes_(S-boxes)

      - Then we have another permutation using this fixed table https://en.wikipedia.org/wiki/DES_supplementary_material#Permutation_(P)

      - Lastly, we do a XOR operation between Left and the result of the last permutation.

      - The Initial Right side becomes the Left side, the last XOR operation becomes the Right side.

    - The last step is the inverse permutation with Right and Left half done in the step one,
      and then we have the cipher text.

      NOTE: For the encrypt method, we first generate all the 16 sub-keys (ASCENDING ORDER)
            For the decrypt method, we start from the 16th key. (DESCENDING ORDER)

*/

// TODO - Implement DAS algorithm by myself

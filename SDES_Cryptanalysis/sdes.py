# Constants
BLOCK_SIZE = 8
KEY_SIZE = 10
ROUND_COUNT = 4

# Initial Permutation (IP)
IP = [4, 8, 2, 7, 1, 5, 6, 3]

# Inverse Initial Permutation (IP^-1)
IP_INV = [5, 3, 8, 1, 6, 7, 4, 2]

# Expansion function (E)
E = [4, 1, 2, 3, 2, 3, 4, 1]

# Permutation function (P)
P = [2, 4, 3, 1]

# S-boxes
S1 = [
    [3, 2, 1, 0],
    [1, 0, 3, 2],
    [1, 3, 0, 2],
    [3, 2, 3, 1],
]

S2 = [
    [2, 0, 1, 3],
    [2, 1, 0, 3],
    [0, 1, 2, 3],
    [3, 0, 1, 0],
]

# Permuted Choice 1 (PC-1)
PC1 = [8, 5, 4, 6, 10, 3, 9, 1, 7, 2]

# Permuted Choice 2 (PC-2)
PC2 = [9, 3, 8, 4, 7, 2, 10, 1]

class SDES:
    def __init__(self, key):
        if len(key) != KEY_SIZE:
            raise ValueError("Invalid key size. S-DES key must be 10 bits.")
        self.key = key
        self.subkeys = self.generate_subkeys()

    def generate_subkeys(self):
        # Permuted Choice 1 (PC-1)
        pc1_key = [self.key[i - 1] for i in PC1]
        c0, d0 = pc1_key[:5], pc1_key[5:]

        subkeys = []
        for i in range(1, 5):
            # Left shifts
            shifts = [1, 2, 2, 2]
            c0 = c0[shifts[i-1]:] + c0[:shifts[i-1]]
            d0 = d0[shifts[i-1]:] + d0[:shifts[i-1]]

            # Permuted Choice 2 (PC-2)
            subkey = [c0[i - 1] if i <= 5 else d0[i - 6] for i in PC2]
            subkeys.append(subkey)

        return subkeys

    def permute(self, input_bits, permutation):
        return [input_bits[i - 1] for i in permutation]

    def f_function(self, r, subkey):
            # Expansion (E)
            expanded = self.permute(r, E)

            # XOR with subkey
            xored = [e ^ k for e, k in zip(expanded, subkey)]

            # S-box substitution
            s1_input = (xored[0] * 2 + xored[3], xored[1] * 2 + xored[2])
            s2_input = (xored[4] * 2 + xored[7], xored[5] * 2 + xored[6])
            s1_output = S1[s1_input[0]][s1_input[1]]
            s2_output = S2[s2_input[0]][s2_input[1]]

            # Combine S-box outputs
            combined = (s1_output << 2) | s2_output
            output = [int(b) for b in f'{combined:04b}']

            # Permutation (P)
            return self.permute(output, P)

    def encrypt(self, plaintext):
        if len(plaintext) != BLOCK_SIZE:
            raise ValueError("Plaintext must be 8 bits.")

        # Initial Permutation (IP)
        block = self.permute(plaintext, IP)

        l, r = block[:4], block[4:]

        for i in range(ROUND_COUNT):
            f_result = self.f_function(r, self.subkeys[i])
            new_r = [l[j] ^ f_result[j] for j in range(4)]
            l, r = r, new_r

        # Final permutation (IP^-1) on reversed block
        ciphertext = self.permute(r + l, IP_INV)
        return ciphertext

    def decrypt(self, ciphertext):

        # Initial Permutation (IP)
        block = self.permute(ciphertext, IP)

        r, l = block[:4], block[4:]

        for i in range(ROUND_COUNT - 1, -1, -1):
            f_result = self.f_function(l, self.subkeys[i])
            new_r = [r[j] ^ f_result[j] for j in range(4)]
            l, r = new_r, l

        # Final permutation (IP^-1)
        plaintext = self.permute(l + r, IP_INV)
        return plaintext

# Test the implementation
if __name__ == "__main__":
    key = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
    plaintext = [0, 0, 0, 0, 0, 0, 0, 0]

    sdes = SDES(key)
    ciphertext = sdes.encrypt(plaintext)
    decrypted = sdes.decrypt(ciphertext)

    print(f"\nSummary:")
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")

    assert plaintext == decrypted, "Decryption failed: result doesn't match original plaintext"
    print("Decryption successful: result matches original plaintext")
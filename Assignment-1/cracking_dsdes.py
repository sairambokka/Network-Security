from sdes import SDES

def xor_bits(a, b):
    return [x ^ y for x, y in zip(a, b)]

class DoubleSBES:
    def __init__(self, key1, key2):
        self.sdes1 = SDES(key1)
        self.sdes2 = SDES(key2)

    def decrypt(self, ciphertext):
        intermediate = self.sdes2.decrypt(ciphertext)
        return self.sdes1.decrypt(intermediate)

def hex_to_bits(hex_string):
    return [int(b) for b in f'{int(hex_string, 16):0{len(hex_string)*4}b}']

def bits_to_bytes(bits):
    return bytes(int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8))

def ds_des_cbc_decrypt(ciphertext, key1, key2, iv):
    ds_des = DoubleSBES(key1, key2)
    plaintext_bits = []
    previous_block = iv

    for i in range(0, len(ciphertext), 8):
        ciphertext_block = ciphertext[i:i+8]
        decrypted_block = ds_des.decrypt(ciphertext_block)
        plaintext_block = xor_bits(decrypted_block, previous_block)
        plaintext_bits.extend(plaintext_block)
        previous_block = ciphertext_block

        print(f"Block {i//8 + 1}:")
        print(f"Ciphertext: {''.join(map(str, ciphertext_block))}")
        print(f"Decrypted:  {''.join(map(str, decrypted_block))}")
        print(f"Plaintext:  {''.join(map(str, plaintext_block))}")
        print(f"ASCII:      {bits_to_bytes(plaintext_block).decode('ascii', errors='replace')}")
        print()

    return bits_to_bytes(plaintext_bits)

# Main decryption process
key1 = [1, 1, 0, 1, 0, 0, 0, 1, 0, 1]
key2 = [1, 0, 0, 1, 1, 1, 0, 1, 0, 1]
iv = hex_to_bits('6a')
ciphertext_hex = "fb7cf0addb5a904590d4070be8fc9502c5506f85707e484e5457c39ccae19b66b0d36c7e03b2754cc36720d9cafa473c3fdff530d09aa20d19c5213f5c9727a3b7ecda681b0bc2bbaa754cf78921b84d1b64f0be150ac28e40816720f1be2aa0f31108fefcad6e332d3fdff5f4f4eab7"

ciphertext_bits = hex_to_bits(ciphertext_hex)
plaintext = ds_des_cbc_decrypt(ciphertext_bits, key1, key2, iv)

# Convert plaintext to ASCII
message = plaintext.decode('ascii', errors='replace')
print("Full decrypted message:")
print(message)
from sdes import SDES

class DoubleSBES:
    def __init__(self, key1, key2):
        self.sdes1 = SDES(key1)
        self.sdes2 = SDES(key2)

    def encrypt(self, plaintext):
        intermediate = self.sdes1.encrypt(plaintext)
        return self.sdes2.encrypt(intermediate)

    def decrypt(self, ciphertext):
        intermediate = self.sdes2.decrypt(ciphertext)
        return self.sdes1.decrypt(intermediate)

def bits_to_byte(bits):
    return int(''.join(map(str, bits)), 2)

def byte_to_bits(byte):
    return [int(b) for b in f'{byte:08b}']

# Test the implementation
if __name__ == "__main__":
    key1 = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]
    key2 = [1, 1, 1, 1, 0, 0, 0, 0, 0, 0]
    plaintext = [0, 1, 0, 0, 0, 0, 1, 0]  # 0x42

    double_sdes = DoubleSBES(key1, key2)
    ciphertext = double_sdes.encrypt(plaintext)
    decrypted = double_sdes.decrypt(ciphertext)

    print(f"\nDouble S-DES Test:")
    print(f"Plaintext:  0x{bits_to_byte(plaintext):02X}")
    print(f"Ciphertext: 0x{bits_to_byte(ciphertext):02X}")
    print(f"Decrypted:  0x{bits_to_byte(decrypted):02X}")

    assert plaintext == decrypted, "Decryption failed: result doesn't match original plaintext"
    print("Decryption successful: result matches original plaintext")
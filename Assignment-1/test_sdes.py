import pytest
from sdes import SDES  # Assuming the SDES class is in the sdes.py file

# Test: Variable Plaintext Known Answer Test
def test_variable_plaintext_known_answer():
    key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # KEY = 0000000000b
    plaintexts = [
        [1, 0, 0, 0, 0, 0, 0, 0],  # P1 = 10000000b
        [0, 1, 0, 0, 0, 0, 0, 0],  # P2 = 01000000b
        [0, 0, 1, 0, 0, 0, 0, 0],  # P3 = 00100000b
        [0, 0, 0, 1, 0, 0, 0, 0],  # P4 = 00010000b
        [0, 0, 0, 0, 1, 0, 0, 0],  # P5 = 00001000b
        [0, 0, 0, 0, 0, 1, 0, 0],  # P6 = 00000100b
        [0, 0, 0, 0, 0, 0, 1, 0],  # P7 = 00000010b
        [0, 0, 0, 0, 0, 0, 0, 1]   # P8 = 00000001b
    ]
    expected_ciphertexts = [
        [0, 0, 0, 1, 0, 1, 1, 1],  # C1 = 00010111b
        [1, 1, 0, 1, 0, 0, 0, 1],  # C2 = 11010001b
        [0, 0, 1, 1, 1, 1, 0, 1],  # C3 = 00111101b
        [1, 0, 1, 0, 0, 1, 0, 0],  # C4 = 10100100b
        [0, 1, 1, 1, 1, 1, 1, 0],  # C5 = 01111110b
        [1, 0, 1, 0, 1, 0, 1, 1],  # C6 = 10101011b
        [1, 0, 0, 1, 1, 1, 0, 1],  # C7 = 10011101b
        [0, 0, 1, 0, 1, 0, 1, 1],  # C8 = 00101011b
    ]
    
    sdes = SDES(key)
    
    for i, plaintext in enumerate(plaintexts):
        ciphertext = sdes.encrypt(plaintext)
        assert ciphertext == expected_ciphertexts[i], f"Failed on P{i+1}. Expected {expected_ciphertexts[i]}, got {ciphertext}"

# Test: Variable Key Known Answer Test
def test_variable_key_known_answer():
    plaintext = [0, 0, 0, 0, 0, 0, 0, 0]  # P = 00000000b
    keys = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # K1 = 1000000000b
        [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],  # K2 = 0100000000b
        [0, 0, 1, 0, 0, 0, 0, 0, 0, 0],  # K3 = 0010000000b
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0],  # K4 = 0001000000b
        [0, 0, 0, 0, 1, 0, 0, 0, 0, 0],  # K5 = 0000100000b
        [0, 0, 0, 0, 0, 1, 0, 0, 0, 0],  # K6 = 0000010000b
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0],  # K7 = 0000001000b
        [0, 0, 0, 0, 0, 0, 0, 1, 0, 0],  # K8 = 0000000100b
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 0],  # K9 = 0000000010b
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1],  # K10 = 0000000001b
    ]
    expected_ciphertexts = [
        [1, 1, 1, 0, 1, 0, 1, 0],  # C1 = 11101010b
        [1, 0, 1, 1, 1, 0, 1, 1],  # C2 = 10111011b
        [0, 0, 0, 1, 1, 0, 0, 1],  # C3 = 00011001b
        [1, 0, 1, 0, 1, 0, 0, 1],  # C4 = 10101001b
        [1, 0, 1, 1, 0, 1, 1, 0],  # C5 = 10110110b
        [0, 1, 0, 0, 0, 1, 1, 1],  # C6 = 01000111b
        [0, 0, 0, 0, 0, 1, 1, 1],  # C7 = 00000111b
        [0, 1, 1, 1, 1, 0, 0, 0],  # C8 = 01111000b
        [0, 1, 1, 0, 1, 0, 0, 1],  # C9 = 01101001b
        [0, 1, 1, 1, 1, 0, 0, 1],  # C10 = 01111001b
    ]
    
    for i, key in enumerate(keys):
        sdes = SDES(key)
        ciphertext = sdes.encrypt(plaintext)
        assert ciphertext == expected_ciphertexts[i], f"Failed on K{i+1}. Expected {expected_ciphertexts[i]}, got {ciphertext}"

# Test: Inverse Permutation Known Answer Test
def test_inverse_permutation_known_answer():
    key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # KEY = 0000000000b
    ciphertexts = [
        [0, 0, 0, 1, 0, 1, 1, 1],  # C1 = 00010111b
        [1, 1, 0, 1, 0, 0, 0, 1],  # C2 = 11010001b
        [0, 0, 1, 1, 1, 1, 0, 1],  # C3 = 00111101b
        [1, 0, 1, 0, 0, 1, 0, 0],  # C4 = 10100100b
        [0, 1, 1, 1, 1, 1, 1, 0],  # C5 = 01111110b
        [1, 0, 1, 0, 1, 0, 1, 1],  # C6 = 10101011b
        [1, 0, 0, 1, 1, 1, 0, 1],  # C7 = 10011101b
        [0, 0, 1, 0, 1, 0, 1, 1],  # C8 = 00101011b
    ]
    expected_plaintexts = [
        [1, 0, 0, 0, 0, 0, 0, 0],  # P1 = 10000000b
        [0, 1, 0, 0, 0, 0, 0, 0],  # P2 = 01000000b
        [0, 0, 1, 0, 0, 0, 0, 0],  # P3 = 00100000b
        [0, 0, 0, 1, 0, 0, 0, 0],  # P4 = 00010000b
        [0, 0, 0, 0, 1, 0, 0, 0],  # P5 = 00001000b
        [0, 0, 0, 0, 0, 1, 0, 0],  # P6 = 00000100b
        [0, 0, 0, 0, 0, 0, 1, 0],  # P7 = 00000010b
        [0, 0, 0, 0, 0, 0, 0, 1],  # P8 = 00000001b
    ]
    
    sdes = SDES(key)
    
    for i, ciphertext in enumerate(ciphertexts):
        plaintext = sdes.decrypt(ciphertext)
        assert plaintext == expected_plaintexts[i], f"Failed on C{i+1}. Expected {expected_plaintexts[i]}, got {plaintext}"

if __name__ == "__main__":
    pytest.main()
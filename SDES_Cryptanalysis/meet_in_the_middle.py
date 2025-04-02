import time
from sdes import SDES
from double_sdes import DoubleSBES, bits_to_byte, byte_to_bits

def meet_in_the_middle_attack(plaintext_ciphertext_pairs):
    start_time = time.time()

    # Step 1: Build a dictionary of all possible encryptions with the first key
    encryptions = {}
    for k1 in range(1024):  # 2^10 possible 10-bit keys
        key1 = [int(b) for b in f'{k1:010b}']
        sdes1 = SDES(key1)
        for pair in plaintext_ciphertext_pairs:
            pt = byte_to_bits(pair[0])
            intermediate = sdes1.encrypt(pt)
            encryptions.setdefault(k1, []).append(bits_to_byte(intermediate))

    # Step 2: Try all possible second keys and check against the dictionary
    for k2 in range(1024):
        key2 = [int(b) for b in f'{k2:010b}']
        sdes2 = SDES(key2)
        match = True
        for pair in plaintext_ciphertext_pairs:
            ct = byte_to_bits(pair[1])
            intermediate = sdes2.decrypt(ct)
            if bits_to_byte(intermediate) not in [enc[plaintext_ciphertext_pairs.index(pair)] for enc in encryptions.values()]:
                match = False
                break
        if match:
            for k1, intermediates in encryptions.items():
                if all(intermediates[i] == bits_to_byte(sdes2.decrypt(byte_to_bits(pair[1]))) for i, pair in enumerate(plaintext_ciphertext_pairs)):
                    end_time = time.time()
                    return (k1, k2, end_time - start_time)

    end_time = time.time()
    return (None, None, end_time - start_time)

# Test the Meet in the Middle attack
if __name__ == "__main__":
    plaintext_ciphertext_pairs = [
        (0x42, 0x53),
        (0x72, 0xc6),
        (0x75, 0x64),
        (0x74, 0x0b),
        (0x65, 0x23)
    ]

    k1, k2, execution_time = meet_in_the_middle_attack(plaintext_ciphertext_pairs)

    if k1 is not None and k2 is not None:
        print(f"Keys found: k1 = {k1:010b}, k2 = {k2:010b}")
        print(f"Execution time: {execution_time:.2f} seconds")

        # Verify the found keys
        double_sdes = DoubleSBES([int(b) for b in f'{k1:010b}'], [int(b) for b in f'{k2:010b}'])
        all_correct = True
        for pt, ct in plaintext_ciphertext_pairs:
            if bits_to_byte(double_sdes.encrypt(byte_to_bits(pt))) != ct:
                all_correct = False
                break
        print("All pairs encrypted correctly:" if all_correct else "Error: Not all pairs encrypted correctly")
    else:
        print("No keys found")
        print(f"Execution time: {execution_time:.2f} seconds")
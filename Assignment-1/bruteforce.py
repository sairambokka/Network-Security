import time
from sdes import SDES
from double_sdes import DoubleSBES, bits_to_byte, byte_to_bits

def brute_force_search(plaintext_ciphertext_pairs):
    start_time = time.time()

    for k1 in range(1024):  # 2^10 possible 10-bit keys
        for k2 in range(1024):
            key1 = [int(b) for b in f'{k1:010b}']
            key2 = [int(b) for b in f'{k2:010b}']
            double_sdes = DoubleSBES(key1, key2)

            if all(bits_to_byte(double_sdes.encrypt(byte_to_bits(pt))) == ct for pt, ct in plaintext_ciphertext_pairs):
                end_time = time.time()
                return (k1, k2, end_time - start_time)

    end_time = time.time()
    return (None, None, end_time - start_time)

# Test the Brute Force search
if __name__ == "__main__":
    plaintext_ciphertext_pairs = [
        (0x42, 0x53),
        (0x72, 0xc6),
        (0x75, 0x64),
        (0x74, 0x0b),
        (0x65, 0x23)
    ]

    k1, k2, execution_time = brute_force_search(plaintext_ciphertext_pairs)

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
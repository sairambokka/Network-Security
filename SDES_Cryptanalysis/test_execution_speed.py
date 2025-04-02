from meet_in_the_middle import meet_in_the_middle_attack
from bruteforce import brute_force_search

plaintext_ciphertext_pairs = [
    (0x42, 0x53),
    (0x72, 0xc6),
    (0x75, 0x64),
    (0x74, 0x0b),
    (0x65, 0x23)
]

print("Running Meet in the Middle attack...")
k1_mitm, k2_mitm, time_mitm = meet_in_the_middle_attack(plaintext_ciphertext_pairs)

print("\nRunning Brute Force search...")
k1_bf, k2_bf, time_bf = brute_force_search(plaintext_ciphertext_pairs)

print("\nResults:")
print(f"Meet in the Middle attack:")
print(f"  Keys found: k1 = {k1_mitm:010b}, k2 = {k2_mitm:010b}")
print(f"  Execution time: {time_mitm:.2f} seconds")

print(f"\nBrute Force search:")
print(f"  Keys found: k1 = {k1_bf:010b}, k2 = {k2_bf:010b}")
print(f"  Execution time: {time_bf:.2f} seconds")

print(f"\nSpeedup factor: {time_bf / time_mitm:.2f}x")
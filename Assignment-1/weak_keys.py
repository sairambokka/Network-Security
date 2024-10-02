from sdes import ROUND_COUNT, PC1, PC2


def find_weak_keys():
    weak_keys = []
    
    def is_weak_key(key):
        # Apply PC1
        pc1_key = [key[i - 1] for i in PC1]
        c, d = pc1_key[:5], pc1_key[5:]
        
        # Check if all subkeys are identical after shifts
        subkeys = []
        for i in range(ROUND_COUNT):
            shifts = [1, 2, 2, 2]
            c = c[shifts[i]:] + c[:shifts[i]]
            d = d[shifts[i]:] + d[:shifts[i]]
            subkey = [c[i - 1] if i <= 5 else d[i - 6] for i in PC2]
            subkeys.append(subkey)
        
        return all(subkey == subkeys[0] for subkey in subkeys)
    
    # Generate all possible 10-bit keys
    for i in range(1024):  # 2^10 = 1024
        key = [int(b) for b in f'{i:010b}']
        if is_weak_key(key):
            weak_keys.append(key)
    
    return weak_keys

# Find and print weak keys
weak_keys = find_weak_keys()
print(f"Number of weak keys found: {len(weak_keys)}")
print("Weak keys:")
for key in weak_keys:
    print(''.join(map(str, key)))
class DES:
    # Initial Permutation Table
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    
    # Final Permutation Table
    FP = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    
    # Expansion Table
    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    
    # Permutation Table
    P = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    
    # S-boxes
    S = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    
    # Permuted Choice 1
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]
    
    # Permuted Choice 2
    PC2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 46, 54,
        29, 36, 44, 52, 50, 36,
        29, 32, 41, 50, 51, 45,
        33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36,
        29, 32
    ]
    
    # Shift schedule
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    def __init__(self, key):
        """Initialize DES with 8-byte key"""
        if len(key) != 8:
            raise ValueError("Key must be 8 bytes")
        self.key = key
        self.subkeys = self._generate_subkeys()
    
    def _string_to_bits(self, s):
        """Convert string to bit array"""
        bits = []
        for char in s:
            byte = ord(char) if isinstance(char, str) else char
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits
    
    def _bits_to_string(self, bits):
        """Convert bit array to bytes"""
        result = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)
    
    def _permute(self, bits, table):
        """Permute bits according to table"""
        return [bits[i - 1] for i in table]
    
    def _left_shift(self, bits, n):
        """Left circular shift"""
        return bits[n:] + bits[:n]
    
    def _xor(self, bits1, bits2):
        """XOR two bit arrays"""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]
    
    def _generate_subkeys(self):
        """Generate 16 subkeys from main key"""
        key_bits = self._string_to_bits(self.key)
        key_permuted = self._permute(key_bits, self.PC1)
        
        C = key_permuted[:28]
        D = key_permuted[28:]
        
        subkeys = []
        for shift in self.SHIFTS:
            C = self._left_shift(C, shift)
            D = self._left_shift(D, shift)
            subkey = self._permute(C + D, self.PC2)
            subkeys.append(subkey)
        
        return subkeys
    
    def _f_function(self, right, subkey):
        """F function in DES"""
        # Expansion
        expanded = self._permute(right, self.E)
        
        # XOR with subkey
        xored = self._xor(expanded, subkey)
        
        # S-box substitution
        output = []
        for i in range(8):
            block = xored[i * 6:(i + 1) * 6]
            row = (block[0] << 1) | block[5]
            col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
            val = self.S[i][row][col]
            for j in range(3, -1, -1):
                output.append((val >> j) & 1)
        
        # Permutation
        return self._permute(output, self.P)
    
    def _process_block(self, block, encrypt=True):
        """Process one 64-bit block"""
        bits = self._string_to_bits(block)
        
        # Initial permutation
        bits = self._permute(bits, self.IP)
        
        left = bits[:32]
        right = bits[32:]
        
        # 16 rounds
        subkeys = self.subkeys if encrypt else self.subkeys[::-1]
        for subkey in subkeys:
            temp = right
            right = self._xor(left, self._f_function(right, subkey))
            left = temp
        
        # Combine and final permutation
        combined = right + left
        final = self._permute(combined, self.FP)
        
        return self._bits_to_string(final)
    
    def encrypt(self, plaintext):
        """Encrypt plaintext (must be multiple of 8 bytes)"""
        # Padding
        pad_len = 8 - (len(plaintext) % 8)
        plaintext += bytes([pad_len] * pad_len)
        
        ciphertext = b''
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i+8]
            ciphertext += self._process_block(block, encrypt=True)
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext"""
        plaintext = b''
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            plaintext += self._process_block(block, encrypt=False)
        
        # Remove padding
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]
        
        return plaintext


# Test functions
if __name__ == "__main__":
    # Test DES implementation
    key = b"secret12"
    des = DES(key)
    
    # Test encryption
    plaintext = b"Hello World! This is a test message."
    print(f"Plaintext:  {plaintext}")
    
    encrypted = des.encrypt(plaintext)
    print(f"Encrypted:  {encrypted.hex()}")
    
    decrypted = des.decrypt(encrypted)
    print(f"Decrypted:  {decrypted}")
    
    # Verify
    if plaintext == decrypted:
        print("\n✅ DES Implementation Working!")
    else:
        print("\n❌ DES Implementation Error!")
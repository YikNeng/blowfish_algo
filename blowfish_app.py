import sqlite3
import struct

# P-array
P_INIT = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B
]

# Import S-boxes
from blowfish_sboxes import S_INIT  # This should contain the full S[4][256] arrays.

class Blowfish:
    # to make a copy of the P-array and S-boxes
    def __init__(self, key: bytes):
        self.P = P_INIT.copy()
        self.S = [sbox.copy() for sbox in S_INIT]
        self.key_expansion(key)

    def encrypt_block(self, L, R):

        # Perform 16 rounds until P[15]
        for i in range(16):
            L ^= self.P[i]  # left part XOR with subkey
            R ^= self.f(L)  # right part XOR with left part produced after function f
            L, R = R, L     # swap left part and right part

        L, R = R, L
        R ^= self.P[16]     # final XOR of right part before combined into encrypted text
        L ^= self.P[17]     # final XOR of left part before combined into encrypted text
        return L, R

    def decrypt_block(self, L, R):

        # Perform 16 rounds that same as encryption but in reverse order
        for i in range(17, 1, -1):
            L ^= self.P[i]
            R ^= self.f(L)
            L, R = R, L

        L, R = R, L
        R ^= self.P[1]       # final XOR of right part before combined into original text
        L ^= self.P[0]       # final XOR of left part before combined into original text
        return L, R

    # to generate p-array and s-boxes based on the user-input key
    def key_expansion(self, key: bytes):
        key_len = len(key)
        j = 0
        for i in range(18):                     # for 18 P-arrays
            k = 0
            for _ in range(4):                  # take 32 bits (4 bytes)
                k = (k << 8) | key[j]           # read 8 bits in one loop
                j = (j + 1) % key_len           # read 8 bits from the beginning if necessary (shorter than 72 bytes [18 x 4 bits])
            self.P[i] ^= k                      # update P[i] by XOR with k

        L = R = 0
        for i in range(0, 18, 2):               # Will be performed every 2 entries for all P[i]
            L, R = self.encrypt_block(L, R)     # update P-arrays to make it key-dependent
            self.P[i] = L                       # replace P[i] with L
            self.P[i+1] = R                     # update P[i+1] with R

        for i in range(4):
            for j in range(0, 256, 2):          # Will be performed every 2 entries for all S[i][j]
                L, R = self.encrypt_block(L, R) # update S-boxes to make it key-dependent
                self.S[i][j] = L                # replace S[i][j] with L
                self.S[i][j+1] = R              # update S[i][j+1] with R

    def f(self, x):
        # split the 32-bit number into four part (a, b, c, d)
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF

        # to perform function F = ((S1[A] + S2[B]) XOR S3[C]) + S4[D]
        h = (self.S[0][a] + self.S[1][b]) & 0xFFFFFFFF  # S1[A]+ S2[B]
        h ^= self.S[2][c]                               # result XOR S3[C]
        h = (h + self.S[3][d]) & 0xFFFFFFFF             # result + S4[D]
        return h

    def encrypt(self, plaintext: bytes):

        # Pad to 8-byte multiple
        while len(plaintext) % 8 != 0:
            plaintext += b'\x00'

        ciphertext = b''
        for i in range(0, len(plaintext), 8):
            L, R = struct.unpack('>II', plaintext[i:i+8])   # Breaks message into 8-byte blocks
            L, R = self.encrypt_block(L, R)                        # Encrypts them one by one
            ciphertext += struct.pack('>II', L, R)         # Combines encrypted pieces together
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        plaintext = b''
        for i in range(0, len(ciphertext), 8):
            L, R = struct.unpack('>II', ciphertext[i:i+8])  # Breaks message into 8-byte blocks
            L, R = self.decrypt_block(L, R)                        # Decryption of each block
            plaintext += struct.pack('>II', L, R)          # Combines decrypted pieces together
        return plaintext.rstrip(b'\x00')


# Database handling

# Create database and table to save messages
def init_db():
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, ciphertext BLOB)")
    conn.commit()
    conn.close()

# save all encrypted messages to the database
def save_message(ciphertext: bytes):
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    c.execute("INSERT INTO messages (ciphertext) VALUES (?)", (ciphertext,))
    conn.commit()
    conn.close()

# fetch all encrypted messages from the database
def get_messages():
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    c.execute("SELECT id, ciphertext FROM messages")
    messages = c.fetchall()
    conn.close()
    return messages

# clear all messages in the database
def clear_messages():
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    c.execute("DELETE FROM messages")
    conn.commit()
    conn.close()


# main application

def main():
    init_db()
    key = input("Enter encryption key: ").encode()
    bf = Blowfish(key)

    while True:
        print("\n----------------------------------------------")
        print("\n1. Encrypt message")
        print("2. View and decrypt messages")
        print("3. Exit")
        choice = input("Choose: ")

        if choice == "1":
            msg = input("Enter message to encrypt: ").encode()
            cipher = bf.encrypt(msg)
            save_message(cipher)
            print(f"Encrypted: {cipher}")
            print("Message encrypted and saved.")

        elif choice == "2":
            messages = get_messages()
            if not messages:
                print("No messages found.")
            for id_, cipher in messages:
                plain = bf.decrypt(cipher).decode(errors='ignore')
                print(f"\nID {id_}:")
                print(f"Encrypted: {cipher}")
                print(f"Decrypted: {plain}")


        elif choice == "3":
            clear_messages()
            print("All messages cleared from the database.")
            break


if __name__ == "__main__":
    main()

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import argparse


BLOCK_SIZE = 16
BMP_HEADER = 54

# PKCS#7 padding
def pad(data):
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    padding = bytes([padding_len] * padding_len)
    return data + padding

def encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i+BLOCK_SIZE]
        ciphertext += cipher.encrypt(block)
    return ciphertext

def encrypt_cbc(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    previous_block = iv
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i+BLOCK_SIZE]
        block = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block = cipher.encrypt(block)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    return ciphertext

# reads a BMP file and separate the header and data
def read_bmp(file_path):
    with open(file_path, 'rb') as f:
        header = f.read(BMP_HEADER)  
        data = f.read()
    return header, data

# writes encrypted data to a BMP file
def write_bmp(file_path, header, data):
    with open(file_path, 'wb') as f:
        f.write(header)
        f.write(data)

# Main function to handle file encryption
def encrypt_file(input_file, flag):
    key = get_random_bytes(BLOCK_SIZE)
    iv = get_random_bytes(BLOCK_SIZE)
    header, data = read_bmp(input_file)

    padded_data = pad(data)
    # print(padded_data)

    # set the output filenames
    new_file_name, ext = os.path.splitext(input_file)
    output_file_ecb = new_file_name + "_ecb" + ext
    output_file_cbc =  new_file_name + "_cbc" + ext

    if flag == "BOTH":
        # ECB Mode
        encrypted_data_ecb = encrypt_ecb(padded_data, key)
        write_bmp(output_file_ecb, header, encrypted_data_ecb) 
        # CBC Mode
        encrypted_data_cbc = encrypt_cbc(padded_data, key, iv)
        write_bmp(output_file_cbc, header, encrypted_data_cbc)
    elif flag == "ECB":
        # ECB Mode
        encrypted_data_ecb = encrypt_ecb(padded_data, key)
        write_bmp(output_file_ecb, header, encrypted_data_ecb)
    elif flag == "CBC":
        # CBC Mode
        encrypted_data_cbc = encrypt_cbc(padded_data, key, iv)
        write_bmp(output_file_cbc, header, encrypted_data_cbc)
    else:
        # shouldn't get here
        print(f"invalid flag got {flag}")

def main():

    parser = argparse.ArgumentParser(description="Block Cipher")
    parser.add_argument("inputfile", type=str, default="./BlockCipher/cp-logo.bmp", help="Input file")
    parser.add_argument("mode", type=str, choices=["ECB", "CBC","BOTH"], default="CBC", help="Block Cipher Mode")

    args = parser.parse_args()
    mode = args.mode
    input_file = args.inputfile

    # Task 1
    encrypt_file(input_file,mode)

if __name__ == "__main__":
    main()
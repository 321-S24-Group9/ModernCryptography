from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import argparse
from urllib.parse import quote, unquote
import re
import matplotlib.pyplot as plt


BLOCK_SIZE = 16
BMP_HEADER = 54

## TASK 1
 
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

    padded_data = pad(data, BLOCK_SIZE)
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

## Task 2

def url_encode(input):
    # Define the characters to be encoded
    special_chars = ";="
    # Encode only the special characters in the input string
    encoded_string = ''.join(quote(char) if char in special_chars else char for char in input)
    return encoded_string

def url_decode(input_string):
    # Decode any percent-encoded characters in the input string
    decoded_string = unquote(input_string)
    return decoded_string

def submit(input,key,iv):
    prepend = "userid=456;userdata="
    postpend = ";session-id=31337"
    plaintext = pad((url_encode(prepend + input + postpend)).encode('utf-8'),BLOCK_SIZE)
    return  encrypt_cbc(plaintext,key,iv)

def modify_ciphertext(ciphertext, input, target_payload):
    pos = len(url_encode("userid=456;userdata="))
    offset = BLOCK_SIZE - pos % BLOCK_SIZE
    block_position = BLOCK_SIZE
    # XOR the target payload with the corresponding bytes in the ciphertext
    modified_ciphertext = bytearray(ciphertext)
    for i in range(len(target_payload)):
        modified_ciphertext[block_position + i] ^= ord(input[offset + i]) ^ ord(target_payload[i])
    return bytes(modified_ciphertext)


def verify(input, key, iv):
    # Decrypt the ciphertext using AES-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(input), BLOCK_SIZE)   
    # Check if the decrypted string contains the pattern ";admin=true;"
    return b";admin=true;" in decrypted

## Task 3

def parse_rsa(output):
    # used Chat-gpt to generate a reg-ex to search through file format
    rsa_pattern = r"rsa\s+(\d+)\s+bits\s+([\d\.]+)s\s+([\d\.]+)s\s+([\d\.]+)\s+([\d\.]+)"
    rsa_results = re.findall(rsa_pattern, output)
    
    rsa_throughput = {}
    for bits, sign_time, verify_time, sign_per_sec, verify_per_sec in rsa_results:
        rsa_throughput[int(bits)] = {
            'sign_time': float(sign_time),
            'verify_time': float(verify_time),
            'sign_per_sec': float(sign_per_sec),
            'verify_per_sec': float(verify_per_sec)
        }
    
    return rsa_throughput

def parse_aes(output):
    # used Chat-gpt to generate a reg-ex to search through file format
    aes_pattern = r"aes-(\d+)-cbc\s+([\d\.]+)k\s+([\d\.]+)k\s+([\d\.]+)k\s+([\d\.]+)k\s+([\d\.]+)k\s+([\d\.]+)k"
    aes_results = re.findall(aes_pattern, output)
    
    aes_throughput = {}
    block_sizes = [16, 64, 256, 1024, 8192, 16384]
    
    for bits, *throughput in aes_results:
        aes_throughput[int(bits)] = {size: float(tp) * 1000 for size, tp in zip(block_sizes, throughput)}
    
    return aes_throughput

def plot_rsa_throughput(rsa_throughput):
    bits = sorted(rsa_throughput.keys())
    sign_per_sec = [rsa_throughput[bit]['sign_per_sec'] for bit in bits]
    verify_per_sec = [rsa_throughput[bit]['verify_per_sec'] for bit in bits]
    
    plt.figure(figsize=(10, 6))
    plt.plot(bits, sign_per_sec, label='Sign Ops per Second', marker='o')
    plt.plot(bits, verify_per_sec, label='Verify Ops per Second', marker='o')
    plt.xlabel('RSA Key Size (bits)')
    plt.ylabel('Operations per Second')
    plt.title('RSA Key Size vs Throughput')
    plt.legend()
    plt.grid(True)
    plt.savefig("./BlockCipher/rsa_plot")
    plt.show()

def plot_aes_throughput(aes_throughput):
    block_sizes = [16, 64, 256, 1024, 8192, 16384]
    
    plt.figure(figsize=(10, 6))
    for key_size in sorted(aes_throughput.keys()):
        throughput = [aes_throughput[key_size][size] for size in block_sizes]
        plt.plot(block_sizes, throughput, label=f'AES-{key_size}-CBC', marker='o')
    
    plt.xlabel('Block Size (bytes)')
    plt.ylabel('Throughput (Bytes per Second)')
    plt.title('AES Block Size vs Throughput')
    plt.legend()
    plt.grid(True)
    plt.savefig("./BlockCipher/aes_plot")
    plt.show()

def task1():
    # Task 1
    parser = argparse.ArgumentParser(description="Block Cipher")
    parser.add_argument("inputfile", type=str, default="./BlockCipher/cp-logo.bmp", help="Input file")
    parser.add_argument("mode", type=str, choices=["ECB", "CBC","BOTH"], default="CBC", help="Block Cipher Mode")

    args = parser.parse_args()
    mode = args.mode
    input_file = args.inputfile

    encrypt_file(input_file,mode)

def task2():
    # Task 2
    key = get_random_bytes(BLOCK_SIZE)
    iv = get_random_bytes(BLOCK_SIZE)
    input = "You're the man now, dog"
    # input = "BBBBBBAadminAtrueA"
    ciphertext = submit(input,key,iv)
    new_ciphertext = modify_ciphertext(ciphertext,input,";admin=true;")
    print(f"input : {input}")
    print(f"ciphertext : {ciphertext}")
    print(f"new ciphertext : {new_ciphertext}")
    
    print(f"verify ciphertext: {verify(ciphertext,key,iv)}")
    print(f"verify new ciphertext: {verify(new_ciphertext,key,iv)}")

def task3():
    with open('./BlockCipher/rsa.txt','r') as file:
        rsa_output = file.read()
    print(rsa_output)
    rsa_throughput = parse_rsa(rsa_output)

    with open('./BlockCipher/aes.txt','r') as file:
        aes_output = file.read()
    print(aes_output)
    aes_throughput = parse_aes(aes_output)
    
    plot_rsa_throughput(rsa_throughput)
    plot_aes_throughput(aes_throughput)
    return

def main():
    # task1()
    task2()
    # task3()
   
if __name__ == "__main__":
    main()
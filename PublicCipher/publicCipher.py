# implement Diffie-Hellman 
import random
from sympy import *
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import binascii

class Person:
    def __init__(self,name):
        self.name = name
        self.key = None
        self.mailbox = []

    def encrypt_message(self,message):
        if self.key is not None:
            msg = pad(message.encode('utf-8'),16)   #encode the string message into bytes
            cipher = AES.new(self.key, AES.MODE_CBC, self.key)
            return cipher.encrypt(msg)

    def decrypt_message(self,message):
        if self.key is not None:
            cipher = AES.new(self.key, AES.MODE_CBC, self.key)
            return unpad(cipher.decrypt(message),16).decode('utf-8')

    def read_mailbox(self, length=1):
        if len(self.mailbox) >= length:
            mailbox = self.mailbox[:length]
            self.mailbox = []
            return mailbox
        else:
            print("Error: not enough messages to read")

    # used by intercept to change/view mailbox contents
    def update_letter(self, index, new_letter):
        if len(self.mailbox) > index and index >= 0:
            if new_letter == None:
                return self.mailbox[index]
            else:
                letter = self.mailbox[index]
                self.mailbox[index] = new_letter 
                return letter
        
    def get_mailbox_length(self):
        return len(self.mailbox)

    def set_key(self,key):
        self.key = key

    def decrypt_mailbox(self):
        if self.key is not None:
            cipher = AES.new(self.key, AES.MODE_CBC, self.key)
            #decrypts, unpads, and then decodes from byte to string
            self.mailbox = [self.decrypt_message(mail) for mail in self.mailbox]
        else:
            print("Error: No key")

    def update_mailbox(self,new_message):
        self.mailbox.append(new_message)

    def send(self,other,message):
        other.update_mailbox(message)

    def intercept(self,other,index,message=None):
        if index==-1:
            index = other.get_mailbox_length()-1
        return other.update_letter(index,message)

## TASK 1

def random_prime():
    primes = [i for i in range(1,1000) if isprime(i)]
    return random.choice(primes)

def step(p,g,c):
    return pow(g,c,p)

def DH(Alice_p,Alice_g):
    # emulates a Diffie-Hellman algorithm
    Alice = Person("Alice")
    Bob = Person("Bob")

    # right now only Alice knows p and g
    # p and g to Bob
    Alice.send(Bob,Alice_p)
    Alice.send(Bob,Alice_g)

    Bob_p,Bob_g = Bob.read_mailbox(2)
    
    a = random_prime()              #Alice's random prime number
    A = step(Alice_p,Alice_g,a)     #Alice's message to send to Bob

    b = random_prime()              #Bob's random prime number
    B = step(Bob_p,Bob_g,b)         #Bob's message to send to Alice

    # send the message
    Alice.send(Bob,A)
    Bob.send(Alice,B)

    # read sent messages
    Alice_B = Alice.read_mailbox(1)[0]
    Bob_A = Bob.read_mailbox(1)[0]

    # validate calculations
    A_key = step(Alice_p,Alice_B,a)
    B_key = step(Bob_p,Bob_A,b)
    if A_key != B_key:
        print("something went wrong with calcs")
        return

    # set up Alice's key
    k_Alice = SHA256.new()
    A_key = A_key.to_bytes((A_key.bit_length() + 7) // 8, byteorder='big')
    k_Alice.update(bytes(A_key))
    Alice.set_key(k_Alice.digest()[:16])
    
    # set up Bob's key
    k_Bob = SHA256.new()
    B_key = B_key.to_bytes((B_key.bit_length() + 7) // 8, byteorder='big')
    k_Bob.update(bytes(B_key))
    Bob.set_key(k_Bob.digest()[:16])

    # secret messages to send
    Alice_message = "Hi Bob!"
    Bob_message = "Hi Alice!"

    # encrypt and send messages
    Alice.send(Bob,Alice.encrypt_message(Alice_message))
    Bob.send(Alice,Bob.encrypt_message(Bob_message))

    #decrypt received messages
    Alice.decrypt_mailbox()
    Bob.decrypt_mailbox()

    #read the decrypted mailbox
    print(Alice.read_mailbox()[0])
    print(Bob.read_mailbox()[0])

## TASK 2


def MITM(Alice_p,Alice_g, it, iv):
    # emulates a Mallory in the Middle attack


    Alice = Person("Alice")
    Bob = Person("Bob")
    Mallory = Person("Mallory")

    it_options = ["g","AB"]
    if it not in it_options:
        print("Error: invalid intercept type")
        return
    iv_options = ["1","p","p-1"]
    if iv not in iv_options:
        print("Error: invalid intercept value")
        return
   

    # right now only Alice knows p and g
    # p and g to Bob
    Alice.send(Bob,Alice_p)
    Alice.send(Bob,Alice_g)
    
    
    Mal_p = Mallory.intercept(Bob,0) 
    if iv == "1":
        iv = 1
    elif iv == "p":
        iv = Mal_p
    elif iv == "p-1":
        iv = Mal_p-1
    if it == "g":
        # Mallory modifies g
        Mal_g = Mallory.intercept(Bob,1, iv)
    else:
        # Mallory just views g
        Mal_g = Mallory.intercept(Bob,1)

    Bob_p,Bob_g = Bob.read_mailbox(2)
    
    a = random_prime()              #Alice's random prime number
    A = step(Alice_p,Alice_g,a)     #Alice's message to send to Bob

    b = random_prime()              #Bob's random prime number
    B = step(Bob_p,Bob_g,b)         #Bob's message to send to Alice

    # send the message
    Alice.send(Bob,A)
    Bob.send(Alice,B)

    # although Mallory should intercept before it reaches mailbox
    # we will simulate intercept as grabbing from the mailbox and modifying
    # changes the A- and B to given iv value and also reveals what A and B was supposed to be
    Mal_B = Mallory.intercept(Alice,-1,iv)
    Mal_A = Mallory.intercept(Bob,-1,iv)

    # read sent messages (they will be incorrect)
    Alice_B = Alice.read_mailbox(1)[0]
    Bob_A = Bob.read_mailbox(1)[0]

    # validate calculations
    A_key = step(Alice_p,Alice_B,a)
    B_key = step(Bob_p,Bob_A,b)

    if A_key != B_key:
        print("something went wrong with calcs")
        return

    # set up Alice's key
    k_Alice = SHA256.new()
    A_key = A_key.to_bytes((A_key.bit_length() + 7) // 8, byteorder='big')
    k_Alice.update(bytes(A_key))
    Alice.set_key(k_Alice.digest()[:16])
    
    # set up Bob's key
    k_Bob = SHA256.new()
    B_key = B_key.to_bytes((B_key.bit_length() + 7) // 8, byteorder='big')
    k_Bob.update(bytes(B_key))
    Bob.set_key(k_Bob.digest()[:16])

    # secret messages to send
    Alice_message = "Hi Bob!"
    Bob_message = "Hi Alice!"

    Alice_encrypted_message = Alice.encrypt_message(Alice_message)
    Bob_encrypted_message = Bob.encrypt_message(Bob_message)

    # encrypt and send messages
    Alice.send(Bob,Alice_encrypted_message)
    Bob.send(Alice,Bob_encrypted_message)

    # intercept the encrypted messages
    Mal_C0 = Mallory.intercept(Bob,-1)
    Mal_C1 = Mallory.intercept(Alice,-1)

    # now we have enough information to decrypt c0 and c1
    if iv == Mal_p:
        key = 0
    else:
        key = iv
    k_Mal = SHA256.new()
    Mal_key = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    k_Mal.update(bytes(Mal_key))
    Mallory.set_key(k_Mal.digest()[:16])
    

    # uncomment below if you want to compare values obtained by each person
    # print(f"Alice_g: {Alice_g}")
    # print(f"Bob_g: {Bob_g}")
    # print(f"Mal_g: {Mal_g}")

    # print(f"Alice_p: {Alice_p}")
    # print(f"Bob_p: {Bob_p}")
    # print(f"Mal_p: {Mal_p}")

    # print(f"Alice_B: {Alice_B}")
    # print(f"Mal_B: {Mal_B}")

    # print(f"Bob_A: {Bob_A}")
    # print(f"Mal_A: {Mal_A}")

    # print(f"Alice_key: {A_key}")
    # print(f"Bob_key: {B_key}")

    # print(f"Alice_enc_mess: {Alice_encrypted_message}")
    # print(f"Mal_C0: {Mal_C0}")

    # print(f"Bob_enc_mess: {Bob_encrypted_message}")
    # print(f"Mal_C1: {Mal_C1}")

    print("Intercepted Message to Bob: ")
    print(Mallory.decrypt_message(Mal_C0))
    print("Intercepted Message to Alice: ")
    print(Mallory.decrypt_message(Mal_C1))


# Task 1
def task1():
    p = """B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
        DF1FB2BC 2E4A4371"""
    g = """A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
        855E6EEB 22B3B2E5"""
    p = int(p.replace(" ","").replace("\n",""),16)
    g = int(g.replace(" ","").replace("\n",""),16)
    DH(p,g)

# Task 2
def task2():
    p,g = 37,5
    # choose what to modify
    # options : "g", "AB" 
    intercept_type = "AB"
    # choose what to change too
    # options : "1", "p", "p-1"
    intercept_value = "1"
    
    MITM(p,g, intercept_type,intercept_value)
    
# Task 3

def euclids_algo(a, b):
    # finds gcd(a,b) and a linear combo of a and b
    # ax + by = gcd(a,b)
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = euclids_algo(b % a, a)
        return (g, x - (b // a) * y, y)

def multiplicative_inverse(e, phi):
    # d*e =& 1 (mod phi)
    # e*x + phi*y =& 1 (mod phi)  
    # d = x % phi
    # use extended euclids algorithm to find gcd, x, y
    g, x, y = euclids_algo(e, phi)
    # if g is not 1, then we aren't dealing with relatively prime values
    if g != 1:
        print("Error : no modular inverse")
    else:
        return x % phi

def generate_symm_keys():
    # public key = (n,e) where n=p*q
    # private key = (n,d) where d*e =& 1 mod(phi(n))

    bits = 2048
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def rsa_encrypt(message,e,n):
    # convert to hex string and then int
    num_message = int(binascii.hexlify(message.encode()).decode(),16)
    # rsa encrypt
    return pow(num_message,e,n)

def rsa_decrypt(message,d,n):
    # rsa decrypt
    num_message = pow(message,d,n)
    # convert to hex string and then string
    hex_string = hex(num_message)[2:]
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    return binascii.unhexlify(hex_string).decode('utf-8')

def rsa_malleability():
    # generate RSA keys
    (Alice_e,Alice_n), (Alice_d,Alice_n) = generate_symm_keys()

    Alice = Person("Alice")
    Bob = Person("Bob")
    Mallory = Person("Mallory")

    # send public key
    Alice.send(Bob,Alice_n)
    Alice.send(Bob,Alice_e)

    # Mal view public key
    Mal_n = Mallory.intercept(Bob,0)
    Mal_e = Mallory.intercept(Bob,1)

    # Bob receives public key
    Bob_n, Bob_e = Bob.read_mailbox(2)

    # Bob chooses a random number
    Bob_s = random.randint(1, Bob_n)
    # computes c using Alice's public key
    Bob_c = pow(Bob_s,Bob_e,Bob_n)

    # send c to Alice
    Bob.send(Alice,Bob_c)

    # Mallory intercepts and changes the value to n
    Mal_c = Mallory.intercept(Alice,-1)
    new_c = Mal_n
    Mallory.intercept(Alice,-1,new_c)

    # Alice recieves 0 as a plaintext and generates AES key
    Alice_c = Alice.read_mailbox()[0]
    Alice_s = pow(Alice_c,Alice_d,Alice_n)

    # set up Alice's key
    k_Alice = SHA256.new()
    A_key = Alice_s.to_bytes((Alice_s.bit_length() + 7) // 8, byteorder='big')
    k_Alice.update(bytes(A_key))
    Alice.set_key(k_Alice.digest()[:16])

    # secret message that Alice wants to send Bob
    Alice_message = "Hi Bob!"
    Alice_encrypted_message = Alice.encrypt_message(Alice_message)

    # send the encrypted message to Bob
    Alice.send(Bob,Alice_encrypted_message)

    # Mallory views the message
    Mal_C0 = Mallory.intercept(Bob,-1)

    # since we changed the value of c to n, 
    # that makes Alice's s value 0 --> the key is 0
    key = 0
    k_Mal = SHA256.new()
    Mal_key = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    k_Mal.update(bytes(Mal_key))
    Mallory.set_key(k_Mal.digest()[:16])

    # prints the secret message
    print(Mallory.decrypt_message(Mal_C0))

    # lets do more damage by sending a message
    # from Mallory as Bob
    Mal_message = "Alice I don't love you anymore - Bob"
    Mal_message_encypted = Mallory.encrypt_message(Mal_message)
    Mallory.send(Alice,Mal_message_encypted)

    # now lets decrypt our mailbox and read the message
    Alice.decrypt_mailbox()
    print(Alice.read_mailbox()[0])


def rsa_signature():
    # generate RSA keys
    (Alice_e,Alice_n), (Alice_d,Alice_n) = generate_symm_keys()

    Alice = Person("Alice")
    Bob = Person("Bob")
    Mallory = Person("Mallory")

    # send public key
    Alice.send(Bob,Alice_n)
    Alice.send(Bob,Alice_e)

    # Mal view public key
    Mal_n = Mallory.intercept(Bob,0)
    Mal_e = Mallory.intercept(Bob,1)

    # Bob receives public key
    Bob_n, Bob_e = Bob.read_mailbox(2)

    # Bob chooses a random number
    Bob_s = random.randint(1, Bob_n)
    # computes c using Alice's public key
    Bob_c = pow(Bob_s,Bob_e,Bob_n)

    # send c to Alice
    Bob.send(Alice,Bob_c)

    # generate the key
    Alice_c = Alice.read_mailbox()[0]
    Alice_s = pow(Alice_c,Alice_d,Alice_n)

    # set up Alice's key
    k_Alice = SHA256.new()
    A_key = Alice_s.to_bytes((Alice_s.bit_length() + 7) // 8, byteorder='big')
    k_Alice.update(bytes(A_key))
    Alice.set_key(k_Alice.digest()[:16])

    # secret message that Alice wants to send Bob
    Alice_m1 = "Hi Bob!"
    Alice_s1 = rsa_encrypt(Alice_m1,Alice_d,Alice_n)

    # send the signature to Bob
    Alice.send(Bob,Alice_s1)

    Alice_m2 = "What's up dog!"
    Alice_s2 = rsa_encrypt(Alice_m2,Alice_d,Alice_n)   
    Alice.send(Bob,Alice_s2)  

    # Mallory views the signatures
    Mal_sig1 = Mallory.intercept(Bob,0)
    Mal_sig2 = Mallory.intercept(Bob,1)

    m1, m2 = Bob.read_mailbox(2)
    m1 = rsa_decrypt(m1,Alice_e, Alice_n)
    m2 = rsa_decrypt(m2,Alice_e, Alice_n)
    print(m1)
    print(m2)

    # draft a new signature to trick Bob
    Mal_sig3 = (Mal_sig1 * Mal_sig2) % Mal_n
    print(Mal_sig3)
    Mallory.send(Bob,Mal_sig3)

    m3 = Bob.read_mailbox()[0]
    m3 = rsa_decrypt(m3,Alice_e,Alice_n)
    print(m3)

    

   

def task3():
    public_key, private_key = generate_symm_keys()

    # to test lets encrypt and decrypt a message
    message = "Alice loves Bob!"
    encrypted = rsa_encrypt(message,public_key[0],public_key[1])
    decrypted = rsa_decrypt(encrypted,private_key[0],private_key[1])
    if message != decrypted:
        print("Error: rsa encryption didn't work")
        return 
    # shows how MIMT can get secret message
    # another way to cause chaos
    # use the key to send a message to Alice
    # we can see that Alice recieves a message from Mallary
    # thinking it was from Bob
    rsa_malleability()

    # lastly, suppose Mallory sees two signatures from Alice
    # still need to implement
    rsa_signature()

    
    
    


def main():
    # task1()
    # task2()
    task3()

if __name__ == "__main__":
    main()



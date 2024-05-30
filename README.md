# ModernCryptography

## Block Ciphers

### Task 1

Implement Block Cipher CBC and EBC modes
Relevant Files: /BlockCipher/cp-logo.bmp, /BlockCipher/mustang.bmp
Created Files: /BlockCipher/cp-logo_ebc.bmp, /BlockCipher/cp-logo_cbc.bmp, /BlockCipher/mustang.ecb.bmp, /BlockCipher/mustang_cbc.bmp
Running Instructions: Uncomment task1() in main() in blockCipher.py
example run:
'''
py blockCipher.py [filename] [{CBC,ECB,BOTH}]
'''
^^ If file can't be found double check the path

### Task 2

Simulate CBC security for user input, create a payload that has ";admin=true;"
Relevant Files: None
Created Files: None
Running Instructions: Uncomment task1() in main() in blockCipher.py
^^ In task2() you can change the input variable to change input

\*\*\* For bit manipulation, we have a buffer from input so that the pretext + buffer is aligned.
Then, use block2[CIPHERTEXT][i] = block2[CIPHERTEXT][i] XOR ord([INPUT][i]) XOR([PAYLOAD][i])

### Task 3

Stat the RSA/AES with different key sizes using openssl, then plot using matlibplot
Relevant Files: script.sh(script to execute openssl on shell), rsa.txt, aes.txt
Created Files: aes_plot.png, rsa_plot.png
Running Instructions: Uncomment task1() in main() in blockCipher.py
^^ If file can't be found double check the path

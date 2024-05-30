#!/bin/sh
openssl speed rsa512 rsa1024 rsa2048 rsa4096 > ./BlockCipher/rsa.txt
openssl speed aes-128-cbc aes-192-cbc aes-256-cbc > ./BlockCipher/aes.txt
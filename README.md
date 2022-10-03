# b3DS
A 3DS/New 3DS Rom Decryptor and Encrypter


Refactored for python3 and tidied, based on the wonderful efforts of jagiella and the author b1k. For reduction of repeated code, decrypt and encrypt functions have been merged into one function which takes a parameter of cmd which can be either 'encrypt' or 'decrypt'.

## Please feel free to further improve this code.

## Prerequisites
* Python 3
* pip
* pycryptodome

## Installation
run `pip install pycrypto` in command prompt.

## Usage
python b3DS.py "File location of rom" eg. C:\Users\User\Downloads\New Super Mario Bros. 2 (USA).3ds
I recommend to chmod +x this file, remove the extension, and place it in your path, so it can be used in any directory on your system.

## Status
Supports all known crypto-types:

* Normal (Key 0x2C)
* 7.x (Key 0x25)
* New3DS 9.3 (Key 0x18)
* New3DS 9.6 (Key 0x1B)

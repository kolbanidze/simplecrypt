#!/usr/bin/python3
# SimpleCrypt: decrypt

from argon2.low_level import hash_secret_raw, Type
from Crypto.Cipher import AES
from getpass import getpass
from gc import collect as garbage_collect
from argparse import ArgumentParser, BooleanOptionalAction
from os.path import isfile, join, dirname, getsize, basename
from os import remove, rename, fsync
from secrets import choice, token_bytes

DEFAULT_FILE_EXTENSION = '.sc'

# Parsing command line arguments.
parser = ArgumentParser(prog="DecryptIt", description="Simple decryption tool. KDF: Argon2. Symmetric cipher: AES-GCM")
parser.add_argument('-o', '--output', help="output file")
parser.add_argument('-P', '--password', help="password")
parser.add_argument('-d', '--delete', help="delete original (unencrypted) file without overwriting (not secure)", action=BooleanOptionalAction)
parser.add_argument('-x', '--secure-delete', help="delete original (unencrypted) file with US DoD 5220.22-M 3 pass", action=BooleanOptionalAction)
parser.add_argument('-f', '--overwrite-file', help="when you try to decrypt 'test.enc' but directory contains 'test' that parameter will allow overwriting 'test'", action=BooleanOptionalAction)
parser.add_argument("file", help="file to decrypt")
args = parser.parse_args()

# Checking file existence.
if not isfile(args.file):
    print(f"File {args.file} not found.")
    exit(1)

# If the user has not selected a file output and the file has a standard extension (.sc), the program will use a file without an extension (.sc) as output.
# If the file does not have a standard extension, the program will require you to specify the file output.
if not args.output:
    extension = args.file[-len(DEFAULT_FILE_EXTENSION):]
    if extension == DEFAULT_FILE_EXTENSION:
        args.output = args.file[:-len(DEFAULT_FILE_EXTENSION)]
    else:
        print(f"File doesn't have {DEFAULT_FILE_EXTENSION} extension. Please specify output file!")
        exit(1)

# Checking output file existence.
if isfile(args.output) and not args.overwrite_file:
    print(f"File {args.output} already exists. Use --overwrite-file (-f) to overwrite")
    exit(1)

if args.delete and args.secure_delete:
    print("You have selected both delete and securely delete. The program will assume that original encrypted file needs to be securely deleted.")
    args.delete = False

# Getting password without echoing it.
if not args.password:
    args.password = getpass("Enter password (no echo): ")

# Opening file and saving file contents to memory.
with open(args.file, "rb") as file:
    contents = file.read()

# Encrypted file format:
# Time cost (4 byte length), Memory cost (4 byte length), Parallelism (4 byte length), 
# Salt size (4 byte length), Key size (4 byte length), Tag (16 bytes), Nonce (16 bytes), Salt, Ciphertext.

# Parsing encrypted file header and ciphertext.
time_cost = int.from_bytes(contents[:4], byteorder='little')
memory_cost = int.from_bytes(contents[4:8], byteorder='little')
parallelism = int.from_bytes(contents[8:12], byteorder='little')
salt_size = int.from_bytes(contents[12:16], byteorder='little')
key_size = int.from_bytes(contents[16:20], byteorder='little')
tag = contents[20:36]
nonce = contents[36:52]
salt = contents[52:52+salt_size]
ciphertext = contents[52+salt_size:]

# Generating decryption key using Argon2 ID.
key = hash_secret_raw(args.password.encode(), salt, time_cost, memory_cost, parallelism, key_size, Type.ID)

# Decrypting plaintext.
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
except ValueError:
    print(f"An error occured while decrypting '{args.output}'. Check your password and '{args.output}' integrity.")
    exit(1)

# Writing plaintext to output file.
with open(args.output, "wb") as file:
    file.write(plaintext)

print(f"[Success] File '{args.file}' was decrypted. Output file: '{args.output}'.")

if args.delete:
    remove(args.file)
    print(f"Original '{file.file}' was deleted without overwriting.")

if args.secure_delete:
    file_size = getsize(args.file)
    filename_size = len(basename(args.file))
    # Erasing file contents
    with open(args.file, "r+b") as file:
        # First pass with zeroes
        file.write(b"\x00"*file_size)
        # Ensure the data is written to disk
        file.flush()
        fsync(file.fileno())
        file.seek(0)
        
        # Second pass with ones
        file.write(b"\xFF"*file_size)
        # Ensure the data is written to disk
        file.flush()
        fsync(file.fileno())
        file.seek(0)

        # Third pass with random data
        file.write(token_bytes(file_size))
        # Ensure the data is written to disk
        file.flush()
        fsync(file.fileno())
        file.seek(0)

    # Erasing file name
    for i in range(filename_size, 0, -1):
        # Creating new file name
        new_name = ''.join([choice("01234567890QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm") for i in range(i)])

        # Renaming file
        new_path = join(dirname(args.file), new_name)
        rename(args.file, new_path)

        args.file = new_path
    remove(args.file)

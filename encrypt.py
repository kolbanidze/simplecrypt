#!/usr/bin/python3
# SimpleCrypt: encrypt

from argon2.low_level import hash_secret_raw, Type
from secrets import token_bytes, choice
from Crypto.Cipher import AES
from getpass import getpass
from os.path import isfile, getsize, basename, join, dirname
from os import remove, fsync, rename
from gc import collect as garbage_collect
from argparse import ArgumentParser, BooleanOptionalAction

DEFAULT_TIME_COST = 2
# Memory cost in KiB
DEFAULT_MEMORY_COST = 19456
DEFAULT_PARALLELISM = 1
# Salt size in bytes
DEFAULT_SALT_SIZE = 16
# Key size in bytes
DEFAULT_KEY_SIZE = 32
# File extension: decrypt it
DEFAULT_FILE_EXTENSION = '.sc'

# NOTE. After encrypting file with default parameters file will be 68 bytes larger.

# Parsing command line arguments.
parser = ArgumentParser(prog="EncryptIt", description="Simple encryption tool. KDF: Argon2. Symmetric cipher: AES-GCM")
parser.add_argument('-t', '--time-cost', help="argon2 time cost. Default: 2", default=DEFAULT_TIME_COST, type=int)
parser.add_argument('-m', '--memory-cost', help="argon2 memory cost (in KiB). Default: 19 MiB = 19456 KiB", default=DEFAULT_MEMORY_COST, type=int)
parser.add_argument('-p', '--parallelism', help="argon2 parallelism. Default 1", default=DEFAULT_PARALLELISM, type=int)
parser.add_argument('-s', '--salt-size', help="argon2 salt size. Default 16 bytes", type=int, default=DEFAULT_SALT_SIZE)
parser.add_argument('-k', '--key-size', help="argon2 key size. Default 32 bytes", type=int, default=DEFAULT_KEY_SIZE)
parser.add_argument('-P', '--password', help="password")
parser.add_argument('-o', '--output', help="output file")
parser.add_argument('-d', '--delete', help="delete original (unencrypted) file without overwriting (not secure)", action=BooleanOptionalAction)
parser.add_argument('-x', '--secure-delete', help="delete original (unencrypted) file with US DoD 5220.22-M 3 pass", action=BooleanOptionalAction)
parser.add_argument('-f', '--overwrite-file', help="when you try to encrypt 'test' but directory contains 'test.enc' that parameter will allow overwriting 'test.enc'", action=BooleanOptionalAction)
parser.add_argument('--i-know-what-i-am-doing', help="use KDF parameters values less than recommended", action=BooleanOptionalAction)
parser.add_argument('file', help="file to encrypt")
args = parser.parse_args()

# Check that the user has selected Argon2 parameters lower than the OWASP recommendations.
if (args.time_cost < DEFAULT_TIME_COST or args.memory_cost < DEFAULT_MEMORY_COST or args.parallelism < DEFAULT_PARALLELISM or args.salt_size < DEFAULT_SALT_SIZE) and not args.i_know_what_i_am_doing:
    print("Warning! Your KDF parameters values are less than recommended.")
    print("To proceed use --i-know-what-i-am-doing")
    exit(1)

# Check that key length is 16, 24 or 32. 
if args.key_size not in (16, 24, 32):
    print("Key length must be 16, 24 or 32 bytes!")
    exit(1)

# Checking parameters for Argon2.
if args.time_cost < 1 or args.time_cost > 2**32-1:
    print("Argon2 time cost must be between 1 and 2^32-1!")
    exit(1)
if args.memory_cost < 8 or args.memory_cost > 2**32-1:
    print("Argon2 memory cost must be between 8 KiB and 2^32-1 KiB!")
    exit(1)
if args.parallelism < 1 or args.parallelism > 2**24-1:
    print("Argon2 parallelism must be between 1 and 2^24-1")
    exit(1)
if args.salt_size < 8 or args.salt_size > 2**32-1:
    print("Argon2 salt size must be between 1 and 2^32-1")
    exit(1)
if args.key_size < 4 or args.key_size > 2**32-1:
    print("Argon2 key size must be between 1 and 2^32-1")
    exit(1)

# Checking file existence
if not isfile(args.file):
    print(f"File {args.file} not found.")
    exit(1)

# Checking if both -d -x were used
if args.delete and args.secure_delete:
    print("You have selected both delete and securely delete. The program will assume that original file needs to be securely deleted.")
    args.delete = False

# If user hasn't specified output file it will save encrypted file in {filename}.sc (if DEFAULT_FILE_EXTENSION is .sc).
if not args.output:
    args.output = args.file + DEFAULT_FILE_EXTENSION

# Check for output file existence.
if isfile(args.output) and not args.overwrite_file:
    print(f"File {args.output} already exists. Use --overwrite-file (-f) to overwrite")
    exit(1)

# Getting password without echoing it.
if not args.password:
    args.password = getpass("Enter password (no echo): ")

# Checking password length for Argon2.
if len(args.password) > 2**32-1:
    print("Argon2 password length must be below 2^32-1")
    exit(1)

# Generating salt.
salt = token_bytes(args.salt_size)

# Generating encryption key using Argon2 ID.
key = hash_secret_raw(args.password.encode(), salt, args.time_cost, args.memory_cost, args.parallelism, args.key_size, type=Type.ID)

# Removing secrets from memory. This is not the safest way to delete a key from memory.
del args.password
garbage_collect()

# Opening file and saving file contents to memory.
with open(args.file, "rb") as file:
    contents = file.read()

# Encrypting file and generating tag & nonce
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(contents)
nonce = cipher.nonce

# Removing secrets from memory. This is not the safest way to delete a key from memory.
del key, cipher, contents
garbage_collect()

# File format:
# Time cost (4 byte length), Memory cost (4 byte length), Parallelism (4 byte length), 
# Salt size (4 byte length), Key size (4 byte length), Tag (16 bytes), Nonce (16 bytes), Salt, Ciphertext

# Writing to output file
with open(args.output, "wb") as file:
    time_cost = args.time_cost.to_bytes(4, byteorder='little')
    memory_cost = args.memory_cost.to_bytes(4, byteorder='little')
    parallelism = args.parallelism.to_bytes(4, byteorder='little')
    salt_size = args.salt_size.to_bytes(4, byteorder='little')
    key_size = args.key_size.to_bytes(4, byteorder='little')
    file.write(time_cost + memory_cost + parallelism + salt_size + key_size + tag + nonce + salt + ciphertext)

print(f"[Success] File '{args.file}' was encrypted. Output file: '{args.output}'.")

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

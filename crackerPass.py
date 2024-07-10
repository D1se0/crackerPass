#!/bin/python3

import hashlib
import argparse
import os
import signal
import sys
from termcolor import colored
from passlib.hash import bcrypt, sha512_crypt, sha256_crypt, sha1_crypt, md5_crypt
from argon2 import PasswordHasher
from hashid import HashID

# Logo de la herramienta
logo = """
  ____               _             ____                 
 / ___| ___ _ __ ___(_)_ __   __ _|  _ \ __ _ _ __ ___  
| |  _ / _ \ '__/ __| | '_ \ / _` | |_) / _` | '_ ` _ \ 
| |_| |  __/ |  \__ \ | | | | (_| |  __/ (_| | | | | | |
 \____|\___|_|  |___/_|_| |_|\__, |_|   \__,_|_| |_| |_|
                              |___/                    
		
		crackerPass v1.0
		By Diseo (@d1se0)
"""

# Diccionario para los formatos de hashes compatibles
hash_functions = {
    'md5': 'md5',
    'sha1': 'sha1',
    'sha224': 'sha224',
    'sha256': 'sha256',
    'sha384': 'sha384',
    'sha512': 'sha512',
    'sha3_256': 'sha3_256',
    'sha3_512': 'sha3_512',
    'bcrypt': 'bcrypt',
    'sha512crypt': 'sha512_crypt',
    'sha256crypt': 'sha256_crypt',
    'sha1crypt': 'sha1_crypt',
    'md5crypt': 'md5_crypt',
    'argon2': 'argon2'
}

# Función para obtener el hash de una contraseña en un formato específico
def get_hash(password, hash_type):
    if hash_type in hashlib.algorithms_available:
        hash_obj = hashlib.new(hash_type)
        hash_obj.update(password.encode('utf-8'))
        return hash_obj.hexdigest()
    elif hash_type == 'bcrypt':
        return bcrypt.hash(password)
    elif hash_type == 'sha512_crypt':
        return sha512_crypt.hash(password)
    elif hash_type == 'sha256_crypt':
        return sha256_crypt.hash(password)
    elif hash_type == 'sha1_crypt':
        return sha1_crypt.hash(password)
    elif hash_type == 'md5_crypt':
        return md5_crypt.hash(password)
    elif hash_type == 'argon2':
        ph = PasswordHasher()
        return ph.hash(password)
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")

# Función para validar el hash de una contraseña en un formato específico
def verify_hash(password, hash_value, hash_type):
    if hash_type in hashlib.algorithms_available:
        return get_hash(password, hash_type) == hash_value
    elif hash_type == 'bcrypt':
        return bcrypt.verify(password, hash_value)
    elif hash_type == 'sha512_crypt':
        return sha512_crypt.verify(password, hash_value)
    elif hash_type == 'sha256_crypt':
        return sha256_crypt.verify(password, hash_value)
    elif hash_type == 'sha1_crypt':
        return sha1_crypt.verify(password, hash_value)
    elif hash_type == 'md5_crypt':
        return md5_crypt.verify(password, hash_value)
    elif hash_type == 'argon2':
        ph = PasswordHasher()
        try:
            return ph.verify(hash_value, password)
        except:
            return False
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")

# Función para crackear la contraseña
def crack_password(hash_value, dictionary_path, hash_type):
    with open(dictionary_path, 'r') as f:
        for line in f:
            password = line.strip()
            if verify_hash(password, hash_value, hash_type):
                return password
    return None

# Función para leer hashes desde un archivo
def read_hashes_from_file(hash_file):
    if not os.path.isfile(hash_file):
        print(colored(f'Error: The file {hash_file} does not exist.', 'red'))
        exit(1)
    
    hashes = []
    with open(hash_file, 'r') as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                name, hash_value = line.split(':', 1)
                hashes.append((name, hash_value))
            else:
                hashes.append(('', line))
    return hashes

# Función para identificar el tipo de hash
def identify_hash(hash_value):
    hashid = HashID()
    identified = hashid.identifyHash(hash_value)
    for result in identified:
        return result
    return 'Unknown'

# Función para manejar la señal SIGINT (Ctrl + C)
def signal_handler(sig, frame):
    print(colored('\n[+] Saliendo...', 'blue'))
    sys.exit(0)

# Función principal
def main():
    signal.signal(signal.SIGINT, signal_handler)  # Manejar señal SIGINT (Ctrl + C)
    
    print(colored(logo, 'cyan'))
    
    parser = argparse.ArgumentParser(description='Crack passwords using a dictionary.')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-c', '--hash', help='Hash to be cracked')
    group.add_argument('-C', '--hashfile', help='File containing hashes to be cracked')
    
    parser.add_argument('-w', '--wordlist', help='Path to the dictionary file')
    parser.add_argument('-t', '--hashtype', help='Hash type', choices=hash_functions.keys())
    parser.add_argument('-o', '--output', help='Output file to save the results')
    parser.add_argument('-i', '--identify', help='Hash to be identified')
    parser.add_argument('-I', '--identifyfile', help='File containing hashes to be identified')
    
    args = parser.parse_args()
    
    # Validación para -C/--hashfile y -I/--identifyfile
    if args.hashfile and not os.path.isfile(args.hashfile):
        print(colored(f'Error: {args.hashfile} is not a valid file.', 'red'))
        exit(1)
    
    if args.identifyfile and not os.path.isfile(args.identifyfile):
        print(colored(f'Error: {args.identifyfile} is not a valid file.', 'red'))
        exit(1)
    
    # Validación para -c/--hash y -i/--identify
    if args.hash and os.path.isfile(args.hash):
        print(colored('Error: -c/--hash should be a hash value, not a file.', 'red'))
        exit(1)
    
    if args.identify and os.path.isfile(args.identify):
        print(colored('Error: -i/--identify should be a hash value, not a file.', 'red'))
        exit(1)

    if args.identify:
        hash_type = identify_hash(args.identify)
        print(colored(f'The hash type is: {hash_type}', 'blue'))
        return
    
    if args.identifyfile:
        hashes = read_hashes_from_file(args.identifyfile)
        for _, hash_value in hashes:
            hash_type = identify_hash(hash_value)
            print(colored(f'The hash type of {hash_value} is: {hash_type}', 'blue'))
        return

    if not args.wordlist and (args.hash or args.hashfile):
        parser.error('the following arguments are required: -w/--wordlist')

    dictionary_path = args.wordlist
    hash_type = args.hashtype
    output_file = args.output
    
    hashes = []
    
    if args.hash:
        hashes.append(('', args.hash))
    elif args.hashfile:
        hashes.extend(read_hashes_from_file(args.hashfile))
    
    results = []
    
    for name, hash_value in hashes:
        print(colored(f'[*] Cracking Hash: {hash_value}', 'yellow'))
        password = crack_password(hash_value, dictionary_path, hash_type)
        
        if password:
            if name:
                result = f'{name}:{password} ({hash_value})'
            else:
                result = f'{password} ({hash_value})'
            results.append(result)
            print(colored(result, 'green'))
        else:
            result = f'{name}: Not found ({hash_value})' if name else f'Not found ({hash_value})'
            results.append(result)
            print(colored(result, 'red'))
    
    if output_file:
        with open(output_file, 'w') as f:
            for result in results:
                f.write(result + '\n')
        print(colored(f'[+] Results saved to {output_file}', 'blue'))

if __name__ == '__main__':
    main()

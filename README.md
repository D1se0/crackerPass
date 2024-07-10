# crackerPass

<p align="center">
  <img src="https://github.com/D1se0/crackerPass/assets/164921056/4f50834c-82e8-4b68-b7ce-c1a854cee780" alt="Directorybrute" width="400">
</p>

----

`crackerPass` is a command line tool designed to crack passwords using dictionaries and verify password hashes in various formats. 
The tool uses different `Python` libraries to handle and verify password hashes, providing flexibility to work with various common hashing algorithms.

## Description

### `crackerPass` supports the following hashing algorithms:

`MD5`
`SHA1`
`SHA224`
`SHA256`
`SHA384`
`SHA512`
`SHA3-256`
`SHA3-512`
`BCrypt`
`SHA512Crypt`
`SHA256Crypt`
`SHA1Crypt`
`MD5Crypt`
`Argon2`

## The tool allows:

Crack passwords using a dictionary file against a specific `hash`.
Verify password hashes using different hashing algorithms.

## Install:

### Clone this repository:

```bash
git clone https://github.com/D1se0/crackerPass.git
cd crackerPass
```

Run the `requirements.sh` script as root to install the necessary dependencies and configure the tool:

```bash
./requirements.sh
```

## Use:

### Parameters:

`-c`, `--hash`: Specifies the hash to crack.

`-C`, `--hashfile`: Specifies a file containing hashes to crack.

`-w`, `--wordlist`: Specifies the path to the dictionary file.

`-t`, `--hashtype`: Specifies the hash type. It can be one of the following: md5, sha1, sha224, sha256, sha384, sha512, sha3_256, sha3_512, bcrypt, sha512crypt, sha256crypt, sha1crypt, md5crypt, argon2.

`-o`, `--output`: Specifies the output file to save the results.

`-i`, `--identify`: Identifies the provided hash type.

`-I`, `--identifyfile`: Identifies the hash types in a file.

## Examples of use:

`Crack` a hash using a dictionary:

```bash
python3 crackerPass.py -c <hash> -w <wordlist> -t <format_hash>
```

Example:

```bash
python3 crackerPass.py -c f806fc5a2a0d5ba2471600758452799c -w /usr/share/wordlists/rockyou.txt -t md5
```

Identify a hash:

```bash
python3 crackerPass.py -i <hash>
```

Crack hashes from a file:

```bash
python3 crackerPass -C <hash_file> -w <wordlist> -t <format_hash>
```

Example:

```bash
python3 crackerPass -C hashes.txt -w /usr/share/wordlists/rockyou.txt -t sha256
```

## Contributions:

Contributions are welcome. If you find any problems, please open an issue in the repository.

## License:

This project is licensed under the `MIT` License. See the `LICENSE` file for details.

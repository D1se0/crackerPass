# crackerPass

<p align="center">
  <img src="https://github.com/D1se0/crackerPass/assets/164921056/4f50834c-82e8-4b68-b7ce-c1a854cee780" alt="Directorybrute" width="400">
</p>

----

`crackerPass` es una herramienta de línea de comandos diseñada para crackear contraseñas utilizando diccionarios y verificar hashes de contraseñas en varios formatos. 
La herramienta utiliza diferentes bibliotecas `Python` para manejar y verificar hashes de contraseñas, proporcionando flexibilidad para trabajar con diversos algoritmos de hash comunes.

## Descripción

### `crackerPass` soporta los siguientes algoritmos de hash:

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

## La herramienta permite:

Crackear contraseñas utilizando un archivo de diccionario contra un `hash` específico.
Verificar hashes de contraseñas utilizando diferentes algoritmos de hash.

## Instalación:

### Clona este repositorio:

```bash
git clone https://github.com/D1se0/crackerPass.git
cd crackerPass
```

Ejecuta el script `requirements.sh` como root para instalar las dependencias necesarias y configurar la herramienta:

```bash
./requirements.sh
```

## Uso:

### Parámetros:

`-c`, `--hash`: Especifica el hash que se desea crackear.

`-C`, `--hashfile`: Especifica un archivo que contiene hashes a crackear.

`-w`, `--wordlist`: Especifica la ruta al archivo de diccionario.

`-t`, `--hashtype`: Especifica el tipo de hash. Puede ser uno de los siguientes: md5, sha1, sha224, sha256, sha384, sha512, sha3_256, sha3_512, bcrypt, sha512crypt, sha256crypt, sha1crypt, md5crypt, argon2.

`-o`, `--output`: Especifica el archivo de salida para guardar los resultados.

`-i`, `--identify`: Identifica el tipo de hash proporcionado.

`-I`, `--identifyfile`: Identifica los tipos de hash en un archivo.

## Ejemplos de uso:

`Crackear` un hash usando un diccionario:

```bash
python3 crackerPass.py -c <hash> -w <wordlist> -t <format_hash>
```

Ejemplo:

```bash
python3 crackerPass.py -c f806fc5a2a0d5ba2471600758452799c -w /usr/share/wordlists/rockyou.txt -t md5
```

Identificar un hash:

```bash
python3 crackerPass.py -i <hash>
```

Crackear hashes desde un archivo:

```bash
python3 crackerPass -C <hash_file> -w <wordlist> -t <format_hash>
```

Ejemplo:

```bash
python3 crackerPass -C hashes.txt -w /usr/share/wordlists/rockyou.txt -t sha256
```

## Contribuciones:

Las contribuciones son bienvenidas. Si encuentras algún problema, por favor, abre un issue en el repositorio.

## Licencia:

Este proyecto está licenciado bajo la Licencia `MIT`. Consulta el archivo `LICENSE` para más detalles.

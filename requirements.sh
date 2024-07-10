#!/bin/bash

# Verificar que se está ejecutando como root
if [ "$(id -u)" != "0" ]; then
    echo "Este script debe ser ejecutado como root" 1>&2
    exit 1
fi

# Actualizar e instalar las dependencias básicas
apt-get update
apt-get install -y python3 python3-pip

# Instalar las bibliotecas Python necesarias
pip3 install termcolor passlib argon2-cffi hashid

# Instalar el paquete de hashid desde GitHub (para asegurar la versión más reciente)
pip3 install git+https://github.com/psypanda/hashID.git

# Copiar el script al directorio /usr/bin sin la extensión .py
cp crackerPass.py /usr/bin/crackerPass
chmod +x /usr/bin/crackerPass

echo "Instalación completa."
echo "El script crackerPass está disponible para ser ejecutado desde cualquier ubicación."


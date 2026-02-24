"""
encryption.py

Laboratorio de Cifrado y Manejo de Credenciales

En este módulo deberás implementar:

- Descifrado AES (MODE_EAX)
- Hash de contraseña con salt usando PBKDF2-HMAC-SHA256
- Verificación de contraseña usando el mismo salt

NO modificar la función encrypt_aes().
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
import hmac

# ==========================================================
# AES-GCM (requiere pip install pycryptodome)
# ==========================================================

def encrypt_aes(texto, clave):
    """
    Cifra un texto usando AES en modo EAX.

    Retorna:
        texto_cifrado_hex
        nonce_hex
        tag_hex
    """

    texto_bytes = texto.encode()

    cipher = AES.new(clave, AES.MODE_EAX)

    nonce = cipher.nonce
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)

    return (
        texto_cifrado.hex(),
        nonce.hex(),
        tag.hex()
    )




def decrypt_aes(texto_cifrado_hex, nonce_hex, tag_hex, clave):
    #conversión de hex a bytes
    texto_cifrado = bytes.fromhex(texto_cifrado_hex)
    nonce = bytes.fromhex(nonce_hex)
    tag = bytes.fromhex(tag_hex)
  
    #AES
    cipher = AES.new(clave, AES.MODE_EAX, nonce=nonce)

    texto_bytes = cipher.decrypt_and_verify(texto_cifrado, tag)

    return texto_bytes.decode()



# ==========================================================
# PASSWORD HASHING (PBKDF2 - SHA256)
# ==========================================================


def hash_password(password):
    #salt aleatoria de 16 bytes
    salt = os.urandom(16)

    #parámetros
    iterations = 200000
    algorithm = "pbkdf2_sha256"

    # clave de 32 bytes
    dk = hashlib.pbkdf2_hmac(
        "sha256",                 
        password.encode(),        
        salt,                     
        iterations,               
        dklen=32                  
    )

    # valores en hex
    return {
        "algorithm": algorithm,
        "iterations": iterations,
        "salt": salt.hex(),
        "hash": dk.hex()
    }

def verify_password(password, stored_data):

    # Extraer salt 
    salt_hex = stored_data["salt"]
    iterations = stored_data["iterations"]
    stored_hash_hex = stored_data["hash"]

    # Convertir salt de hex a bytes
    salt = bytes.fromhex(salt_hex)

    # Recalcular hash 
    new_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        iterations,
        dklen=32
    )
    #compare_digest 
    return hmac.compare_digest(new_hash.hex(), stored_hash_hex)



if __name__ == "__main__":

    print("=== PRUEBA AES ===")

    texto = "Hola Mundo"
    clave = get_random_bytes(16)

    texto_cifrado, nonce, tag = encrypt_aes(texto, clave)

    print("Texto cifrado:", texto_cifrado)
    print("Nonce:", nonce)
    print("Tag:", tag)

    # Cuando implementen decrypt_aes, esto debe funcionar
    texto_descifrado = decrypt_aes(texto_cifrado, nonce, tag, clave)
    print("Texto descifrado:", texto_descifrado)


    print("\n=== PRUEBA HASH ===")

    password = "Password123!"

    # Cuando implementen hash_password:
    pwd_data = hash_password(password)
    print("Hash generado:", pwd_data)

    # Cuando implementen verify_password:
    print("Verificación correcta:",
    verify_password("Password123!", pwd_data))
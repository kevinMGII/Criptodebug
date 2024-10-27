from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

# Generamos una master key global para cifrar y descifrar claves y la almacenamos en .env

def generar_master_key():
    # Usamos HKDF para derivar una master key desde otra key
    key = AESGCM.generate_key(128)
    salt = os.urandom(12)  # Para aumentar la seguridad
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Longitud de la master key (32 bytes = 256 bits)
        salt=salt,
        info=None,
        backend=default_backend()
    )
    master_key_base64 = base64.b64encode(hkdf.derive(key)).decode('utf-8')

    # Guardamos la master key en el archivo master_key.txt

    with open("master_key.txt", "w") as archivo:
        archivo.write(f"MASTER_KEY={master_key_base64}\n")

generar_master_key()
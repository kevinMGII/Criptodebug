import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from clase_json_mensaje import JsonFormatMensaje
from clase_usuario import Usuario

class Mensaje:
    def __init__(self, emisor: Usuario, receptor:Usuario, mensaje: str):
        self.emisor = emisor
        self.receptor = receptor
        self.mensaje = mensaje

    def obtener_master_key(self):
        """Obtiene la master key del archivo master_key.txt"""

        # Abre el archivo y lee su contenido
        with open("master_key.txt", "r") as archivo:
            for linea in archivo:
                if linea.startswith("MASTER_KEY="):
                    master_key_base64 = linea.split("=", 1)[1].strip()
                    return base64.b64decode(master_key_base64)

    def cifrar_key_con_master_key(self, key, master_key):
        # Ciframos la clave AES con la master key usando AESGCM
        nonce_key = os.urandom(12)
        aesgcm_master = AESGCM(master_key)
        key_cifrada = aesgcm_master.encrypt(nonce_key, key, None)
        return key_cifrada, nonce_key

    def enviar_mensaje(self):
        # Generamos una key aleatoria para cifrar el mensaje
        key = AESGCM.generate_key(128)
        aesgcm = AESGCM(key)
        nonce_mensaje = os.urandom(12)
        # Cifrar el mensaje con la clave AES
        m_cifrado = aesgcm.encrypt(nonce_mensaje, self.mensaje.encode('utf-8'), None)

        # Cifrar la clave AES con la master key
        master_key = self.obtener_master_key()
        key_cifrada, nonce_key = self.cifrar_key_con_master_key(key, master_key)
        print(nonce_key)
        # Crear y almacenar el mensaje en formato JSON
        json_mensaje = JsonFormatMensaje(self.emisor.username, m_cifrado, self.receptor.username, key_cifrada,
                                         nonce_mensaje, nonce_key)
        json_mensaje.add_mensaje()
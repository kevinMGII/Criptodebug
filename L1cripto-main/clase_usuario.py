import json, re
import os
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
from clase_json_usuario import JsonFormatUsuario
from clase_json import JsonFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Usuario:
    def __init__(self, username:str) -> None:
        self.username = username


    def comprobar_password(self, password: str) -> bool:
        """Al menos 8 caracteres una mayuscula una minuscula un numero y
        un caracter especial"""
        if (len(password) >= 8 and
                re.search(r"[A-Z]", password) and
                re.search(r"[a-z]", password) and
                re.search(r"[0-9]", password) and
                re.search(r"[@$!%*?&.]", password)):
            return True
        return False

    def extraer_datos(self, ruta:str):
        # Encuentro la entrada en el JSON
        with open(ruta, 'r') as archivo_json:
            data = json.load(archivo_json)  # Abrimos el almacen JSON
            for user in data:  # Iteramos en la lista de carga del JSON
                if user['user'] == self.username:  # Si el usuario es correcto:
                    return base64.b64decode(user['key']), base64.b64decode(user['salt'])
        return 0

    def registered(self, ruta:str) -> bool:
        with open(ruta, 'r') as archivo_json:
            try:
                data = list(json.load(archivo_json))  # Cargar datos del JSON
            except json.JSONDecodeError:
                data = []  # Si el archivo está vacío o corrupto, inicializar como una lista vacía
        for user in data:
            if user['user'] == self.username:
                return True
        return False

    def registrar(self, password:str):
        continuar = True
        while continuar:
            if not self.registered('almacen_usuario.json'):
                # Creamos un salt para el usuario
                salt = os.urandom(16)
                # derivar
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                )
                key = kdf.derive(password.encode('utf-8'))
                store = JsonFormatUsuario(self.username, key, salt)
                store.add_user()
                return True
            else:
                return False

    def login(self, password: str) -> str:
        if self.registered('almacen_usuario.json'):
            datos_almacenados = self.extraer_datos('almacen_usuario.json')  # Sacamos la key y el salt
            if datos_almacenados == 0:
                return "No se encontraron datos almacenados."

            kdf = Scrypt(
                salt=datos_almacenados[1],
                length=32,
                n=2 ** 14,
                r=8,
                p=1,
            )

            # Verificamos que las contraseñas son iguales

            try:
                kdf.verify(password.encode('utf-8'), datos_almacenados[0])
                return "Inicio de sesión exitoso."  # Mensaje de éxito
            except Exception:
                return "La contraseña es incorrecta."  # Mensaje de error al verificar la contraseña
        else:
            return "El usuario no está registrado."  # Mensaje si el usuario no está registrado

    def ver_mensajes(self):

        info_json = JsonFormat('almacen_mensaje.json')
        info_receptor = info_json.extraer_datos_json()

        # Filtrar los mensajes donde el usuario es el receptor
        mensajes_recibidos = [msg for msg in info_receptor if msg["receptor"] == self.username]

        if not mensajes_recibidos:
            return False

        # Obtener la master key del usuario
        with open("master_key.txt", "r") as archivo:
            for linea in archivo:
                if linea.startswith("MASTER_KEY="):
                    master_key_base64 = linea.split("=", 1)[1].strip()

        if not master_key_base64:
            raise ValueError("MASTER_KEY no encontrada")

        # Decodificar la master_key de base64 a bytes
        master_key = base64.b64decode(master_key_base64)
        aesgcm_master = AESGCM(master_key)

        mensajes_descifrados = []

        for mensaje in mensajes_recibidos:
            # Decodificar la clave cifrada y el nonce para la clave
            clave_cifrada = base64.b64decode(mensaje['key'])
            nonce_clave = base64.b64decode(mensaje['nonce_key'])
            clave_original = self.desencriptar_clave(aesgcm_master, nonce_clave, clave_cifrada)

            if clave_original is None:
                continue  # Saltar mensajes que no se pueden descifrar

            # Decodificar el nonce del mensaje
            nonce_mensaje = base64.b64decode(mensaje['nonce_mensaje'])

            # Usar la clave original para desencriptar el mensaje
            aesgcm = AESGCM(clave_original)
            mensaje_cifrado = base64.b64decode(mensaje['mensaje'])
            mensaje_descifrado = self.desencriptar_mensaje(aesgcm, nonce_mensaje, mensaje_cifrado)

            # Agregar el mensaje descifrado a la lista
            if mensaje_descifrado:
                mensajes_descifrados.append((mensaje['id'], mensaje['emisor'], mensaje_descifrado.decode('utf-8')))

        return mensajes_descifrados

    def desencriptar_clave(self, aesgcm, nonce_clave, clave_cifrada):
        try:
            return aesgcm.decrypt(nonce_clave, clave_cifrada, None)
        except InvalidTag:
            print("Error: el tag de autenticación no coincide. Los datos pueden haber sido alterados.")
            return None

    def desencriptar_mensaje(self, aesgcm, nonce_mensaje, mensaje_cifrado):
        try:
            return aesgcm.decrypt(nonce_mensaje, mensaje_cifrado, None)
        except InvalidTag:
            print("Error: el tag de autenticación no coincide al descifrar el mensaje.")
            return None

    #Guardar los mensajes restantes (no leídos) en el archivo JSON
    def borrar_mensaje(self, mensaje_id):
        info_json = JsonFormat('almacen_mensaje.json')
        info_receptor = info_json.extraer_datos_json()

        # Filtrar los mensajes, excluyendo el que queremos borrar
        mensajes_restantes = [msg for msg in info_receptor if msg['id'] != mensaje_id]

        # Escribir de nuevo los mensajes restantes en el archivo JSON
        with open('almacen_mensaje.json', 'w') as archivo_json:
            json.dump(mensajes_restantes, archivo_json, indent=4)

        return True

import json
import base64
from clase_json import JsonFormat

class JsonFormatUsuario:
    def __init__(self, user:str, key:bytes, salt:bytes):
        self.user = user
        self.key = base64.b64encode(key).decode('utf-8')
        self.salt = base64.b64encode(salt).decode('utf-8')
    def create_dictionary_usuario(self):
        """Crea y devuelve un diccionario con el contenido del usuario del JSON"""
        dictionary = {'salt': self.salt,
                      'user': self.user,
                      'key': self.key}
        return dictionary
    def add_user(self):
        """Añade un nuevo usuario al almacen de JSON que gestiona los usuarios"""
        dictionary = self.create_dictionary_usuario()
        json_objeto = JsonFormat('almacen_usuario.json')
        json_objeto.add_json(dictionary)

    def actualizar_password(self):
        """Metodo utilizado para actualizar una contraseña olvidada"""
        # Abrimos el almacen y guardamos los datos
        try:
            with open('almacen_usuario.json', 'r') as archivo_json:
                usuarios = json.load(archivo_json)

            # Buscamos el usuario que necesitamos y actualizamos la key y el salt a los nuevos
            for user in usuarios:
                if user['user'] == self.user:
                    user['key'] = self.key
                    user['salt'] = self.salt
                    break
            else:
                return False  # Usuario no encontrado

            # Guardamos los cambios en el archivo JSON
            with open('almacen_usuario.json', 'w') as archivo_json:
                json.dump(usuarios, archivo_json, indent=4)

            return True
        except Exception:
            return False
    def __str__(self):
        return json.dumps(self.create_dictionary_usuario())
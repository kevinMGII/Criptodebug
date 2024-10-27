import json, base64, uuid
from clase_json import JsonFormat

class JsonFormatMensaje:
    def __init__(self, user1:str, mensaje:bytes, user2:str, key:bytes, nonce_mensaje:bytes, nonce_key:bytes):
        self.user1 = user1
        self.mensaje = base64.b64encode(mensaje).decode('utf-8')
        self.user2 = user2
        self.key = base64.b64encode(key).decode('utf-8')
        self.nonce_mensaje = base64.b64encode(nonce_mensaje).decode('utf-8')
        self.nonce_key = base64.b64encode(nonce_key).decode('utf-8')
        self.id = str(uuid.uuid4()) # Generamos un id unico para luego borrar las cartas
    def create_dictionary_mensaje(self):
        """Crea y devuelve un diccionario con el contenido del JSON del mensaje"""
        dictionary = {'id': self.id,
                      'emisor': self.user1,
                      'mensaje': self.mensaje,
                      'receptor': self.user2,
                      'key': self.key,
                      'nonce_mensaje': self.nonce_mensaje,
                      'nonce_key': self.nonce_key}
        return dictionary
    def add_mensaje(self):
        """Añade un nuevo mensaje al almacen de JSON donde se gestionan los mensajes"""
        dictionary = self.create_dictionary_mensaje()
        json_objeto = JsonFormat('almacen_mensaje.json')
        json_objeto.add_json(dictionary)
    def __str__(self):
        return json.dumps(self.create_dictionary_mensaje())
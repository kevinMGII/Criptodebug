import json

class JsonFormat:
    def __init__(self, ruta: str):
        self.ruta = ruta
    def add_json(self, dictionary):

        data = self.extraer_datos_json()

        # Agregar el nuevo diccionario a la lista
        data.append(dictionary)

        # Guardar la lista de diccionarios actualizada en el archivo
        with open(self.ruta, 'w') as archivo_json:
            json.dump(data, archivo_json)

    def extraer_datos_json(self):
        """Extrae los datos del JSON en una lista, y devuelve esa lista"""
        with open(self.ruta, 'r') as archivo_json:
            try:
                data = json.load(archivo_json)  # Cargar datos del JSON
                if type(data) != list:
                    # Si el archivo no es una lista, inicializar como lista vacía
                    data = []
            except json.JSONDecodeError:
                # Si el archivo está vacío o corrupto, inicializar como lista vacía
                data = []
        return data


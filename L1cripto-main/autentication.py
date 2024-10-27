from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from clase_json import JsonFormat
from clase_json_usuario import JsonFormatUsuario
from clase_usuario import Usuario
from clase_mensajes import Mensaje
import os

# Creamos la app web con Flask para generar una interfaz gráfica en el navegador
app = Flask(__name__)

# Clave secreta para manejar las sesiones
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    # Renderizar el archivo inicio.html desde la carpeta 'templates'
    return render_template('inicio.html')

@app.route('/pagina_registro', methods=['GET'])
def pagina_registro():
    # Desde la página inicio venimos al html del registro al pulsar el botón/enlace
    return render_template('registro.html')

@app.route('/register', methods=['POST'])

# Se accede al enviar el formulario de registro

def register():

    # Cogemos los datos importantes del registro

    username = request.form['usuario']
    password = request.form['password']
    repetir_password = request.form['repetir_password']

    # Creamos el objeto usuario
    nuevo_usuario = Usuario(username)

    # Verificamos si la contraseña cumple los requisitos mínimos
    if not nuevo_usuario.comprobar_password(password):
        # Si la contraseña es incorrecta, pasamos un mensaje de error al html para que se muestre
        error_message = "La contraseña no es válida. Debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un símbolo."
        return render_template('registro.html', error=error_message)

    # Si la contraseña es válida, continuamos con el registro
    elif nuevo_usuario.registrar(password):
        if repetir_password == password:
            # Almaceno el username que registré en session
            session["usuario_actual"] = username
            return redirect(url_for('pagina_app'))
        else:
            # Si no coinciden mandamos al html un error
            error_message = "Las contraseñas no coinciden"
            return render_template('registro.html', error=error_message)

    else:
        # En caso de que el usuario ya esté registrado
        error_message = "El usuario ya está registrado."
        return render_template('registro.html', error=error_message)

@app.route('/pagina_logIn', methods=['GET'])
def pagina_logIn():
    # Se llega desde la página de registro usando el enlace ("Ya tienes cuenta? Inicia sesión)
    return render_template('logIn.html')

@app.route('/logIn', methods=['POST'])
def logIn():

    # Recogemos los datos del formulario logIn
    username = request.form['usuario']
    password = request.form['password']

    #Creamos un objeto usuario para trabajar con los métodos necesarios
    usuario = Usuario(username)

    #Almaceno el username que inicia sesión en session
    session["usuario_actual"] = username

    # Comprobamos si el inicio de sesión ha sido exitoso
    texto = usuario.login(password)
    if texto == "Inicio de sesión exitoso.":
        return redirect(url_for('pagina_app'))  # Redirigimos a la página de la app tras el login
    else:
        # Si no es correcto, mandamos un mensaje de error y nos mantenemos en el logIn
        error_message = texto
        return render_template('logIn.html', error=error_message)

@app.route('/nueva_password', methods=['POST'])
def nueva_password():
    # Recogemos los datos que nos manda js en formato json
    data = request.json
    username = data.get('usuario')
    new_password = data.get('new_password')

    # Creamos un objeto Usuario y verificamos si la nueva contraseña es válida
    usuario = Usuario(username)
    if not usuario.comprobar_password(new_password):
        # Jsonify es una función de Flask que alerta al usuario de un error en formato json
        return jsonify({"success": False, "error": "La contraseña no cumple con los requisitos."})

    # Derivamos la nueva contraseña con un salt nuevo
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    new_key = kdf.derive(new_password.encode('utf-8'))

    # Creamos una instancia de jsonUsuario y llamamos al metodo actualizar_contraseña
    
    jsonUsuario = JsonFormatUsuario(username, new_key, salt)
    if jsonUsuario.actualizar_password():
        # Si es correcto, tenemos que guardar el usuario en session y returnear
        session["usuario_actual"] = username
        # Si va bien, devuelve un redirect a la página y un jsonify para la alerta exitosa
        return jsonify({"success": True, "redirect": url_for('pagina_app')})
    else:
        return jsonify({"success": False, "error": "Usuario no encontrado o error al actualizar."})

@app.route('/pagina_app', methods=['GET'])
def pagina_app():
    return render_template('app.html')

# Nueva ruta para la página de leer mensajes
@app.route('/pagina_leer', methods=['GET'])
def pagina_leer():
    
    # Recogemos el usuario actual (receptor) de la session
    usuario_actual = session.get('usuario_actual')
    if usuario_actual:
        usuario = Usuario(usuario_actual)

        # Obtenemos los mensaje descifrado para el receptor (usuario actual)
        mensaje_info = usuario.ver_mensajes()  # Devuelve una lista

        # Si va bien, redirigimos a la página html de leer.html
        if mensaje_info:
            return render_template('leer.html', mensajes = mensaje_info)
        else:
            error_message = "No tienes mensajes sin leer."
            return render_template('leer.html', error=error_message)
    else:
        return redirect(url_for('pagina_logIn'))

# Nueva ruta para la página de enviar mensajes
@app.route('/pagina_enviar', methods=['GET'])
def pagina_enviar():

    # Cogemos del json de usuarios todos los usuarios disponibles
    json_info = JsonFormat("almacen_usuario.json")
    lista_usuarios = json_info.extraer_datos_json()

    # Pasamos la lisyta de nombres de usuario al html de enviar mensaje
    lista_username = []
    for usuario in lista_usuarios:
        lista_username.append(usuario['user'])
    return render_template('enviar.html', usuarios = lista_username)

@app.route('/enviar', methods=['POST'])
def enviar():

    # Recogemos los datos necesarios del formulario de envio
    receptor_username = request.form['usuario_receptor']
    mensaje = request.form['mensaje']

    # Creamos el usuario emisor y receptor
    emisor = Usuario(session['usuario_actual'])
    receptor = Usuario(receptor_username)

    # Si el receptor está registrado, creamos un objeto mensaje y enviamos el mensaje
    if receptor.registered("almacen_usuario.json"):
        mensajeClase = Mensaje(emisor, receptor, mensaje)
        mensajeClase.enviar_mensaje()
        return redirect(url_for('pagina_app'))
    else:
        error_message = "No se encuentra el usuario solicitado"
        return render_template('enviar.html', error=error_message)

@app.route('/borrar_carta', methods=['POST'])
def borrar_carta():

    # Recogemos el id único del mensaje del formulario de lectura (este id se crea en la clase json del mensaje)
    mensaje_id = request.form['id_mensaje']

    # Creamos un objeto mensaje llamando al username de session y borramos la carta con ese id
    usuario_actual_info = session.get('usuario_actual')
    usuario_actual = Usuario(usuario_actual_info)

    if usuario_actual.borrar_mensaje(mensaje_id):
        return redirect(url_for('pagina_leer'))  # Redirigir a la página de lectura

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)



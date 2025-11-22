from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-key-2024")

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://lalo:EduLC@5bpv.kcdyemv.mongodb.net/escuela")

try:
    client = MongoClient(
        MONGO_URI,
        tls=True,
        tlsAllowInvalidCertificates=False,
        serverSelectionTimeoutMS=10000
    )
    db = client.get_default_database()
    print("✅ Conexión segura establecida con MongoDB Atlas")
except Exception as e:
    print("❌ Conexión segura falló, intentando modo escolar...")
    try:
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsAllowInvalidCertificates=True,
            serverSelectionTimeoutMS=10000
        )
        db = client.get_default_database()
        print("✅ Conexión establecida con MongoDB Atlas (modo escolar)")
    except Exception as e:
        db = None
        print("❌ No se pudo conectar con MongoDB Atlas:", e)

# Crear colecciones si no existen
def init_db():
    if db is not None:
        collections = db.list_collection_names()
        required_collections = ['usuarios', 'rutinas', 'notas', 'ejercicios', 'historial_rutinas']
        
        for coll in required_collections:
            if coll not in collections:
                db.create_collection(coll)
                print(f"✅ Colección '{coll}' creada")

# Ejecutar inicialización
init_db()

# Funciones de contexto para las plantillas
@app.context_processor
def utility_processor():
    def get_badge_color(tipo):
        colores = {
            'fuerza': 'bg-primary',
            'cardio': 'bg-danger', 
            'velocidad': 'bg-warning'
        }
        return colores.get(tipo, 'bg-secondary')
    
    def get_tipo_icono(tipo):
        iconos = {
            'fuerza': 'bi bi-dumbbell',
            'cardio': 'bi bi-heart-pulse',
            'velocidad': 'bi bi-lightning-charge'
        }
        return iconos.get(tipo, 'bi bi-activity')
    
    return dict(
        get_badge_color=get_badge_color,
        get_tipo_icono=get_tipo_icono
    )

# Middleware para verificar autenticación
@app.before_request
def require_login():
    allowed_routes = ['index', 'login', 'register', 'ayuda', 'static']
    if request.endpoint not in allowed_routes and 'user_id' not in session:
        return redirect(url_for('login'))

# Rutas de autenticación
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Completa todos los campos.", "danger")
            return render_template("login.html")

        if db is None:
            flash("Error de conexión con la base de datos.", "danger")
            return render_template("login.html")

        usuario = db.usuarios.find_one({"email": email})
        if usuario and check_password_hash(usuario["password"], password):
            session["user_id"] = str(usuario["_id"])
            session["user_nombre"] = usuario["nombre"]
            flash(f"¡Bienvenido {usuario['nombre']}!", "success")
            return redirect(url_for("index"))
        else:
            flash("Credenciales incorrectas.", "danger")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not all([nombre, email, password, confirm_password]):
            flash("Completa todos los campos.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Las contraseñas no coinciden.", "danger")
            return render_template("register.html")

        if db is None:
            flash("Error de conexión con la base de datos.", "danger")
            return render_template("register.html")

        # Verificar si el email ya existe
        if db.usuarios.find_one({"email": email}):
            flash("Este email ya está registrado.", "warning")
            return render_template("register.html")

        # Crear nuevo usuario
        nuevo_usuario = {
            "nombre": nombre,
            "email": email,
            "password": generate_password_hash(password),
            "fecha_registro": datetime.now(),
            "racha_actual": 0,
            "racha_maxima": 0
        }

        db.usuarios.insert_one(nuevo_usuario)
        flash("¡Registro exitoso! Ahora puedes iniciar sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("index"))

# Rutas principales
@app.route("/")
def index():
    if 'user_id' not in session:
        return render_template("home.html")
    
    # Obtener estadísticas del usuario
    usuario = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
    total_rutinas = db.rutinas.count_documents({"usuario_id": ObjectId(session["user_id"])})
    total_notas = db.notas.count_documents({"usuario_id": ObjectId(session["user_id"])})
    
    return render_template("home.html", 
                         usuario=usuario,
                         total_rutinas=total_rutinas,
                         total_notas=total_notas)

@app.route("/nuevo")
def nuevo():
    return render_template("nuevo.html")

@app.route("/ayuda")
def ayuda():
    return render_template("ayuda.html")

@app.route("/configuracion")
def configuracion():
    usuario = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
    return render_template("configuracion.html", usuario=usuario)

@app.route("/notas")
def notas():
    notas_usuario = list(db.notas.find({"usuario_id": ObjectId(session["user_id"])}).sort("fecha_creacion", -1))
    return render_template("notas.html", notas=notas_usuario)

@app.route("/perfil")
def perfil():
    usuario = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
    total_rutinas = db.rutinas.count_documents({"usuario_id": ObjectId(session["user_id"])})
    total_notas = db.notas.count_documents({"usuario_id": ObjectId(session["user_id"])})
    
    return render_template("perfil.html", 
                         usuario=usuario,
                         total_rutinas=total_rutinas,
                         total_notas=total_notas)

@app.route("/racha")
def racha():
    usuario = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
    return render_template("racha.html", usuario=usuario)

# Gestión de rutinas
@app.route("/rutinas")
def rutinas():
    rutinas_usuario = list(db.rutinas.find({"usuario_id": ObjectId(session["user_id"])}).sort("fecha_creacion", -1))
    return render_template("rutinas.html", rutinas=rutinas_usuario)

@app.route("/rutina/nueva", methods=["GET", "POST"])
def nueva_rutina():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        descripcion = request.form.get("descripcion", "").strip()
        tipo = request.form.get("tipo", "").strip()
        duracion = request.form.get("duracion", "").strip()
        ejercicios = request.form.get("ejercicios", "").strip()

        if not nombre:
            flash("El nombre de la rutina es obligatorio.", "danger")
            return render_template("nueva_rutina.html")

        nueva_rutina = {
            "usuario_id": ObjectId(session["user_id"]),
            "nombre": nombre,
            "descripcion": descripcion,
            "tipo": tipo,
            "duracion": duracion,
            "ejercicios": ejercicios,
            "fecha_creacion": datetime.now(),
            "completada": False
        }

        db.rutinas.insert_one(nueva_rutina)
        flash("¡Rutina creada correctamente!", "success")
        return redirect(url_for("rutinas"))

    return render_template("nueva_rutina.html")

# Ruta para guardar rutinas desde el formulario nuevo.html
@app.route("/rutina/guardar", methods=["POST"])
def guardar_rutina():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        data = request.get_json()
        
        # Crear nueva rutina
        nueva_rutina = {
            "usuario_id": ObjectId(session["user_id"]),
            "nombre": data.get("nombre"),
            "descripcion": data.get("descripcion"),
            "tipo": data.get("tipo"),
            "nivel": data.get("nivel"),
            "duracion": data.get("duracion"),
            "ejercicios": data.get("ejercicios", []),
            "fecha_creacion": datetime.now(),
            "completada": False,
            "estado": "pendiente"
        }
        
        # Guardar en la colección de rutinas
        resultado = db.rutinas.insert_one(nueva_rutina)
        
        # También guardar en historial como rutina pendiente
        historial = {
            "usuario_id": ObjectId(session["user_id"]),
            "rutina_id": resultado.inserted_id,
            "nombre": data.get("nombre"),
            "descripcion": data.get("descripcion"),
            "tipo": data.get("tipo"),
            "nivel": data.get("nivel"),
            "duracion": data.get("duracion"),
            "ejercicios": data.get("ejercicios", []),
            "fecha_creacion": datetime.now(),
            "estado": "pendiente",
            "fecha_completada": None
        }
        db.historial_rutinas.insert_one(historial)
        
        return jsonify({"success": True, "message": "Rutina guardada correctamente"})
    
    except Exception as e:
        print(f"Error al guardar rutina: {e}")
        return jsonify({"success": False, "message": "Error al guardar la rutina"})

# Ruta para completar rutinas
@app.route("/rutina/completar/<id>", methods=["POST"])
def completar_rutina(id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        # Actualizar rutina como completada
        db.rutinas.update_one(
            {"_id": ObjectId(id), "usuario_id": ObjectId(session["user_id"])},
            {"$set": {"completada": True, "estado": "completada"}}
        )
        
        # Actualizar en historial
        db.historial_rutinas.update_one(
            {"rutina_id": ObjectId(id), "usuario_id": ObjectId(session["user_id"])},
            {"$set": {
                "estado": "completada",
                "fecha_completada": datetime.now()
            }}
        )
        
        # Actualizar racha del usuario
        usuario = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
        nueva_racha = usuario.get("racha_actual", 0) + 1
        racha_maxima = max(usuario.get("racha_maxima", 0), nueva_racha)
        
        db.usuarios.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {
                "racha_actual": nueva_racha,
                "racha_maxima": racha_maxima
            }}
        )
        
        return jsonify({"success": True, "message": "¡Rutina completada! Racha actualizada."})
    
    except Exception as e:
        print(f"Error al completar rutina: {e}")
        return jsonify({"success": False, "message": "Error al completar la rutina"})

# Ruta para obtener el historial de rutinas
@app.route("/historial-rutinas")
def historial_rutinas():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Obtener todas las rutinas del usuario (activas y completadas)
    historial = list(db.historial_rutinas.find(
        {"usuario_id": ObjectId(session["user_id"])}
    ).sort("fecha_creacion", -1))
    
    # Convertir ObjectId a string para las plantillas
    for item in historial:
        item['_id'] = str(item['_id'])
        item['usuario_id'] = str(item['usuario_id'])
        if 'rutina_id' in item:
            item['rutina_id'] = str(item['rutina_id'])
    
    return render_template("historial_rutinas.html", historial=historial)

# Ruta para obtener datos del historial en formato JSON
@app.route("/historial-rutinas-data")
def historial_rutinas_data():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        historial = list(db.historial_rutinas.find(
            {"usuario_id": ObjectId(session["user_id"])}
        ).sort("fecha_creacion", -1))
        
        # Convertir ObjectId a string
        for item in historial:
            item['_id'] = str(item['_id'])
            item['usuario_id'] = str(item['usuario_id'])
            if 'rutina_id' in item:
                item['rutina_id'] = str(item['rutina_id'])
        
        return jsonify({"success": True, "rutinas": historial})
    
    except Exception as e:
        print(f"Error al obtener historial: {e}")
        return jsonify({"success": False, "message": "Error al obtener el historial"})

# Ruta para eliminar rutinas del historial
@app.route("/historial/eliminar/<id>", methods=["POST"])
def eliminar_historial(id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        # Primero obtener el rutina_id para eliminar de ambas colecciones
        historial_item = db.historial_rutinas.find_one({
            "_id": ObjectId(id),
            "usuario_id": ObjectId(session["user_id"])
        })
        
        if historial_item:
            rutina_id = historial_item.get('rutina_id')
            
            # Eliminar de historial_rutinas
            resultado_historial = db.historial_rutinas.delete_one({
                "_id": ObjectId(id),
                "usuario_id": ObjectId(session["user_id"])
            })
            
            # También eliminar de rutinas si existe
            if rutina_id:
                db.rutinas.delete_one({
                    "_id": rutina_id,
                    "usuario_id": ObjectId(session["user_id"])
                })
            
            if resultado_historial.deleted_count > 0:
                return jsonify({"success": True, "message": "Rutina eliminada correctamente"})
            else:
                return jsonify({"success": False, "message": "No se pudo eliminar la rutina"})
        else:
            return jsonify({"success": False, "message": "Rutina no encontrada"})
    
    except Exception as e:
        print(f"Error al eliminar rutina: {e}")
        return jsonify({"success": False, "message": "Error al eliminar la rutina"})

# Ruta para obtener detalles de una rutina
@app.route("/rutina/<id>")
def obtener_rutina(id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        rutina = db.rutinas.find_one({
            "_id": ObjectId(id),
            "usuario_id": ObjectId(session["user_id"])
        })
        
        if rutina:
            # Convertir ObjectId a string para JSON
            rutina['_id'] = str(rutina['_id'])
            rutina['usuario_id'] = str(rutina['usuario_id'])
            return jsonify({"success": True, "rutina": rutina})
        else:
            return jsonify({"success": False, "message": "Rutina no encontrada"})
    
    except Exception as e:
        print(f"Error al obtener rutina: {e}")
        return jsonify({"success": False, "message": "Error al obtener la rutina"})

# Gestión de notas
@app.route("/nota/nueva", methods=["GET", "POST"])
def nueva_nota():
    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        contenido = request.form.get("contenido", "").strip()

        if not titulo:
            flash("El título es obligatorio.", "danger")
            return render_template("nueva_nota.html")

        nueva_nota = {
            "usuario_id": ObjectId(session["user_id"]),
            "titulo": titulo,
            "contenido": contenido,
            "fecha_creacion": datetime.now(),
            "fecha_actualizacion": datetime.now()
        }

        db.notas.insert_one(nueva_nota)
        flash("¡Nota creada correctamente!", "success")
        return redirect(url_for("notas"))

    return render_template("nueva_nota.html")

@app.route("/nota/editar/<id>", methods=["GET", "POST"])
def editar_nota(id):
    nota = db.notas.find_one({"_id": ObjectId(id), "usuario_id": ObjectId(session["user_id"])})
    
    if not nota:
        flash("Nota no encontrada.", "warning")
        return redirect(url_for("notas"))

    if request.method == "POST":
        titulo = request.form.get("titulo", "").strip()
        contenido = request.form.get("contenido", "").strip()

        if not titulo:
            flash("El título es obligatorio.", "danger")
            return render_template("editar_nota.html", nota=nota)

        db.notas.update_one(
            {"_id": ObjectId(id)},
            {"$set": {
                "titulo": titulo,
                "contenido": contenido,
                "fecha_actualizacion": datetime.now()
            }}
        )
        flash("¡Nota actualizada correctamente!", "success")
        return redirect(url_for("notas"))

    return render_template("editar_nota.html", nota=nota)

@app.route("/nota/eliminar/<id>", methods=["POST"])
def eliminar_nota(id):
    db.notas.delete_one({"_id": ObjectId(id), "usuario_id": ObjectId(session["user_id"])})
    flash("Nota eliminada correctamente.", "info")
    return redirect(url_for("notas"))

# Rutas CRUD originales (mantenidas para compatibilidad)
@app.route("/list")
def list_old():
    if db is None:
        flash("Error al obtener datos: la base de datos no está conectada.", "danger")
        return render_template("index.html", datos=[])
    try:
        datos = db.registros.find()
    except Exception as e:
        flash(f"Error al obtener datos: {e}", "danger")
        datos = []
    return render_template("index_old.html", datos=datos)

@app.route("/new", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        campo1 = request.form.get("campo1", "").strip()
        campo2 = request.form.get("campo2", "").strip()

        if not campo1 or not campo2:
            flash("Completa todos los campos.", "danger")
            return redirect(url_for("create"))

        if db is not None:
            db.registros.insert_one({
                "campo1": campo1,
                "campo2": campo2
            })
            flash("Registro creado correctamente.", "success")
        else:
            flash("Error: Base de datos no conectada.", "danger")

        return redirect(url_for("list_old"))
    return render_template("create.html")

if __name__ == "__main__":
    app.run(debug=True)

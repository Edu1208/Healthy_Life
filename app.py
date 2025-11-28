from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from datetime import datetime, timedelta
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
        required_collections = ['usuarios', 'rutinas', 'notas', 'historial_rutinas', 'rachas']
        
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

        resultado = db.usuarios.insert_one(nuevo_usuario)
        usuario_id = resultado.inserted_id

        # Crear perfil por defecto
        perfil_default = {
            "usuario_id": usuario_id,
            "especialidad": "General",
            "descripcion": "Apasionado del fitness y el desarrollo personal.",
            "etiquetas": ["Fitness", "Salud", "Bienestar"],
            "fecha_actualizacion": datetime.now()
        }
        db.perfiles.insert_one(perfil_default)

        # Crear racha inicial
        racha_default = {
            "usuario_id": usuario_id,
            "dias_consecutivos": 0,
            "record_personal": 0,
            "dias_completados": [],
            "fecha_ultimo_dia": None,
            "hitos": [3, 7, 14, 30, 60, 90],
            "recordatorio": {
                "activo": True,
                "hora": "19:00",
                "frecuencia": "diario"
            }
        }
        db.rachas.insert_one(racha_default)

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

# Gestión de Notas
@app.route("/notas")
def notas():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    notas_usuario = list(db.notas.find({"usuario_id": ObjectId(session["user_id"])}).sort("fecha_creacion", -1))
    return render_template("notas.html", notas=notas_usuario)

@app.route("/nota/nueva", methods=["POST"])
def nueva_nota():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        data = request.get_json()
        
        nueva_nota = {
            "usuario_id": ObjectId(session["user_id"]),
            "titulo": data.get("titulo"),
            "contenido": data.get("contenido"),
            "categoria": data.get("categoria", "General"),
            "estado": data.get("estado", "Activa"),
            "fecha_creacion": datetime.now(),
            "fecha_actualizacion": datetime.now()
        }
        
        db.notas.insert_one(nueva_nota)
        return jsonify({"success": True, "message": "Nota creada correctamente"})
    
    except Exception as e:
        print(f"Error al crear nota: {e}")
        return jsonify({"success": False, "message": "Error al crear la nota"})

@app.route("/nota/editar/<id>", methods=["POST"])
def editar_nota(id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        data = request.get_json()
        
        db.notas.update_one(
            {"_id": ObjectId(id), "usuario_id": ObjectId(session["user_id"])},
            {"$set": {
                "titulo": data.get("titulo"),
                "contenido": data.get("contenido"),
                "categoria": data.get("categoria"),
                "estado": data.get("estado"),
                "fecha_actualizacion": datetime.now()
            }}
        )
        
        return jsonify({"success": True, "message": "Nota actualizada correctamente"})
    
    except Exception as e:
        print(f"Error al editar nota: {e}")
        return jsonify({"success": False, "message": "Error al editar la nota"})

@app.route("/nota/eliminar/<id>", methods=["POST"])
def eliminar_nota(id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        resultado = db.notas.delete_one({"_id": ObjectId(id), "usuario_id": ObjectId(session["user_id"])})
        
        if resultado.deleted_count > 0:
            return jsonify({"success": True, "message": "Nota eliminada correctamente"})
        else:
            return jsonify({"success": False, "message": "Nota no encontrada"})
    
    except Exception as e:
        print(f"Error al eliminar nota: {e}")
        return jsonify({"success": False, "message": "Error al eliminar la nota"})

# Gestión de Perfil
@app.route("/perfil")
def perfil():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    usuario = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
    perfil_usuario = db.perfiles.find_one({"usuario_id": ObjectId(session["user_id"])})
    total_rutinas = db.rutinas.count_documents({"usuario_id": ObjectId(session["user_id"])})
    total_notas = db.notas.count_documents({"usuario_id": ObjectId(session["user_id"])})
    
    # Obtener racha actual
    racha = db.rachas.find_one({"usuario_id": ObjectId(session["user_id"])})
    
    return render_template("perfil.html", 
                         usuario=usuario,
                         perfil=perfil_usuario,
                         racha=racha,
                         total_rutinas=total_rutinas,
                         total_notas=total_notas)

@app.route("/perfil/actualizar", methods=["POST"])
def actualizar_perfil():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        data = request.get_json()
        
        # Actualizar perfil
        db.perfiles.update_one(
            {"usuario_id": ObjectId(session["user_id"])},
            {"$set": {
                "especialidad": data.get("especialidad"),
                "descripcion": data.get("descripcion"),
                "etiquetas": data.get("etiquetas", []),
                "fecha_actualizacion": datetime.now()
            }},
            upsert=True
        )
        
        # Actualizar nombre de usuario si es necesario
        if data.get("nombre"):
            db.usuarios.update_one(
                {"_id": ObjectId(session["user_id"])},
                {"$set": {"nombre": data.get("nombre")}}
            )
            session["user_nombre"] = data.get("nombre")
        
        return jsonify({"success": True, "message": "Perfil actualizado correctamente"})
    
    except Exception as e:
        print(f"Error al actualizar perfil: {e}")
        return jsonify({"success": False, "message": "Error al actualizar el perfil"})

# Gestión de Racha - Funciones auxiliares
def calcular_tasa_exito(dias_completados):
    if not dias_completados:
        return 0
    
    try:
        # Convertir strings a datetime objects
        fechas = [datetime.strptime(d, "%Y-%m-%d") for d in dias_completados]
        primer_dia = min(fechas)
        hoy = datetime.now()
        dias_totales = (hoy - primer_dia).days + 1
        
        return round((len(dias_completados) / dias_totales) * 100)
    except Exception as e:
        print(f"Error calculando tasa de éxito: {e}")
        return 0

def calcular_hitos_alcanzados(dias_consecutivos):
    hitos = [3, 7, 14, 30, 60, 90]
    return len([h for h in hitos if dias_consecutivos >= h])

def calcular_progreso_mensual(dias_completados):
    if not dias_completados:
        return 0
    
    try:
        hoy = datetime.now()
        mes_actual = hoy.month
        año_actual = hoy.year
        
        dias_mes_actual = [d for d in dias_completados 
                          if datetime.strptime(d, "%Y-%m-%d").month == mes_actual 
                          and datetime.strptime(d, "%Y-%m-%d").year == año_actual]
        
        return len(dias_mes_actual)
    except Exception as e:
        print(f"Error calculando progreso mensual: {e}")
        return 0

# Gestión de Racha - Rutas principales
@app.route("/racha")
def racha():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    usuario = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
    racha_usuario = db.rachas.find_one({"usuario_id": ObjectId(session["user_id"])})
    
    if not racha_usuario:
        # Crear racha si no existe
        racha_usuario = {
            "usuario_id": ObjectId(session["user_id"]),
            "dias_consecutivos": 0,
            "record_personal": 0,
            "dias_completados": [],
            "fecha_ultimo_dia": None,
            "hitos": [3, 7, 14, 30, 60, 90],
            "recordatorio": {
                "activo": True,
                "hora": "19:00",
                "frecuencia": "diario"
            }
        }
        db.rachas.insert_one(racha_usuario)
        racha_usuario = db.rachas.find_one({"usuario_id": ObjectId(session["user_id"])})
    
    return render_template("racha.html", usuario=usuario, racha=racha_usuario)

@app.route("/racha/marcar-dia", methods=["POST"])
def marcar_dia_racha():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        hoy = datetime.now()
        hoy_str = hoy.strftime("%Y-%m-%d")
        
        racha = db.rachas.find_one({"usuario_id": ObjectId(session["user_id"])})
        
        if not racha:
            return jsonify({"success": False, "message": "Racha no encontrada"})
        
        # Verificar si ya se marcó hoy
        if hoy_str in racha.get("dias_completados", []):
            return jsonify({"success": False, "message": "Ya has marcado tu entrenamiento para hoy"})
        
        # Verificar si la racha debe reiniciarse
        dias_consecutivos = racha.get("dias_consecutivos", 0)
        fecha_ultimo_dia = racha.get("fecha_ultimo_dia")
        
        if fecha_ultimo_dia:
            # Convertir fecha_ultimo_dia a datetime si es string
            if isinstance(fecha_ultimo_dia, str):
                fecha_ultimo_dia = datetime.strptime(fecha_ultimo_dia, "%Y-%m-%d")
            
            # Calcular días desde el último registro
            dias_desde_ultimo = (hoy - fecha_ultimo_dia).days
            
            if dias_desde_ultimo > 1:
                # Se rompió la racha, reiniciar
                dias_consecutivos = 0
        
        # Calcular nueva racha
        nueva_racha = dias_consecutivos + 1
        record_personal = max(racha.get("record_personal", 0), nueva_racha)
        
        # Actualizar racha
        db.rachas.update_one(
            {"usuario_id": ObjectId(session["user_id"])},
            {"$set": {
                "dias_consecutivos": nueva_racha,
                "record_personal": record_personal,
                "fecha_ultimo_dia": hoy
            },
             "$push": {"dias_completados": hoy_str}}
        )
        
        # Actualizar también en usuarios
        db.usuarios.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {
                "racha_actual": nueva_racha,
                "racha_maxima": record_personal
            }}
        )
        
        return jsonify({
            "success": True, 
            "message": "¡Día marcado correctamente!",
            "nueva_racha": nueva_racha,
            "record_personal": record_personal
        })
    
    except Exception as e:
        print(f"Error al marcar día de racha: {e}")
        return jsonify({"success": False, "message": "Error al marcar el día"})

@app.route("/racha/actualizar-recordatorio", methods=["POST"])
def actualizar_recordatorio_racha():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        data = request.get_json()
        
        db.rachas.update_one(
            {"usuario_id": ObjectId(session["user_id"])},
            {"$set": {
                "recordatorio": {
                    "activo": data.get("activo", True),
                    "hora": data.get("hora", "19:00"),
                    "frecuencia": data.get("frecuencia", "diario")
                }
            }}
        )
        
        return jsonify({"success": True, "message": "Recordatorio actualizado correctamente"})
    
    except Exception as e:
        print(f"Error al actualizar recordatorio: {e}")
        return jsonify({"success": False, "message": "Error al actualizar el recordatorio"})

@app.route("/racha/datos")
def obtener_datos_racha():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        racha = db.rachas.find_one({"usuario_id": ObjectId(session["user_id"])})
        
        if racha:
            # Convertir ObjectId a string para JSON
            racha['_id'] = str(racha['_id'])
            racha['usuario_id'] = str(racha['usuario_id'])
            
            # Convertir fecha_ultimo_dia si existe
            if 'fecha_ultimo_dia' in racha and racha['fecha_ultimo_dia']:
                if isinstance(racha['fecha_ultimo_dia'], datetime):
                    racha['fecha_ultimo_dia'] = racha['fecha_ultimo_dia'].strftime("%Y-%m-%d")
            
            return jsonify({"success": True, "racha": racha})
        else:
            return jsonify({"success": False, "message": "Racha no encontrada"})
    
    except Exception as e:
        print(f"Error al obtener datos de racha: {e}")
        return jsonify({"success": False, "message": "Error al obtener los datos de racha"})

@app.route("/racha/estadisticas-completas")
def estadisticas_completas_racha():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        racha = db.rachas.find_one({"usuario_id": ObjectId(session["user_id"])})
        usuario = db.usuarios.find_one({"_id": ObjectId(session["user_id"])})
        
        if not racha:
            return jsonify({"success": False, "message": "Racha no encontrada"})
        
        # Calcular estadísticas avanzadas
        estadisticas = {
            "racha_actual": racha.get("dias_consecutivos", 0),
            "record_personal": racha.get("record_personal", 0),
            "total_dias_activos": len(racha.get("dias_completados", [])),
            "tasa_exito": calcular_tasa_exito(racha.get("dias_completados", [])),
            "hitos_alcanzados": calcular_hitos_alcanzados(racha.get("dias_consecutivos", 0)),
            "progreso_mensual": calcular_progreso_mensual(racha.get("dias_completados", [])),
            "consistencia_semanal": calcular_consistencia_semanal(racha.get("dias_completados", [])),
            "mejor_racha": racha.get("record_personal", 0),
            "dias_este_mes": calcular_progreso_mensual(racha.get("dias_completados", []))
        }
        
        return jsonify({"success": True, "estadisticas": estadisticas})
    
    except Exception as e:
        print(f"Error al obtener estadísticas completas: {e}")
        return jsonify({"success": False, "message": "Error al obtener estadísticas"})

def calcular_consistencia_semanal(dias_completados):
    if not dias_completados:
        return 0
    
    try:
        # Calcular consistencia de las últimas 4 semanas
        hoy = datetime.now()
        total_semanas = 4
        dias_por_semana = []
        
        for i in range(total_semanas):
            inicio_semana = hoy - timedelta(days=hoy.weekday() + (7 * i))
            fin_semana = inicio_semana + timedelta(days=6)
            
            dias_semana = [d for d in dias_completados 
                          if inicio_semana.date() <= datetime.strptime(d, "%Y-%m-%d").date() <= fin_semana.date()]
            
            dias_por_semana.append(len(dias_semana))
        
        # Calcular promedio de días por semana
        promedio = sum(dias_por_semana) / total_semanas
        return round((promedio / 7) * 100)  # Porcentaje de consistencia
    except Exception as e:
        print(f"Error calculando consistencia semanal: {e}")
        return 0

# Gestión de rutinas
@app.route("/rutinas")
def rutinas():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
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

@app.route("/rutina/guardar", methods=["POST"])
def guardar_rutina():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        data = request.get_json()
        
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
        
        resultado = db.rutinas.insert_one(nueva_rutina)
        
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

@app.route("/rutina/completar/<id>", methods=["POST"])
def completar_rutina(id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        db.rutinas.update_one(
            {"_id": ObjectId(id), "usuario_id": ObjectId(session["user_id"])},
            {"$set": {"completada": True, "estado": "completada"}}
        )
        
        db.historial_rutinas.update_one(
            {"rutina_id": ObjectId(id), "usuario_id": ObjectId(session["user_id"])},
            {"$set": {
                "estado": "completada",
                "fecha_completada": datetime.now()
            }}
        )
        
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

@app.route("/historial-rutinas")
def historial_rutinas():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    historial = list(db.historial_rutinas.find(
        {"usuario_id": ObjectId(session["user_id"])}
    ).sort("fecha_creacion", -1))
    
    for item in historial:
        item['_id'] = str(item['_id'])
        item['usuario_id'] = str(item['usuario_id'])
        if 'rutina_id' in item:
            item['rutina_id'] = str(item['rutina_id'])
    
    return render_template("historial_rutinas.html", historial=historial)

@app.route("/historial-rutinas-data")
def historial_rutinas_data():
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        historial = list(db.historial_rutinas.find(
            {"usuario_id": ObjectId(session["user_id"])}
        ).sort("fecha_creacion", -1))
        
        for item in historial:
            item['_id'] = str(item['_id'])
            item['usuario_id'] = str(item['usuario_id'])
            if 'rutina_id' in item:
                item['rutina_id'] = str(item['rutina_id'])
        
        return jsonify({"success": True, "rutinas": historial})
    
    except Exception as e:
        print(f"Error al obtener historial: {e}")
        return jsonify({"success": False, "message": "Error al obtener el historial"})

@app.route("/historial/eliminar/<id>", methods=["POST"])
def eliminar_historial(id):
    if 'user_id' not in session:
        return jsonify({"success": False, "message": "Usuario no autenticado"})
    
    try:
        historial_item = db.historial_rutinas.find_one({
            "_id": ObjectId(id),
            "usuario_id": ObjectId(session["user_id"])
        })
        
        if historial_item:
            rutina_id = historial_item.get('rutina_id')
            
            resultado_historial = db.historial_rutinas.delete_one({
                "_id": ObjectId(id),
                "usuario_id": ObjectId(session["user_id"])
            })
            
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
            rutina['_id'] = str(rutina['_id'])
            rutina['usuario_id'] = str(rutina['usuario_id'])
            return jsonify({"success": True, "rutina": rutina})
        else:
            return jsonify({"success": False, "message": "Rutina no encontrada"})
    
    except Exception as e:
        print(f"Error al obtener rutina: {e}")
        return jsonify({"success": False, "message": "Error al obtener la rutina"})

if __name__ == "__main__":
    app.run(debug=True)

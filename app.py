from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import bcrypt
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'healthy_life_secret_key_2024'

# Configuración de MongoDB Atlas - REEMPLAZA CON TU CADENA DE CONEXIÓN
app.config['MONGO_URI'] = 'mongodb+srv://usuario:password@cluster0.mongodb.net/healthy_life_db?retryWrites=true&w=majority'
mongo = PyMongo(app)

# Función para verificar si el usuario está logueado
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor inicia sesión para acceder a esta página', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Ruta de inicio
@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('home.html')
    return render_template('home.html')

# Ruta del home
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = mongo.db.users.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['user_name'] = user['nombre']
            flash('¡Inicio de sesión exitoso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email o contraseña incorrectos', 'danger')
    
    return render_template('login.html')

# Ruta de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        
        # Verificar si el usuario ya existe
        if mongo.db.users.find_one({'email': email}):
            flash('El email ya está registrado', 'danger')
            return render_template('register.html')
        
        # Crear nuevo usuario
        hashed_password = generate_password_hash(password)
        
        user_id = mongo.db.users.insert_one({
            'nombre': nombre,
            'email': email,
            'password': hashed_password,
            'fecha_registro': datetime.utcnow(),
            'descripcion': '¡Bienvenido a Healthy Life! Comienza tu journey fitness.',
            'especialidad': 'General',
            'etiquetas': ['Fitness', 'Salud']
        }).inserted_id
        
        session['user_id'] = str(user_id)
        session['user_name'] = nombre
        flash('¡Registro exitoso! Bienvenido a Healthy Life', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html')

# Ruta de logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('index'))

# Ruta para crear nueva rutina
@app.route('/nuevo')
@login_required
def nuevo():
    return render_template('nuevo.html')

# Ruta para guardar rutina
@app.route('/rutina/guardar', methods=['POST'])
@login_required
def guardar_rutina():
    try:
        data = request.json
        
        rutina = {
            'usuario_id': ObjectId(session['user_id']),
            'nombre': data['nombre'],
            'descripcion': data.get('descripcion', ''),
            'tipo': data['tipo'],
            'duracion': data['duracion'],
            'ejercicios': data['ejercicios'],
            'fecha_creacion': datetime.utcnow(),
            'completada': False,
            'fecha_completada': None
        }
        
        result = mongo.db.rutinas.insert_one(rutina)
        
        return jsonify({
            'success': True,
            'message': 'Rutina guardada correctamente',
            'rutina_id': str(result.inserted_id)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al guardar la rutina: {str(e)}'
        }), 500

# Ruta para obtener historial de rutinas
@app.route('/historial-rutinas-data')
@login_required
def historial_rutinas_data():
    try:
        rutinas = list(mongo.db.rutinas.find(
            {'usuario_id': ObjectId(session['user_id'])},
            sort=[('fecha_creacion', -1)]
        ))
        
        # Convertir ObjectId a string para JSON
        for rutina in rutinas:
            rutina['_id'] = str(rutina['_id'])
            rutina['usuario_id'] = str(rutina['usuario_id'])
            if rutina.get('fecha_creacion'):
                rutina['fecha_creacion'] = rutina['fecha_creacion'].isoformat()
            if rutina.get('fecha_completada'):
                rutina['fecha_completada'] = rutina['fecha_completada'].isoformat()
        
        return jsonify({
            'success': True,
            'rutinas': rutinas
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al cargar rutinas: {str(e)}'
        }), 500

# Ruta para ver una rutina específica
@app.route('/rutina/<rutina_id>')
@login_required
def ver_rutina(rutina_id):
    try:
        rutina = mongo.db.rutinas.find_one({
            '_id': ObjectId(rutina_id),
            'usuario_id': ObjectId(session['user_id'])
        })
        
        if not rutina:
            return jsonify({
                'success': False,
                'message': 'Rutina no encontrada'
            }), 404
        
        rutina['_id'] = str(rutina['_id'])
        rutina['usuario_id'] = str(rutina['usuario_id'])
        if rutina.get('fecha_creacion'):
            rutina['fecha_creacion'] = rutina['fecha_creacion'].isoformat()
        if rutina.get('fecha_completada'):
            rutina['fecha_completada'] = rutina['fecha_completada'].isoformat()
        
        return jsonify({
            'success': True,
            'rutina': rutina
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al cargar la rutina: {str(e)}'
        }), 500

# Ruta para eliminar rutina
@app.route('/historial/eliminar/<rutina_id>', methods=['POST'])
@login_required
def eliminar_rutina(rutina_id):
    try:
        result = mongo.db.rutinas.delete_one({
            '_id': ObjectId(rutina_id),
            'usuario_id': ObjectId(session['user_id'])
        })
        
        if result.deleted_count == 0:
            return jsonify({
                'success': False,
                'message': 'Rutina no encontrada'
            }), 404
        
        return jsonify({
            'success': True,
            'message': 'Rutina eliminada correctamente'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al eliminar la rutina: {str(e)}'
        }), 500

# Ruta para completar rutina
@app.route('/rutina/completar/<rutina_id>', methods=['POST'])
@login_required
def completar_rutina(rutina_id):
    try:
        result = mongo.db.rutinas.update_one(
            {
                '_id': ObjectId(rutina_id),
                'usuario_id': ObjectId(session['user_id'])
            },
            {
                '$set': {
                    'completada': True,
                    'fecha_completada': datetime.utcnow()
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({
                'success': False,
                'message': 'Rutina no encontrada'
            }), 404
        
        return jsonify({
            'success': True,
            'message': '¡Rutina completada! Buen trabajo'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al completar la rutina: {str(e)}'
        }), 500

# =============================================
# SISTEMA DE NOTAS
# =============================================

@app.route('/notas')
@login_required
def notas():
    return render_template('notas.html')

@app.route('/notas/listar')
@login_required
def listar_notas():
    try:
        notas = list(mongo.db.notas.find(
            {'usuario_id': ObjectId(session['user_id'])},
            sort=[('fecha_creacion', -1)]
        ))
        
        for nota in notas:
            nota['_id'] = str(nota['_id'])
            nota['usuario_id'] = str(nota['usuario_id'])
            if nota.get('fecha_creacion'):
                nota['fecha_creacion'] = nota['fecha_creacion'].isoformat()
            if nota.get('fecha_actualizacion'):
                nota['fecha_actualizacion'] = nota['fecha_actualizacion'].isoformat()
        
        return jsonify({
            'success': True,
            'notas': notas
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al cargar las notas: {str(e)}'
        }), 500

@app.route('/notas/crear', methods=['POST'])
@login_required
def crear_nota():
    try:
        data = request.json
        
        if not data.get('titulo'):
            return jsonify({
                'success': False,
                'message': 'El título es obligatorio'
            }), 400
        
        nota = {
            'usuario_id': ObjectId(session['user_id']),
            'titulo': data['titulo'],
            'descripcion': data.get('descripcion', ''),
            'categoria': data.get('categoria', 'General'),
            'fecha_creacion': datetime.utcnow(),
            'fecha_actualizacion': datetime.utcnow()
        }
        
        result = mongo.db.notas.insert_one(nota)
        
        return jsonify({
            'success': True,
            'message': 'Nota creada correctamente',
            'nota_id': str(result.inserted_id)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al crear la nota: {str(e)}'
        }), 500

@app.route('/notas/obtener/<nota_id>')
@login_required
def obtener_nota(nota_id):
    try:
        nota = mongo.db.notas.find_one({
            '_id': ObjectId(nota_id),
            'usuario_id': ObjectId(session['user_id'])
        })
        
        if not nota:
            return jsonify({
                'success': False,
                'message': 'Nota no encontrada'
            }), 404
        
        nota['_id'] = str(nota['_id'])
        nota['usuario_id'] = str(nota['usuario_id'])
        if nota.get('fecha_creacion'):
            nota['fecha_creacion'] = nota['fecha_creacion'].isoformat()
        if nota.get('fecha_actualizacion'):
            nota['fecha_actualizacion'] = nota['fecha_actualizacion'].isoformat()
        
        return jsonify({
            'success': True,
            'nota': nota
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al cargar la nota: {str(e)}'
        }), 500

@app.route('/notas/editar/<nota_id>', methods=['PUT'])
@login_required
def editar_nota(nota_id):
    try:
        data = request.json
        
        if not data.get('titulo'):
            return jsonify({
                'success': False,
                'message': 'El título es obligatorio'
            }), 400
        
        result = mongo.db.notas.update_one(
            {
                '_id': ObjectId(nota_id),
                'usuario_id': ObjectId(session['user_id'])
            },
            {
                '$set': {
                    'titulo': data['titulo'],
                    'descripcion': data.get('descripcion', ''),
                    'categoria': data.get('categoria', 'General'),
                    'fecha_actualizacion': datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            return jsonify({
                'success': False,
                'message': 'Nota no encontrada'
            }), 404
        
        return jsonify({
            'success': True,
            'message': 'Nota actualizada correctamente'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al actualizar la nota: {str(e)}'
        }), 500

@app.route('/notas/eliminar/<nota_id>', methods=['DELETE'])
@login_required
def eliminar_nota(nota_id):
    try:
        result = mongo.db.notas.delete_one({
            '_id': ObjectId(nota_id),
            'usuario_id': ObjectId(session['user_id'])
        })
        
        if result.deleted_count == 0:
            return jsonify({
                'success': False,
                'message': 'Nota no encontrada'
            }), 404
        
        return jsonify({
            'success': True,
            'message': 'Nota eliminada correctamente'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error al eliminar la nota: {str(e)}'
        }), 500

# =============================================
# SISTEMA DE PERFIL
# =============================================

@app.route('/perfil')
@login_required
def perfil():
    return render_template('perfil.html')

@app.route('/perfil/datos')
@login_required
def perfil_datos():
    try:
        usuario = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        
        if not usuario:
            return jsonify({'success': False, 'message': 'Usuario no encontrado'}), 404
        
        # Obtener estadísticas
        total_rutinas = mongo.db.rutinas.count_documents({'usuario_id': ObjectId(session['user_id'])})
        rutinas_completadas = mongo.db.rutinas.count_documents({
            'usuario_id': ObjectId(session['user_id']),
            'completada': True
        })
        total_notas = mongo.db.notas.count_documents({'usuario_id': ObjectId(session['user_id'])})
        
        # Obtener racha actual (días consecutivos con rutinas completadas)
        hoy = datetime.utcnow().date()
        racha = 0
        for i in range(30):  # Verificar últimos 30 días
            fecha = hoy - timedelta(days=i)
            inicio_dia = datetime.combine(fecha, datetime.min.time())
            fin_dia = datetime.combine(fecha, datetime.max.time())
            
            tiene_rutina = mongo.db.rutinas.count_documents({
                'usuario_id': ObjectId(session['user_id']),
                'fecha_completada': {'$gte': inicio_dia, '$lte': fin_dia},
                'completada': True
            }) > 0
            
            if tiene_rutina:
                racha += 1
            else:
                break
        
        perfil_data = {
            '_id': str(usuario['_id']),
            'nombre': usuario.get('nombre', 'Usuario'),
            'email': usuario.get('email', ''),
            'descripcion': usuario.get('descripcion', ''),
            'especialidad': usuario.get('especialidad', 'General'),
            'etiquetas': usuario.get('etiquetas', []),
            'fecha_registro': usuario.get('fecha_registro', datetime.utcnow()).strftime('%d/%m/%Y'),
            'estadisticas': {
                'total_rutinas': total_rutinas,
                'rutinas_completadas': rutinas_completadas,
                'total_notas': total_notas,
                'racha_actual': racha
            }
        }
        
        return jsonify({'success': True, 'perfil': perfil_data})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/perfil/editar', methods=['POST'])
@login_required
def editar_perfil():
    try:
        data = request.json
        
        update_data = {}
        if 'nombre' in data:
            update_data['nombre'] = data['nombre']
        if 'descripcion' in data:
            update_data['descripcion'] = data['descripcion']
        if 'especialidad' in data:
            update_data['especialidad'] = data['especialidad']
        if 'etiquetas' in data:
            update_data['etiquetas'] = data['etiquetas']
        
        if update_data:
            mongo.db.users.update_one(
                {'_id': ObjectId(session['user_id'])},
                {'$set': update_data}
            )
            
            if 'nombre' in update_data:
                session['user_name'] = update_data['nombre']
        
        return jsonify({'success': True, 'message': 'Perfil actualizado correctamente'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================
# SISTEMA DE RACHA
# =============================================

@app.route('/racha')
@login_required
def racha():
    return render_template('racha.html')

@app.route('/racha/datos')
@login_required
def racha_datos():
    try:
        # Calcular días completados en el último mes
        hoy = datetime.utcnow()
        inicio_mes = datetime(hoy.year, hoy.month, 1)
        
        # Obtener rutinas completadas este mes
        rutinas_completadas = list(mongo.db.rutinas.find({
            'usuario_id': ObjectId(session['user_id']),
            'completada': True,
            'fecha_completada': {'$gte': inicio_mes}
        }))
        
        # Extraer días únicos con rutinas completadas
        dias_completados = list(set([
            rutina['fecha_completada'].strftime('%a %b %d %Y')
            for rutina in rutinas_completadas
            if rutina.get('fecha_completada')
        ]))
        
        # Calcular racha actual
        racha_actual = 0
        for i in range(30):
            fecha = hoy - timedelta(days=i)
            fecha_str = fecha.strftime('%a %b %d %Y')
            
            if fecha_str in dias_completados:
                racha_actual += 1
            else:
                break
        
        # Calcular récord personal (máxima racha)
        todas_rutinas = list(mongo.db.rutinas.find({
            'usuario_id': ObjectId(session['user_id']),
            'completada': True
        }, sort=[('fecha_completada', 1)]))
        
        record_personal = 0
        racha_temporal = 0
        fecha_anterior = None
        
        for rutina in todas_rutinas:
            if rutina.get('fecha_completada'):
                if fecha_anterior and (rutina['fecha_completada'] - fecha_anterior).days == 1:
                    racha_temporal += 1
                else:
                    racha_temporal = 1
                
                record_personal = max(record_personal, racha_temporal)
                fecha_anterior = rutina['fecha_completada']
        
        datos_racha = {
            'diasConsecutivos': racha_actual,
            'recordPersonal': record_personal,
            'diasCompletados': dias_completados,
            'fechaUltimoDia': todas_rutinas[-1]['fecha_completada'].isoformat() if todas_rutinas else None
        }
        
        return jsonify({'success': True, 'racha': datos_racha})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/racha/marcar-dia', methods=['POST'])
@login_required
def marcar_dia_racha():
    try:
        # Para marcar un día, el usuario debe tener al menos una rutina completada hoy
        hoy = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        manana = hoy + timedelta(days=1)
        
        rutinas_hoy = mongo.db.rutinas.count_documents({
            'usuario_id': ObjectId(session['user_id']),
            'completada': True,
            'fecha_completada': {'$gte': hoy, '$lt': manana}
        })
        
        if rutinas_hoy > 0:
            return jsonify({
                'success': True, 
                'message': '¡Día marcado correctamente! Ya tienes rutinas completadas hoy.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Completa al menos una rutina hoy para marcar el día en tu racha.'
            })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================
# OTRAS RUTAS
# =============================================

@app.route('/ayuda')
@login_required
def ayuda():
    return render_template('ayuda.html')

@app.route('/configuracion')
@login_required
def configuracion():
    return render_template('configuracion.html')

@app.route('/exportar-datos')
@login_required
def exportar_datos():
    try:
        user_id = ObjectId(session['user_id'])
        
        # Obtener todos los datos del usuario
        usuario = mongo.db.users.find_one({'_id': user_id})
        rutinas = list(mongo.db.rutinas.find({'usuario_id': user_id}))
        notas = list(mongo.db.notas.find({'usuario_id': user_id}))
        
        datos_exportar = {
            'usuario': {
                'nombre': usuario.get('nombre'),
                'email': usuario.get('email'),
                'fecha_registro': usuario.get('fecha_registro').isoformat() if usuario.get('fecha_registro') else None
            },
            'rutinas': [
                {
                    'nombre': r['nombre'],
                    'tipo': r['tipo'],
                    'duracion': r['duracion'],
                    'ejercicios': r['ejercicios'],
                    'fecha_creacion': r['fecha_creacion'].isoformat() if r.get('fecha_creacion') else None,
                    'completada': r.get('completada', False)
                }
                for r in rutinas
            ],
            'notas': [
                {
                    'titulo': n['titulo'],
                    'descripcion': n['descripcion'],
                    'categoria': n['categoria'],
                    'fecha_creacion': n['fecha_creacion'].isoformat() if n.get('fecha_creacion') else None
                }
                for n in notas
            ],
            'fecha_exportacion': datetime.utcnow().isoformat()
        }
        
        return jsonify(datos_exportar)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/eliminar-cuenta', methods=['DELETE'])
@login_required
def eliminar_cuenta():
    try:
        user_id = ObjectId(session['user_id'])
        
        # Eliminar todos los datos del usuario
        mongo.db.rutinas.delete_many({'usuario_id': user_id})
        mongo.db.notas.delete_many({'usuario_id': user_id})
        mongo.db.users.delete_one({'_id': user_id})
        
        session.clear()
        
        return jsonify({'success': True, 'message': 'Cuenta eliminada correctamente'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/historial_rutinas')
@login_required
def historial_rutinas():
    return render_template('historial_rutinas.html')

# Context processor para agregar variables globales
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

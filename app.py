from flask import Flask, render_template, request, redirect, url_for, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
import os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://lalo:EduLC@5bpv.kcdyemv.mongodb.net/escuela")

try:
    client = MongoClient(
        MONGO_URI,
        tls=True,
        tlsAllowInvalidCertificates=False,
        serverSelectionTimeoutMS=10000
    )
    db = client.get_default_database()
    print("Conexión segura establecida con MongoDB Atlas")
except Exception as e:
    print("Conexión segura falló, intentando modo escolar...")
    try:
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsAllowInvalidCertificates=True,
            serverSelectionTimeoutMS=10000
        )
        db = client.get_default_database()
        print(" Conexión establecida con MongoDB Atlas (modo escolar sin SSL)")
    except Exception as e:
        db = None
        print(" No se pudo conectar con MongoDB Atlas:", e)

@app.route("/")
def index():
    if db is None:
        flash("Error al obtener datos: la base de datos no está conectada.", "danger")
        return render_template("index.html", datos=[])
    try:
        datos = db.rutinas.find()
    except Exception as e:
        flash(f"Error al obtener datos: {e}", "danger")
        datos = []
    return render_template("index.html", datos=datos)

@app.route("/new", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        tipo = request.form.get("tipo", "").strip()
        duracion = request.form.get("duracion", "").strip()
        frecuencia = request.form.get("frecuencia", "").strip()
        nivel = request.form.get("nivel", "").strip()
        descripcion = request.form.get("descripcion", "").strip()

        if not nombre or not tipo or not duracion:
            flash("Completa los campos obligatorios.", "danger")
            return redirect(url_for("create"))

        if db is not None:
            db.rutinas.insert_one({
                "nombre": nombre,
                "tipo": tipo,
                "duracion": duracion,
                "frecuencia": frecuencia,
                "nivel": nivel,
                "descripcion": descripcion
            })
            flash("Rutina creada correctamente.", "success")
        else:
            flash("Error: Base de datos no conectada.", "danger")

        return redirect(url_for("index"))
    return render_template("create.html")

@app.route("/view/<id>")
def view(id):
    if db is None:
        flash("Base de datos no conectada.", "danger")
        return redirect(url_for("index"))
    dato = db.rutinas.find_one({"_id": ObjectId(id)})
    if not dato:
        flash("Rutina no encontrada.", "warning")
        return redirect(url_for("index"))
    return render_template("view.html", dato=dato)

@app.route("/edit/<id>", methods=["GET", "POST"])
def edit(id):
    if db is None:
        flash("Base de datos no conectada.", "danger")
        return redirect(url_for("index"))
    dato = db.rutinas.find_one({"_id": ObjectId(id)})
    if not dato:
        flash("Rutina no encontrada.", "warning")
        return redirect(url_for("index"))

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        tipo = request.form.get("tipo", "").strip()
        duracion = request.form.get("duracion", "").strip()
        frecuencia = request.form.get("frecuencia", "").strip()
        nivel = request.form.get("nivel", "").strip()
        descripcion = request.form.get("descripcion", "").strip()

        if not nombre or not tipo or not duracion:
            flash("Completa los campos obligatorios.", "danger")
            return redirect(url_for("edit", id=id))

        db.rutinas.update_one(
            {"_id": ObjectId(id)},
            {"$set": {
                "nombre": nombre,
                "tipo": tipo,
                "duracion": duracion,
                "frecuencia": frecuencia,
                "nivel": nivel,
                "descripcion": descripcion
            }}
        )
        flash("Rutina actualizada correctamente.", "info")
        return redirect(url_for("index"))

    return render_template("edit.html", dato=dato)

@app.route("/delete/<id>", methods=["POST"])
def delete(id):
    if db is None:
        flash("Base de datos no conectada.", "danger")
        return redirect(url_for("index"))
    db.rutinas.delete_one({"_id": ObjectId(id)})
    flash("Rutina eliminada correctamente.", "secondary")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
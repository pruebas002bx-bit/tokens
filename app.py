import os
import hmac
import hashlib
import time
from flask import Flask, request, jsonify, render_template_string, redirect
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# --- CONFIGURACIÓN (Variables de Entorno) ---
# Render inyectará estos valores automáticamente desde lo que configuraste en el dashboard
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", "26367") # Puerto por defecto Aiven Postgres
SECRET_KEY = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4").encode()

# --- CONEXIÓN BASE DE DATOS (PostgreSQL) ---
def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        dbname=DB_NAME,
        port=DB_PORT,
        sslmode='require' # Obligatorio para Aiven
    )

# --- SEGURIDAD ANTI-PIRATERÍA ---
def verify_signature(hwid, timestamp, received_sig):
    # 1. Evitar ataques de repetición (Replay Attack) - 5 minutos de tolerancia
    if abs(time.time() - float(timestamp)) > 300:
        return False
    
    # 2. Reconstruir la firma esperada
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    
    # 3. Comparar firmas de forma segura
    return hmac.compare_digest(expected_sig, received_sig)

# ================= RUTAS DE LA APLICACIÓN =================

# 1. RUTA RAÍZ (Redirección Automática)
@app.route('/')
def home():
    return redirect('/admin/panel')

# 2. API PARA EL SOFTWARE (Cliente Desktop)
@app.route('/api/check_tokens', methods=['POST'])
def check_tokens():
    try:
        data = request.json
        hwid = data.get('hwid')
        timestamp = data.get('timestamp')
        signature = data.get('signature')
        token_type = data.get('type') # 'supervigilancia' o 'practica'

        # Verificar autenticidad
        if not verify_signature(hwid, timestamp, signature):
            return jsonify({"status": "error", "msg": "Firma de seguridad inválida"}), 403

        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Buscar la máquina por HWID
                cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
                client = cursor.fetchone()

                if not client:
                    return jsonify({"status": "error", "msg": "Máquina no registrada"}), 404

                # Verificar saldo del tipo de token solicitado
                columna_token = f'tokens_{token_type}'
                current_tokens = client.get(columna_token, 0)

                if current_tokens > 0:
                    # Descontar 1 token
                    new_tokens = current_tokens - 1
                    cursor.execute(f"UPDATE clientes SET {columna_token} = %s WHERE hwid = %s", (new_tokens, hwid))
                    conn.commit()
                    return jsonify({"status": "success", "remaining": new_tokens, "type": token_type})
                else:
                    # Sin saldo
                    return jsonify({"status": "denied", "msg": "Sin saldo disponible", "type": token_type}), 402
        finally:
            conn.close()

    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

# 3. PANEL DE ADMINISTRACIÓN (Tu Interfaz Web)
@app.route('/admin/panel')
def admin_panel():
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            clients = cursor.fetchall()
        conn.close()
    except Exception as e:
        return f"Error conectando a BD: {e}"
    
    # HTML simple embebido
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Panel Alfa Security</title>
        <style>
            body{font-family:'Segoe UI', sans-serif; padding:20px; background-color:#f4f4f9;}
            h1{color:#333;}
            table{border-collapse:collapse; width:100%; background:white; box-shadow:0 1px 3px rgba(0,0,0,0.2);}
            th,td{border:1px solid #ddd; padding:12px; text-align:left;}
            th{background-color:#007bff; color:white;}
            tr:nth-child(even){background-color:#f2f2f2;}
            input,select{padding:8px; border:1px solid #ccc; border-radius:4px;}
            button{padding:8px 12px; border:none; border-radius:4px; cursor:pointer; font-weight:bold;}
            .btn-add{background-color:#28a745; color:white;}
            .btn-reg{background-color:#007bff; color:white;}
            .container{max-width:1200px; margin:0 auto;}
            .card{background:white; padding:20px; margin-bottom:20px; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.1);}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Panel de Control - Alfa Security Tokens</h1>
            
            <div class="card">
                <h3>Registrar Nueva Escuela / Máquina</h3>
                <form action="/admin/register" method="post" style="display:flex; gap:10px;">
                    <input type="text" name="nombre" placeholder="Nombre de la Escuela" required style="flex:1;">
                    <input type="text" name="hwid" placeholder="HWID (Huella de Hardware)" required style="flex:2;">
                    <button type="submit" class="btn-reg">Registrar Cliente</button>
                </form>
            </div>

            <div class="card">
                <h3>Clientes Activos</h3>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Escuela / Cliente</th>
                        <th>HWID</th>
                        <th>Tokens Supervigilancia</th>
                        <th>Tokens Práctica</th>
                        <th>Recargar Saldo</th>
                    </tr>
                    {% for c in clients %}
                    <tr>
                        <td>{{ c.id }}</td>
                        <td><strong>{{ c.nombre }}</strong></td>
                        <td><small style="font-family:monospace;">{{ c.hwid }}</small></td>
                        <td style="color: {% if c.tokens_supervigilancia > 0 %}green{% else %}red{% endif %}; font-weight:bold;">
                            {{ c.tokens_supervigilancia }}
                        </td>
                        <td style="color: {% if c.tokens_practica > 0 %}green{% else %}red{% endif %}; font-weight:bold;">
                            {{ c.tokens_practica }}
                        </td>
                        <td>
                            <form action="/admin/add_tokens" method="post" style="display:flex; gap:5px;">
                                <input type="hidden" name="hwid" value="{{ c.hwid }}">
                                <input type="number" name="amount" placeholder="#" style="width:60px;" required>
                                <select name="type">
                                    <option value="supervigilancia">Supervigilancia</option>
                                    <option value="practica">Práctica</option>
                                </select>
                                <button type="submit" class="btn-add">+</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html, clients=clients)

# 4. PROCESO DE RECARGA (POST)
@app.route('/admin/add_tokens', methods=['POST'])
def add_tokens():
    hwid = request.form['hwid']
    amount = int(request.form['amount'])
    t_type = request.form['type'] # 'supervigilancia' o 'practica'
    
    columna = f"tokens_{t_type}"
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Sumar tokens a la cantidad actual
            cursor.execute(f"UPDATE clientes SET {columna} = {columna} + %s WHERE hwid = %s", (amount, hwid))
            conn.commit()
    finally:
        conn.close()
    
    return redirect('/admin/panel')

# 5. PROCESO DE REGISTRO (POST)
@app.route('/admin/register', methods=['POST'])
def register():
    nombre = request.form['nombre']
    hwid = request.form['hwid']
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO clientes (nombre, hwid, tokens_supervigilancia, tokens_practica) VALUES (%s, %s, 0, 0)", 
                (nombre, hwid)
            )
            conn.commit()
    except Exception as e:
        return f"Error al registrar (¿HWID duplicado?): {e}"
    finally:
        conn.close()
        
    return redirect('/admin/panel')

if __name__ == '__main__':
    # Ejecutar en puerto local (Render ignora esto y usa Gunicorn, pero sirve para test local)
    app.run(host='0.0.0.0', port=10000)
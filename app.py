import os
import hmac
import hashlib
import time
from flask import Flask, request, jsonify, render_template_string, redirect
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# --- CONFIGURACIÓN DE BASE DE DATOS ---
# Recogemos las variables. Si pegaste la URL completa en DB_HOST, el código lo detectará.
DB_HOST = os.getenv("DB_HOST") 
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", "26367")
SECRET_KEY = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4").encode()

# --- CONEXIÓN INTELIGENTE (SOLUCIÓN A TU ERROR) ---
def get_db_connection():
    # CASO A: Si DB_HOST es la URL larga (postgres://...), la usamos directamente
    if DB_HOST and (DB_HOST.startswith("postgres://") or DB_HOST.startswith("postgresql://")):
        return psycopg2.connect(DB_HOST, sslmode='require')
    
    # CASO B: Si DB_HOST es solo el dominio (pg-xxx.aivencloud.com), usamos los campos separados
    else:
        return psycopg2.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            dbname=DB_NAME,
            port=DB_PORT,
            sslmode='require'
        )

# --- SEGURIDAD ANTI-PIRATERÍA ---
def verify_signature(hwid, timestamp, received_sig):
    if abs(time.time() - float(timestamp)) > 300:
        return False
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# ================= RUTAS =================

@app.route('/')
def home():
    return redirect('/admin/panel')

@app.route('/api/check_tokens', methods=['POST'])
def check_tokens():
    try:
        data = request.json
        hwid = data.get('hwid')
        timestamp = data.get('timestamp')
        signature = data.get('signature')
        token_type = data.get('type') 

        if not verify_signature(hwid, timestamp, signature):
            return jsonify({"status": "error", "msg": "Firma inválida"}), 403

        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
                client = cursor.fetchone()

                if not client:
                    return jsonify({"status": "error", "msg": "Máquina no registrada"}), 404

                columna = f"tokens_{token_type}"
                # Verificar que la columna exista (seguridad extra)
                if columna not in client:
                     return jsonify({"status": "error", "msg": f"Tipo de token inválido: {token_type}"}), 400

                current_tokens = client[columna]

                if current_tokens > 0:
                    new_tokens = current_tokens - 1
                    # Usamos inyección segura de SQL para el nombre de la columna
                    query = f"UPDATE clientes SET {columna} = %s WHERE hwid = %s"
                    cursor.execute(query, (new_tokens, hwid))
                    conn.commit()
                    return jsonify({"status": "success", "remaining": new_tokens, "type": token_type})
                else:
                    return jsonify({"status": "denied", "msg": "Sin saldo", "type": token_type}), 402
        finally:
            conn.close()

    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route('/admin/panel')
def admin_panel():
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            clients = cursor.fetchall()
        conn.close()
    except Exception as e:
        return f"<h1>Error de Conexión a Base de Datos</h1><p>{e}</p>"
    
    html = """
    <style>body{font-family:sans-serif; padding:20px; background:#f4f4f9;} h1{color:#333;} table{border-collapse:collapse; width:100%; background:white; box-shadow:0 1px 3px rgba(0,0,0,0.1);} th,td{border:1px solid #ddd; padding:12px; text-align:left;} th{background-color:#007bff; color:white;} tr:nth-child(even){background-color:#f9f9f9;} input,select{padding:8px; border:1px solid #ccc; border-radius:4px;} button{padding:8px 12px; border:none; border-radius:4px; cursor:pointer; font-weight:bold;} .btn-add{background-color:#28a745; color:white;} .btn-reg{background-color:#007bff; color:white;} .card{background:white; padding:20px; margin-bottom:20px; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.1);}</style>
    
    <div style="max-width:1200px; margin:0 auto;">
        <h1>🛡️ Panel Alfa Security</h1>
        
        <div class="card">
            <h3>Registrar Nueva Escuela</h3>
            <form action="/admin/register" method="post" style="display:flex; gap:10px;">
                <input type="text" name="nombre" placeholder="Nombre Escuela" required style="flex:1;">
                <input type="text" name="hwid" placeholder="HWID Cliente" required style="flex:2;">
                <button type="submit" class="btn-reg">Registrar</button>
            </form>
        </div>

        <div class="card">
            <h3>Clientes Activos</h3>
            <table>
                <tr><th>ID</th><th>Escuela</th><th>HWID</th><th>S.Vigilancia</th><th>Práctica</th><th>Recargar</th></tr>
                {% for c in clients %}
                <tr>
                    <td>{{ c.id }}</td>
                    <td><b>{{ c.nombre }}</b></td>
                    <td><small style="font-family:monospace">{{ c.hwid }}</small></td>
                    <td style="color:{% if c.tokens_supervigilancia > 0 %}green{% else %}red{% endif %}"><b>{{ c.tokens_supervigilancia }}</b></td>
                    <td style="color:{% if c.tokens_practica > 0 %}green{% else %}red{% endif %}"><b>{{ c.tokens_practica }}</b></td>
                    <td>
                        <form action="/admin/add_tokens" method="post" style="margin:0; display:flex; gap:5px;">
                            <input type="hidden" name="hwid" value="{{ c.hwid }}">
                            <input type="number" name="amount" placeholder="#" style="width:60px;" required>
                            <select name="type">
                                <option value="supervigilancia">Super</option>
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
    """
    return render_template_string(html, clients=clients)

@app.route('/admin/add_tokens', methods=['POST'])
def add_tokens():
    try:
        hwid = request.form['hwid']
        amount = int(request.form['amount'])
        t_type = request.form['type']
        
        columna = f"tokens_{t_type}"
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            query = f"UPDATE clientes SET {columna} = {columna} + %s WHERE hwid = %s"
            cursor.execute(query, (amount, hwid))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"Error agregando tokens: {e}"

@app.route('/admin/register', methods=['POST'])
def register():
    try:
        nombre = request.form['nombre']
        hwid = request.form['hwid']
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO clientes (nombre, hwid, tokens_supervigilancia, tokens_practica) VALUES (%s, %s, 0, 0)", (nombre, hwid))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"Error registrando (posible HWID duplicado): {e}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
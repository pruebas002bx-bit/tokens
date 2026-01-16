import os
import hmac
import hashlib
import time
from flask import Flask, request, jsonify, render_template_string
import pymysql

app = Flask(__name__)

# --- CONFIGURACIÓN (Variables de Entorno en Render) ---
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = int(os.getenv("DB_PORT", 3306))
SECRET_KEY = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4").encode()

# --- CONEXIÓN BD ---
def get_db_connection():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, port=DB_PORT, cursorclass=pymysql.cursors.DictCursor)

# --- SEGURIDAD ---
def verify_signature(hwid, timestamp, received_sig):
    # Evitar ataques de repetición (Replay Attack) - 5 minutos de tolerancia
    if abs(time.time() - float(timestamp)) > 300:
        return False
    
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# --- API PARA EL SOFTWARE (CLIENTE) ---
@app.route('/api/check_tokens', methods=['POST'])
def check_tokens():
    data = request.json
    hwid = data.get('hwid')
    timestamp = data.get('timestamp')
    signature = data.get('signature')
    token_type = data.get('type') # 'supervigilancia' o 'practica'

    if not verify_signature(hwid, timestamp, signature):
        return jsonify({"status": "error", "msg": "Firma inválida o reloj desincronizado"}), 403

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Buscar cliente
            cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()

            if not client:
                # Auto-registro (Opcional: o devolver error si no está registrado)
                return jsonify({"status": "error", "msg": "Máquina no registrada"}), 404

            current_tokens = client[f'tokens_{token_type}']

            if current_tokens > 0:
                # DESCONTAR TOKEN
                new_tokens = current_tokens - 1
                cursor.execute(f"UPDATE clientes SET tokens_{token_type} = %s WHERE hwid = %s", (new_tokens, hwid))
                conn.commit()
                return jsonify({"status": "success", "remaining": new_tokens, "type": token_type})
            else:
                return jsonify({"status": "denied", "msg": "Sin saldo", "type": token_type}), 402
    finally:
        conn.close()

# --- PANEL ADMIN (TU INTERFAZ WEB) ---
# En Render configuras usuario/pass básico para entrar aquí
@app.route('/admin/panel')
def admin_panel():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM clientes")
        clients = cursor.fetchall()
    conn.close()
    
    html = """
    <h1>Panel Alfa Security - Control de Tokens</h1>
    <table border="1">
        <tr><th>ID</th><th>Nombre Escuela</th><th>HWID</th><th>Tokens Supervigilancia</th><th>Tokens Práctica</th><th>Acción</th></tr>
        {% for c in clients %}
        <tr>
            <td>{{ c.id }}</td>
            <td>{{ c.nombre }}</td>
            <td>{{ c.hwid }}</td>
            <td>{{ c.tokens_supervigilancia }}</td>
            <td>{{ c.tokens_practica }}</td>
            <td>
                <form action="/admin/add_tokens" method="post">
                    <input type="hidden" name="hwid" value="{{ c.hwid }}">
                    <input type="number" name="amount" placeholder="Cantidad">
                    <select name="type">
                        <option value="supervigilancia">Supervigilancia</option>
                        <option value="practica">Práctica</option>
                    </select>
                    <button type="submit">Recargar</button>
                </form>
            </td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Registrar Nueva Máquina</h2>
    <form action="/admin/register" method="post">
        <input type="text" name="nombre" placeholder="Nombre Escuela">
        <input type="text" name="hwid" placeholder="HWID del Cliente">
        <button type="submit">Registrar</button>
    </form>
    """
    return render_template_string(html, clients=clients)

@app.route('/admin/add_tokens', methods=['POST'])
def add_tokens():
    hwid = request.form['hwid']
    amount = int(request.form['amount'])
    t_type = request.form['type']
    
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(f"UPDATE clientes SET tokens_{t_type} = tokens_{t_type} + %s WHERE hwid = %s", (amount, hwid))
        conn.commit()
    conn.close()
    return "Recarga Exitosa <a href='/admin/panel'>Volver</a>"

@app.route('/admin/register', methods=['POST'])
def register():
    nombre = request.form['nombre']
    hwid = request.form['hwid']
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("INSERT INTO clientes (nombre, hwid, tokens_supervigilancia, tokens_practica) VALUES (%s, %s, 0, 0)", (nombre, hwid))
        conn.commit()
    conn.close()
    return "Registro Exitoso <a href='/admin/panel'>Volver</a>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
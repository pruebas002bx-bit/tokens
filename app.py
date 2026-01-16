import os
import hmac
import hashlib
import time
from flask import Flask, request, jsonify, render_template_string
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# --- CONFIGURACIÓN (Variables de Entorno) ---
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", "26367")
SECRET_KEY = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4").encode()

# --- CONEXIÓN BD (PostgreSQL) ---
def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        dbname=DB_NAME,
        port=DB_PORT,
        sslmode='require'
    )

# --- SEGURIDAD ---
def verify_signature(hwid, timestamp, received_sig):
    if abs(time.time() - float(timestamp)) > 300:
        return False
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# --- API ---
@app.route('/api/check_tokens', methods=['POST'])
def check_tokens():
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

            current_tokens = client[f'tokens_{token_type}']

            if current_tokens > 0:
                new_tokens = current_tokens - 1
                cursor.execute(f"UPDATE clientes SET tokens_{token_type} = %s WHERE hwid = %s", (new_tokens, hwid))
                conn.commit()
                return jsonify({"status": "success", "remaining": new_tokens, "type": token_type})
            else:
                return jsonify({"status": "denied", "msg": "Sin saldo", "type": token_type}), 402
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500
    finally:
        conn.close()

# --- PANEL ADMIN ---
@app.route('/admin/panel')
def admin_panel():
    conn = get_db_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
        clients = cursor.fetchall()
    conn.close()
    
    html = """
    <style>body{font-family:sans-serif; padding:20px;} table{border-collapse:collapse; width:100%;} th,td{border:1px solid #ddd; padding:8px; text-align:left;} th{background-color:#f2f2f2;} input,select,button{padding:5px;}</style>
    <h1>Panel Alfa Security (PostgreSQL)</h1>
    <table>
        <tr><th>ID</th><th>Escuela</th><th>HWID</th><th>Tokens Supervigilancia</th><th>Tokens Práctica</th><th>Recargar</th></tr>
        {% for c in clients %}
        <tr>
            <td>{{ c.id }}</td>
            <td>{{ c.nombre }}</td>
            <td><small>{{ c.hwid }}</small></td>
            <td><b>{{ c.tokens_supervigilancia }}</b></td>
            <td><b>{{ c.tokens_practica }}</b></td>
            <td>
                <form action="/admin/add_tokens" method="post" style="margin:0;">
                    <input type="hidden" name="hwid" value="{{ c.hwid }}">
                    <input type="number" name="amount" placeholder="#" style="width:50px;" required>
                    <select name="type">
                        <option value="supervigilancia">Super</option>
                        <option value="practica">Práctica</option>
                    </select>
                    <button type="submit" style="background:#4CAF50; color:white; border:none; cursor:pointer;">+</button>
                </form>
            </td>
        </tr>
        {% endfor %}
    </table>
    
    <h3>Registrar Nueva Máquina</h3>
    <form action="/admin/register" method="post" style="background:#f9f9f9; padding:15px; border:1px solid #ddd;">
        <input type="text" name="nombre" placeholder="Nombre Escuela" required>
        <input type="text" name="hwid" placeholder="HWID del Cliente" required style="width:300px;">
        <button type="submit" style="background:#008CBA; color:white; border:none; cursor:pointer; padding:5px 15px;">Registrar</button>
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
    return "<script>window.location.href='/admin/panel';</script>"

@app.route('/admin/register', methods=['POST'])
def register():
    nombre = request.form['nombre']
    hwid = request.form['hwid']
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("INSERT INTO clientes (nombre, hwid, tokens_supervigilancia, tokens_practica) VALUES (%s, %s, 0, 0)", (nombre, hwid))
        conn.commit()
    conn.close()
    return "<script>window.location.href='/admin/panel';</script>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
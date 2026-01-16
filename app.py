import os
import hmac
import hashlib
import time
import datetime
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# --- CONFIGURACIÓN ---
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", "26367")
SECRET_KEY = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4").encode()

# --- CONEXIÓN BD ---
def get_db_connection():
    if DB_HOST and (DB_HOST.startswith("postgres://") or DB_HOST.startswith("postgresql://")):
        return psycopg2.connect(DB_HOST, sslmode='require')
    else:
        return psycopg2.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME, port=DB_PORT, sslmode='require'
        )

# --- SEGURIDAD ---
def verify_signature(hwid, timestamp, received_sig):
    if abs(time.time() - float(timestamp)) > 300: return False
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# ================= LÓGICA DEL SISTEMA =================

# 1. API: CONSUMO DE TOKENS DESDE EL SOFTWARE
@app.route('/api/check_tokens', methods=['POST'])
def check_tokens():
    try:
        data = request.json
        hwid = data.get('hwid')
        timestamp = data.get('timestamp')
        signature = data.get('signature')
        token_type = data.get('type', 'practica')

        if not verify_signature(hwid, timestamp, signature):
            return jsonify({"status": "error", "msg": "Firma inválida"}), 403

        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
                client = cursor.fetchone()

                if not client:
                    return jsonify({"status": "error", "msg": "No registrado"}), 404

                col = f"tokens_{token_type}"
                if client.get(col, 0) > 0:
                    # 1. Descontar
                    cursor.execute(f"UPDATE clientes SET {col} = {col} - 1 WHERE hwid = %s", (hwid,))
                    
                    # 2. Guardar en Historial
                    cursor.execute("""
                        INSERT INTO historial (hwid, accion, cantidad, tipo_token)
                        VALUES (%s, 'CONSUMO', -1, %s)
                    """, (hwid, token_type))
                    
                    conn.commit()
                    
                    # Obtener saldo nuevo
                    cursor.execute(f"SELECT {col} FROM clientes WHERE hwid = %s", (hwid,))
                    new_bal = cursor.fetchone()[col]
                    
                    return jsonify({"status": "success", "remaining": new_bal, "type": token_type})
                else:
                    return jsonify({"status": "denied", "msg": "Sin saldo", "type": token_type}), 402
        finally:
            conn.close()
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

# ================= INTERFAZ WEB (PANEL) =================

# ESTILOS CSS (TEMA TACTICAL BLACK/RED)
CSS_STYLE = """
<style>
    :root { --bg: #0f0f0f; --card: #1a1a1a; --border: #333; --red: #b91c1c; --red-hover: #dc2626; --text: #eee; --text-dim: #888; }
    body { background-color: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }
    h1, h2, h3 { color: var(--text); font-weight: 800; text-transform: uppercase; letter-spacing: 1px; }
    h1 span { color: var(--red); }
    
    .container { max-width: 1200px; margin: 0 auto; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    .card-header { border-bottom: 2px solid var(--red); padding-bottom: 10px; margin-bottom: 15px; font-size: 1.2rem; font-weight: bold; }
    
    /* TABLAS */
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th { text-align: left; padding: 12px; background: #252525; color: var(--text-dim); font-size: 0.9rem; text-transform: uppercase; }
    td { padding: 12px; border-bottom: 1px solid var(--border); }
    tr:hover { background: #222; }
    
    /* INPUTS & BOTONES */
    input, select { background: #000; border: 1px solid #444; color: white; padding: 8px; border-radius: 4px; font-family: monospace; }
    input:focus { border-color: var(--red); outline: none; }
    
    button { cursor: pointer; font-weight: bold; padding: 8px 15px; border-radius: 4px; border: none; transition: 0.2s; }
    .btn-action { background: var(--red); color: white; }
    .btn-action:hover { background: var(--red-hover); }
    .btn-hist { background: #333; color: #ccc; text-decoration: none; padding: 6px 10px; border-radius: 4px; font-size: 0.8rem; }
    .btn-hist:hover { background: #555; color: white; }
    
    /* UTILIDADES */
    .badge { padding: 3px 8px; border-radius: 10px; font-size: 0.8rem; font-weight: bold; }
    .badge-green { background: #064e3b; color: #6ee7b7; }
    .badge-red { background: #450a0a; color: #fca5a5; }
    .flex-row { display: flex; gap: 10px; align-items: center; }
    .hwid-font { font-family: monospace; color: var(--text-dim); font-size: 0.85rem; }
    .logo-area { display: flex; align-items: center; gap: 15px; margin-bottom: 30px; }
    .back-link { display: inline-block; margin-bottom: 15px; color: var(--text-dim); text-decoration: none; }
    .back-link:hover { color: var(--red); }
</style>
"""

@app.route('/')
def home():
    return redirect('/admin/panel')

@app.route('/admin/panel')
def admin_panel():
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Ordenar clientes por ID descendente
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            clients = cursor.fetchall()
            
            # Estadísticas rápidas
            cursor.execute("SELECT SUM(tokens_practica) as tp, SUM(tokens_supervigilancia) as ts FROM clientes")
            stats = cursor.fetchone()
    finally:
        conn.close()

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Alpha Security - Command Center</title>{CSS_STYLE}</head>
    <body>
        <div class="container">
            <div class="logo-area">
                <h1>ALPHA <span>SECURITY</span></h1>
                <div style="margin-left: auto; text-align: right; font-size: 0.9rem; color: #666;">
                    TOKENS EN CIRCULACIÓN<br>
                    PRÁCTICA: <b style="color:white">{stats['tp'] or 0}</b> | SUPER: <b style="color:white">{stats['ts'] or 0}</b>
                </div>
            </div>

            <div class="card">
                <div class="card-header">NUEVA LICENCIA</div>
                <form action="/admin/register" method="post" class="flex-row">
                    <input type="text" name="nombre" placeholder="Nombre Escuela / Cliente" required style="flex:1">
                    <input type="text" name="hwid" placeholder="HWID (Hardware ID)" required style="flex:2">
                    <button type="submit" class="btn-action">REGISTRAR SISTEMA</button>
                </form>
            </div>

            <div class="card">
                <div class="card-header">CLIENTES ACTIVOS</div>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>CLIENTE</th>
                            <th>SALDO PRÁCTICA</th>
                            <th>SALDO SUPERV.</th>
                            <th>GESTIÓN / RECARGA</th>
                            <th>AUDITORÍA</th>
                        </tr>
                    </thead>
                    <tbody>
                    {''.join([f"""
                        <tr>
                            <td><span style="color:#555">#{c['id']}</span></td>
                            <td>
                                <b>{c['nombre']}</b><br>
                                <span class="hwid-font">{c['hwid']}</span>
                            </td>
                            <td>
                                <span class="badge { 'badge-green' if c['tokens_practica'] > 0 else 'badge-red' }">
                                    {c['tokens_practica']}
                                </span>
                            </td>
                            <td>
                                <span class="badge { 'badge-green' if c['tokens_supervigilancia'] > 0 else 'badge-red' }">
                                    {c['tokens_supervigilancia']}
                                </span>
                            </td>
                            <td>
                                <form action="/admin/add_tokens" method="post" class="flex-row">
                                    <input type="hidden" name="hwid" value="{c['hwid']}">
                                    <input type="number" name="amount" placeholder="+/-" style="width:60px" required>
                                    <select name="type">
                                        <option value="practica">Práctica</option>
                                        <option value="supervigilancia">Super</option>
                                    </select>
                                    <button type="submit" class="btn-action">OK</button>
                                </form>
                            </td>
                            <td>
                                <a href="/admin/history/{c['hwid']}" class="btn-hist">VER HISTORIAL</a>
                            </td>
                        </tr>
                    """ for c in clients])}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/admin/history/<hwid>')
def history(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Obtener nombre cliente
            cursor.execute("SELECT nombre FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            name = client['nombre'] if client else "Desconocido"

            # Obtener historial (limitado a últimos 100)
            cursor.execute("""
                SELECT * FROM historial 
                WHERE hwid = %s 
                ORDER BY fecha DESC 
                LIMIT 100
            """, (hwid,))
            logs = cursor.fetchall()
    finally:
        conn.close()

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Historial - {name}</title>{CSS_STYLE}</head>
    <body>
        <div class="container">
            <a href="/admin/panel" class="back-link">← VOLVER AL PANEL PRINCIPAL</a>
            
            <div class="card">
                <div class="card-header">HISTORIAL DE MOVIMIENTOS: <span style="color:var(--red)">{name}</span></div>
                <div style="margin-bottom:15px; color:#666; font-size:0.9rem">HWID: {hwid}</div>
                
                <table>
                    <thead>
                        <tr>
                            <th>FECHA / HORA</th>
                            <th>ACCIÓN</th>
                            <th>TIPO TOKEN</th>
                            <th>CANTIDAD</th>
                        </tr>
                    </thead>
                    <tbody>
                    {''.join([f"""
                        <tr>
                            <td style="color:#aaa">{log['fecha']}</td>
                            <td>
                                <span style="color:{'#ef4444' if log['accion']=='CONSUMO' else '#10b981' if log['accion']=='RECARGA' else '#f59e0b'}">
                                    <b>{log['accion']}</b>
                                </span>
                            </td>
                            <td>{log['tipo_token'].upper()}</td>
                            <td style="font-weight:bold; color:{'#ef4444' if log['cantidad'] < 0 else '#10b981'}">
                                {log['cantidad']}
                            </td>
                        </tr>
                    """ for log in logs])}
                    </tbody>
                </table>
                { '<div style="padding:20px; text-align:center; color:#666">No hay registros recientes.</div>' if not logs else '' }
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/admin/add_tokens', methods=['POST'])
def add_tokens():
    try:
        hwid = request.form['hwid']
        amount = int(request.form['amount']) # Puede ser negativo para corregir
        token_type = request.form['type']
        
        # Determinar acción para el log
        accion = "RECARGA"
        if amount < 0: accion = "CORRECCION"
        
        col = f"tokens_{token_type}"
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # 1. Actualizar Saldo
            cursor.execute(f"UPDATE clientes SET {col} = {col} + %s WHERE hwid = %s", (amount, hwid))
            
            # 2. Guardar Log
            cursor.execute("""
                INSERT INTO historial (hwid, accion, cantidad, tipo_token)
                VALUES (%s, %s, %s, %s)
            """, (hwid, accion, amount, token_type))
            
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"Error: {e}"

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
        return f"Error al registrar (¿HWID duplicado?): {e}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
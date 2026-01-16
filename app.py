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

# CLAVE MAESTRA PARA GESTIÓN (RECARGAS/CORRECCIONES)
ADMIN_PASS = "1032491753Outlook*+"

# --- CONEXIÓN BD ---
def get_db_connection():
    if DB_HOST and (DB_HOST.startswith("postgres://") or DB_HOST.startswith("postgresql://")):
        return psycopg2.connect(DB_HOST, sslmode='require')
    else:
        return psycopg2.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME, port=DB_PORT, sslmode='require'
        )

# --- SEGURIDAD HMAC (Para el Software Cliente) ---
def verify_signature(hwid, timestamp, received_sig):
    if abs(time.time() - float(timestamp)) > 300: return False
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# ================= LÓGICA DEL SISTEMA =================

# 1. API: CONSUMO DE TOKENS (SOLO SOFTWARE)
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
                    
                    # 2. Guardar en Historial (Consumo automático)
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

# ================= INTERFAZ WEB (PANEL CLARO) =================

# ESTILOS CSS (TEMA LIGHT / CLARO PROFESIONAL)
CSS_STYLE = """
<style>
    :root { 
        --bg: #f3f4f6; 
        --card: #ffffff; 
        --border: #e5e7eb; 
        --primary: #2563eb; /* Azul corporativo */
        --primary-hover: #1d4ed8;
        --red: #dc2626; 
        --text: #111827; 
        --text-dim: #6b7280; 
        --header-bg: #f9fafb;
    }
    body { background-color: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }
    h1, h2, h3 { color: #1f2937; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; }
    h1 span { color: var(--primary); }
    
    .container { max-width: 1200px; margin: 0 auto; }
    
    .card { 
        background: var(--card); 
        border: 1px solid var(--border); 
        border-radius: 12px; 
        padding: 25px; 
        margin-bottom: 25px; 
        box-shadow: 0 1px 3px rgba(0,0,0,0.05); 
    }
    .card-header { 
        border-bottom: 2px solid var(--border); 
        padding-bottom: 15px; 
        margin-bottom: 20px; 
        font-size: 1.1rem; 
        font-weight: bold; 
        color: #374151;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    /* TABLAS */
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.95rem; }
    th { text-align: left; padding: 15px; background: var(--header-bg); color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase; border-bottom: 1px solid var(--border); font-weight: 700; }
    td { padding: 15px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:hover { background: #f9fafb; }
    
    /* INPUTS & BOTONES */
    input, select { 
        background: #fff; 
        border: 1px solid #d1d5db; 
        color: #111827; 
        padding: 8px 12px; 
        border-radius: 6px; 
        font-family: inherit;
        outline: none;
        transition: border 0.2s;
    }
    input:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.1); }
    
    button { cursor: pointer; font-weight: bold; padding: 9px 16px; border-radius: 6px; border: none; transition: 0.2s; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
    
    .btn-action { background: var(--primary); color: white; }
    .btn-action:hover { background: var(--primary-hover); }
    
    .btn-hist { 
        background: white; 
        color: #4b5563; 
        border: 1px solid #d1d5db; 
        text-decoration: none; 
        padding: 6px 12px; 
        border-radius: 6px; 
        font-size: 0.8rem; 
        display: inline-block;
    }
    .btn-hist:hover { background: #f3f4f6; color: #111827; border-color: #9ca3af; }
    
    /* UTILIDADES */
    .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.85rem; font-weight: 700; display: inline-block; min-width: 30px; text-align: center; }
    .badge-green { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
    .badge-red { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
    
    .flex-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .hwid-font { font-family: 'Consolas', monospace; color: var(--text-dim); font-size: 0.8rem; background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
    
    .logo-area { display: flex; align-items: center; gap: 15px; margin-bottom: 30px; }
    .stats-box { background: white; padding: 10px 20px; border-radius: 8px; border: 1px solid var(--border); font-size: 0.9rem; color: #555; }
    
    .back-link { display: inline-block; margin-bottom: 20px; color: var(--primary); text-decoration: none; font-weight: 600; }
    .back-link:hover { text-decoration: underline; }

    /* Input Password Específico */
    .pass-input { border: 1px solid #fca5a5; background: #fff1f2; }
    .pass-input:focus { border-color: #dc2626; box-shadow: 0 0 0 2px rgba(220, 38, 38, 0.1); }
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
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            clients = cursor.fetchall()
            
            cursor.execute("SELECT SUM(tokens_practica) as tp, SUM(tokens_supervigilancia) as ts FROM clientes")
            stats = cursor.fetchone()
    finally:
        conn.close()

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Alpha Security - Panel de Control</title>{CSS_STYLE}</head>
    <body>
        <div class="container">
            <div class="logo-area">
                <h1>ALPHA <span>SECURITY</span></h1>
                <div class="stats-box" style="margin-left: auto;">
                    TOKENS GLOBALES ACTIVOS<br>
                    Práctica: <b style="color:#2563eb">{stats['tp'] or 0}</b> &nbsp;|&nbsp; Supervigilancia: <b style="color:#2563eb">{stats['ts'] or 0}</b>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span>REGISTRAR NUEVA MÁQUINA</span>
                </div>
                <form action="/admin/register" method="post" class="flex-row">
                    <input type="text" name="nombre" placeholder="Nombre Escuela / Cliente" required style="flex:2">
                    <input type="text" name="hwid" placeholder="HWID (Hardware ID)" required style="flex:3">
                    <button type="submit" class="btn-action">CREAR CLIENTE</button>
                </form>
            </div>

            <div class="card">
                <div class="card-header">LISTADO DE CLIENTES</div>
                <table>
                    <thead>
                        <tr>
                            <th>CLIENTE / HWID</th>
                            <th>SALDO PRÁCTICA</th>
                            <th>SALDO SUPERV.</th>
                            <th style="width: 450px;">GESTIÓN (REQUIERE CLAVE)</th>
                            <th>HISTORIAL</th>
                        </tr>
                    </thead>
                    <tbody>
                    {''.join([f"""
                        <tr>
                            <td>
                                <div style="font-weight:bold; font-size:1rem; color:#111827;">{c['nombre']}</div>
                                <div class="hwid-font" style="margin-top:4px;">{c['hwid']}</div>
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
                                <form action="/admin/add_tokens" method="post" class="flex-row" style="background: #f9fafb; padding: 8px; border-radius: 8px; border: 1px solid #eee;">
                                    <input type="hidden" name="hwid" value="{c['hwid']}">
                                    
                                    <input type="number" name="amount" placeholder="+/-" style="width:50px; text-align:center;" required>
                                    
                                    <select name="type">
                                        <option value="practica">Práctica</option>
                                        <option value="supervigilancia">Supervigilancia</option>
                                    </select>
                                    
                                    <input type="password" name="admin_pass" class="pass-input" placeholder="Clave Admin" style="width:100px;" required>
                                    
                                    <button type="submit" class="btn-action" style="padding: 8px 12px;">Aplicar</button>
                                </form>
                            </td>
                            <td style="text-align:center;">
                                <a href="/admin/history/{c['hwid']}" class="btn-hist">Ver Logs</a>
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
            # Info Cliente
            cursor.execute("SELECT nombre FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            name = client['nombre'] if client else "Desconocido"

            # Historial
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
            <a href="/admin/panel" class="back-link">← VOLVER AL PANEL</a>
            
            <div class="card">
                <div class="card-header">
                    <span>HISTORIAL DE MOVIMIENTOS: <span style="color:#2563eb">{name}</span></span>
                </div>
                <div style="margin-bottom:20px; color:#555; background:#f3f4f6; padding:10px; border-radius:6px; font-family:monospace;">
                    ID: {hwid}
                </div>
                
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
                            <td style="color:#555">{log['fecha']}</td>
                            <td>
                                <span style="
                                    font-weight:bold;
                                    color:{'#dc2626' if log['accion']=='CONSUMO' else '#16a34a' if log['accion']=='RECARGA' else '#d97706'}
                                ">
                                    {log['accion']}
                                </span>
                            </td>
                            <td style="text-transform:uppercase; font-size:0.85rem; font-weight:600; color:#4b5563;">
                                {log['tipo_token']}
                            </td>
                            <td>
                                <span style="
                                    font-weight:bold; 
                                    font-size:1rem;
                                    color:{'#dc2626' if log['cantidad'] < 0 else '#16a34a'}
                                ">
                                    {'+' if log['cantidad'] > 0 else ''}{log['cantidad']}
                                </span>
                            </td>
                        </tr>
                    """ for log in logs])}
                    </tbody>
                </table>
                { '<div style="padding:40px; text-align:center; color:#9ca3af; font-style:italic;">No hay registros de actividad reciente.</div>' if not logs else '' }
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/admin/add_tokens', methods=['POST'])
def add_tokens():
    try:
        # 1. VERIFICAR CLAVE MAESTRA
        password_input = request.form.get('admin_pass', '')
        if password_input != ADMIN_PASS:
            return """
            <h1 style='color:red; font-family:sans-serif; text-align:center; margin-top:50px;'>
                ACCESO DENEGADO
            </h1>
            <p style='text-align:center; font-family:sans-serif;'>La clave de administrador es incorrecta.</p>
            <div style='text-align:center;'><a href='/admin/panel'>Volver a intentar</a></div>
            """, 403

        # 2. PROCESAR TRANSACCIÓN
        hwid = request.form['hwid']
        amount = int(request.form['amount']) # Positivo para recarga, negativo para corrección
        token_type = request.form['type']
        
        # Etiqueta para el log
        accion = "RECARGA"
        if amount < 0: accion = "CORRECCION"
        
        col = f"tokens_{token_type}"
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Actualizar Saldo
            cursor.execute(f"UPDATE clientes SET {col} = {col} + %s WHERE hwid = %s", (amount, hwid))
            
            # Guardar en Historial
            cursor.execute("""
                INSERT INTO historial (hwid, accion, cantidad, tipo_token)
                VALUES (%s, %s, %s, %s)
            """, (hwid, accion, amount, token_type))
            
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"Error procesando solicitud: {e}"

@app.route('/admin/register', methods=['POST'])
def register():
    try:
        # (Opcional) Podrías requerir clave aquí también, pero el pedido fue para asignar/modificar.
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
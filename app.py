import os
import hmac
import hashlib
import time
import datetime
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# --- CONFIGURACIÓN DE ENTORNO ---
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", "26367")
SECRET_KEY = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4").encode()

# --- CONEXIÓN BASE DE DATOS ---
def get_db_connection():
    if DB_HOST and (DB_HOST.startswith("postgres://") or DB_HOST.startswith("postgresql://")):
        return psycopg2.connect(DB_HOST, sslmode='require')
    else:
        return psycopg2.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME, port=DB_PORT, sslmode='require'
        )

# --- SEGURIDAD HMAC ---
def verify_signature(hwid, timestamp, received_sig):
    if abs(time.time() - float(timestamp)) > 300: return False
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# =========================================================
# API (LÓGICA DEL SOFTWARE)
# =========================================================

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
                    cursor.execute(f"UPDATE clientes SET {col} = {col} - 1 WHERE hwid = %s", (hwid,))
                    cursor.execute("""
                        INSERT INTO historial (hwid, accion, cantidad, tipo_token)
                        VALUES (%s, 'CONSUMO', -1, %s)
                    """, (hwid, token_type))
                    conn.commit()
                    
                    cursor.execute(f"SELECT {col} FROM clientes WHERE hwid = %s", (hwid,))
                    new_bal = cursor.fetchone()[col]
                    return jsonify({"status": "success", "remaining": new_bal, "type": token_type})
                else:
                    return jsonify({"status": "denied", "msg": "Sin saldo", "type": token_type}), 402
        finally:
            conn.close()
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

# =========================================================
# DISEÑO WEB (ALPHA TACTICAL DARK)
# =========================================================

# Definimos el CSS como una variable separada para evitar conflictos con f-strings
CSS_THEME = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Roboto+Mono:wght@400;700&display=swap');

    :root {
        --bg-color: #050505;
        --card-bg: #121212;
        --border-color: #27272a;
        --accent-red: #b91c1c;       /* Rojo Oscuro */
        --accent-red-hover: #dc2626; /* Rojo Brillante */
        --text-white: #ffffff;
        --text-gray: #a1a1aa;
        --success: #15803d;
    }

    body {
        background-color: var(--bg-color);
        color: var(--text-white);
        font-family: 'Rajdhani', sans-serif;
        margin: 0;
        padding: 0;
        background-image: radial-gradient(circle at 50% 0%, #200505 0%, #050505 60%);
    }

    /* BARRA DE CARGA SUPERIOR */
    #nprogress {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 3px;
        z-index: 9999;
        display: none;
    }
    #nprogress .bar {
        height: 100%;
        background: var(--accent-red);
        width: 0%;
        transition: width 0.3s ease;
        box-shadow: 0 0 15px var(--accent-red);
    }

    /* CONTENEDOR PRINCIPAL */
    .container {
        max-width: 1300px;
        margin: 0 auto;
        padding: 20px;
    }

    /* HEADER / LOGO */
    .header {
        text-align: center;
        padding: 40px 0 30px 0;
        border-bottom: 1px solid var(--border-color);
        margin-bottom: 30px;
    }
    .brand-logo {
        max-height: 140px; /* Ajusta el tamaño del logo aquí */
        display: block;
        margin: 0 auto;
        filter: drop-shadow(0 0 10px rgba(185, 28, 28, 0.3)); /* Resplandor rojo suave */
    }

    /* TARJETAS DE ESTADÍSTICAS */
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 20px;
        margin-bottom: 40px;
    }
    .stat-card {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-left: 4px solid var(--accent-red);
        border-radius: 6px;
        padding: 20px;
        display: flex;
        flex-direction: column;
    }
    .stat-title { color: var(--text-gray); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; font-weight: 700; }
    .stat-value { font-size: 2.2rem; font-weight: 700; margin-top: 5px; font-family: 'Roboto Mono', monospace; }

    /* FORMULARIO REGISTRO */
    .action-panel {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 25px;
        margin-bottom: 30px;
        display: flex;
        align-items: center;
        gap: 15px;
        flex-wrap: wrap;
    }
    .panel-title { font-size: 1.2rem; font-weight: 700; color: var(--accent-red); text-transform: uppercase; margin-right: auto; }

    /* TABLA ESTILO TÁCTICO */
    .table-responsive {
        overflow-x: auto;
        border: 1px solid var(--border-color);
        border-radius: 8px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        background: var(--card-bg);
        font-size: 1rem;
    }
    th {
        background: #0f0f0f;
        color: var(--text-gray);
        text-align: left;
        padding: 15px 20px;
        text-transform: uppercase;
        font-size: 0.85rem;
        letter-spacing: 1px;
        border-bottom: 2px solid var(--border-color);
    }
    td {
        padding: 15px 20px;
        border-bottom: 1px solid var(--border-color);
        vertical-align: middle;
    }
    tr:hover { background: #1a1a1a; }

    /* INPUTS & BOTONES */
    input, select {
        background: #000;
        border: 1px solid #333;
        color: white;
        padding: 10px 15px;
        border-radius: 4px;
        font-family: 'Roboto Mono', monospace;
        font-size: 0.9rem;
        outline: none;
    }
    input:focus { border-color: var(--accent-red); box-shadow: 0 0 5px rgba(220, 38, 38, 0.5); }

    .btn {
        background: var(--accent-red);
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 4px;
        font-weight: 700;
        text-transform: uppercase;
        cursor: pointer;
        transition: 0.2s;
        text-decoration: none;
        display: inline-block;
        font-size: 0.9rem;
    }
    .btn:hover { background: var(--accent-red-hover); box-shadow: 0 0 10px rgba(220, 38, 38, 0.4); }
    
    .btn-outline {
        background: transparent;
        border: 1px solid var(--border-color);
        color: var(--text-gray);
    }
    .btn-outline:hover {
        border-color: var(--text-white);
        color: var(--text-white);
        background: #1a1a1a;
        box-shadow: none;
    }

    /* BARRAS DE STOCK */
    .stock-bar-container {
        width: 100%;
        height: 6px;
        background: #27272a;
        border-radius: 3px;
        margin-top: 8px;
        overflow: hidden;
    }
    .stock-bar-fill { height: 100%; transition: width 0.3s; }
    
    /* UTILS */
    .hwid-tag {
        font-family: 'Roboto Mono', monospace;
        font-size: 0.75rem;
        color: #555;
        background: #000;
        padding: 2px 6px;
        border-radius: 3px;
        border: 1px solid #222;
        margin-top: 4px;
        display: inline-block;
    }
    .badge-hist { font-size: 0.8rem; letter-spacing: 1px; }
</style>
<script>
    function loading() {
        const b = document.getElementById('nprogress');
        const f = b.querySelector('.bar');
        b.style.display='block';
        setTimeout(()=>f.style.width='50%', 50);
        setTimeout(()=>f.style.width='90%', 800);
    }
</script>
"""

# =========================================================
# RUTAS DE INTERFAZ
# =========================================================

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
            
            total_clientes = len(clients)
    finally:
        conn.close()

    rows = ""
    for c in clients:
        # Lógica visual de la barra de progreso (Max visual 100)
        tp = int(c['tokens_practica'])
        ts = int(c['tokens_supervigilancia'])
        
        # Color rojo si es bajo (<10), verde si es normal
        color_p = "#15803d" if tp > 10 else "#b91c1c"
        color_s = "#15803d" if ts > 10 else "#b91c1c"
        
        # Ancho barra (tope 100%)
        width_p = min(100, tp)
        width_s = min(100, ts)

        rows += f"""
        <tr>
            <td>
                <div style="font-weight:700; font-size:1.1rem;">{c['nombre']}</div>
                <div class="hwid-tag">{c['hwid']}</div>
            </td>
            <td>
                <div style="font-family:'Roboto Mono'; font-size:1.2rem; font-weight:700;">{tp}</div>
                <div class="stock-bar-container"><div class="stock-bar-fill" style="width:{width_p}%; background:{color_p}"></div></div>
            </td>
            <td>
                <div style="font-family:'Roboto Mono'; font-size:1.2rem; font-weight:700;">{ts}</div>
                <div class="stock-bar-container"><div class="stock-bar-fill" style="width:{width_s}%; background:{color_s}"></div></div>
            </td>
            <td>
                <form action="/admin/add_tokens" method="post" onsubmit="loading()" style="display:flex; gap:10px;">
                    <input type="hidden" name="hwid" value="{c['hwid']}">
                    <input type="number" name="amount" placeholder="+/-" style="width:70px; text-align:center;" required>
                    <select name="type">
                        <option value="practica">Práctica</option>
                        <option value="supervigilancia">Supervigilancia</option>
                    </select>
                    <button type="submit" class="btn">APLICAR</button>
                </form>
            </td>
            <td style="text-align:right;">
                <a href="/admin/history/{c['hwid']}" class="btn btn-outline badge-hist" onclick="loading()">AUDITORÍA</a>
            </td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ALPHA COMMAND CENTER</title>
        {CSS_THEME}
    </head>
    <body>
        <div id="nprogress"><div class="bar"></div></div>

        <div class="container">
            <div class="header">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" alt="Alpha Security" class="brand-logo">
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-title">Sistemas Activos</div>
                    <div class="stat-value" style="color: white;">{total_clientes}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Tokens Práctica (Circulación)</div>
                    <div class="stat-value" style="color: #4ade80;">{stats['tp'] or 0}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Tokens Supervigilancia (Circulación)</div>
                    <div class="stat-value" style="color: #f87171;">{stats['ts'] or 0}</div>
                </div>
            </div>

            <div class="action-panel">
                <div class="panel-title">NUEVO DESPLIEGUE</div>
                <form action="/admin/register" method="post" onsubmit="loading()" style="display:flex; gap:15px; flex:1;">
                    <input type="text" name="nombre" placeholder="Nombre de la Unidad / Escuela" required style="flex:1">
                    <input type="text" name="hwid" placeholder="ID de Hardware (HWID)" required style="flex:1">
                    <button type="submit" class="btn">REGISTRAR UNIDAD</button>
                </form>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th style="width:30%">Unidad</th>
                            <th style="width:15%">Stock Práctica</th>
                            <th style="width:15%">Stock Supervig.</th>
                            <th style="width:30%">Gestión de Recursos</th>
                            <th style="width:10%; text-align:right">Logs</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
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
            cursor.execute("SELECT nombre FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            name = client['nombre'] if client else "Desconocido"

            cursor.execute("""
                SELECT * FROM historial 
                WHERE hwid = %s 
                ORDER BY fecha DESC 
                LIMIT 100
            """, (hwid,))
            logs = cursor.fetchall()
    finally:
        conn.close()

    log_rows = ""
    for log in logs:
        # Colores para el historial
        accion = log['accion']
        color_acc = "#b91c1c" if accion == "CONSUMO" else "#15803d" if accion == "RECARGA" else "#f59e0b"
        
        cant = log['cantidad']
        txt_cant = f"{cant:+}" if cant != 0 else "0"
        color_cant = "#b91c1c" if cant < 0 else "#15803d"

        log_rows += f"""
        <tr>
            <td style="color: #666; font-family:'Roboto Mono'; font-size:0.85rem;">{log['fecha']}</td>
            <td><span style="color:{color_acc}; font-weight:700;">{accion}</span></td>
            <td style="text-transform:uppercase; font-size:0.9rem;">{log['tipo_token']}</td>
            <td><span style="color:{color_cant}; font-family:'Roboto Mono'; font-weight:700; font-size:1.1rem;">{txt_cant}</span></td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Historial | {name}</title>
        {CSS_THEME}
    </head>
    <body>
        <div id="nprogress"><div class="bar"></div></div>
        
        <div class="container">
            <div style="margin-bottom: 20px;">
                <a href="/admin/panel" class="btn btn-outline" onclick="loading()">← VOLVER AL COMANDO</a>
            </div>

            <div class="action-panel" style="flex-direction:column; align-items:flex-start;">
                <div style="font-size:0.9rem; color:var(--accent-red); font-weight:700; letter-spacing:1px;">EXPEDIENTE TÁCTICO</div>
                <div style="font-size:2.5rem; font-weight:700; line-height:1;">{name}</div>
                <div class="hwid-tag" style="font-size:1rem; padding:8px 12px;">ID: {hwid}</div>
            </div>

            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Fecha / Hora</th>
                            <th>Evento</th>
                            <th>Recurso</th>
                            <th>Movimiento</th>
                        </tr>
                    </thead>
                    <tbody>
                        {log_rows}
                    </tbody>
                </table>
                { '<div style="padding:40px; text-align:center; color:#444;">Sin actividad reciente registrada.</div>' if not logs else '' }
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
        amount = int(request.form['amount'])
        token_type = request.form['type']
        
        accion = "RECARGA" if amount >= 0 else "CORRECCION"
        col = f"tokens_{token_type}"
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Actualizar Saldo
            cursor.execute(f"UPDATE clientes SET {col} = {col} + %s WHERE hwid = %s", (amount, hwid))
            # Guardar Log
            cursor.execute("""
                INSERT INTO historial (hwid, accion, cantidad, tipo_token)
                VALUES (%s, %s, %s, %s)
            """, (hwid, accion, amount, token_type))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"<h2 style='color:red'>Error Crítico: {e}</h2>"

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
        return f"<h2 style='color:red'>Error al registrar: {e}</h2>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
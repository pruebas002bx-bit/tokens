import os
import hmac
import hashlib
import time
import datetime
import json
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

# --- CONEXIÓN BASE DE DATOS ROBUSTA ---
def get_db_connection():
    try:
        if DB_HOST and (DB_HOST.startswith("postgres://") or DB_HOST.startswith("postgresql://")):
            return psycopg2.connect(DB_HOST, sslmode='require')
        else:
            return psycopg2.connect(
                host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME, port=DB_PORT, sslmode='require'
            )
    except Exception as e:
        print(f"Error de conexión DB: {e}")
        return None

# --- SEGURIDAD HMAC ---
def verify_signature(hwid, timestamp, received_sig):
    if abs(time.time() - float(timestamp)) > 300: return False
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# =========================================================
# API (COMUNICACIÓN CON EL SOFTWARE DE ESCRITORIO)
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
        if not conn:
            return jsonify({"status": "error", "msg": "Error DB Connection"}), 500

        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
                client = cursor.fetchone()

                if not client:
                    return jsonify({"status": "error", "msg": "No registrado"}), 404

                col = f"tokens_{token_type}"
                if client.get(col, 0) > 0:
                    # Descontar
                    cursor.execute(f"UPDATE clientes SET {col} = {col} - 1 WHERE hwid = %s", (hwid,))
                    # Registrar Historial
                    cursor.execute("""
                        INSERT INTO historial (hwid, accion, cantidad, tipo_token)
                        VALUES (%s, 'CONSUMO', -1, %s)
                    """, (hwid, token_type))
                    conn.commit()
                    
                    # Consultar Saldo Actual
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
# INTERFAZ WEB (CRM DASHBOARD)
# =========================================================

CSS_THEME = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

    :root {
        --primary: #b91c1c;       /* Rojo Alpha */
        --primary-hover: #991b1b;
        --bg: #f3f4f6;            /* Gris Fondo */
        --surface: #ffffff;       /* Blanco Tarjetas */
        --text-main: #111827;     /* Negro Texto */
        --text-muted: #6b7280;    /* Gris Texto */
        --border: #e5e7eb;
        --success: #059669;
        --warning: #d97706;
    }

    * { box-sizing: border-box; }

    body {
        background-color: var(--bg);
        color: var(--text-main);
        font-family: 'Inter', sans-serif;
        margin: 0; padding: 0;
    }

    /* --- NAVBAR --- */
    .navbar {
        background: var(--surface);
        border-bottom: 1px solid var(--border);
        padding: 0.8rem 2rem;
        display: flex; align-items: center; justify-content: space-between;
        position: sticky; top: 0; z-index: 100;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
    }
    .brand-logo { height: 45px; }
    .brand-title { font-weight: 800; font-size: 1.1rem; color: var(--primary); letter-spacing: 0.5px; }

    /* --- LAYOUT --- */
    .container { max-width: 1400px; margin: 2rem auto; padding: 0 1.5rem; }

    /* --- TABS SYSTEM --- */
    .tabs-nav {
        display: flex;
        gap: 1rem;
        margin-bottom: 2rem;
        border-bottom: 2px solid var(--border);
    }
    .tab-btn {
        background: transparent;
        border: none;
        padding: 1rem 1.5rem;
        font-size: 0.95rem;
        font-weight: 600;
        color: var(--text-muted);
        cursor: pointer;
        position: relative;
        transition: all 0.3s;
    }
    .tab-btn:hover { color: var(--text-main); }
    .tab-btn.active {
        color: var(--primary);
    }
    .tab-btn.active::after {
        content: ''; position: absolute; bottom: -2px; left: 0; width: 100%; height: 3px; background: var(--primary);
    }
    
    .tab-content { display: none; animation: fadeIn 0.4s ease; }
    .tab-content.active { display: block; }
    
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* --- CARDS & PANELS --- */
    .card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        margin-bottom: 1.5rem;
    }
    .section-title {
        font-size: 1.1rem; font-weight: 800; color: var(--text-main);
        margin-bottom: 1.5rem; display: flex; align-items: center; gap: 8px;
    }
    .section-title::before { content:''; display:block; width:4px; height:20px; background:var(--primary); border-radius:2px; }

    /* --- FORMULARIOS --- */
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; }
    .full-width { grid-column: 1 / -1; }
    
    .input-group label { display: block; font-size: 0.8rem; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; }
    input, select, textarea {
        width: 100%; padding: 0.7rem;
        border: 1px solid var(--border); border-radius: 6px;
        font-family: inherit; font-size: 0.95rem;
        transition: border 0.2s;
    }
    input:focus { border-color: var(--primary); outline: none; box-shadow: 0 0 0 3px rgba(185, 28, 28, 0.1); }

    /* --- CLIENT LIST (ACORDEÓN) --- */
    .client-item {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; margin-bottom: 1rem; overflow: hidden;
        transition: all 0.2s;
    }
    .client-item:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05); }
    
    .client-header {
        padding: 1.2rem; cursor: pointer;
        display: flex; justify-content: space-between; align-items: center;
        background: #fff;
    }
    .client-profile { display: flex; align-items: center; gap: 15px; }
    .client-logo { width: 48px; height: 48px; border-radius: 50%; object-fit: cover; background: #f3f4f6; border: 1px solid #e5e7eb; }
    
    .client-details {
        padding: 1.5rem; background: #f9fafb; border-top: 1px solid var(--border);
        display: none; /* Oculto por defecto */
    }
    .client-details.open { display: block; }

    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
    
    /* --- DASHBOARD STATS --- */
    .kpi-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .kpi-card {
        background: var(--surface); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border);
        display: flex; flex-direction: column; align-items: flex-start;
    }
    .kpi-title { font-size: 0.8rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; }
    .kpi-num { font-size: 2rem; font-weight: 800; color: var(--text-main); margin-top: 5px; }
    .text-red { color: var(--primary); }
    .text-green { color: var(--success); }

    /* --- BOTONES & BADGES --- */
    .btn {
        background: var(--primary); color: white; padding: 0.7rem 1.5rem; border-radius: 6px;
        font-weight: 700; border: none; cursor: pointer; text-decoration: none;
        display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-size: 0.9rem;
        transition: background 0.2s;
    }
    .btn:hover { background: var(--primary-hover); }
    
    .btn-outline { background: white; color: var(--text-main); border: 1px solid var(--border); }
    .btn-outline:hover { background: #f3f4f6; border-color: var(--text-muted); }

    .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; }
    .bg-green-soft { background: #dcfce7; color: #166534; }
    .bg-red-soft { background: #fee2e2; color: #991b1b; }
    
    .hwid-badge { font-family: monospace; background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; color: #555; margin-top: 4px; display: inline-block; }

    /* MAPA */
    iframe.map { width: 100%; height: 250px; border: none; border-radius: 8px; margin-top: 10px; }
</style>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    function openTab(tabId) {
        // Ocultar todos los contenidos
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        // Desactivar todos los botones
        document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
        
        // Activar el seleccionado
        document.getElementById(tabId).classList.add('active');
        document.getElementById('btn-' + tabId).classList.add('active');
    }

    function toggleDetails(id) {
        document.getElementById('detail-' + id).classList.toggle('open');
    }
</script>
"""

@app.route('/')
def home():
    return redirect('/admin/panel')

@app.route('/admin/panel')
def admin_panel():
    conn = get_db_connection()
    if not conn:
        return "Error crítico: No hay conexión a Base de Datos."

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # 1. Clientes
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            clients = cursor.fetchall()
            
            # 2. Estadísticas Globales (KPIs)
            cursor.execute("SELECT SUM(tokens_practica) as tp, SUM(tokens_supervigilancia) as ts FROM clientes")
            tokens_data = cursor.fetchone()
            
            cursor.execute("SELECT COUNT(*) as total FROM clientes")
            total_clients = cursor.fetchone()['total']

            # 3. Datos para Gráfica (Ventas por Mes - Últimos 12 Meses)
            cursor.execute("""
                SELECT TO_CHAR(fecha, 'YYYY-MM') as mes, SUM(cantidad) as total 
                FROM historial 
                WHERE accion = 'RECARGA' 
                GROUP BY mes 
                ORDER BY mes ASC 
                LIMIT 12
            """)
            chart_raw = cursor.fetchall()
            labels = [r['mes'] for r in chart_raw]
            values = [r['total'] for r in chart_raw]

    finally:
        conn.close()

    # --- GENERADOR DE HTML DE CLIENTES (TAB 1) ---
    clients_html = ""
    for c in clients:
        address = c.get('direccion') or 'Bogotá, Colombia'
        map_query = address.replace(" ", "+")
        map_url = f"https://maps.google.com/maps?q={map_query}&t=&z=13&ie=UTF8&iwloc=&output=embed"
        
        # Logo fallback
        logo = c.get('logo_url') if c.get('logo_url') and len(c.get('logo_url')) > 5 else "https://ui-avatars.com/api/?name=" + c['nombre'].replace(" ", "+") + "&background=random&size=128"

        clients_html += f"""
        <div class="client-item">
            <div class="client-header" onclick="toggleDetails({c['id']})">
                <div class="client-profile">
                    <img src="{logo}" class="client-logo">
                    <div>
                        <div style="font-weight:700; font-size:1.1rem; color:var(--text-main);">{c['nombre']}</div>
                        <div class="hwid-badge">{c['hwid']}</div>
                    </div>
                </div>
                <div style="display:flex; gap:15px; align-items:center;">
                    <div style="text-align:right;">
                        <div style="font-size:0.75rem; font-weight:700; color:var(--text-muted);">PRÁCTICA</div>
                        <div class="badge bg-green-soft" style="font-size:1rem;">{c['tokens_practica']}</div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-size:0.75rem; font-weight:700; color:var(--text-muted);">SUPERVIG.</div>
                        <div class="badge bg-red-soft" style="font-size:1rem;">{c['tokens_supervigilancia']}</div>
                    </div>
                    <div style="margin-left:10px; color:var(--text-muted);">▼</div>
                </div>
            </div>

            <div id="detail-{c['id']}" class="client-details">
                <div class="info-grid">
                    <div>
                        <h4 style="margin-top:0; color:var(--primary);">DATOS DE LA UNIDAD</h4>
                        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:15px; margin-bottom:15px;">
                            <div>
                                <div class="input-group"><label>Responsable</label></div>
                                <div>{c.get('responsable') or '---'}</div>
                            </div>
                            <div>
                                <div class="input-group"><label>Email</label></div>
                                <a href="mailto:{c.get('email')}" style="color:var(--primary); font-weight:600;">{c.get('email') or '---'}</a>
                            </div>
                            <div>
                                <div class="input-group"><label>Teléfono 1</label></div>
                                <div>{c.get('telefono1') or '---'}</div>
                            </div>
                            <div>
                                <div class="input-group"><label>Teléfono 2</label></div>
                                <div>{c.get('telefono2') or '---'}</div>
                            </div>
                        </div>
                        <div class="input-group"><label>Ubicación Física</label></div>
                        <div style="margin-bottom:5px;">{address}</div>
                        <iframe class="map" src="{map_url}"></iframe>
                    </div>

                    <div style="background:white; padding:20px; border-radius:8px; border:1px solid var(--border); height:fit-content;">
                        <h4 style="margin-top:0; color:var(--text-main);">GESTIÓN DE SALDO</h4>
                        <form action="/admin/add_tokens" method="post">
                            <input type="hidden" name="hwid" value="{c['hwid']}">
                            
                            <div class="input-group" style="margin-bottom:10px;">
                                <label>Cantidad (+ Agregar / - Quitar)</label>
                                <input type="number" name="amount" placeholder="Ej: 50 o -5" required style="font-size:1.1rem; font-weight:bold;">
                            </div>
                            
                            <div class="input-group" style="margin-bottom:15px;">
                                <label>Tipo de Token</label>
                                <select name="type">
                                    <option value="practica">Práctica (Entrenamiento)</option>
                                    <option value="supervigilancia">Supervigilancia (Certificación)</option>
                                </select>
                            </div>

                            <div style="display:flex; gap:10px;">
                                <button type="submit" class="btn" style="flex:1;">ACTUALIZAR</button>
                                <a href="/admin/history/{c['hwid']}" class="btn btn-outline">LOGS</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        """

    return render_template_string(f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Alpha Security | CRM</title>
        {CSS_THEME}
    </head>
    <body>
        
        <nav class="navbar">
            <div style="display:flex; align-items:center; gap:12px;">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="brand-logo">
                <div class="brand-title">COMMAND CENTER</div>
            </div>
            <div style="font-size:0.85rem; font-weight:600; color:var(--text-muted);">
                SISTEMA EN LÍNEA
            </div>
        </nav>

        <div class="container">
            
            <div class="tabs-nav">
                <button id="btn-units" class="tab-btn active" onclick="openTab('units')">UNIDADES ACTIVAS</button>
                <button id="btn-register" class="tab-btn" onclick="openTab('register')">REGISTRAR NUEVA</button>
                <button id="btn-stats" class="tab-btn" onclick="openTab('stats')">ESTADÍSTICAS & BI</button>
            </div>

            <div id="units" class="tab-content active">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem;">
                    <div class="section-title" style="margin:0;">RED DE ESCUELAS ({total_clients})</div>
                    <input type="text" placeholder="Buscar unidad..." style="width:250px;">
                </div>
                {clients_html}
            </div>

            <div id="register" class="tab-content">
                <div class="card" style="max-width:800px; margin:0 auto;">
                    <div class="section-title">ALTA DE NUEVA UNIDAD TÁCTICA</div>
                    <form action="/admin/register" method="post">
                        <div class="form-grid">
                            <div class="input-group full-width">
                                <label>Nombre de la Escuela / Organización</label>
                                <input type="text" name="nombre" required placeholder="Ej: Academia de Seguridad Alpha">
                            </div>

                            <div class="input-group full-width">
                                <label>Hardware ID (HWID) del Simulador</label>
                                <input type="text" name="hwid" required placeholder="Copiar ID desde el software cliente" style="font-family:monospace;">
                            </div>

                            <div class="input-group">
                                <label>Nombre del Responsable</label>
                                <input type="text" name="responsable" placeholder="Director / Admin">
                            </div>

                            <div class="input-group">
                                <label>Email de Contacto</label>
                                <input type="email" name="email" placeholder="contacto@escuela.com">
                            </div>

                            <div class="input-group">
                                <label>Teléfono Principal</label>
                                <input type="text" name="telefono1" placeholder="Móvil / WhatsApp">
                            </div>

                            <div class="input-group">
                                <label>Teléfono Secundario</label>
                                <input type="text" name="telefono2" placeholder="Fijo / Opcional">
                            </div>

                            <div class="input-group full-width">
                                <label>Dirección Física (Geolocalización)</label>
                                <input type="text" name="direccion" placeholder="Calle, Número, Ciudad, País">
                            </div>

                            <div class="input-group full-width">
                                <label>URL del Logo (Opcional)</label>
                                <input type="text" name="logo_url" placeholder="https://miweb.com/logo.png">
                            </div>
                        </div>
                        <div style="margin-top:2rem; text-align:right;">
                            <button type="submit" class="btn" style="width:100%;">REGISTRAR UNIDAD</button>
                        </div>
                    </form>
                </div>
            </div>

            <div id="stats" class="tab-content">
                
                <div class="kpi-container">
                    <div class="kpi-card">
                        <div class="kpi-title">Unidades Activas</div>
                        <div class="kpi-num">{total_clients}</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-title">Tokens Práctica (Circulando)</div>
                        <div class="kpi-num text-green">{tokens_data['tp'] or 0}</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-title">Tokens Supervig. (Circulando)</div>
                        <div class="kpi-num text-red">{tokens_data['ts'] or 0}</div>
                    </div>
                </div>

                <div class="card">
                    <div class="section-title">RENDIMIENTO DE VENTAS (Recargas por Mes)</div>
                    <div style="height:400px; position:relative;">
                        <canvas id="salesChart"></canvas>
                    </div>
                </div>
            </div>

        </div>

        <script>
            // Inicializar Gráfica
            const ctx = document.getElementById('salesChart').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: {json.dumps(labels)},
                    datasets: [{{
                        label: 'Total Tokens Vendidos',
                        data: {json.dumps(values)},
                        borderColor: '#b91c1c',
                        backgroundColor: 'rgba(185, 28, 28, 0.1)',
                        borderWidth: 3,
                        pointBackgroundColor: '#fff',
                        pointBorderColor: '#b91c1c',
                        pointRadius: 6,
                        tension: 0.3,
                        fill: true
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ display: false }}
                    }},
                    scales: {{
                        y: {{ beginAtZero: true, grid: {{ color: '#e5e7eb' }} }},
                        x: {{ grid: {{ display: false }} }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """)

# =========================================================
# RUTAS DE ACCIÓN (BACKEND)
# =========================================================

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

    rows = ""
    for log in logs:
        is_neg = log['cantidad'] < 0
        color = "#b91c1c" if is_neg else "#059669"
        sign = "" if is_neg else "+"
        rows += f"""
        <tr>
            <td style="color:#6b7280; font-family:monospace;">{log['fecha']}</td>
            <td><span style="font-weight:700; color:{'#b91c1c' if log['accion']=='CONSUMO' else '#2563eb'}">{log['accion']}</span></td>
            <td style="text-transform:uppercase; font-size:0.85rem;">{log['tipo_token']}</td>
            <td><span style="font-weight:800; color:{color}">{sign}{log['cantidad']}</span></td>
        </tr>
        """

    return render_template_string(f"""
        <!DOCTYPE html>
        <html><head><title>Historial {name}</title>{CSS_THEME}</head><body>
        <div class="container" style="max-width:900px;">
            <a href="/admin/panel" class="btn btn-outline" style="margin-bottom:20px;">← VOLVER</a>
            <div class="card">
                <div class="section-title">HISTORIAL DE MOVIMIENTOS: <span style="color:var(--primary); margin-left:10px;">{name}</span></div>
                <table style="width:100%; border-collapse:collapse;">
                    <thead style="background:#f9fafb; border-bottom:2px solid #e5e7eb;">
                        <tr><th style="padding:10px; text-align:left;">FECHA</th><th style="padding:10px; text-align:left;">ACCIÓN</th><th style="padding:10px; text-align:left;">TIPO</th><th style="padding:10px; text-align:left;">CANTIDAD</th></tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
        </body></html>
    """)

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
            cursor.execute(f"UPDATE clientes SET {col} = {col} + %s WHERE hwid = %s", (amount, hwid))
            cursor.execute("""
                INSERT INTO historial (hwid, accion, cantidad, tipo_token) VALUES (%s, %s, %s, %s)
            """, (hwid, accion, amount, token_type))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"Error: {e}"

@app.route('/admin/register', methods=['POST'])
def register():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO clientes 
                (nombre, hwid, responsable, telefono1, telefono2, email, direccion, logo_url, tokens_supervigilancia, tokens_practica) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0, 0)
            """, (
                request.form['nombre'], request.form['hwid'],
                request.form.get('responsable', ''), request.form.get('telefono1', ''),
                request.form.get('telefono2', ''), request.form.get('email', ''),
                request.form.get('direccion', ''), request.form.get('logo_url', '')
            ))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"<h2>Error al registrar: {e}</h2>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
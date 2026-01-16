import os
import hmac
import hashlib
import time
import datetime
import json
import requests
import io
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, send_file
import psycopg2
from psycopg2.extras import RealDictCursor
from fpdf import FPDF

app = Flask(__name__)

# --- CONFIGURACIÓN DE ENTORNO ---
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", "26367")
SECRET_KEY = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4").encode()

# API KEY IMGBB
IMGBB_API_KEY = "df01bb05ce03159d54c33e1e22eba2cf"

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
        print(f"Error DB Connection: {e}")
        return None

# --- SEGURIDAD HMAC ---
def verify_signature(hwid, timestamp, received_sig):
    if abs(time.time() - float(timestamp)) > 300: return False
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# =========================================================
# LÓGICA PDF (REPORTES)
# =========================================================
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.set_text_color(185, 28, 28) # Rojo Alpha
        self.cell(0, 10, 'ALPHA SECURITY - REPORTE DE MOVIMIENTOS', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'C')

# =========================================================
# API (SOFTWARE CLIENTE)
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
        if not conn: return jsonify({"status": "error", "msg": "DB Error"}), 500

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
# INTERFAZ WEB (CRM PRO LIGHT)
# =========================================================

CSS_THEME = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

    :root {
        --primary: #b91c1c; 
        --primary-hover: #991b1b;
        --bg: #f3f4f6;
        --surface: #ffffff;
        --text-main: #1f2937;
        --text-muted: #6b7280;
        --border: #e5e7eb;
        --success: #059669;
        --success-hover: #047857;
    }

    * { box-sizing: border-box; }
    body { background-color: var(--bg); color: var(--text-main); font-family: 'Inter', sans-serif; margin: 0; }

    /* NAVBAR */
    .navbar {
        background: var(--surface); border-bottom: 1px solid var(--border); padding: 0.8rem 2rem;
        display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100;
    }
    .brand-logo { height: 45px; }

    .container { max-width: 1400px; margin: 2rem auto; padding: 0 1.5rem; }

    /* TABS */
    .tabs-nav { display: flex; gap: 1rem; margin-bottom: 2rem; border-bottom: 2px solid var(--border); }
    .tab-btn {
        background: transparent; border: none; padding: 1rem 1.5rem; font-size: 0.95rem; font-weight: 600;
        color: var(--text-muted); cursor: pointer; position: relative; transition: all 0.3s;
    }
    .tab-btn:hover { color: var(--text-main); }
    .tab-btn.active { color: var(--primary); }
    .tab-btn.active::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 100%; height: 3px; background: var(--primary); }
    .tab-content { display: none; animation: fadeIn 0.4s ease; }
    .tab-content.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* CARDS & FORMS */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    .section-title { font-size: 1.1rem; font-weight: 800; color: var(--text-main); margin-bottom: 1.5rem; border-left: 4px solid var(--primary); padding-left: 10px; }
    
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; }
    .full-width { grid-column: 1 / -1; }
    label { display: block; font-size: 0.8rem; font-weight: 700; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; }
    input, select { width: 100%; padding: 0.7rem; border: 1px solid var(--border); border-radius: 6px; font-family: inherit; font-size: 0.95rem; }
    input:focus { border-color: var(--primary); outline: none; }

    /* CLIENT LIST */
    .client-item { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; transition: all 0.2s; }
    .client-item:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.05); }
    .client-header { padding: 1.2rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
    .client-profile { display: flex; align-items: center; gap: 15px; }
    .client-logo { width: 50px; height: 50px; border-radius: 50%; object-fit: cover; border: 2px solid #eee; }
    .client-details { padding: 1.5rem; background: #fcfcfc; border-top: 1px solid var(--border); display: none; }
    .client-details.open { display: block; }

    /* BOTONES TOKEN */
    .token-control { display: flex; align-items: center; gap: 10px; background: #f8fafc; padding: 10px; border-radius: 8px; border: 1px solid #eee; }
    .btn-icon { width: 40px; height: 40px; border-radius: 6px; border: none; color: white; font-weight: bold; font-size: 1.2rem; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: 0.2s; }
    .btn-add { background: var(--success); } .btn-add:hover { background: var(--success-hover); }
    .btn-sub { background: var(--primary); } .btn-sub:hover { background: var(--primary-hover); }
    
    /* OTROS BOTONES */
    .btn { background: var(--primary); color: white; padding: 0.7rem 1.5rem; border-radius: 6px; font-weight: 700; border: none; cursor: pointer; text-decoration: none; display: inline-block; font-size: 0.9rem; }
    .btn:hover { background: var(--primary-hover); }
    .btn-outline { background: white; border: 1px solid var(--border); color: var(--text-main); }
    .btn-danger { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
    .btn-danger:hover { background: #fecaca; }

    /* UPLOAD FILE */
    .file-upload { position: relative; overflow: hidden; display: inline-block; }
    .file-upload input[type=file] { font-size: 100px; position: absolute; left: 0; top: 0; opacity: 0; cursor: pointer; }
    .file-btn { background: #374151; color: white; padding: 8px 15px; border-radius: 6px; display: inline-block; cursor: pointer; font-size: 0.9rem; }

    .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; }
    .bg-green { background: #dcfce7; color: #166534; }
    .bg-red { background: #fee2e2; color: #991b1b; }
    
    iframe.map { width: 100%; height: 250px; border: none; border-radius: 8px; margin-top: 10px; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    function openTab(id) {
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        document.getElementById('btn-'+id).classList.add('active');
    }
    function toggleDetails(id) { document.getElementById('det-'+id).classList.toggle('open'); }
    function updateFileName(input) {
        document.getElementById('file-name').innerText = input.files[0] ? input.files[0].name : "Ningún archivo seleccionado";
    }
</script>
"""

@app.route('/')
def home():
    return redirect('/admin/panel')

@app.route('/admin/panel')
def admin_panel():
    conn = get_db_connection()
    if not conn: return "Error crítico: No hay conexión a Base de Datos."
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # 1. Clientes
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            clients = cursor.fetchall()
            
            # 2. Stats
            cursor.execute("SELECT SUM(tokens_practica) as tp, SUM(tokens_supervigilancia) as ts, COUNT(*) as total FROM clientes")
            stats = cursor.fetchone()
            
            # 3. Chart Data
            cursor.execute("""
                SELECT TO_CHAR(fecha, 'YYYY-MM') as mes, SUM(cantidad) as total 
                FROM historial WHERE accion = 'RECARGA' 
                GROUP BY mes ORDER BY mes ASC LIMIT 12
            """)
            chart = cursor.fetchall()
            labels = [r['mes'] for r in chart]
            values = [r['total'] for r in chart]
    finally:
        conn.close()

    # --- RENDER TAB 1: CLIENTES ---
    clients_html = ""
    for c in clients:
        # Validación de dirección segura
        raw_address = c.get('direccion')
        if not raw_address or raw_address.strip() == "":
            raw_address = "Bogotá, Colombia"
        
        map_query = raw_address.replace(" ", "+")
        map_url = f"https://maps.google.com/maps?q={map_query}&t=&z=13&ie=UTF8&iwloc=&output=embed"
        
        # Logo fallback
        logo = c.get('logo_url') or f"https://ui-avatars.com/api/?name={c['nombre']}&background=random"

        clients_html += f"""
        <div class="client-item">
            <div class="client-header" onclick="toggleDetails({c['id']})">
                <div class="client-profile">
                    <img src="{logo}" class="client-logo">
                    <div>
                        <div style="font-weight:700; font-size:1.1rem;">{c['nombre']}</div>
                        <div style="font-family:monospace; color:#666; font-size:0.85rem;">{c['hwid']}</div>
                    </div>
                </div>
                <div style="display:flex; gap:20px; align-items:center;">
                    <div style="text-align:right;">
                        <div style="font-size:0.7rem; font-weight:700; color:#888;">PRÁCTICA</div>
                        <span class="badge bg-green">{c['tokens_practica']}</span>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-size:0.7rem; font-weight:700; color:#888;">SUPERVIG.</div>
                        <span class="badge bg-red">{c['tokens_supervigilancia']}</span>
                    </div>
                    <div style="color:#aaa;">▼</div>
                </div>
            </div>

            <div id="det-{c['id']}" class="client-details">
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:30px;">
                    <div>
                        <div class="section-title" style="margin-bottom:1rem; font-size:0.9rem;">DATOS DE LA UNIDAD</div>
                        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; font-size:0.9rem;">
                            <div><b>Responsable:</b><br>{c.get('responsable','-')}</div>
                            <div><b>Email:</b><br><a href="mailto:{c.get('email')}" style="color:#b91c1c;">{c.get('email','-')}</a></div>
                            <div><b>Tel 1:</b><br>{c.get('telefono1','-')}</div>
                            <div><b>Tel 2:</b><br>{c.get('telefono2','-')}</div>
                        </div>
                        <div style="margin-top:15px;">
                            <b>Dirección:</b> {raw_address}
                            <iframe class="map" src="{map_url}"></iframe>
                        </div>
                    </div>

                    <div>
                        <div class="section-title" style="margin-bottom:1rem; font-size:0.9rem;">CONTROL DE TOKENS</div>
                        <form action="/admin/add_tokens" method="post" style="background:white; padding:20px; border-radius:8px; border:1px solid #eee;">
                            <input type="hidden" name="hwid" value="{c['hwid']}">
                            
                            <div style="margin-bottom:15px;">
                                <label>Tipo de Token</label>
                                <select name="type">
                                    <option value="practica">Práctica (Entrenamiento)</option>
                                    <option value="supervigilancia">Supervigilancia</option>
                                </select>
                            </div>

                            <label>Operación</label>
                            <div class="token-control">
                                <input type="number" name="amount" placeholder="Cantidad" required style="font-weight:bold; font-size:1.1rem; border:none; background:transparent;">
                                <button type="submit" name="action" value="sub" class="btn-icon btn-sub" title="Restar (Corregir)">-</button>
                                <button type="submit" name="action" value="add" class="btn-icon btn-add" title="Agregar (Recargar)">+</button>
                            </div>
                        </form>

                        <div style="margin-top:20px; display:flex; gap:10px; justify-content:flex-end;">
                            <a href="/admin/history/{c['hwid']}" class="btn btn-outline" style="font-size:0.8rem;">📜 VER HISTORIAL</a>
                            
                            <form action="/admin/delete_client" method="post" onsubmit="return confirm('¿ESTÁ SEGURO? Esta acción borrará la escuela y su historial permanentemente.');">
                                <input type="hidden" name="hwid" value="{c['hwid']}">
                                <button type="submit" class="btn btn-danger" style="padding:0.5rem 1rem; font-size:0.8rem;">🗑 DAR DE BAJA</button>
                            </form>
                        </div>
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
        <title>ALPHA COMMAND CRM</title>
        {CSS_THEME}
    </head>
    <body>
        <nav class="navbar">
            <div style="display:flex; align-items:center; gap:10px;">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="brand-logo">
                <div style="font-weight:800; font-size:1.2rem; color:#b91c1c;">COMMAND CENTER</div>
            </div>
        </nav>

        <div class="container">
            <div class="tabs-nav">
                <button id="btn-units" class="tab-btn active" onclick="openTab('units')">UNIDADES EN RED</button>
                <button id="btn-reg" class="tab-btn" onclick="openTab('reg')">REGISTRAR NUEVA</button>
                <button id="btn-stats" class="tab-btn" onclick="openTab('stats')">INTELIGENCIA</button>
            </div>

            <div id="units" class="tab-content active">
                <div style="margin-bottom:1rem; display:flex; justify-content:space-between;">
                    <div class="section-title" style="margin:0;">CARTERA DE CLIENTES ({stats['total']})</div>
                </div>
                {clients_html}
            </div>

            <div id="reg" class="tab-content">
                <div class="card" style="max-width:800px; margin:0 auto;">
                    <div class="section-title">ALTA DE NUEVA ESCUELA</div>
                    <form action="/admin/register" method="post" enctype="multipart/form-data">
                        <div class="form-grid">
                            <div class="full-width">
                                <label>Nombre Institución</label>
                                <input type="text" name="nombre" required placeholder="Ej: Academia Alpha">
                            </div>
                            <div class="full-width">
                                <label>Hardware ID (HWID)</label>
                                <input type="text" name="hwid" required placeholder="Código único del simulador">
                            </div>
                            
                            <div class="full-width" style="background:#f9fafb; padding:15px; border-radius:8px; border:1px dashed #ccc;">
                                <label>Logo de la Escuela (Imagen)</label>
                                <div class="file-upload">
                                    <label class="file-btn">
                                        <input type="file" name="logo_file" accept="image/*" onchange="updateFileName(this)">
                                        📂 Seleccionar Archivo
                                    </label>
                                    <span id="file-name" style="margin-left:10px; color:#666; font-size:0.9rem;">Ningún archivo seleccionado</span>
                                </div>
                            </div>

                            <div>
                                <label>Responsable</label>
                                <input type="text" name="responsable">
                            </div>
                            <div>
                                <label>Email</label>
                                <input type="email" name="email">
                            </div>
                            <div>
                                <label>Teléfono 1</label>
                                <input type="text" name="telefono1">
                            </div>
                            <div>
                                <label>Teléfono 2</label>
                                <input type="text" name="telefono2">
                            </div>
                            <div class="full-width">
                                <label>Dirección Física (Para Mapa)</label>
                                <input type="text" name="direccion" placeholder="Calle, Número, Ciudad">
                            </div>
                        </div>
                        <div style="margin-top:2rem; text-align:right;">
                            <button type="submit" class="btn">GUARDAR EN BASE DE DATOS</button>
                        </div>
                    </form>
                </div>
            </div>

            <div id="stats" class="tab-content">
                <div class="form-grid" style="margin-bottom:2rem;">
                    <div class="card" style="text-align:center;">
                        <div style="color:#666; font-size:0.8rem; font-weight:700;">TOTAL ESCUELAS</div>
                        <div style="font-size:2.5rem; font-weight:800; color:#1f2937;">{stats['total']}</div>
                    </div>
                    <div class="card" style="text-align:center;">
                        <div style="color:#666; font-size:0.8rem; font-weight:700;">TOKENS PRÁCTICA</div>
                        <div style="font-size:2.5rem; font-weight:800; color:#059669;">{stats['tp'] or 0}</div>
                    </div>
                    <div class="card" style="text-align:center;">
                        <div style="color:#666; font-size:0.8rem; font-weight:700;">TOKENS SUPERVIG.</div>
                        <div style="font-size:2.5rem; font-weight:800; color:#b91c1c;">{stats['ts'] or 0}</div>
                    </div>
                </div>
                <div class="card">
                    <div class="section-title">HISTÓRICO DE VENTAS</div>
                    <div style="height:350px;">
                        <canvas id="chart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <script>
            const ctx = document.getElementById('chart').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: {json.dumps(labels)},
                    datasets: [{{
                        label: 'Tokens Recargados',
                        data: {json.dumps(values)},
                        borderColor: '#b91c1c',
                        backgroundColor: 'rgba(185, 28, 28, 0.1)',
                        fill: true, tension: 0.3
                    }}]
                }},
                options: {{ responsive: true, maintainAspectRatio: false }}
            }});
        </script>
    </body>
    </html>
    """)

# =========================================================
# RUTAS DE ACCIÓN
# =========================================================

@app.route('/admin/register', methods=['POST'])
def register():
    try:
        # 1. Subir Imagen a ImgBB
        logo_url = ""
        file = request.files.get('logo_file')
        if file and file.filename != '':
            try:
                payload = {'key': IMGBB_API_KEY}
                files = {'image': file.read()}
                res = requests.post('https://api.imgbb.com/1/upload', data=payload, files=files)
                if res.status_code == 200:
                    logo_url = res.json()['data']['url']
            except Exception as e:
                print(f"Error ImgBB: {e}")

        # 2. Guardar en BD
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
                request.form.get('direccion', ''), logo_url
            ))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"Error: {e}"

@app.route('/admin/add_tokens', methods=['POST'])
def add_tokens():
    try:
        hwid = request.form['hwid']
        raw_amount = int(request.form['amount'])
        action = request.form['action'] # 'add' or 'sub'
        token_type = request.form['type']
        
        final_amount = raw_amount if action == 'add' else -raw_amount
        accion_label = "RECARGA" if action == 'add' else "CORRECCION"
        col = f"tokens_{token_type}"
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(f"UPDATE clientes SET {col} = {col} + %s WHERE hwid = %s", (final_amount, hwid))
            cursor.execute("""
                INSERT INTO historial (hwid, accion, cantidad, tipo_token) VALUES (%s, %s, %s, %s)
            """, (hwid, accion_label, final_amount, token_type))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"Error: {e}"

@app.route('/admin/delete_client', methods=['POST'])
def delete_client():
    try:
        hwid = request.form['hwid']
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM clientes WHERE hwid = %s", (hwid,))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"Error borrando: {e}"

@app.route('/admin/history/<hwid>')
def history(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            name = client['nombre'] if client else "Desconocido"

            cursor.execute("SELECT * FROM historial WHERE hwid = %s ORDER BY fecha DESC LIMIT 100", (hwid,))
            logs = cursor.fetchall()
    finally:
        conn.close()
    
    log_rows = ""
    for l in logs:
        color = "#059669" if l['cantidad'] > 0 else "#b91c1c"
        log_rows += f"<tr><td>{l['fecha']}</td><td>{l['accion']}</td><td>{l['tipo_token']}</td><td style='color:{color}; font-weight:bold'>{l['cantidad']}</td></tr>"

    return render_template_string(f"""
        <!DOCTYPE html><html><head><title>Logs</title>{CSS_THEME}</head><body>
        <div class="container" style="max-width:900px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                <a href="/admin/panel" class="btn btn-outline">← VOLVER</a>
                <a href="/admin/download_pdf/{hwid}" class="btn">DESCARGAR REPORTE PDF</a>
            </div>
            <div class="card">
                <div class="section-title">HISTORIAL: {name}</div>
                <table style="width:100%; border-collapse:collapse;">
                    <tr style="background:#f9fafb; text-align:left;"><th style="padding:10px;">FECHA</th><th>ACCIÓN</th><th>TOKEN</th><th>CANT.</th></tr>
                    {log_rows}
                </table>
            </div>
        </div></body></html>
    """)

@app.route('/admin/download_pdf/<hwid>')
def download_pdf(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            cursor.execute("SELECT * FROM historial WHERE hwid = %s ORDER BY fecha DESC", (hwid,))
            logs = cursor.fetchall()
    finally:
        conn.close()

    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    
    # Info Cliente
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, f"CLIENTE: {client['nombre']}", 0, 1)
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 5, f"HWID: {hwid}", 0, 1)
    pdf.cell(0, 5, f"Responsable: {client.get('responsable','')}", 0, 1)
    pdf.cell(0, 5, f"Fecha Reporte: {datetime.datetime.now()}", 0, 1)
    pdf.ln(10)
    
    # Tabla
    pdf.set_fill_color(240, 240, 240)
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(50, 10, "Fecha", 1, 0, 'C', 1)
    pdf.cell(40, 10, "Accion", 1, 0, 'C', 1)
    pdf.cell(40, 10, "Tipo", 1, 0, 'C', 1)
    pdf.cell(30, 10, "Cant.", 1, 1, 'C', 1)
    
    pdf.set_font("Arial", '', 9)
    for log in logs:
        pdf.cell(50, 8, str(log['fecha']), 1)
        pdf.cell(40, 8, str(log['accion']), 1)
        pdf.cell(40, 8, str(log['tipo_token']), 1)
        pdf.cell(30, 8, str(log['cantidad']), 1, 1, 'C')

    buffer = io.BytesIO()
    pdf_content = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_content)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Reporte_{client['nombre'].replace(' ','_')}.pdf",
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
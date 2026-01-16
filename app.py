import os
import hmac
import hashlib
import time
import datetime
import json
import requests
import io
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, send_file, session
import psycopg2
from psycopg2.extras import RealDictCursor
from fpdf import FPDF

app = Flask(__name__)
# Necesario para manejar sesiones (cookies firmadas)
app.secret_key = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4")

# --- CONFIGURACIÓN DE ENTORNO ---
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", "26367")
SECRET_KEY = os.getenv("SECRET_KEY", "TU_CLAVE_MAESTRA_SUPER_SECRETA_V4").encode()
IMGBB_API_KEY = "df01bb05ce03159d54c33e1e22eba2cf"
ADMIN_PASS = "1032491753Outlook*+"

# --- CONEXIÓN BASE DE DATOS ---
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

# --- SEGURIDAD ---
def verify_signature(hwid, timestamp, received_sig):
    if abs(time.time() - float(timestamp)) > 300: return False
    data = f"{hwid}:{timestamp}".encode()
    expected_sig = hmac.new(SECRET_KEY, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, received_sig)

# =========================================================
# ESTILOS CSS GLOBALES (LIGHT MODE PRO)
# =========================================================
CSS_THEME = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

    :root {
        --primary: #b91c1c; 
        --primary-dark: #991b1b;
        --secondary: #4b5563;
        --bg: #f3f4f6;
        --surface: #ffffff;
        --text-main: #1f2937;
        --border: #e5e7eb;
        --success: #059669;
        --money: #047857;
        --assist: #2563eb; 
    }

    * { box-sizing: border-box; }
    body { background-color: var(--bg); color: var(--text-main); font-family: 'Inter', sans-serif; margin: 0; }

    /* NAVBAR */
    .navbar {
        background: var(--surface); border-bottom: 1px solid var(--border); padding: 0.8rem 2rem;
        display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100;
        box-shadow: 0 2px 4px rgba(0,0,0,0.02);
    }
    .brand-logo { height: 45px; }

    .container { max-width: 1400px; margin: 2rem auto; padding: 0 1.5rem; }

    /* CARDS */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 1.5rem; }
    
    /* LOGIN PAGE SPECIFIC */
    .login-wrapper {
        display: flex; align-items: center; justify-content: center; height: 100vh; background: #f3f4f6;
    }
    .login-card {
        background: white; width: 400px; padding: 30px; border-radius: 16px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
        text-align: center;
    }
    .login-logo { height: 60px; margin-bottom: 20px; }
    
    .login-tabs { display: flex; margin-bottom: 20px; border-bottom: 2px solid #e5e7eb; }
    .lt-btn {
        flex: 1; padding: 10px; cursor: pointer; font-weight: 600; color: #6b7280; background: none; border: none;
        transition: all 0.3s;
    }
    .lt-btn.active { color: var(--primary); border-bottom: 3px solid var(--primary); }
    
    .login-form { display: none; }
    .login-form.active { display: block; animation: fadeIn 0.3s; }
    
    @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }

    input { 
        width: 100%; padding: 12px; border: 1px solid #d1d5db; border-radius: 8px; margin-bottom: 15px; 
        font-family: 'Inter'; font-size: 14px;
    }
    input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(185, 28, 28, 0.1); }

    .btn-login {
        width: 100%; background: var(--primary); color: white; padding: 12px; border-radius: 8px;
        font-weight: 700; border: none; cursor: pointer; transition: background 0.2s;
    }
    .btn-login:hover { background: var(--primary-dark); }

    /* DASHBOARD ELEMENTS */
    .finance-grid { 
        display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px;
    }
    .fin-card {
        background: white; border: 1px solid #e5e7eb; border-radius: 10px; padding: 20px; text-align: center;
    }
    .fin-card.highlight { border: 2px solid var(--primary); background: #fff5f5; }
    
    .fin-label { font-size: 0.8rem; font-weight: 700; color: #6b7280; text-transform: uppercase; margin-bottom: 5px; }
    .fin-val { font-size: 1.8rem; font-weight: 800; color: #111827; }
    
    .text-red { color: var(--primary); }
    .text-green { color: var(--money); }
    .text-blue { color: var(--assist); }

    /* TABLAS */
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 12px; background: #f9fafb; font-size: 0.8rem; text-transform: uppercase; color: #6b7280; }
    td { padding: 12px; border-bottom: 1px solid #e5e7eb; font-size: 0.9rem; }
    
    /* UTILS */
    .btn-outline { background: white; border: 1px solid #e5e7eb; color: #374151; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-weight: 600; }
    .btn-outline:hover { background: #f3f4f6; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }
    .bg-green { background: #dcfce7; color: #166534; }
    .bg-red { background: #fee2e2; color: #991b1b; }
</style>
"""

# =========================================================
# LÓGICA PDF
# =========================================================
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.set_text_color(185, 28, 28)
        self.cell(0, 10, 'ALPHA SECURITY - REPORTE DE OPERACIONES', 0, 1, 'C')
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
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
                client = cursor.fetchone()

                if not client:
                    return jsonify({"status": "error", "msg": "No registrado"}), 404

                if client.get('bloqueado', False):
                    return jsonify({"status": "error", "msg": "SISTEMA BLOQUEADO. PAGO PENDIENTE."}), 403

                modelo = client.get('modelo_negocio', 'tokens')

                if modelo == 'tokens':
                    col = f"tokens_{token_type}"
                    if client.get(col, 0) > 0:
                        cursor.execute(f"UPDATE clientes SET {col} = {col} - 1 WHERE hwid = %s", (hwid,))
                        cursor.execute("INSERT INTO historial (hwid, accion, cantidad, tipo_token) VALUES (%s, 'CONSUMO', -1, %s)", (hwid, token_type))
                        conn.commit()
                        
                        cursor.execute(f"SELECT {col} FROM clientes WHERE hwid = %s", (hwid,))
                        new_bal = cursor.fetchone()[col]
                        return jsonify({"status": "success", "remaining": new_bal, "type": token_type, "mode": "tokens"})
                    else:
                        return jsonify({"status": "denied", "msg": "Sin saldo", "type": token_type}), 402

                else: # CONTEO
                    cursor.execute("UPDATE clientes SET conteo_activaciones = conteo_activaciones + 1 WHERE hwid = %s", (hwid,))
                    cursor.execute("INSERT INTO historial (hwid, accion, cantidad, tipo_token) VALUES (%s, 'ACTIVACION_SOCIO', 1, %s)", (hwid, token_type))
                    conn.commit()
                    return jsonify({"status": "success", "remaining": 999999, "type": token_type, "mode": "conteo"})

        finally:
            conn.close()
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

# =========================================================
# RUTAS WEB (LOGIN & PANELES)
# =========================================================

@app.route('/')
def login_page():
    return render_template_string(f"""
    <!DOCTYPE html>
    <html lang="es">
    <head><meta charset="UTF-8"><title>Alpha Security - Login</title>{CSS_THEME}
    <script>
        function showTab(tab) {{
            document.querySelectorAll('.login-form').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.lt-btn').forEach(el => el.classList.remove('active'));
            document.getElementById('form-' + tab).classList.add('active');
            document.getElementById('btn-' + tab).classList.add('active');
        }}
    </script>
    </head>
    <body>
        <div class="login-wrapper">
            <div class="login-card">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="login-logo">
                
                <div class="login-tabs">
                    <button id="btn-admin" class="lt-btn active" onclick="showTab('admin')">ADMINISTRADOR</button>
                    <button id="btn-user" class="lt-btn" onclick="showTab('user')">SOCIO / CLIENTE</button>
                </div>

                <form id="form-admin" class="login-form active" action="/auth/login" method="POST">
                    <input type="hidden" name="role" value="admin">
                    <input type="password" name="password" placeholder="Clave Maestra" required>
                    <button type="submit" class="btn-login">INGRESAR AL SISTEMA</button>
                </form>

                <form id="form-user" class="login-form" action="/auth/login" method="POST">
                    <input type="hidden" name="role" value="user">
                    <input type="text" name="hwid" placeholder="Ingrese su HWID (ID Máquina)" required style="font-family:monospace;">
                    <button type="submit" class="btn-login" style="background-color:#4b5563;">CONSULTAR ESTADO</button>
                </form>
                
                <div style="margin-top:20px; font-size:0.8rem; color:#9ca3af;">
                    Alpha Security Systems &copy; 2025
                </div>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/auth/login', methods=['POST'])
def auth_login():
    role = request.form.get('role')
    
    if role == 'admin':
        password = request.form.get('password')
        if password == ADMIN_PASS:
            session['admin_logged_in'] = True
            return redirect('/admin/panel')
        else:
            return "<h1>ACCESO DENEGADO: Contraseña Incorrecta</h1><a href='/'>Volver</a>"
    
    elif role == 'user':
        hwid = request.form.get('hwid').strip()
        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
                client = cursor.fetchone()
                if client:
                    return redirect(f"/client/dashboard/{hwid}")
                else:
                    return "<h1>ERROR: HWID No encontrado en la base de datos.</h1><a href='/'>Volver</a>"
        finally:
            conn.close()
            
    return redirect('/')

# --- PANEL CLIENTE (SOLO LECTURA) ---
@app.route('/client/dashboard/<path:hwid>')
def client_dashboard(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            
            # Obtener historial reciente
            cursor.execute("SELECT * FROM historial WHERE hwid = %s ORDER BY fecha DESC LIMIT 50", (hwid,))
            logs = cursor.fetchall()
    finally:
        conn.close()

    if not client: return "Cliente no encontrado"

    # --- LÓGICA FINANCIERA (IDÉNTICA AL ADMIN) ---
    activaciones = client.get('conteo_activaciones', 0)
    valor_unit = client.get('valor_activacion', 5000)
    pct_alpha = client.get('porcentaje_alpha', 70)
    
    # Asistente
    has_assist = client.get('asistente_activo', False)
    pct_assist = client.get('asistente_porcentaje', 0) if has_assist else 0
    
    # Cálculos
    total_generado = activaciones * valor_unit
    deuda_alpha = int(total_generado * (pct_alpha / 100))
    pago_asistente = int(total_generado * (pct_assist / 100))
    ganancia_socio = total_generado - deuda_alpha - pago_asistente

    # Determinar texto del modelo
    if client.get('modelo_negocio') == 'tokens':
        model_html = f"""
        <div class="fin-card">
            <div class="fin-label">SALDO DISPONIBLE</div>
            <div class="fin-val text-green">{client.get('tokens_practica',0)}</div>
            <div class="fin-label" style="margin-top:10px">PRÁCTICA</div>
        </div>
        <div class="fin-card">
            <div class="fin-label">SALDO DISPONIBLE</div>
            <div class="fin-val text-red">{client.get('tokens_supervigilancia',0)}</div>
            <div class="fin-label" style="margin-top:10px">SUPERVIGILANCIA</div>
        </div>
        """
        financial_summary = ""
    else:
        # Modo Conteo (Socio)
        model_html = f"""
        <div class="fin-card">
            <div class="fin-label">TOTAL ACTIVACIONES</div>
            <div class="fin-val">{activaciones}</div>
        </div>
        <div class="fin-card">
            <div class="fin-label">TOTAL CAJA BRUTO</div>
            <div class="fin-val">${total_generado:,.0f}</div>
        </div>
        """
        
        financial_summary = f"""
        <h3 style="margin-top:30px; border-bottom:2px solid #e5e7eb; padding-bottom:10px;">RESUMEN DE LIQUIDACIÓN</h3>
        <div class="finance-grid">
            <div class="fin-card highlight">
                <div class="fin-label">A PAGAR A ALPHA ({pct_alpha}%)</div>
                <div class="fin-val text-red">${deuda_alpha:,.0f}</div>
                <div style="font-size:0.7rem; margin-top:5px; color:#666;">DEBE SER TRANSFERIDO</div>
            </div>
            <div class="fin-card">
                <div class="fin-label">MI GANANCIA NETA</div>
                <div class="fin-val text-green">${ganancia_socio:,.0f}</div>
            </div>
            {f'''
            <div class="fin-card">
                <div class="fin-label">PAGO ASISTENTE ({pct_assist}%)</div>
                <div class="fin-val text-blue">${pago_asistente:,.0f}</div>
            </div>
            ''' if has_assist else ''}
        </div>
        """

    # Bloqueo Visual
    status_badge = '<span class="badge bg-green">ACTIVO</span>'
    if client.get('bloqueado', False):
        status_badge = '<span class="badge bg-red">SERVICIO SUSPENDIDO</span>'

    # Tabla Logs
    log_rows = ""
    for l in logs:
        color = "#059669" if l['cantidad'] > 0 else "#b91c1c"
        log_rows += f"<tr><td>{l['fecha']}</td><td>{l['accion']}</td><td>{l['tipo_token']}</td><td style='color:{color}; font-weight:bold'>{l['cantidad']}</td></tr>"

    return render_template_string(f"""
    <!DOCTYPE html>
    <html lang="es">
    <head><meta charset="UTF-8"><title>Portal de Socio</title>{CSS_THEME}</head>
    <body>
        <nav class="navbar">
            <div style="display:flex; align-items:center; gap:10px;">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="brand-logo">
                <div style="font-weight:800; font-size:1.2rem; color:var(--primary);">PORTAL DE SOCIO</div>
            </div>
            <a href="/" class="btn-outline" style="font-size:0.8rem;">CERRAR SESIÓN</a>
        </nav>

        <div class="container">
            <div class="card" style="border-left: 5px solid var(--primary);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h1 style="margin:0; font-size:1.8rem; color:#111827;">{client['nombre']}</h1>
                        <div style="color:#6b7280; font-family:monospace; margin-top:5px;">ID: {hwid}</div>
                        <div style="margin-top:10px;">{status_badge}</div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-size:0.8rem; font-weight:bold; color:#6b7280;">MODELO DE NEGOCIO</div>
                        <div style="font-size:1.2rem; font-weight:900; color:var(--primary);">{client.get('modelo_negocio','TOKENS').upper()}</div>
                    </div>
                </div>
            </div>

            <div class="finance-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                {model_html}
            </div>

            {financial_summary}

            <div class="card">
                <div class="section-title">HISTORIAL DE MOVIMIENTOS RECIENTES</div>
                <table>
                    <thead><tr><th>FECHA</th><th>EVENTO</th><th>TIPO</th><th>CANTIDAD</th></tr></thead>
                    <tbody>{log_rows}</tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """)

# --- PANEL ADMIN (COMPLETO) ---
@app.route('/admin/panel')
def admin_panel():
    # Protección de sesión simple (Para evitar acceso directo por URL sin login)
    # En producción usar Flask-Login, aquí usamos chequeo manual
    # Nota: Si reinicias el servidor, la sesión se pierde.
    # Para simplicidad en este entorno, puedes quitar el if si da problemas.
    # if not session.get('admin_logged_in'): return redirect('/')

    conn = get_db_connection()
    if not conn: return "Error DB"
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            all_clients = cursor.fetchall()
            
            cursor.execute("SELECT SUM(tokens_practica) as tp, SUM(tokens_supervigilancia) as ts, COUNT(*) as total FROM clientes")
            stats = cursor.fetchone()
            
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

    clients_tokens = [c for c in all_clients if c.get('modelo_negocio') != 'conteo']
    clients_conteo = [c for c in all_clients if c.get('modelo_negocio') == 'conteo']

    html_tokens = ""
    for c in clients_tokens:
        logo = c.get('logo_url') or f"https://ui-avatars.com/api/?name={c['nombre']}&background=random"
        raw_addr = c.get('direccion') or 'Bogota'
        map_url = f"https://maps.google.com/maps?q={raw_addr.replace(' ','+')}&output=embed"
        
        is_blocked = c.get('bloqueado', False)
        blocked_class = "blocked" if is_blocked else ""
        blocked_badge = '<div class="blocked-badge">BLOQUEADO</div>' if is_blocked else ''
        
        btn_block_html = f"""
            <form action="/admin/toggle_block" method="post" style="display:inline;" onsubmit="return confirm('¿Cambiar estado?');">
                <input type="hidden" name="hwid" value="{c['hwid']}">
                <input type="hidden" name="new_status" value="{'false' if is_blocked else 'true'}">
                <button class="btn {'btn-unblock' if is_blocked else 'btn-block'}" style="font-size:0.8rem; padding:5px;">
                    {'🔓' if is_blocked else '🔒'}
                </button>
            </form>
        """

        html_tokens += f"""
        <div class="client-item {blocked_class}">
            {blocked_badge}
            <div class="client-header" onclick="toggleDetails({c['id']})">
                <div class="client-profile">
                    <img src="{logo}" class="client-logo">
                    <div>
                        <div style="font-weight:700;">{c['nombre']}</div>
                        <div style="color:#666; font-size:0.8rem;">{c['hwid']}</div>
                    </div>
                </div>
                <div style="display:flex; gap:15px; align-items:center;">
                    <span class="badge bg-gray">PRÁCTICA: {c['tokens_practica']}</span>
                    <span class="badge bg-red">SUPER: {c['tokens_supervigilancia']}</span>
                    <span>▼</span>
                </div>
            </div>
            <div id="det-{c['id']}" class="client-details">
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
                    <div>
                        <strong>Responsable:</strong> {c.get('responsable','-')}<br>
                        <strong>Tel:</strong> {c.get('telefono1','-')}<br>
                        <iframe class="map" src="{map_url}"></iframe>
                    </div>
                    <div>
                        <h4 style="margin-top:0;">CONTROL</h4>
                        <form action="/admin/add_tokens" method="post">
                            <input type="hidden" name="hwid" value="{c['hwid']}">
                            <div style="margin-bottom:10px;">
                                <select name="type"><option value="practica">Práctica</option><option value="supervigilancia">Supervigilancia</option></select>
                            </div>
                            <div class="token-control">
                                <input type="number" name="amount" placeholder="Cant." required>
                                <button type="submit" name="action" value="sub" class="btn-icon btn-sub">-</button>
                                <button type="submit" name="action" value="add" class="btn-icon btn-add">+</button>
                            </div>
                        </form>
                        <div style="margin-top:10px; display:flex; gap:5px; justify-content:flex-end;">
                            {btn_block_html}
                            <a href="/admin/history/{c['hwid']}" class="btn btn-outline" style="font-size:0.8rem; padding:5px;">HISTORIAL</a>
                            <form action="/admin/delete_client" method="post" style="display:inline;" onsubmit="return confirm('¿Borrar?');">
                                <input type="hidden" name="hwid" value="{c['hwid']}">
                                <button class="btn btn-danger" style="font-size:0.8rem; padding:5px;">🗑</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    html_conteo = ""
    for c in clients_conteo:
        logo = c.get('logo_url') or f"https://ui-avatars.com/api/?name={c['nombre']}&background=random"
        activaciones = c.get('conteo_activaciones', 0)
        valor_unit = c.get('valor_activacion', 5000)
        
        is_blocked = c.get('bloqueado', False)
        blocked_class = "blocked" if is_blocked else ""
        blocked_badge = '<div class="blocked-badge">BLOQUEADO POR PAGO</div>' if is_blocked else ''
        
        btn_block_html = f"""
            <form action="/admin/toggle_block" method="post" style="display:inline;" onsubmit="return confirm('¿Bloquear/Desbloquear?');">
                <input type="hidden" name="hwid" value="{c['hwid']}">
                <input type="hidden" name="new_status" value="{'false' if is_blocked else 'true'}">
                <button class="btn {'btn-unblock' if is_blocked else 'btn-block'}" style="font-size:0.8rem;">
                    {'🔓 REACTIVAR' if is_blocked else '🔒 BLOQUEAR'}
                </button>
            </form>
        """

        pct_alpha = c.get('porcentaje_alpha', 70)
        has_assist = c.get('asistente_activo', False)
        pct_assist = c.get('asistente_porcentaje', 0)
        
        total_generado = activaciones * valor_unit
        ganancia_alpha = int(total_generado * (pct_alpha / 100))
        ganancia_assist = int(total_generado * (pct_assist / 100)) if has_assist else 0
        ganancia_socio = total_generado - ganancia_alpha - ganancia_assist

        html_conteo += f"""
        <div class="client-item {blocked_class}" style="border-left: 5px solid var(--primary);">
            {blocked_badge}
            <div class="client-header" onclick="toggleDetails({c['id']})">
                <div class="client-profile">
                    <img src="{logo}" class="client-logo">
                    <div>
                        <div style="font-weight:700; color:var(--primary);">{c['nombre']}</div>
                        <div style="color:#666; font-size:0.8rem;">SOCIO AL {pct_alpha}%</div>
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:0.7rem; font-weight:700; color:#888;">ACT</div>
                    <div style="font-size:1.2rem; font-weight:800;">{activaciones}</div>
                </div>
            </div>
            <div id="det-{c['id']}" class="client-details">
                <div class="finance-grid">
                    <div class="fin-box"><div class="fin-label">PRECIO</div><div class="fin-val">${valor_unit:,.0f}</div></div>
                    <div class="fin-box"><div class="fin-label">TOTAL</div><div class="fin-val fin-money">${total_generado:,.0f}</div></div>
                    <div class="fin-box"><div class="fin-label">ALPHA ({pct_alpha}%)</div><div class="fin-val fin-alpha">${ganancia_alpha:,.0f}</div></div>
                    <div class="fin-box"><div class="fin-label">SOCIO</div><div class="fin-val">${ganancia_socio:,.0f}</div></div>
                    <div class="fin-box" style="{'opacity:0.3;' if not has_assist else ''}"><div class="fin-label">ASIST. ({pct_assist}%)</div><div class="fin-val fin-assist">${ganancia_assist:,.0f}</div></div>
                </div>
                <div style="text-align:right;">
                    <form action="/admin/reset_counter" method="post" style="display:inline;" onsubmit="return confirm('¿Corte de Caja? Se reiniciará el contador.');">
                        <input type="hidden" name="hwid" value="{c['hwid']}">
                        <button class="btn btn-outline" style="font-size:0.8rem;">🔄 CORTE</button>
                    </form>
                    {btn_block_html}
                    <a href="/admin/history/{c['hwid']}" class="btn btn-outline" style="font-size:0.8rem;">📜 DETALLES</a>
                    <form action="/admin/delete_client" method="post" style="display:inline;" onsubmit="return confirm('¿Borrar?');">
                        <input type="hidden" name="hwid" value="{c['hwid']}">
                        <button class="btn btn-danger" style="font-size:0.8rem;">🗑</button>
                    </form>
                </div>
            </div>
        </div>
        """

    return render_template_string(f"""
    <!DOCTYPE html>
    <html lang="es">
    <head><meta charset="UTF-8"><title>Admin Panel</title>{CSS_THEME}</head>
    <body>
        <nav class="navbar">
            <div style="display:flex; align-items:center; gap:10px;">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="brand-logo">
                <div style="font-weight:800; font-size:1.2rem; color:var(--primary);">ADMINISTRADOR</div>
            </div>
            <a href="/" class="btn-outline" style="font-size:0.8rem;">SALIR</a>
        </nav>

        <div class="container">
            <div class="tabs-nav">
                <button id="btn-units" class="tab-btn tab-btn-tokens active" onclick="openTab('units')">PREPAGO</button>
                <button id="btn-partners" class="tab-btn tab-btn-socio" onclick="openTab('partners')">SOCIOS</button>
                <button id="btn-reg" class="tab-btn" onclick="openTab('reg')">NUEVO</button>
                <button id="btn-stats" class="tab-btn" onclick="openTab('stats')">DATA</button>
            </div>

            <div id="units" class="tab-content active">
                {html_tokens if html_tokens else '<div style="text-align:center; padding:40px; color:#999;">Vacío.</div>'}
            </div>

            <div id="partners" class="tab-content">
                {html_conteo if html_conteo else '<div style="text-align:center; padding:40px; color:#999;">Vacío.</div>'}
            </div>

            <div id="reg" class="tab-content">
                <div class="card" style="max-width:800px; margin:0 auto;">
                    <div style="margin-bottom:1.5rem; font-weight:800;">REGISTRAR CLIENTE</div>
                    <form action="/admin/register" method="post" enctype="multipart/form-data">
                        <div class="form-grid">
                            <div class="full-width">
                                <label>Modelo</label>
                                <select name="modelo_negocio" onchange="toggleModelFields(this)">
                                    <option value="tokens">PREPAGO (Venta Tokens)</option>
                                    <option value="conteo">SOCIO (Comisión)</option>
                                </select>
                            </div>
                            <div id="conteo-fields" class="full-width form-grid" style="display:none; background:#fff1f2; padding:15px; border-radius:8px;">
                                <div><label>Valor Activación</label><input type="number" name="valor_activacion" value="5000"></div>
                                <div><label>% Alpha</label><input type="number" name="porcentaje_alpha" value="70"></div>
                                <div class="full-width">
                                    <label style="display:flex; gap:10px;"><input type="checkbox" name="asistente_activo" style="width:auto;" onchange="toggleAssistFields(this)"> ASISTENTE EXTERNO</label>
                                </div>
                                <div id="assist-fields" class="full-width form-grid" style="display:none;">
                                    <div><label>Nombre</label><input type="text" name="asistente_nombre"></div>
                                    <div><label>% Asistente</label><input type="number" name="asistente_porcentaje" value="10"></div>
                                    <div class="full-width" style="font-weight:bold; color:#2563eb; margin-top:5px;">Datos Bancarios</div>
                                    <div><label>Banco</label><input type="text" name="asistente_banco"></div>
                                    <div><label>Cuenta</label><input type="text" name="asistente_cuenta"></div>
                                    <div><label>Tipo</label><select name="asistente_tipo_cuenta"><option>Ahorros</option><option>Corriente</option><option>Nequi/Davi</option></select></div>
                                </div>
                            </div>
                            <div class="full-width"><label>Nombre</label><input type="text" name="nombre" required></div>
                            <div class="full-width"><label>HWID</label><input type="text" name="hwid" required style="font-family:monospace;"></div>
                            <div class="full-width"><label>Logo</label><div class="file-upload"><label class="file-btn"><input type="file" name="logo_file" onchange="updateFileName(this)">Subir</label><span id="file-name" style="margin-left:10px;">...</span></div></div>
                            <div><label>Responsable</label><input type="text" name="responsable"></div>
                            <div><label>Email</label><input type="email" name="email"></div>
                            <div><label>Tel 1</label><input type="text" name="telefono1"></div>
                            <div><label>Tel 2</label><input type="text" name="telefono2"></div>
                            <div class="full-width"><label>Dirección</label><input type="text" name="direccion"></div>
                        </div>
                        <div style="margin-top:20px; text-align:right;"><button type="submit" class="btn">GUARDAR</button></div>
                    </form>
                </div>
            </div>

            <div id="stats" class="tab-content">
                <div class="card" style="height:400px;"><canvas id="chart"></canvas></div>
            </div>
        </div>
        <script>
            const ctx = document.getElementById('chart').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: {json.dumps(labels)},
                    datasets: [{{ label: 'Ventas', data: {json.dumps(values)}, borderColor: '#b91c1c', backgroundColor: 'rgba(185,28,28,0.1)', fill: true }}]
                }},
                options: {{ responsive: true, maintainAspectRatio: false }}
            }});
        </script>
    </body></html>
    """)

# =========================================================
# ACCIONES ADMIN
# =========================================================
@app.route('/admin/register', methods=['POST'])
def register():
    try:
        logo_url = ""
        file = request.files.get('logo_file')
        if file and file.filename != '':
            try:
                payload = {'key': IMGBB_API_KEY}
                files = {'image': file.read()}
                res = requests.post('https://api.imgbb.com/1/upload', data=payload, files=files)
                if res.status_code == 200: logo_url = res.json()['data']['url']
            except: pass

        asistente_activo = True if request.form.get('asistente_activo') == 'on' else False
        asistente_nombre = request.form.get('asistente_nombre', '')
        try: asistente_porc = int(request.form.get('asistente_porcentaje', 0))
        except: asistente_porc = 0
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO clientes 
                (nombre, hwid, responsable, telefono1, telefono2, email, direccion, logo_url, 
                 tokens_supervigilancia, tokens_practica, modelo_negocio, valor_activacion, porcentaje_alpha,
                 asistente_activo, asistente_nombre, asistente_porcentaje, asistente_banco, asistente_cuenta, asistente_tipo_cuenta) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0, 0, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                request.form['nombre'], request.form['hwid'],
                request.form.get('responsable',''), request.form.get('telefono1',''),
                request.form.get('telefono2',''), request.form.get('email',''),
                request.form.get('direccion',''), logo_url,
                request.form.get('modelo_negocio','tokens'),
                request.form.get('valor_activacion', 5000),
                request.form.get('porcentaje_alpha', 70),
                asistente_activo, asistente_nombre, asistente_porc,
                request.form.get('asistente_banco',''), request.form.get('asistente_cuenta',''), request.form.get('asistente_tipo_cuenta','')
            ))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e: return f"Error: {e}"

@app.route('/admin/add_tokens', methods=['POST'])
def add_tokens():
    try:
        hwid, amount, action = request.form['hwid'], int(request.form['amount']), request.form['action']
        token_type = request.form['type']
        final_amount = amount if action == 'add' else -amount
        label = "RECARGA" if action == 'add' else "CORRECCION"
        col = f"tokens_{token_type}"
        
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(f"UPDATE clientes SET {col} = {col} + %s WHERE hwid = %s", (final_amount, hwid))
            cursor.execute("INSERT INTO historial (hwid, accion, cantidad, tipo_token) VALUES (%s, %s, %s, %s)", (hwid, label, final_amount, token_type))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e: return f"Error: {e}"

@app.route('/admin/toggle_block', methods=['POST'])
def toggle_block():
    try:
        hwid = request.form['hwid']
        new_status = True if request.form['new_status'].lower() == 'true' else False
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("UPDATE clientes SET bloqueado = %s WHERE hwid = %s", (new_status, hwid))
            accion_txt = "BLOQUEO_ADMIN" if new_status else "DESBLOQUEO_ADMIN"
            cursor.execute("INSERT INTO historial (hwid, accion, cantidad, tipo_token) VALUES (%s, %s, 0, 'system')", (hwid, accion_txt))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e: return f"Error: {e}"

@app.route('/admin/reset_counter', methods=['POST'])
def reset_counter():
    try:
        hwid = request.form['hwid']
        conn = get_db_connection()
        # USO DE RealDictCursor CORRIGE EL ERROR DE TUPLE INDICES
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT conteo_activaciones FROM clientes WHERE hwid=%s", (hwid,))
            row = cursor.fetchone()
            total = row['conteo_activaciones'] if row else 0
            
            cursor.execute("INSERT INTO historial (hwid, accion, cantidad, tipo_token) VALUES (%s, 'CORTE_CAJA', %s, 'conteo')", (hwid, total))
            cursor.execute("UPDATE clientes SET conteo_activaciones = 0 WHERE hwid = %s", (hwid,))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e: return f"Error: {e}"

@app.route('/admin/delete_client', methods=['POST'])
def delete_client():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM clientes WHERE hwid = %s", (request.form['hwid'],))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except: return "Error borrando"

# MANEJO DE HISTORIAL/DETALLE COMPLETO
@app.route('/admin/history/<path:hwid>')
def history(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            cursor.execute("SELECT * FROM historial WHERE hwid = %s ORDER BY fecha DESC", (hwid,))
            logs = cursor.fetchall()
    finally: conn.close()

    if not client: return "Cliente no encontrado"

    # Preparar datos de perfil para el admin (Igual que en el dashboard del cliente pero con controles)
    logo = client.get('logo_url') or f"https://ui-avatars.com/api/?name={client['nombre']}&background=random"
    
    # Datos Asistente
    has_assist = client.get('asistente_activo', False)
    assist_info_html = ""
    if has_assist:
        aname = client.get('asistente_nombre','')
        apct = client.get('asistente_porcentaje',0)
        abk = client.get('asistente_banco','---')
        acc = client.get('asistente_cuenta','---')
        assist_info_html = f"""
        <div class="stat-item" style="border-left:2px solid #2563eb; padding-left:10px;">
            <h3 style="color:#2563eb">{aname} ({apct}%)</h3>
            <span>{abk} - {acc}</span>
        </div>
        """

    # Resumen Financiero (Solo si es Socio)
    finance_html = ""
    if client.get('modelo_negocio') == 'conteo':
        act = client.get('conteo_activaciones', 0)
        val = client.get('valor_activacion', 5000)
        tot = act * val
        pct_al = client.get('porcentaje_alpha', 70)
        due_alpha = int(tot * (pct_al/100))
        
        finance_html = f"""
        <div class="finance-grid" style="margin-top:20px;">
            <div class="fin-card"><div class="fin-label">ACTIVACIONES</div><div class="fin-val">{act}</div></div>
            <div class="fin-card"><div class="fin-label">TOTAL CAJA</div><div class="fin-val">${tot:,.0f}</div></div>
            <div class="fin-card highlight"><div class="fin-label">DEUDA ALPHA</div><div class="fin-val text-red">${due_alpha:,.0f}</div></div>
        </div>
        """

    # Logs
    rows = ""
    for l in logs:
        c = "#059669" if l['cantidad'] > 0 else "#b91c1c"
        rows += f"<tr><td>{l['fecha']}</td><td>{l['accion']}</td><td>{l['tipo_token']}</td><td style='color:{c}; font-weight:bold'>{l['cantidad']}</td></tr>"

    return render_template_string(f"""
        <!DOCTYPE html><html><head><title>Detalle Admin</title>{CSS_THEME}</head><body>
        <div class="container">
            <a href="/admin/panel" class="btn btn-outline" style="margin-bottom:20px;">← VOLVER AL PANEL</a>
            
            <div class="profile-header">
                <img src="{logo}" class="profile-img">
                <div class="profile-info">
                    <h1>{client['nombre']}</h1>
                    <div class="profile-meta">{client['hwid']}</div>
                    <div class="profile-meta">{client.get('direccion','')} | {client.get('telefono1','')}</div>
                </div>
                <div class="profile-stats">
                    {assist_info_html}
                    <div class="stat-item">
                        <h3>{client.get('modelo_negocio','TOKENS').upper()}</h3>
                        <span>MODELO</span>
                    </div>
                </div>
            </div>

            {finance_html}

            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                    <div class="section-title" style="margin:0;">HISTORIAL DE MOVIMIENTOS</div>
                    <a href="/admin/download_pdf/{hwid}" class="btn">DESCARGAR REPORTE PDF</a>
                </div>
                <table>
                    <thead><tr><th>FECHA</th><th>ACCIÓN</th><th>TIPO</th><th>CANTIDAD</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div></body></html>
    """)

@app.route('/admin/download_pdf/<path:hwid>')
def download_pdf(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            cursor.execute("SELECT * FROM historial WHERE hwid = %s ORDER BY fecha DESC", (hwid,))
            logs = cursor.fetchall()
    finally: conn.close()

    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 12)
    name = client['nombre'] if client else "Desconocido"
    pdf.cell(0, 10, f"CLIENTE: {name}", 0, 1)
    pdf.ln(10)
    
    pdf.set_font("Arial", 'B', 10); pdf.set_fill_color(220, 220, 220)
    pdf.cell(50, 10, "Fecha", 1, 0, 'C', 1)
    pdf.cell(50, 10, "Accion", 1, 0, 'C', 1)
    pdf.cell(40, 10, "Tipo", 1, 0, 'C', 1)
    pdf.cell(30, 10, "Cant.", 1, 1, 'C', 1)
    
    pdf.set_font("Arial", '', 9)
    for log in logs:
        pdf.cell(50, 8, str(log['fecha']), 1)
        pdf.cell(50, 8, str(log['accion']), 1)
        pdf.cell(40, 8, str(log['tipo_token']), 1)
        pdf.cell(30, 8, str(log['cantidad']), 1, 1, 'C')

    buffer = io.BytesIO()
    pdf_content = pdf.output(dest='S').encode('latin-1')
    buffer.write(pdf_content)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="Reporte.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
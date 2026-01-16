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
# API
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

                # VERIFICAR BLOQUEO
                if client.get('bloqueado', False):
                    return jsonify({"status": "error", "msg": "SISTEMA BLOQUEADO POR ADMINISTRACION."}), 403

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
# ESTILOS CSS
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
        --border: #e5e7eb;
        --success: #059669;
        --money: #047857;
        --assist: #2563eb; 
    }

    * { box-sizing: border-box; }
    body { background-color: var(--bg); color: var(--text-main); font-family: 'Inter', sans-serif; margin: 0; }

    .navbar {
        background: var(--surface); border-bottom: 1px solid var(--border); padding: 0.8rem 2rem;
        display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .brand-logo { height: 45px; }

    .container { max-width: 1400px; margin: 2rem auto; padding: 0 1.5rem; }

    /* TABS */
    .tabs-nav { display: flex; gap: 1rem; margin-bottom: 2rem; border-bottom: 2px solid var(--border); padding-bottom: 1px; }
    .tab-btn {
        background: transparent; border: none; padding: 1rem 1.5rem; font-size: 0.95rem; font-weight: 700;
        color: #6b7280; cursor: pointer; position: relative; transition: all 0.3s;
        border-radius: 8px 8px 0 0;
    }
    .tab-btn:hover { background: #e5e7eb; color: var(--primary); }
    .tab-btn.active { 
        background: var(--surface); border: 1px solid var(--border); border-bottom: 2px solid var(--surface); 
        margin-bottom: -2px; color: var(--primary); border-top: 4px solid var(--primary);
    }

    .tab-content { display: none; animation: fadeIn 0.4s ease; }
    .tab-content.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

    /* LOGIN */
    .login-wrapper { display: flex; align-items: center; justify-content: center; height: 100vh; background: #f3f4f6; }
    .login-card { background: white; width: 400px; padding: 30px; border-radius: 16px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.1); text-align: center; }
    .login-tabs { display: flex; margin-bottom: 20px; border-bottom: 2px solid #e5e7eb; }
    .lt-btn { flex: 1; padding: 10px; cursor: pointer; font-weight: 600; color: #6b7280; background: none; border: none; }
    .lt-btn.active { color: var(--primary); border-bottom: 3px solid var(--primary); }
    .login-form { display: none; }
    .login-form.active { display: block; }

    /* CARDS */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 1.5rem; }
    
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; }
    .full-width { grid-column: 1 / -1; }
    
    input, select { width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px; font-family: inherit; }
    input:focus { border-color: var(--primary); outline: none; box-shadow: 0 0 0 3px rgba(185, 28, 28, 0.1); }

    /* CLIENT LIST */
    .client-item { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; position: relative; transition: transform 0.2s; }
    .client-item:hover { transform: translateY(-2px); box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
    .client-item.blocked { border-left: 5px solid #000; opacity: 0.9; background: #f3f4f6; }
    
    .client-header { padding: 1.2rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
    .client-profile { display: flex; align-items: center; gap: 15px; }
    .client-logo { width: 50px; height: 50px; border-radius: 50%; object-fit: cover; border: 2px solid #eee; }
    .client-details { padding: 1.5rem; background: #fcfcfc; border-top: 1px solid var(--border); display: none; }
    .client-details.open { display: block; }

    .blocked-badge {
        position: absolute; top: 10px; right: 50px;
        background: #000; color: #fff; padding: 2px 8px; 
        font-size: 10px; font-weight: bold; border-radius: 4px; letter-spacing: 1px;
    }

    /* FINANCE */
    .finance-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; background: #f8fafc; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0; margin-bottom: 15px; }
    .fin-box { text-align: center; }
    .fin-label { font-size: 0.7rem; color: #64748b; font-weight: bold; }
    .fin-val { font-size: 1.1rem; font-weight: 800; color: #0f172a; }
    .fin-money { color: var(--money); }
    .fin-alpha { color: var(--primary); }
    .fin-assist { color: var(--assist); }
    
    .bank-info { font-size: 0.8rem; color: #4b5563; background: #eff6ff; padding: 8px; border-radius: 4px; margin-top: 5px; border: 1px solid #bfdbfe; }

    /* BOTONES */
    .btn { background: var(--primary); color: white; padding: 8px 16px; border-radius: 6px; font-weight: 700; border: none; cursor: pointer; text-decoration: none; display: inline-block; font-size: 0.9rem; }
    .btn:hover { background: var(--primary-hover); }
    .btn-outline { background: white; border: 1px solid var(--border); color: var(--text-main); }
    .btn-danger { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
    
    .btn-block { background: #000; color: #fff; }
    .btn-unblock { background: #16a34a; color: #fff; }

    .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; }
    .bg-gray { background: #e5e7eb; color: #374151; }
    .bg-red { background: #fee2e2; color: #991b1b; }
    .bg-green { background: #dcfce7; color: #166534; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    function openTab(id) {
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        document.getElementById('btn-'+id).classList.add('active');
    }
    function showLoginTab(tab) {
        document.querySelectorAll('.login-form').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.lt-btn').forEach(el => el.classList.remove('active'));
        document.getElementById('form-' + tab).classList.add('active');
        document.getElementById('btn-' + tab).classList.add('active');
    }
    function toggleDetails(id) { document.getElementById('det-'+id).classList.toggle('open'); }
    function updateFileName(input) { document.getElementById('file-name').innerText = input.files[0] ? input.files[0].name : "Sin archivo"; }
    function toggleModelFields(select) {
        const fields = document.getElementById('conteo-fields');
        if (select.value === 'conteo') fields.style.display = 'grid';
        else fields.style.display = 'none';
    }
    function toggleAssistFields(checkbox) {
        const div = document.getElementById('assist-fields');
        div.style.display = checkbox.checked ? 'grid' : 'none';
    }
</script>
"""

# =========================================================
# RUTAS LOGIN
# =========================================================
@app.route('/')
def login_page():
    return render_template_string(f"""
    <!DOCTYPE html>
    <html lang="es">
    <head><meta charset="UTF-8"><title>Alpha Security - Acceso</title>{CSS_THEME}</head>
    <body>
        <div class="login-wrapper">
            <div class="login-card">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="login-logo" style="height:60px; margin-bottom:20px;">
                
                <div class="login-tabs">
                    <button id="btn-admin" class="lt-btn active" onclick="showLoginTab('admin')">ADMINISTRADOR</button>
                    <button id="btn-user" class="lt-btn" onclick="showLoginTab('user')">SOCIO / USUARIO</button>
                </div>

                <form id="form-admin" class="login-form active" action="/auth/login" method="POST">
                    <input type="hidden" name="role" value="admin">
                    <input type="password" name="password" placeholder="Clave Maestra" required>
                    <button type="submit" class="btn" style="width:100%;">ENTRAR AL PANEL</button>
                </form>

                <form id="form-user" class="login-form" action="/auth/login" method="POST">
                    <input type="hidden" name="role" value="user">
                    <input type="text" name="hwid" placeholder="ID de Máquina (HWID)" required style="font-family:monospace;">
                    <button type="submit" class="btn" style="width:100%; background-color:#4b5563;">VER ESTADO</button>
                </form>
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
            return "<h1>ACCESO DENEGADO</h1><a href='/'>Volver</a>"
    
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
                    return "<h1>HWID NO ENCONTRADO</h1><p>Contacte a soporte.</p><a href='/'>Volver</a>"
        finally:
            conn.close()
    return redirect('/')

# =========================================================
# PANEL DE ADMINISTRADOR (CON TABS RESTAURADOS)
# =========================================================
@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin_logged_in'): return redirect('/')

    conn = get_db_connection()
    if not conn: return "Error DB"
    
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # 1. Clientes
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            all_clients = cursor.fetchall()
            
            # 2. Stats
            cursor.execute("SELECT SUM(tokens_practica) as tp, SUM(tokens_supervigilancia) as ts, COUNT(*) as total FROM clientes")
            stats = cursor.fetchone()
            
            # 3. Chart
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

    # --- HTML TAB 1: PREPAGO ---
    html_tokens = ""
    for c in clients_tokens:
        logo = c.get('logo_url') or f"https://ui-avatars.com/api/?name={c['nombre']}&background=random"
        is_blocked = c.get('bloqueado', False)
        blocked_class = "blocked" if is_blocked else ""
        blocked_badge = '<div class="blocked-badge">BLOQUEADO</div>' if is_blocked else ''
        
        btn_block_html = f"""
            <form action="/admin/toggle_block" method="post" style="display:inline;" onsubmit="return confirm('¿Cambiar estado?');">
                <input type="hidden" name="hwid" value="{c['hwid']}">
                <input type="hidden" name="new_status" value="{'false' if is_blocked else 'true'}">
                <button class="btn {'btn-unblock' if is_blocked else 'btn-block'}" style="font-size:0.8rem; padding:6px 10px;">
                    {'🔓 DESBLOQUEAR' if is_blocked else '🔒 BLOQUEAR'}
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
                        <div style="font-weight:700; font-size:1.1rem;">{c['nombre']}</div>
                        <div style="color:#666; font-size:0.8rem;">{c['hwid']}</div>
                    </div>
                </div>
                <div style="display:flex; gap:15px;">
                    <span class="badge bg-gray">PRÁCTICA: {c['tokens_practica']}</span>
                    <span class="badge bg-red">SUPER: {c['tokens_supervigilancia']}</span>
                </div>
            </div>
            <div id="det-{c['id']}" class="client-details">
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
                    <div>
                        <strong>Responsable:</strong> {c.get('responsable','-')}<br>
                        <strong>Tel:</strong> {c.get('telefono1','-')}<br>
                        <strong>Dirección:</strong> {c.get('direccion','-')}
                    </div>
                    <div>
                        <h4 style="margin-top:0;">GESTIÓN TOKENS</h4>
                        <form action="/admin/add_tokens" method="post" style="margin-bottom:10px;">
                            <input type="hidden" name="hwid" value="{c['hwid']}">
                            <div style="display:flex; gap:5px; margin-bottom:5px;">
                                <select name="type"><option value="practica">Práctica</option><option value="supervigilancia">Super</option></select>
                                <input type="number" name="amount" placeholder="Cant" style="width:80px;">
                            </div>
                            <div class="token-control">
                                <button type="submit" name="action" value="sub" class="btn-icon btn-sub" title="Restar">-</button>
                                <button type="submit" name="action" value="add" class="btn-icon btn-add" title="Agregar">+</button>
                            </div>
                        </form>
                        <div style="text-align:right; display:flex; gap:5px; justify-content:flex-end;">
                            {btn_block_html}
                            <a href="/admin/history/{c['hwid']}" class="btn btn-outline" style="font-size:0.8rem;">HISTORIAL</a>
                            <form action="/admin/delete_client" method="post" onsubmit="return confirm('¿Borrar?');">
                                <input type="hidden" name="hwid" value="{c['hwid']}">
                                <button class="btn btn-danger" style="font-size:0.8rem;">🗑</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """

    # --- HTML TAB 2: SOCIOS ---
    html_conteo = ""
    for c in clients_conteo:
        logo = c.get('logo_url') or f"https://ui-avatars.com/api/?name={c['nombre']}&background=random"
        activaciones = c.get('conteo_activaciones', 0)
        valor_unit = c.get('valor_activacion', 5000)
        
        is_blocked = c.get('bloqueado', False)
        blocked_class = "blocked" if is_blocked else ""
        blocked_badge = '<div class="blocked-badge">BLOQUEADO POR PAGO</div>' if is_blocked else ''
        
        btn_block_html = f"""
            <form action="/admin/toggle_block" method="post" style="display:inline;" onsubmit="return confirm('¿Cambiar estado?');">
                <input type="hidden" name="hwid" value="{c['hwid']}">
                <input type="hidden" name="new_status" value="{'false' if is_blocked else 'true'}">
                <button class="btn {'btn-unblock' if is_blocked else 'btn-block'}" style="font-size:0.8rem;">
                    {'🔓 DESBLOQUEAR' if is_blocked else '🔒 BLOQUEAR'}
                </button>
            </form>
        """

        # Asistente
        pct_alpha = c.get('porcentaje_alpha', 70)
        has_assist = c.get('asistente_activo', False)
        pct_assist = c.get('asistente_porcentaje', 0)
        name_assist = c.get('asistente_nombre', 'Asistente')
        
        # Banco
        bk_info = ""
        if has_assist:
            bk_info = f"<div class='bank-info'><b>{name_assist}:</b> {c.get('asistente_banco','-')} | {c.get('asistente_cuenta','-')}</div>"

        # Finanzas
        total_gen = activaciones * valor_unit
        g_alpha = int(total_gen * (pct_alpha/100))
        g_assist = int(total_gen * (pct_assist/100)) if has_assist else 0
        g_socio = total_gen - g_alpha - g_assist

        html_conteo += f"""
        <div class="client-item {blocked_class}" style="border-left:5px solid var(--primary);">
            {blocked_badge}
            <div class="client-header" onclick="toggleDetails({c['id']})">
                <div class="client-profile">
                    <img src="{logo}" class="client-logo">
                    <div>
                        <div style="font-weight:700; color:var(--primary);">{c['nombre']}</div>
                        <div style="color:#666; font-size:0.8rem;">SOCIO ({pct_alpha}% ALPHA)</div>
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:0.7rem; font-weight:700; color:#888;">ACTIVACIONES</div>
                    <div style="font-size:1.2rem; font-weight:800;">{activaciones}</div>
                </div>
            </div>
            <div id="det-{c['id']}" class="client-details">
                <div class="finance-grid">
                    <div class="fin-box"><div class="fin-label">PRECIO</div><div class="fin-val">${valor_unit:,.0f}</div></div>
                    <div class="fin-box"><div class="fin-label">TOTAL</div><div class="fin-val fin-money">${total_gen:,.0f}</div></div>
                    <div class="fin-box"><div class="fin-label">ALPHA</div><div class="fin-val fin-alpha">${g_alpha:,.0f}</div></div>
                    <div class="fin-box"><div class="fin-label">SOCIO</div><div class="fin-val">${g_socio:,.0f}</div></div>
                    <div class="fin-box" style="{'opacity:0.3' if not has_assist else ''}">
                        <div class="fin-label">ASIST. ({pct_assist}%)</div><div class="fin-val fin-assist">${g_assist:,.0f}</div>
                    </div>
                </div>
                {bk_info}
                <div style="text-align:right; margin-top:15px; display:flex; gap:5px; justify-content:flex-end;">
                    <form action="/admin/reset_counter" method="post" onsubmit="return confirm('¿Corte de caja? Se reiniciará a 0.');">
                        <input type="hidden" name="hwid" value="{c['hwid']}">
                        <button class="btn btn-outline" style="font-size:0.8rem;">🔄 CORTE</button>
                    </form>
                    {btn_block_html}
                    <a href="/admin/history/{c['hwid']}" class="btn btn-outline" style="font-size:0.8rem;">📜 DETALLES</a>
                    <form action="/admin/delete_client" method="post" onsubmit="return confirm('¿Borrar?');">
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
    <head><meta charset="UTF-8"><title>Alpha Admin</title>{CSS_THEME}</head>
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
                <button id="btn-units" class="tab-btn tab-btn-tokens active" onclick="openTab('units')">PREPAGO (TOKENS)</button>
                <button id="btn-partners" class="tab-btn tab-btn-socio" onclick="openTab('partners')">SOCIOS (COMISIÓN)</button>
                <button id="btn-reg" class="tab-btn" onclick="openTab('reg')">REGISTRAR NUEVO</button>
                <button id="btn-stats" class="tab-btn" onclick="openTab('stats')">ESTADÍSTICAS</button>
            </div>

            <div id="units" class="tab-content active">
                {html_tokens if html_tokens else '<div style="text-align:center; padding:40px; color:#999;">No hay clientes prepago.</div>'}
            </div>

            <div id="partners" class="tab-content">
                {html_conteo if html_conteo else '<div style="text-align:center; padding:40px; color:#999;">No hay socios registrados.</div>'}
            </div>

            <div id="reg" class="tab-content">
                <div class="card" style="max-width:800px; margin:0 auto;">
                    <h2 style="color:var(--primary); margin-bottom:20px;">NUEVA UNIDAD</h2>
                    <form action="/admin/register" method="post" enctype="multipart/form-data">
                        <div class="form-grid">
                            <div class="full-width">
                                <label>MODELO DE NEGOCIO</label>
                                <select name="modelo_negocio" onchange="toggleModelFields(this)">
                                    <option value="tokens">PREPAGO (Venta de Tokens)</option>
                                    <option value="conteo">SOCIO (Comisión por uso)</option>
                                </select>
                            </div>

                            <div id="conteo-fields" class="full-width form-grid" style="display:none; background:#fff1f2; padding:15px; border-radius:8px;">
                                <div><label>Valor Activación ($)</label><input type="number" name="valor_activacion" value="5000"></div>
                                <div><label>% Alpha</label><input type="number" name="porcentaje_alpha" value="70"></div>
                                
                                <div class="full-width" style="margin-top:10px; border-top:1px dashed #fca5a5; padding-top:10px;">
                                    <label style="display:flex; align-items:center; gap:10px; cursor:pointer;">
                                        <input type="checkbox" name="asistente_activo" style="width:auto;" onchange="toggleAssistFields(this)">
                                        <span>ACTIVAR ASISTENTE EXTERNO (COMISIONISTA)</span>
                                    </label>
                                </div>

                                <div id="assist-fields" class="full-width form-grid" style="display:none; margin-top:5px;">
                                    <div><label>Nombre</label><input type="text" name="asistente_nombre"></div>
                                    <div><label>% Comisión</label><input type="number" name="asistente_porcentaje" value="10"></div>
                                    <div class="full-width" style="font-weight:bold; color:#2563eb; margin-top:5px;">Datos Bancarios Asistente</div>
                                    <div><label>Banco</label><input type="text" name="asistente_banco"></div>
                                    <div><label>Tipo</label><select name="asistente_tipo_cuenta"><option>Ahorros</option><option>Corriente</option><option>Nequi/Davi</option></select></div>
                                    <div class="full-width"><label>Número de Cuenta</label><input type="text" name="asistente_cuenta"></div>
                                </div>
                            </div>

                            <div class="full-width"><label>Nombre Unidad</label><input type="text" name="nombre" required></div>
                            <div class="full-width"><label>HWID (ID Máquina)</label><input type="text" name="hwid" required style="font-family:monospace;"></div>
                            
                            <div class="full-width"><label>Logo</label><div class="file-upload"><label class="file-btn"><input type="file" name="logo_file" onchange="updateFileName(this)">Subir</label><span id="file-name" style="margin-left:10px;">...</span></div></div>

                            <div><label>Responsable</label><input type="text" name="responsable"></div>
                            <div><label>Email</label><input type="email" name="email"></div>
                            <div><label>Teléfono 1</label><input type="text" name="telefono1"></div>
                            <div><label>Teléfono 2</label><input type="text" name="telefono2"></div>
                            <div class="full-width"><label>Dirección</label><input type="text" name="direccion"></div>
                        </div>
                        <div style="margin-top:20px; text-align:right;"><button type="submit" class="btn">GUARDAR UNIDAD</button></div>
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

# --- PANEL CLIENTE ---
@app.route('/client/dashboard/<path:hwid>')
def client_dashboard(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clientes WHERE hwid = %s", (hwid,))
            client = cursor.fetchone()
            cursor.execute("SELECT * FROM historial WHERE hwid = %s ORDER BY fecha DESC LIMIT 50", (hwid,))
            logs = cursor.fetchall()
    finally: conn.close()

    if not client: return "Cliente no encontrado"

    activaciones = client.get('conteo_activaciones', 0)
    valor_unit = client.get('valor_activacion', 5000)
    
    # Asistente
    has_assist = client.get('asistente_activo', False)
    pct_assist = client.get('asistente_porcentaje', 0) if has_assist else 0
    pct_alpha = client.get('porcentaje_alpha', 70)
    
    # Cálculos
    total_gen = activaciones * valor_unit
    g_alpha = int(total_gen * (pct_alpha/100))
    g_assist = int(total_gen * (pct_assist/100))
    g_socio = total_gen - g_alpha - g_assist

    # HTML Diferenciado
    if client.get('modelo_negocio') == 'tokens':
        model_html = f"""
        <div class="fin-card"><div class="fin-label">TOKENS PRÁCTICA</div><div class="fin-val text-green">{client.get('tokens_practica',0)}</div></div>
        <div class="fin-card"><div class="fin-label">TOKENS SUPER</div><div class="fin-val text-red">{client.get('tokens_supervigilancia',0)}</div></div>
        """
        finance_html = ""
    else:
        model_html = f"""
        <div class="fin-card"><div class="fin-label">ACTIVACIONES</div><div class="fin-val">{activaciones}</div></div>
        <div class="fin-card"><div class="fin-label">BRUTO TOTAL</div><div class="fin-val">${total_gen:,.0f}</div></div>
        """
        finance_html = f"""
        <h3 style="margin-top:30px; border-bottom:2px solid #e5e7eb; padding-bottom:10px;">ESTADO DE CUENTA</h3>
        <div class="finance-grid">
            <div class="fin-card highlight"><div class="fin-label">A PAGAR ALPHA</div><div class="fin-val text-red">${g_alpha:,.0f}</div></div>
            <div class="fin-card"><div class="fin-label">MI GANANCIA</div><div class="fin-val text-green">${g_socio:,.0f}</div></div>
            {f'<div class="fin-card"><div class="fin-label">PAGO ASISTENTE</div><div class="fin-val text-blue">${g_assist:,.0f}</div></div>' if has_assist else ''}
        </div>
        """

    # Logs
    log_html = ""
    for l in logs:
        log_html += f"<tr><td>{l['fecha']}</td><td>{l['accion']}</td><td>{l['tipo_token']}</td><td>{l['cantidad']}</td></tr>"

    status = '<span class="badge bg-red">BLOQUEADO</span>' if client.get('bloqueado') else '<span class="badge bg-green">ACTIVO</span>'

    return render_template_string(f"""
    <!DOCTYPE html><html><head><title>Socio</title>{CSS_THEME}</head><body>
        <nav class="navbar">
            <div style="display:flex; align-items:center; gap:10px;">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="brand-logo">
                <div style="font-weight:800; font-size:1.2rem; color:var(--primary);">PORTAL SOCIO</div>
            </div>
            <a href="/" class="btn-outline" style="font-size:0.8rem;">SALIR</a>
        </nav>
        <div class="container">
            <div class="card" style="border-left:5px solid var(--primary);">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div><h1>{client['nombre']}</h1><div style="color:#666;">{hwid}</div><div style="margin-top:10px;">{status}</div></div>
                    <div style="text-align:right;"><div>MODELO</div><div style="font-size:1.2rem; font-weight:bold; color:var(--primary);">{client.get('modelo_negocio','TOKENS').upper()}</div></div>
                </div>
            </div>
            <div class="finance-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">{model_html}</div>
            {finance_html}
            <div class="card"><div class="section-title">HISTORIAL</div>
            <table><thead><tr><th>FECHA</th><th>EVENTO</th><th>TIPO</th><th>CANT</th></tr></thead><tbody>{log_html}</tbody></table>
            </div>
        </div>
    </body></html>
    """)

# --- RUTAS DE ACCIÓN ---
@app.route('/admin/toggle_block', methods=['POST'])
def toggle_block():
    hwid = request.form['hwid']
    new_stat = True if request.form['new_status']=='true' else False
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute("UPDATE clientes SET bloqueado=%s WHERE hwid=%s", (new_stat, hwid))
        conn.commit()
    conn.close()
    return redirect('/admin/panel')

@app.route('/admin/reset_counter', methods=['POST'])
def reset_counter():
    hwid = request.form['hwid']
    conn = get_db_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as c:
        c.execute("SELECT conteo_activaciones FROM clientes WHERE hwid=%s", (hwid,))
        row = c.fetchone()
        tot = row['conteo_activaciones'] if row else 0
        c.execute("INSERT INTO historial (hwid, accion, cantidad, tipo_token) VALUES (%s, 'CORTE_CAJA', %s, 'conteo')", (hwid, tot))
        c.execute("UPDATE clientes SET conteo_activaciones=0 WHERE hwid=%s", (hwid,))
        conn.commit()
    conn.close()
    return redirect('/admin/panel')

@app.route('/admin/delete_client', methods=['POST'])
def delete_client():
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute("DELETE FROM clientes WHERE hwid=%s", (request.form['hwid'],))
        conn.commit()
    conn.close()
    return redirect('/admin/panel')

# --- DETALLES E HISTORIAL COMPLETO ---
@app.route('/admin/history/<path:hwid>')
def history(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT * FROM clientes WHERE hwid=%s", (hwid,))
            cl = c.fetchone()
            c.execute("SELECT * FROM historial WHERE hwid=%s ORDER BY fecha DESC", (hwid,))
            logs = c.fetchall()
    finally: conn.close()

    if not cl: return "Cliente no encontrado"

    # Info Asistente
    assist_info = ""
    if cl.get('asistente_activo'):
        assist_info = f"""
        <div class="fin-box" style="border:1px solid #2563eb;">
            <div class="fin-label" style="color:#2563eb;">ASISTENTE</div>
            <div class="fin-val" style="font-size:1rem;">{cl.get('asistente_nombre','')}</div>
            <div style="font-size:0.7rem;">{cl.get('asistente_banco','')} | {cl.get('asistente_cuenta','')}</div>
        </div>
        """

    # Resumen Financiero
    fin_html = ""
    if cl.get('modelo_negocio') == 'conteo':
        act = cl.get('conteo_activaciones', 0)
        tot = act * cl.get('valor_activacion', 5000)
        pa = int(tot * (cl.get('porcentaje_alpha',70)/100))
        pas = int(tot * (cl.get('asistente_porcentaje',0)/100)) if cl.get('asistente_activo') else 0
        soc = tot - pa - pas
        fin_html = f"""
        <div class="finance-grid">
            <div class="fin-box"><div class="fin-label">TOTAL CAJA</div><div class="fin-val">${tot:,.0f}</div></div>
            <div class="fin-box highlight"><div class="fin-label">DEUDA ALPHA</div><div class="fin-val text-red">${pa:,.0f}</div></div>
            <div class="fin-box"><div class="fin-label">SOCIO</div><div class="fin-val text-green">${soc:,.0f}</div></div>
            {assist_info}
        </div>
        """

    rows = "".join([f"<tr><td>{l['fecha']}</td><td>{l['accion']}</td><td>{l['tipo_token']}</td><td>{l['cantidad']}</td></tr>" for l in logs])

    return render_template_string(f"""
        <!DOCTYPE html><html><head><title>Detalle</title>{CSS_THEME}</head><body>
        <div class="container">
            <a href="/admin/panel" class="btn btn-outline" style="margin-bottom:20px;">← VOLVER</a>
            <div class="profile-header">
                <div class="profile-info"><h1>{cl['nombre']}</h1><div class="profile-meta">{cl['hwid']}</div></div>
                <div class="profile-stats"><div class="stat-item"><h3>{cl.get('modelo_negocio','TOKENS').upper()}</h3><span>MODELO</span></div></div>
            </div>
            {fin_html}
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                    <div class="section-title" style="margin:0;">HISTORIAL</div>
                    <a href="/admin/download_pdf/{hwid}" class="btn">PDF</a>
                </div>
                <table><thead><tr><th>FECHA</th><th>ACCION</th><th>TIPO</th><th>CANT</th></tr></thead><tbody>{rows}</tbody></table>
            </div>
        </div></body></html>
    """)

@app.route('/admin/download_pdf/<path:hwid>')
def download_pdf(hwid):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT * FROM clientes WHERE hwid=%s", (hwid,))
            client = c.fetchone()
            c.execute("SELECT * FROM historial WHERE hwid=%s ORDER BY fecha DESC", (hwid,))
            logs = c.fetchall()
    finally: conn.close()

    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, f"CLIENTE: {client['nombre'] if client else 'Unknown'}", 0, 1)
    pdf.ln(10)
    pdf.set_font("Arial", '', 9)
    for l in logs:
        pdf.cell(50, 8, str(l['fecha']), 1)
        pdf.cell(50, 8, str(l['accion']), 1)
        pdf.cell(40, 8, str(l['tipo_token']), 1)
        pdf.cell(30, 8, str(l['cantidad']), 1, 1, 'C')

    buf = io.BytesIO()
    pdf.output(dest='S').encode('latin-1')
    buf.write(pdf.output(dest='S').encode('latin-1'))
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="Reporte.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
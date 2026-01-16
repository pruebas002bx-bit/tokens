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
IMGBB_API_KEY = "df01bb05ce03159d54c33e1e22eba2cf"

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

                if client.get('bloqueado', False):
                    return jsonify({"status": "error", "msg": "SISTEMA BLOQUEADO. CONTACTE A SOPORTE."}), 403

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
# INTERFAZ WEB (CRM PRO)
# =========================================================

CSS_THEME = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

    :root {
        --primary: #b91c1c; 
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

    .navbar {
        background: var(--surface); border-bottom: 1px solid var(--border); padding: 0.8rem 2rem;
        display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100;
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
    .tab-btn:hover { background: #e5e7eb; }
    .tab-btn.active { background: var(--surface); border: 1px solid var(--border); border-bottom: 2px solid var(--surface); margin-bottom: -2px; color: var(--text-main); }
    
    .tab-btn-socio.active { border-top: 4px solid var(--primary); color: var(--primary); }
    .tab-btn-tokens.active { border-top: 4px solid var(--secondary); color: var(--secondary); }

    .tab-content { display: none; animation: fadeIn 0.4s ease; }
    .tab-content.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

    /* CARDS */
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 1.5rem; }
    
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; }
    .full-width { grid-column: 1 / -1; }
    label { display: block; font-size: 0.75rem; font-weight: 700; color: #6b7280; margin-bottom: 5px; text-transform: uppercase; }
    input, select { width: 100%; padding: 0.7rem; border: 1px solid var(--border); border-radius: 6px; font-family: inherit; }
    
    /* CLIENT LIST */
    .client-item { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; position: relative; }
    .client-item.blocked { border-left: 5px solid #000; opacity: 0.8; background: #e5e7eb; }
    
    .client-header { padding: 1.2rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
    .client-profile { display: flex; align-items: center; gap: 15px; }
    .client-logo { width: 50px; height: 50px; border-radius: 50%; object-fit: cover; border: 2px solid #eee; }
    .client-details { padding: 1.5rem; background: #fcfcfc; border-top: 1px solid var(--border); display: none; }
    .client-details.open { display: block; }

    .blocked-badge {
        position: absolute; top: 10px; right: 50px;
        background: #000; color: #fff; padding: 2px 8px; 
        font-size: 10px; font-weight: bold; border-radius: 4px;
        letter-spacing: 1px;
    }

    /* FINANCE GRID */
    .finance-grid { 
        display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; 
        background: #f8fafc; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0; margin-bottom: 15px; 
    }
    .fin-box { text-align: center; }
    .fin-label { font-size: 0.7rem; color: #64748b; font-weight: bold; }
    .fin-val { font-size: 1.1rem; font-weight: 800; color: #0f172a; }
    .fin-money { color: var(--money); }
    .fin-alpha { color: var(--primary); }
    .fin-assist { color: var(--assist); }

    .bank-info {
        font-size: 0.8rem; color: #4b5563; background: #eff6ff; 
        padding: 5px; border-radius: 4px; margin-top: 5px; border: 1px solid #bfdbfe;
    }

    /* BUTTONS */
    .btn { background: var(--primary); color: white; padding: 0.7rem 1.5rem; border-radius: 6px; font-weight: 700; border: none; cursor: pointer; text-decoration: none; display: inline-block; font-size: 0.9rem; }
    .btn:hover { background: var(--primary-hover); }
    .btn-outline { background: white; border: 1px solid var(--border); color: var(--text-main); }
    .btn-danger { background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
    
    .btn-block { background: #000; color: #fff; }
    .btn-block:hover { background: #333; }
    .btn-unblock { background: #16a34a; color: #fff; }
    .btn-unblock:hover { background: #15803d; }

    .token-control { display: flex; align-items: center; gap: 5px; }
    .btn-icon { width: 35px; height: 35px; border-radius: 6px; border: none; color: white; font-weight: bold; cursor: pointer; }
    .btn-add { background: var(--success); }
    .btn-sub { background: var(--primary); }

    .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; }
    .bg-gray { background: #e5e7eb; color: #374151; }
    .bg-red { background: #fee2e2; color: #991b1b; }
    
    iframe.map { width: 100%; height: 200px; border: none; border-radius: 8px; }
    
    .file-upload { position: relative; overflow: hidden; display: inline-block; }
    .file-upload input[type=file] { font-size: 100px; position: absolute; left: 0; top: 0; opacity: 0; cursor: pointer; }
    .file-btn { background: #374151; color: white; padding: 8px 15px; border-radius: 6px; display: inline-block; cursor: pointer; font-size: 0.9rem; }
    
    /* ESTILO PARA DETALLES DE SOCIO */
    .profile-header { display: flex; gap: 20px; align-items: center; margin-bottom: 20px; background: white; padding: 20px; border-radius: 12px; border: 1px solid #e5e7eb; }
    .profile-img { width: 80px; height: 80px; border-radius: 50%; object-fit: cover; }
    .profile-info h1 { margin: 0; font-size: 1.5rem; color: #111827; }
    .profile-meta { color: #6b7280; font-size: 0.9rem; }
    .profile-stats { margin-left: auto; display: flex; gap: 20px; text-align: right; }
    .stat-item h3 { margin: 0; font-size: 1.2rem; color: var(--primary); }
    .stat-item span { font-size: 0.8rem; color: #6b7280; font-weight: bold; }
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
            all_clients = cursor.fetchall()
            
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

    clients_tokens = [c for c in all_clients if c.get('modelo_negocio') != 'conteo']
    clients_conteo = [c for c in all_clients if c.get('modelo_negocio') == 'conteo']

    html_tokens = ""
    for c in clients_tokens:
        logo = c.get('logo_url') or f"https://ui-avatars.com/api/?name={c['nombre']}&background=random"
        raw_addr = c.get('direccion') or 'Bogota, Colombia'
        map_url = f"https://maps.google.com/maps?q={raw_addr.replace(' ','+')}&output=embed"
        
        is_blocked = c.get('bloqueado', False)
        blocked_class = "blocked" if is_blocked else ""
        blocked_badge = '<div class="blocked-badge">BLOQUEADO POR PAGO</div>' if is_blocked else ''
        
        btn_block_html = f"""
            <form action="/admin/toggle_block" method="post" style="display:inline;" onsubmit="return confirm('¿Cambiar estado de servicio?');">
                <input type="hidden" name="hwid" value="{c['hwid']}">
                <input type="hidden" name="new_status" value="{'false' if is_blocked else 'true'}">
                <button class="btn {'btn-unblock' if is_blocked else 'btn-block'}" style="font-size:0.8rem; padding:5px 10px;">
                    {'🔓 REACTIVAR' if is_blocked else '🔒 BLOQUEAR SERVICIO'}
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
                        <h4 style="margin-top:0;">CONTROL DE TOKENS</h4>
                        <form action="/admin/add_tokens" method="post">
                            <input type="hidden" name="hwid" value="{c['hwid']}">
                            <div style="margin-bottom:10px;">
                                <label>Tipo</label>
                                <select name="type"><option value="practica">Práctica</option><option value="supervigilancia">Supervigilancia</option></select>
                            </div>
                            <label>Gestión</label>
                            <div class="token-control">
                                <input type="number" name="amount" placeholder="Cant." required style="font-weight:bold;">
                                <button type="submit" name="action" value="sub" class="btn-icon btn-sub">-</button>
                                <button type="submit" name="action" value="add" class="btn-icon btn-add">+</button>
                            </div>
                        </form>
                        <div style="margin-top:20px; text-align:right;">
                            {btn_block_html}
                            <a href="/admin/history/{c['hwid']}" class="btn btn-outline" style="padding:5px 10px; font-size:0.8rem;">HISTORIAL</a>
                            <form action="/admin/delete_client" method="post" style="display:inline;" onsubmit="return confirm('¿Borrar?');">
                                <input type="hidden" name="hwid" value="{c['hwid']}">
                                <button class="btn btn-danger" style="padding:5px 10px; font-size:0.8rem;">BORRAR</button>
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
            <form action="/admin/toggle_block" method="post" style="display:inline;" onsubmit="return confirm('¿Cambiar estado de servicio?');">
                <input type="hidden" name="hwid" value="{c['hwid']}">
                <input type="hidden" name="new_status" value="{'false' if is_blocked else 'true'}">
                <button class="btn {'btn-unblock' if is_blocked else 'btn-block'}" style="font-size:0.8rem;">
                    {'🔓 REACTIVAR' if is_blocked else '🔒 BLOQUEAR SERVICIO'}
                </button>
            </form>
        """

        pct_alpha = c.get('porcentaje_alpha', 70)
        has_assist = c.get('asistente_activo', False)
        pct_assist = c.get('asistente_porcentaje', 0)
        name_assist = c.get('asistente_nombre', 'Asistente')
        
        banco = c.get('asistente_banco', '')
        cuenta = c.get('asistente_cuenta', '')
        tipo_cta = c.get('asistente_tipo_cuenta', '')
        
        bank_info_html = ""
        if has_assist and (banco or cuenta):
            bank_info_html = f"""
            <div class="bank-info">
                <b>DATOS PAGO:</b><br>{banco}<br>{tipo_cta} - {cuenta}
            </div>
            """

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
                        <div style="font-weight:700; font-size:1.1rem; color:var(--primary);">{c['nombre']}</div>
                        <div style="color:#666; font-size:0.8rem;">SOCIO AL {pct_alpha}% / {100-pct_alpha}%</div>
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="font-size:0.7rem; font-weight:700; color:#888;">ACTIVACIONES</div>
                    <div style="font-size:1.2rem; font-weight:800;">{activaciones}</div>
                </div>
            </div>
            <div id="det-{c['id']}" class="client-details">
                
                <div class="finance-grid">
                    <div class="fin-box">
                        <div class="fin-label">PRECIO X PLAY</div>
                        <div class="fin-val">${valor_unit:,.0f}</div>
                    </div>
                    <div class="fin-box">
                        <div class="fin-label">TOTAL CAJA</div>
                        <div class="fin-val fin-money">${total_generado:,.0f}</div>
                    </div>
                    <div class="fin-box">
                        <div class="fin-label">TU PARTE ({pct_alpha}%)</div>
                        <div class="fin-val fin-alpha">${ganancia_alpha:,.0f}</div>
                    </div>
                    <div class="fin-box">
                        <div class="fin-label">PARTE SOCIO</div>
                        <div class="fin-val">${ganancia_socio:,.0f}</div>
                    </div>
                    <div class="fin-box" style="{'opacity:0.3;' if not has_assist else ''}">
                        <div class="fin-label">{name_assist.upper()[:10] if has_assist else 'SIN ASISTENTE'} ({pct_assist}%)</div>
                        <div class="fin-val fin-assist">${ganancia_assist:,.0f}</div>
                        {bank_info_html}
                    </div>
                </div>

                <div style="text-align:right;">
                    <form action="/admin/reset_counter" method="post" style="display:inline;" onsubmit="return confirm('¿Reiniciar contador a CERO? Se usará para el siguiente corte.');">
                        <input type="hidden" name="hwid" value="{c['hwid']}">
                        <button class="btn btn-outline" style="font-size:0.8rem;">🔄 REINICIAR CORTE</button>
                    </form>
                    
                    {btn_block_html}
                    
                    <a href="/admin/history/{c['hwid']}" class="btn btn-outline" style="font-size:0.8rem;">📜 DETALLES</a>
                    
                    <form action="/admin/delete_client" method="post" style="display:inline;" onsubmit="return confirm('¿Borrar?');">
                        <input type="hidden" name="hwid" value="{c['hwid']}">
                        <button class="btn btn-danger" style="font-size:0.8rem;">🗑 BORRAR</button>
                    </form>
                </div>
            </div>
        </div>
        """

    return render_template_string(f"""
    <!DOCTYPE html>
    <html lang="es">
    <head><meta charset="UTF-8"><title>ALPHA CRM</title>{CSS_THEME}</head>
    <body>
        <nav class="navbar">
            <div style="display:flex; align-items:center; gap:10px;">
                <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="brand-logo">
                <div style="font-weight:800; font-size:1.2rem; color:var(--primary);">COMMAND CENTER</div>
            </div>
        </nav>

        <div class="container">
            <div class="tabs-nav">
                <button id="btn-units" class="tab-btn tab-btn-tokens active" onclick="openTab('units')">MODELO PREPAGO (TOKENS)</button>
                <button id="btn-partners" class="tab-btn tab-btn-socio" onclick="openTab('partners')">MODELO SOCIO (CONTEO)</button>
                <button id="btn-reg" class="tab-btn" onclick="openTab('reg')">REGISTRAR UNIDAD</button>
                <button id="btn-stats" class="tab-btn" onclick="openTab('stats')">INTELIGENCIA</button>
            </div>

            <div id="units" class="tab-content active">
                <div style="margin-bottom:1rem; font-weight:800; font-size:1.1rem; color:var(--text-main);">CLIENTES PREPAGO</div>
                {html_tokens if html_tokens else '<div style="text-align:center; padding:40px; color:#999;">No hay clientes en este modelo.</div>'}
            </div>

            <div id="partners" class="tab-content">
                <div style="margin-bottom:1rem; font-weight:800; font-size:1.1rem; color:var(--primary);">SOCIOS COMERCIALES (CRÉDITO INFINITO)</div>
                {html_conteo if html_conteo else '<div style="text-align:center; padding:40px; color:#999;">No hay socios registrados.</div>'}
            </div>

            <div id="reg" class="tab-content">
                <div class="card" style="max-width:800px; margin:0 auto;">
                    <div style="margin-bottom:1.5rem; border-left:4px solid var(--primary); padding-left:10px; font-weight:800; font-size:1.1rem;">ALTA DE NUEVA UNIDAD</div>
                    <form action="/admin/register" method="post" enctype="multipart/form-data">
                        <div class="form-grid">
                            <div class="full-width">
                                <label>Modelo de Negocio</label>
                                <select name="modelo_negocio" onchange="toggleModelFields(this)">
                                    <option value="tokens">PREPAGO (Venta de Tokens)</option>
                                    <option value="conteo">SOCIO (Conteo y Porcentaje)</option>
                                </select>
                            </div>

                            <div id="conteo-fields" class="full-width form-grid" style="display:none; background:#fff1f2; padding:15px; border-radius:8px; border:1px solid #fecaca;">
                                <div><label>Valor por Activación ($)</label><input type="number" name="valor_activacion" value="5000"></div>
                                <div><label>Tu Porcentaje (%)</label><input type="number" name="porcentaje_alpha" value="70"></div>
                                
                                <div class="full-width" style="margin-top:10px; border-top:1px dashed #fca5a5; padding-top:10px;">
                                    <label style="display:flex; align-items:center; gap:10px; cursor:pointer;">
                                        <input type="checkbox" name="asistente_activo" style="width:auto;" onchange="toggleAssistFields(this)">
                                        <span>ACTIVAR ASISTENTE EXTERNO (COMISIONISTA)</span>
                                    </label>
                                </div>

                                <div id="assist-fields" class="full-width form-grid" style="display:none; margin-top:5px;">
                                    <div><label>Nombre Asistente</label><input type="text" name="asistente_nombre" placeholder="Ej: Juan Vendedor"></div>
                                    <div><label>Porcentaje Asistente (%)</label><input type="number" name="asistente_porcentaje" value="10"></div>
                                    <div class="full-width" style="margin-top:5px; font-weight:bold; color:#2563eb;">Datos Bancarios Asistente</div>
                                    <div><label>Banco</label><input type="text" name="asistente_banco" placeholder="Ej: Bancolombia"></div>
                                    <div><label>Tipo Cuenta</label><select name="asistente_tipo_cuenta"><option>Ahorros</option><option>Corriente</option><option>Nequi/Daviplata</option></select></div>
                                    <div class="full-width"><label>Número de Cuenta</label><input type="text" name="asistente_cuenta" placeholder="000-000-000"></div>
                                </div>
                            </div>

                            <div class="full-width"><label>Nombre</label><input type="text" name="nombre" required></div>
                            <div class="full-width"><label>HWID</label><input type="text" name="hwid" required style="font-family:monospace;"></div>
                            
                            <div class="full-width" style="background:#f9fafb; padding:15px; border:1px dashed #ccc; border-radius:6px;">
                                <label>Logo (Imagen)</label>
                                <div class="file-upload">
                                    <label class="file-btn"><input type="file" name="logo_file" onchange="updateFileName(this)">📂 Subir</label>
                                    <span id="file-name" style="margin-left:10px; font-size:0.8rem; color:#666;">Sin archivo</span>
                                </div>
                            </div>

                            <div><label>Responsable</label><input type="text" name="responsable"></div>
                            <div><label>Email</label><input type="email" name="email"></div>
                            <div><label>Teléfono 1</label><input type="text" name="telefono1"></div>
                            <div><label>Teléfono 2</label><input type="text" name="telefono2"></div>
                            <div class="full-width"><label>Dirección</label><input type="text" name="direccion"></div>
                        </div>
                        <div style="margin-top:2rem; text-align:right;">
                            <button type="submit" class="btn">GUARDAR UNIDAD</button>
                        </div>
                    </form>
                </div>
            </div>

            <div id="stats" class="tab-content">
                <div class="card">
                    <div style="margin-bottom:1.5rem; border-left:4px solid var(--primary); padding-left:10px; font-weight:800; font-size:1.1rem;">HISTÓRICO DE VENTAS</div>
                    <div style="height:350px;"><canvas id="chart"></canvas></div>
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
                        label: 'Ventas', data: {json.dumps(values)},
                        borderColor: '#b91c1c', backgroundColor: 'rgba(185, 28, 28, 0.1)', fill: true
                    }}]
                }},
                options: {{ responsive: true, maintainAspectRatio: false }}
            }});
        </script>
    </body></html>
    """)

# =========================================================
# RUTAS DE ACCIÓN
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
        
        asis_banco = request.form.get('asistente_banco', '')
        asis_cuenta = request.form.get('asistente_cuenta', '')
        asis_tipo = request.form.get('asistente_tipo_cuenta', '')

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
                asis_banco, asis_cuenta, asis_tipo
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
        # SOLUCIÓN ERROR TUPLE: Usamos RealDictCursor para poder acceder por nombre
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

    # Datos adicionales para el perfil
    logo = client.get('logo_url') or f"https://ui-avatars.com/api/?name={client['nombre']}&background=random"
    modelo = "SOCIO (CONTEO)" if client.get('modelo_negocio') == 'conteo' else "PREPAGO (TOKENS)"
    
    # Asistente
    has_assist = client.get('asistente_activo', False)
    assist_info = "NO"
    if has_assist:
        name = client.get('asistente_nombre', '')
        pct = client.get('asistente_porcentaje', 0)
        bank = client.get('asistente_banco', '---')
        acc = client.get('asistente_cuenta', '---')
        assist_info = f"<b>{name}</b> ({pct}%)<br><span style='font-size:0.8rem'>{bank} - {acc}</span>"

    # Filas
    log_rows = ""
    for l in logs:
        color = "#059669" if l['cantidad'] > 0 else "#b91c1c"
        log_rows += f"<tr><td>{l['fecha']}</td><td>{l['accion']}</td><td>{l['tipo_token']}</td><td style='color:{color}; font-weight:bold'>{l['cantidad']}</td></tr>"

    return render_template_string(f"""
        <!DOCTYPE html><html><head><title>Detalles</title>{CSS_THEME}</head><body>
        <div class="container">
            <a href="/admin/panel" class="btn btn-outline" style="margin-bottom:20px;">← VOLVER</a>
            
            <div class="profile-header">
                <img src="{logo}" class="profile-img">
                <div class="profile-info">
                    <h1>{client['nombre']}</h1>
                    <div class="profile-meta">{client['hwid']} | {client.get('direccion', '---')}</div>
                    <div class="profile-meta" style="margin-top:5px; color:#2563eb;">RESPONSABLE: {client.get('responsable', '---')} | TEL: {client.get('telefono1', '---')}</div>
                </div>
                <div class="profile-stats">
                    <div class="stat-item"><h3>{modelo}</h3><span>MODELO NEGOCIO</span></div>
                    <div class="stat-item"><h3>{assist_info}</h3><span>ASISTENTE</span></div>
                </div>
            </div>

            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                    <div class="section-title" style="margin:0;">HISTORIAL DE MOVIMIENTOS</div>
                    <a href="/admin/download_pdf/{hwid}" class="btn">DESCARGAR REPORTE PDF</a>
                </div>
                <table style="width:100%; border-collapse:collapse;">
                    <tr style="background:#f9fafb; text-align:left; border-bottom:2px solid #e5e7eb;">
                        <th style="padding:10px;">FECHA</th><th>ACCIÓN</th><th>TOKEN/TIPO</th><th>CANTIDAD</th>
                    </tr>
                    {log_rows}
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
    
    name_safe = client['nombre'] if client else "Desconocido"
    pdf.cell(0, 10, f"CLIENTE: {name_safe}", 0, 1)
    
    if client:
        pdf.set_font("Arial", '', 10)
        pdf.cell(0, 5, f"HWID: {hwid}", 0, 1)
        pdf.cell(0, 5, f"MODELO: {client.get('modelo_negocio', 'TOKENS').upper()}", 0, 1)
        if client.get('asistente_activo'):
            pdf.cell(0, 5, f"ASISTENTE: {client.get('asistente_nombre')} ({client.get('asistente_porcentaje')}%)", 0, 1)
    
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
    return send_file(buffer, as_attachment=True, download_name=f"Reporte.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
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
# INTERFAZ WEB (CRM ALPHA LIGHT)
# =========================================================

CSS_THEME = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

    :root {
        --primary: #b91c1c; /* Rojo Alpha */
        --primary-dark: #991b1b;
        --bg: #f8f9fa;      /* Gris Muy Claro */
        --surface: #ffffff; /* Blanco Puro */
        --text-main: #1f2937;
        --text-light: #6b7280;
        --border: #e5e7eb;
        --success: #059669;
    }

    body {
        background-color: var(--bg);
        color: var(--text-main);
        font-family: 'Inter', sans-serif;
        margin: 0;
        padding: 0;
    }

    /* HEADER */
    .navbar {
        background: var(--surface);
        border-bottom: 1px solid var(--border);
        padding: 1rem 2rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 2px 4px rgba(0,0,0,0.02);
    }
    .brand-img { height: 50px; } /* Ajusta altura logo */

    .container { max-width: 1400px; margin: 2rem auto; padding: 0 1.5rem; }

    /* DASHBOARD */
    .dashboard-grid {
        display: grid;
        grid-template-columns: 3fr 1fr;
        gap: 2rem;
        margin-bottom: 3rem;
    }
    .chart-card {
        background: var(--surface);
        border-radius: 12px;
        padding: 1.5rem;
        border: 1px solid var(--border);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
    }
    .kpi-grid {
        display: grid;
        grid-template-rows: repeat(2, 1fr);
        gap: 1rem;
    }
    .kpi-card {
        background: var(--surface);
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid var(--border);
        border-left: 5px solid var(--primary);
        display: flex;
        flex-direction: column;
        justify-content: center;
    }
    .kpi-label { font-size: 0.85rem; color: var(--text-light); text-transform: uppercase; font-weight: 700; }
    .kpi-value { font-size: 2.5rem; font-weight: 800; color: var(--text-main); line-height: 1; margin-top: 0.5rem; }

    /* SECCIONES */
    .section-title {
        font-size: 1.25rem;
        font-weight: 800;
        color: var(--text-main);
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .section-title::before {
        content: ''; display: block; width: 6px; height: 24px; background: var(--primary); border-radius: 2px;
    }

    /* FORMULARIO REGISTRO (EXPANDIDO) */
    .form-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
    }
    .full-width { grid-column: 1 / -1; }
    
    .input-group label { display: block; font-size: 0.8rem; font-weight: 600; color: var(--text-light); margin-bottom: 4px; }
    input, select, textarea {
        width: 100%;
        padding: 0.6rem;
        border: 1px solid var(--border);
        border-radius: 6px;
        font-family: inherit;
        background: #fff;
        color: var(--text-main);
        transition: border 0.2s;
        box-sizing: border-box; /* Importante para padding */
    }
    input:focus { border-color: var(--primary); outline: none; box-shadow: 0 0 0 3px rgba(185, 28, 28, 0.1); }

    /* TABLA CLIENTES */
    .client-card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
        margin-bottom: 1rem;
        overflow: hidden;
        transition: transform 0.2s;
    }
    .client-card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05); }
    
    .client-header {
        padding: 1rem 1.5rem;
        background: #fcfcfc;
        border-bottom: 1px solid var(--border);
        display: flex;
        justify-content: space-between;
        align-items: center;
        cursor: pointer;
    }
    .client-info { display: flex; align-items: center; gap: 1rem; }
    .client-logo { width: 40px; height: 40px; border-radius: 50%; object-fit: cover; background: #eee; border: 1px solid #ddd; }
    .client-name { font-weight: 700; font-size: 1.1rem; color: var(--text-main); }
    .client-hwid { font-family: monospace; color: var(--text-light); font-size: 0.85rem; background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }

    .client-body {
        padding: 1.5rem;
        display: none; /* Oculto por defecto */
        background: #fff;
    }
    .client-body.active { display: block; }

    .details-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 2rem;
    }
    .map-frame {
        width: 100%;
        height: 200px;
        border: 0;
        border-radius: 8px;
        background: #eee;
    }
    
    /* BOTONES */
    .btn {
        background: var(--primary); color: white; border: none; padding: 0.6rem 1.2rem;
        border-radius: 6px; font-weight: 600; cursor: pointer; text-decoration: none;
        display: inline-flex; align-items: center; gap: 6px; font-size: 0.9rem;
    }
    .btn:hover { background: var(--primary-dark); }
    .btn-sm { padding: 0.4rem 0.8rem; font-size: 0.8rem; }
    .btn-outline { background: white; border: 1px solid var(--border); color: var(--text-main); }
    .btn-outline:hover { background: #f9fafb; border-color: var(--text-light); }
    
    .badge { padding: 4px 8px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; }
    .badge-p { background: #dcfce7; color: #166534; }
    .badge-s { background: #fee2e2; color: #991b1b; }

</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    function toggleDetails(id) {
        const el = document.getElementById('details-' + id);
        el.classList.toggle('active');
    }
</script>
"""

@app.route('/')
def home():
    return redirect('/admin/panel')

@app.route('/admin/panel')
def admin_panel():
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # 1. Obtener Clientes
            cursor.execute("SELECT * FROM clientes ORDER BY id DESC")
            clients = cursor.fetchall()
            
            # 2. KPIs Globales
            cursor.execute("SELECT SUM(tokens_practica) as tp, SUM(tokens_supervigilancia) as ts FROM clientes")
            kpis = cursor.fetchone()
            
            # 3. Datos para la Gráfica (Ventas/Recargas por Mes)
            # Filtramos accion='RECARGA' y agrupamos por mes
            cursor.execute("""
                SELECT TO_CHAR(fecha, 'YYYY-MM') as mes, SUM(cantidad) as total 
                FROM historial 
                WHERE accion = 'RECARGA' 
                GROUP BY mes 
                ORDER BY mes ASC 
                LIMIT 12
            """)
            chart_data = cursor.fetchall()
            
            # Preparar arrays para Chart.js
            labels = [row['mes'] for row in chart_data]
            values = [row['total'] for row in chart_data]
            
    finally:
        conn.close()

    # Construir HTML de clientes
    clients_html = ""
    for c in clients:
        # Mapa URL
        address = c.get('direccion', 'Bogotá, Colombia')
        map_url = f"https://maps.google.com/maps?q={address}&output=embed"
        logo = c.get('logo_url') or "https://ui-avatars.com/api/?name=" + c['nombre'].replace(" ", "+") + "&background=random"
        
        clients_html += f"""
        <div class="client-card">
            <div class="client-header" onclick="toggleDetails({c['id']})">
                <div class="client-info">
                    <img src="{logo}" class="client-logo">
                    <div>
                        <div class="client-name">{c['nombre']}</div>
                        <div class="client-hwid">{c['hwid']}</div>
                    </div>
                </div>
                <div style="display:flex; gap:15px; align-items:center;">
                    <div><span class="badge badge-p">PRÁCTICA: {c['tokens_practica']}</span></div>
                    <div><span class="badge badge-s">SUPER: {c['tokens_supervigilancia']}</span></div>
                    <div style="font-size:0.8rem; color:#888;">▼ Ver Detalles</div>
                </div>
            </div>
            
            <div id="details-{c['id']}" class="client-body">
                <div class="details-grid">
                    <div>
                        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin-bottom:15px;">
                            <div>
                                <label style="font-size:0.75rem; color:#888; font-weight:bold;">RESPONSABLE</label>
                                <div>{c.get('responsable') or 'N/A'}</div>
                            </div>
                            <div>
                                <label style="font-size:0.75rem; color:#888; font-weight:bold;">EMAIL</label>
                                <div><a href="mailto:{c.get('email')}" style="color:#b91c1c;">{c.get('email') or 'N/A'}</a></div>
                            </div>
                            <div>
                                <label style="font-size:0.75rem; color:#888; font-weight:bold;">TELÉFONO 1</label>
                                <div>{c.get('telefono1') or 'N/A'}</div>
                            </div>
                            <div>
                                <label style="font-size:0.75rem; color:#888; font-weight:bold;">TELÉFONO 2</label>
                                <div>{c.get('telefono2') or 'N/A'}</div>
                            </div>
                        </div>
                        <label style="font-size:0.75rem; color:#888; font-weight:bold;">UBICACIÓN: {c.get('direccion')}</label>
                        <iframe class="map-frame" src="{map_url}"></iframe>
                    </div>
                    
                    <div style="background:#f9fafb; padding:20px; border-radius:8px; border:1px solid #eee;">
                        <h4 style="margin-top:0;">GESTIÓN DE RECURSOS</h4>
                        <form action="/admin/add_tokens" method="post">
                            <input type="hidden" name="hwid" value="{c['hwid']}">
                            <div style="margin-bottom:10px;">
                                <label>Operación</label>
                                <div style="display:flex; gap:10px;">
                                    <input type="number" name="amount" placeholder="+ Cantidad" required style="font-weight:bold;">
                                    <select name="type">
                                        <option value="practica">Práctica</option>
                                        <option value="supervigilancia">Supervigilancia</option>
                                    </select>
                                </div>
                                <div style="font-size:0.75rem; color:#666; margin-top:5px;">* Usa números negativos (ej: -5) para corregir/quitar.</div>
                            </div>
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:20px;">
                                <a href="/admin/history/{c['hwid']}" class="btn btn-outline btn-sm">VER HISTORIAL</a>
                                <button type="submit" class="btn">APLICAR CAMBIOS</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>ALPHA COMMAND CENTER</title>
        {CSS_THEME}
    </head>
    <body>
        <nav class="navbar">
            <img src="https://i.ibb.co/j9Pp0YLz/Logo-2.png" class="brand-img" alt="Alpha Logo">
            <div style="font-weight:800; font-size:1.2rem; color:#b91c1c;">COMMAND CENTER</div>
        </nav>

        <div class="container">
            
            <div class="dashboard-grid">
                <div class="chart-card">
                    <div class="section-title">VENTAS DE TOKENS (Último Año)</div>
                    <canvas id="salesChart" height="100"></canvas>
                </div>
                
                <div class="kpi-grid">
                    <div class="kpi-card">
                        <div class="kpi-label">TOKENS PRÁCTICA ACTIVOS</div>
                        <div class="kpi-value" style="color:#15803d;">{kpis['tp'] or 0}</div>
                    </div>
                    <div class="kpi-card">
                        <div class="kpi-label">TOKENS SUPERV. ACTIVOS</div>
                        <div class="kpi-value" style="color:#b91c1c;">{kpis['ts'] or 0}</div>
                    </div>
                </div>
            </div>

            <div class="chart-card" style="margin-bottom:3rem;">
                <div class="section-title">REGISTRAR NUEVA UNIDAD / ESCUELA</div>
                <form action="/admin/register" method="post">
                    <div class="form-grid">
                        <div class="input-group full-width">
                            <label>Nombre de la Escuela / Unidad</label>
                            <input type="text" name="nombre" required placeholder="Ej: Academia Táctica Alpha">
                        </div>
                        
                        <div class="input-group">
                            <label>ID de Hardware (HWID)</label>
                            <input type="text" name="hwid" required placeholder="Código único de la máquina">
                        </div>
                        
                        <div class="input-group">
                            <label>Nombre Responsable</label>
                            <input type="text" name="responsable" placeholder="Director o Encargado">
                        </div>

                        <div class="input-group">
                            <label>Teléfono Principal</label>
                            <input type="text" name="telefono1" placeholder="Celular / WhatsApp">
                        </div>

                        <div class="input-group">
                            <label>Teléfono Secundario</label>
                            <input type="text" name="telefono2" placeholder="Opcional">
                        </div>

                        <div class="input-group full-width">
                            <label>Dirección Física (Para Mapa)</label>
                            <input type="text" name="direccion" placeholder="Ej: Calle 123 #45-67, Bogotá">
                        </div>

                        <div class="input-group full-width">
                            <label>Email de Contacto</label>
                            <input type="email" name="email" placeholder="contacto@escuela.com">
                        </div>
                        
                        <div class="input-group full-width">
                            <label>URL del Logo (Opcional)</label>
                            <input type="text" name="logo_url" placeholder="https://...">
                        </div>
                    </div>
                    <div style="margin-top:20px; text-align:right;">
                        <button type="submit" class="btn">GUARDAR UNIDAD EN BD</button>
                    </div>
                </form>
            </div>

            <div class="section-title">UNIDADES ACTIVAS EN RED</div>
            {clients_html}
            
        </div>

        <script>
            // Configuración de la Gráfica
            const ctx = document.getElementById('salesChart').getContext('2d');
            new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: {json.dumps(labels)},
                    datasets: [{{
                        label: 'Tokens Vendidos',
                        data: {json.dumps(values)},
                        borderColor: '#b91c1c',
                        backgroundColor: 'rgba(185, 28, 28, 0.1)',
                        tension: 0.4,
                        fill: true,
                        pointBackgroundColor: '#fff',
                        pointBorderColor: '#b91c1c',
                        pointBorderWidth: 2,
                        pointRadius: 5
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ display: false }}
                    }},
                    scales: {{
                        y: {{ beginAtZero: true, grid: {{ color: '#f3f4f6' }} }},
                        x: {{ grid: {{ display: false }} }}
                    }}
                }}
            }});
        </script>
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
                LIMIT 50
            """, (hwid,))
            logs = cursor.fetchall()
    finally:
        conn.close()

    log_rows = ""
    for log in logs:
        acc = log['accion']
        cant = log['cantidad']
        color = "#15803d" if cant > 0 else "#b91c1c"
        
        log_rows += f"""
        <div style="display:flex; justify-content:space-between; padding:15px; border-bottom:1px solid #eee; align-items:center;">
            <div>
                <div style="font-weight:700; color:#333;">{acc} ({log['tipo_token'].upper()})</div>
                <div style="font-size:0.8rem; color:#888;">{log['fecha']}</div>
            </div>
            <div style="font-size:1.2rem; font-weight:800; color:{color};">
                {'+' if cant > 0 else ''}{cant}
            </div>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Historial {name}</title>{CSS_THEME}</head>
    <body>
        <div class="container" style="max-width:800px;">
            <a href="/admin/panel" class="btn btn-outline" style="margin-bottom:20px;">← Volver</a>
            <div class="chart-card">
                <div class="section-title">HISTORIAL DE TRANSACCIONES</div>
                <h2 style="margin:0; color:#b91c1c;">{name}</h2>
                <div style="font-family:monospace; color:#666; margin-bottom:20px;">{hwid}</div>
                <div style="border:1px solid #eee; border-radius:8px; overflow:hidden;">
                    {log_rows if logs else '<div style="padding:20px; text-align:center;">Sin movimientos.</div>'}
                </div>
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
            cursor.execute(f"UPDATE clientes SET {col} = {col} + %s WHERE hwid = %s", (amount, hwid))
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
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO clientes (nombre, hwid, responsable, telefono1, telefono2, email, direccion, logo_url, tokens_supervigilancia, tokens_practica) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0, 0)
            """, (
                request.form['nombre'],
                request.form['hwid'],
                request.form.get('responsable', ''),
                request.form.get('telefono1', ''),
                request.form.get('telefono2', ''),
                request.form.get('email', ''),
                request.form.get('direccion', ''),
                request.form.get('logo_url', '')
            ))
            conn.commit()
        conn.close()
        return redirect('/admin/panel')
    except Exception as e:
        return f"<h2 style='color:red'>Error al registrar: {e}</h2>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
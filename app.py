from flask import Flask, request, render_template_string, redirect, session, abort
from werkzeug.security import check_password_hash
from werkzeug.serving import WSGIRequestHandler
import sqlite3
import secrets
import os
import logging

WSGIRequestHandler.server_version = "SecureDev-Web"
WSGIRequestHandler.sys_version = ""

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

REQUEST_METRICS = defaultdict(int)
FAILED_ATTEMPTS = defaultdict(int)
BLOCKED_IPS = set()
RUTAS_CONOCIDAS = {'/', '/login', '/dashboard', '/update_bio', '/logout', '/metrics'}

def db_query(query, params=(), fetch=False):
    """Consultas parametrizadas para prevenir SQL Injection"""
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    result = cursor.fetchall() if fetch else None
    conn.commit()
    conn.close()
    return result

@app.before_request
def verificar_bloqueo_ip():
    """Bloquea automáticamente IPs que superan el umbral de intentos fallidos"""
    if request.path == '/metrics':
        return None
    ip_cliente = request.remote_addr or 'unknown'
    if ip_cliente in BLOCKED_IPS:
        abort(429, description="IP bloqueada por actividad maliciosa detectada")

@app.after_request
def registrar_metricas_y_cabeceras(response):
    """Registra métricas HTTP para Grafana e inyecta cabeceras de seguridad"""
    ruta = request.path if request.path in RUTAS_CONOCIDAS else '/not_found'
    if ruta != '/metrics':
        REQUEST_METRICS[(request.method, ruta, str(response.status_code))] += 1

    ip_cliente = request.remote_addr or 'unknown'
    if response.status_code in (401, 404) and ip_cliente not in BLOCKED_IPS:
        FAILED_ATTEMPTS[ip_cliente] += 1
        if FAILED_ATTEMPTS[ip_cliente] >= 8:
            BLOCKED_IPS.add(ip_cliente)
            logging.warning(f"INCIDENTE DE SEGURIDAD: IP {ip_cliente} bloqueada tras {FAILED_ATTEMPTS[ip_cliente]} intentos sospechosos.")

    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

@app.route('/metrics')
def metrics():
    """Endpoint de métricas en formato Prometheus para Grafana"""
    lineas = [
        "# HELP http_requests_total Total de peticiones HTTP por metodo, ruta y codigo",
        "# TYPE http_requests_total counter"
    ]
    for (metodo, ruta, estado), conteo in REQUEST_METRICS.items():
        lineas.append(f'http_requests_total{{method="{metodo}",endpoint="{ruta}",status="{estado}"}} {conteo}')

    lineas.extend([
        "# HELP security_blocked_ips_total Total de IPs bloqueadas por respuesta a incidentes",
        "# TYPE security_blocked_ips_total counter",
        f"security_blocked_ips_total {len(BLOCKED_IPS)}"
    ])
    return Response("\n".join(lineas) + "\n", mimetype="text/plain")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username', '').strip()
        pw = request.form.get('password', '')
        
        usuarios = db_query("SELECT * FROM usuarios WHERE username = ?", (user,), fetch=True)
        
        if usuarios and check_password_hash(usuarios[0]['password'], pw):
            session.clear()
            session['username'] = usuarios[0]['username']
            session['csrf_token'] = secrets.token_hex(16)
            return redirect('/dashboard')
            
        return "<h3>Acceso denegado</h3><a href='/login'>Volver</a>", 401

    return '''
        <h2>Login del Sistema Académico</h2>
        <form method="post">
            Usuario: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Ingresar">
        </form>
    '''

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect('/login')

    filas = db_query("SELECT * FROM usuarios WHERE username = ?", (username,), fetch=True)
    if not filas:
        session.clear()
        return redirect('/login')
        
    datos = filas[0]
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

    html = """
    <h1>Panel de {{ username }}</h1>
    <p><b>Rol:</b> {{ rol }}</p>
    <p><b>Biografía:</b> {{ bio }}</p>
    <hr>
    <h3>Actualizar Biografía</h3>
    <form action="/update_bio" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" name="nueva_bio" placeholder="Escribe algo..." maxlength="200">
        <input type="submit" value="Guardar Cambios">
    </form>
    <br><a href="/logout">Cerrar Sesión</a>
    """
    return render_template_string(
        html,
        username=datos['username'],
        rol=datos['rol'],
        bio=datos['bio'],
        csrf_token=session['csrf_token']
    )

@app.route('/update_bio', methods=['POST'])
def update_bio():
    username = session.get('username')
    if not username:
        return redirect('/login')

    token_recibido = request.form.get('csrf_token', '')
    token_sesion = session.get('csrf_token', '')
    if not token_recibido or not secrets.compare_digest(token_recibido, token_sesion):
        abort(403, description="Token CSRF inválido o ausente")

    nueva_bio = request.form.get('nueva_bio', '').strip()
    db_query("UPDATE usuarios SET bio = ? WHERE username = ?", (nueva_bio, username))
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/')
def home():
    return redirect('/login')

if __name__ == '__main__':
    host_bind = os.environ.get('FLASK_HOST', '127.0.0.1')
    app.run(debug=False, host=host_bind, port=5000)
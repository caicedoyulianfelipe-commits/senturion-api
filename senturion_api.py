from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import sqlite3
import datetime
import ipinfo
import psutil
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
CORS(app)
auth = HTTPBasicAuth()

IPINFO_TOKEN = "2ee7b937864c94"
handler = ipinfo.getHandler(IPINFO_TOKEN)
DB_PATH = 'senturion_logs.db'

USERS = {
    "yulian_felipe": "CAICEDO27"
}

@auth.verify_password
def verify_password(username, password):
    if username in USERS and USERS[username] == password:
        return username
    return None

# --- Funciones de Base de Datos ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # AÑADIMOS la columna threat_level (INTEGER default 0)
    c.execute('''CREATE TABLE IF NOT EXISTS ips
                 (ip text primary key, location text, city text, timestamp text, blocked integer default 0, threat_level integer default 0)''')
    conn.commit()
    conn.close()

def log_ip(ip_address, location, city):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Actualizamos la inserción para incluir la nueva columna por defecto
    c.execute("INSERT OR REPLACE INTO ips VALUES (?, ?, ?, ?, COALESCE((SELECT blocked FROM ips WHERE ip = ?), 0), COALESCE((SELECT threat_level FROM ips WHERE ip = ?), 0))", 
              (ip_address, location, city, datetime.datetime.now().isoformat(), ip_address, ip_address))
    conn.commit()
    conn.close()

# NUEVA FUNCIÓN: Registrar un evento y aumentar el nivel de amenaza
@app.route('/api/log_event', methods=['POST'])
@auth.login_required
def log_event():
    data = request.get_json()
    ip_address = data.get('ip')
    event_type = data.get('event_type', 'generic_event')

    if not ip_address:
        abort(400, description="IP required")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Aumenta el nivel de amenaza en 1 por cada evento registrado
    c.execute("UPDATE ips SET threat_level = threat_level + 1 WHERE ip = ?", (ip_address,))
    conn.commit()
    
    # Lógica de Regla Inteligente: Bloqueo automático si el nivel de amenaza > 5
    c.execute("SELECT threat_level FROM ips WHERE ip = ?", (ip_address,))
    result = c.fetchone()
    if result and result[0] > 5:
        c.execute("UPDATE ips SET blocked = 1 WHERE ip = ?", (ip_address,))
        conn.commit()
        conn.close()
        return jsonify({"status": "auto_blocked", "ip": ip_address, "reason": "Threat level exceeded threshold"})

    conn.close()
    return jsonify({"status": "event_logged", "ip": ip_address, "event": event_type})


def get_logged_ips_from_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Seleccionamos la nueva columna threat_level
    c.execute("SELECT ip, location, city, blocked, threat_level FROM ips")
    ips_data = c.fetchall()
    conn.close()
    logged_ips = []
    for ip, location, city, blocked, threat_level in ips_data:
        logged_ips.append({"ip": ip, "location": location, "city": city, "blocked": blocked, "threat_level": threat_level})
    return logged_ips

# ... [block_ip, extract_ip_from_request, get_status siguen abajo, sin cambios importantes en su lógica interna] ...

@app.route('/api/block_ip', methods=['POST'])
@auth.login_required
def block_ip():
    data = request.get_json()
    ip_to_block = data.get('ip')
    if not ip_to_block:
        abort(400, description="IP required")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE ips SET blocked = 1 WHERE ip = ?", (ip_to_block,))
    # Opcional: Establecer el nivel de amenaza alto al bloquear manualmente
    c.execute("UPDATE ips SET threat_level = 999 WHERE ip = ?", (ip_to_block,))
    conn.commit()
    conn.close()
    return jsonify({"status": "blocked", "ip": ip_to_block})

def extract_ip_from_request(req):
    if "X-Forwarded-For" in req.headers:
        ip_list = req.headers["X-Forwarded-For"].split(',')
        client_ip = ip_list.strip() if ip_list else req.remote_addr.strip()
    else:
        client_ip = req.remote_addr.strip()
    return client_ip

@app.route('/api/status', methods=['GET'])
@auth.login_required
def get_status():
    ip_address = extract_ip_from_request(request)
    # Verificación de bloqueo temprano
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT blocked FROM ips WHERE ip = ?", (ip_address,))
    result = c.fetchone()
    conn.close()
    if result and result[0] == 1: 
        abort(403, description="Access Blocked by Senturion System") 

    location, city = "0,0", "Desconocida"
    try:
        details = handler.getDetails(ip_address)
        location = details.loc
        city = details.city
    except Exception as e:
        print(f"Error fetching IP info: {e}")
        
    log_ip(ip_address, location, city)
    logged_ips_list = get_logged_ips_from_db()
    conexiones_activas = len(logged_ips_list)
    # Calculamos las alertas pendientes basadas en el nivel de amenaza > 0
    pending_alerts_count = sum(1 for ip_data in logged_ips_list if ip_data['threat_level'] > 0 and ip_data['blocked'] == 0)


    return jsonify({
        "threats_blocked": sum(1 for ip_data in logged_ips_list if ip_data['blocked']), # Ahora este contador es real
        "active_connections": conexiones_activas,
        "pending_alerts": pending_alerts_count,
        "system_status": f"VIGILANCIA ACTIVA ({conexiones_activas} nodos)",
        "server_location": "4.7110,-74.0721",
        "logged_ips": logged_ips_list,
        "logs": [
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {conexiones_activas} IPs rastreadas. Alertas Pendientes: {pending_alerts_count}",
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Última conexión: {city}.",
        ]
    })

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)


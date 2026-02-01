from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import sqlite3
import datetime
import ipinfo
import psutil
# Eliminamos los imports de nmap y scapy que fallaban

app = Flask(__name__)
CORS(app)

IPINFO_TOKEN = "2ee7b937864c94"
handler = ipinfo.getHandler(IPINFO_TOKEN)
DB_PATH = 'senturion_logs.db'

# --- Funciones de Base de Datos ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ips
                 (ip text primary key, location text, city text, timestamp text, blocked integer default 0)''')
    conn.commit()
    conn.close()

def log_ip(ip_address, location, city):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO ips VALUES (?, ?, ?, ?, COALESCE((SELECT blocked FROM ips WHERE ip = ?), 0))", 
              (ip_address, location, city, datetime.datetime.now().isoformat(), ip_address))
    conn.commit()
    conn.close()

def get_logged_ips_from_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip, location, city, blocked FROM ips")
    ips_data = c.fetchall()
    conn.close()
    
    logged_ips = []
    for ip, location, city, blocked in ips_data:
        logged_ips.append({"ip": ip, "location": location, "city": city, "blocked": blocked})
    return logged_ips

# --- Funciones de Control de IP ---

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    data = request.get_json()
    ip_to_block = data.get('ip')
    if not ip_to_block:
        abort(400, description="IP required")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE ips SET blocked = 1 WHERE ip = ?", (ip_to_block,))
    conn.commit()
    conn.close()
    return jsonify({"status": "blocked", "ip": ip_to_block})

# Eliminamos las rutas /api/scan_ports y /api/ping_recon que usaban nmap/scapy

def extract_ip_from_request(req):
    """Función a prueba de fallos para extraer la IP real."""
    if req.headers.getlist("X-Forwarded-For"):
        client_ip = req.headers.getlist("X-Forwarded-For")
        if isinstance(client_ip, list):
             client_ip = client_ip[0] # Toma la primera IP de la lista
        return client_ip.strip()
    else:
        return req.remote_addr.strip()

@app.route('/api/status', methods=['GET'])
def get_status():
    # USAMOS LA FUNCIÓN A PRUEBA DE FALLOS
    ip_address = extract_ip_from_request(request)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT blocked FROM ips WHERE ip = ?", (ip_address,))
    result = c.fetchone()
    conn.close()
    if result and result[0] == 1: # Corregimos el acceso a la tupla
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

    return jsonify({
        "threats_blocked": 2847,
        "active_connections": conexiones_activas,
        "pending_alerts": 0 if not logged_ips_list else sum(1 for ip in logged_ips_list if ip['blocked']),
        "system_status": f"VIGILANCIA ACTIVA ({conexiones_activas} nodos)",
        "server_location": "4.7110,-74.0721",
        "logged_ips": logged_ips_list,
        "logs": [
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {conexiones_activas} IPs rastreadas. Alertas Pendientes: {sum(1 for ip in logged_ips_list if ip['blocked'])}",
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Última conexión: {city}.",
        ]
    })

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)


from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import sqlite3
import datetime
import ipinfo
import psutil
import nmap
from scapy.all import IP, ICMP, sr1, conf 

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

# --- Funciones de Control y Escaneo ---

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

# NUEVA RUTA: Escaneo de Puertos del Servidor (Usando Nmap)
@app.route('/api/scan_ports', methods=['GET'])
def scan_ports():
    nm = nmap.PortScanner()
    nm.scan('127.0.0.1', '20-100') 
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append({"port": port, "service": nm[host][proto][port]['name']})
    return jsonify({"status": "scan_complete", "open_ports": open_ports, "target": "localhost"})

# NUEVA RUTA SOFISTICADA: Ping de Reconocimiento (Usando Scapy)
@app.route('/api/ping_recon/<ip>', methods=['GET'])
def ping_recon(ip):
    conf.verb = 0 
    packet = IP(dst=ip)/ICMP()
    resp, unans = sr1(packet, timeout=2) 
    if resp:
        return jsonify({"ip": ip, "status": "vivo", "summary": resp.summary()})
    else:
        return jsonify({"ip": ip, "status": "muerto", "summary": "No hay respuesta ICMP"})

@app.route('/api/status', methods=['GET'])
def get_status():
    # LA LÍNEA CORREGIDA: Toma la primera IP y le quita los espacios
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT blocked FROM ips WHERE ip = ?", (ip_address,))
    result = c.fetchone()
    conn.close()
    if result and result[0] == 1: # Se corrigió el acceso a la tupla
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


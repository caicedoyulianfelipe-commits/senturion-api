from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import datetime
import ipinfo
import psutil

app = Flask(__name__)
CORS(app)

# Reemplaza esto con tu token de ipinfo.io
IPINFO_TOKEN = "2ee7b937864c94"
# Asegúrate de haber obtenido tu token en https://ipinfo.io
handler = ipinfo.getHandler(IPINFO_TOKEN)
DB_PATH = 'senturion_logs.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ips
                 (ip text primary key, location text, city text, timestamp text)''')
    conn.commit()
    conn.close()

def log_ip(ip_address, location, city):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Insertamos o actualizamos la IP si ya existe
    c.execute("REPLACE INTO ips VALUES (?, ?, ?, ?)", 
              (ip_address, location, city, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_logged_ips_from_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip, location, city FROM ips")
    ips_data = c.fetchall()
    conn.close()
    
    # Convertimos los datos al formato que el frontend espera
    logged_ips = []
    for ip, location, city in ips_data:
        logged_ips.append({"ip": ip, "location": location, "city": city})
    return logged_ips

@app.route('/api/status', methods=['GET'])
def get_status():
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Limpiamos la IP si viene con proxy
    if ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()

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
        "pending_alerts": 1 if conexiones_activas > 1 else 0,
        "mitigated_attacks": 847,
        "system_status": f"VIGILANCIA ACTIVA ({conexiones_activas} nodos)",
        "server_location": "4.7110,-74.0721", # Ubicación del servidor (Bogotá por defecto)
        "logged_ips": logged_ips_list, # Lista de todas las IPs con ubicación y ciudad
        "logs": [
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {conexiones_activas} IPs rastreadas.",
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Última conexión: {city}",
        ]
    })

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)

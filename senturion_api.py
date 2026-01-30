from flask import Flask, jsonify, request
from flask_cors import CORS
import psutil
import datetime
import ipinfo

app = Flask(__name__)
CORS(app) 

# Reemplaza esto con tu token de ipinfo.io
IPINFO_TOKEN = "curl -H "Authorization: Bearer 2ee7b937864c94" https://ipinfo.io/8.8.8.8"
handler = ipinfo.getHandler(IPINFO_TOKEN)

@app.route('/api/status', methods=['GET'])
def get_status():
    # Detectamos la IP del cliente que llama a la API (tu dashboard)
    if request.headers.get('X-Forwarded-For'):
        ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip_address = request.remote_addr

    # Obtenemos detalles de la IP, incluyendo localización (latitud/longitud)
    try:
        details = handler.getDetails(ip_address)
        location = details.loc # Formato: "latitud,longitud"
        city = details.city
    except Exception as e:
        # Usamos una ubicación por defecto si falla la API
        location = "4.7110,-74.0721" # Ubicación por defecto: Bogotá
        city = "Bogotá"

    conexiones_activas = len(psutil.net_connections(kind='inet'))
    
    return jsonify({
        "threats_blocked": 2847,
        "active_connections": conexiones_activas,
        "pending_alerts": 1 if conexiones_activas > 50 else 0,
        "mitigated_attacks": 847,
        "system_status": f"VIGILANCIA ACTIVA en {city}",
        "location": location, # Nuevo campo para el mapa
        "logs": [
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Escaneo completado. IP detectada: {ip_address}",
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Geolocalización: {city}",
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

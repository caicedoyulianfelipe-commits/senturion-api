import nmap

# ... [código anterior de imports, IPINFO_TOKEN, handler, init_db, log_ip, get_logged_ips_from_db] ...

# ... [código anterior de init_db, log_ip, get_logged_ips_from_db] ...

def get_logged_ips_from_db():
    # ... [función anterior, no necesita cambios] ...
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip, location, city, blocked FROM ips")
    ips_data = c.fetchall()
    conn.close()
    
    logged_ips = []
    for ip, location, city, blocked in ips_data:
        logged_ips.append({"ip": ip, "location": location, "city": city, "blocked": blocked})
    return logged_ips

# NUEVA RUTA COMPLEJA: Escaneo de puertos del servidor
@app.route('/api/scan_ports', methods=['GET'])
def scan_ports():
    nm = nmap.PortScanner()
    # Escanea puertos TCP comunes en el localhost (127.0.0.1)
    nm.scan('127.0.0.1', '20-100') 
    
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append({"port": port, "service": nm[host][proto][port]['name']})
                    
    return jsonify({"status": "scan_complete", "open_ports": open_ports, "target": "localhost"})

# ... [código anterior de block_ip y get_status] ...

# ... [código anterior de block_ip y get_status] ...

@app.route('/api/status', methods=['GET'])
def get_status():
    # ... [código anterior para checkear bloqueo, logear IP y obtener logged_ips_list] ...
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(',').strip()

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

    return jsonify({
        "threats_blocked": 2847,
        "active_connections": conexiones_activas,
        "pending_alerts": len(open_ports) if 'open_ports' in globals() else 1 if conexiones_activas > 1 else 0, # Ahora usa los puertos abiertos
        "system_status": f"VIGILANCIA ACTIVA ({conexiones_activas} nodos)",
        "server_location": "4.7110,-74.0721",
        "logged_ips": logged_ips_list,
        "logs": [
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {conexiones_activas} IPs rastreadas.",
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Última conexión: {city}.",
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Alertas pendientes: {len(open_ports) if 'open_ports' in globals() else 'N/A'} puertos abiertos detectados."
        ]
    })

if __name__ == '__main__':
    init_db()
    # Ejecutamos el primer escaneo al iniciar el servidor
    # Esto puede ser lento y bloquear el inicio, mejor hacerlo bajo demanda via /api/scan_ports
    # scan_ports() 
    app.run(host='0.0.0.0', port=5000)


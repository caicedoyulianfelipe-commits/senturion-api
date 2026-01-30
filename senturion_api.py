from flask import Flask, jsonify
from flask_cors import CORS
import psutil
import datetime

app = Flask(__name__)
CORS(app) 

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "threats_blocked": 2847,
        "active_connections": len(psutil.net_connections()),
        "pending_alerts": 3,
        "mitigated_attacks": 847,
        "system_status": "OPERATIVO",
        "response_time": "0.3ms",
        "last_update": datetime.datetime.now().strftime("%H:%M:%S")
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

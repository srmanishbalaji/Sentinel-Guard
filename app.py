from flask import Flask, render_template, jsonify, request, redirect, url_for
import csv
import os
import subprocess
import mysql.connector
from services.usb_security import USBSecurityManager
import logging
from datetime import datetime, timedelta
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "data", "intrusion_log.csv")

# ── USB Security Manager ──────────────────────────────────────
usb_manager = USBSecurityManager(CSV_PATH)

# ── Network process handle ────────────────────────────────────
network_process = None

# ── CSV cache (avoids re-reading file on every request) ───────
_log_cache       = []
_log_cache_mtime = 0.0

# ── MySQL connection ──────────────────────────────────────────
try:
    db = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="malu@2303",
        database="sentinel_guard",
        auth_plugin='mysql_native_password'
    )
    cursor = db.cursor()
    logger.info("MySQL connected successfully")
except Exception as e:
    logger.error(f"MySQL connection failed: {e}")
    db = None
    cursor = None

# ════════════════════════════════════════════════════════════════
#  CSV HELPERS  (with file-mtime cache — fast after first load)
# ════════════════════════════════════════════════════════════════

def read_logs():
    global _log_cache, _log_cache_mtime
    try:
        mtime = os.path.getmtime(CSV_PATH)
    except OSError:
        return []

    # Return cached version if file hasn't changed
    if mtime == _log_cache_mtime and _log_cache:
        return _log_cache

    logs = []
    try:
        with open(CSV_PATH, newline='', encoding='utf-8') as f:
            rows = list(csv.reader(f))
        for i, row in enumerate(rows):
            if len(row) < 4:
                continue
            if i == 0 and not row[0].strip()[:4].isdigit():
                continue  # skip header row
            logs.append({
                'Timestamp':  row[0].strip(),
                'Event Type': row[1].strip() if len(row) > 1 else '',
                'Drive':      row[2].strip() if len(row) > 2 else '',
                'Status':     row[3].strip().upper() if len(row) > 3 else '',
                'Details':    row[4].strip() if len(row) > 4 else '',
            })
    except Exception as e:
        logger.error(f"read_logs error: {e}")
        return _log_cache  # return stale cache on error

    _log_cache       = logs
    _log_cache_mtime = mtime
    return logs

def parse_dt(ts_str):
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    return None

def get_stats():
    logs = read_logs()
    return {
        'total':   len(logs),
        'blocked': sum(1 for r in logs if r['Status'] == 'BLOCKED'),
        'active':  sum(1 for r in logs if r['Status'] == 'ACTIVE'),
        'stopped': sum(1 for r in logs if r['Status'] == 'STOPPED'),
        'logs':    logs
    }

def usb_events_chart():
    logs = read_logs()
    if not logs:
        return {'labels': [], 'allowed': [], 'blocked': []}
    dates = [parse_dt(r['Timestamp']).date() for r in logs if parse_dt(r['Timestamp'])]
    if not dates:
        return {'labels': [], 'allowed': [], 'blocked': []}
    day_range, d = [], min(dates)
    while d <= max(dates):
        day_range.append(d)
        d += timedelta(days=1)
    labels = [d.strftime('%b %d') for d in day_range]
    ac, bc = defaultdict(int), defaultdict(int)
    for r in logs:
        dt = parse_dt(r['Timestamp'])
        if not dt:
            continue
        l = dt.date().strftime('%b %d')
        if r['Status'] == 'ACTIVE':  ac[l] += 1
        if r['Status'] == 'BLOCKED': bc[l] += 1
    return {'labels': labels, 'allowed': [ac[l] for l in labels], 'blocked': [bc[l] for l in labels]}

def events_per_day():
    logs = read_logs()
    if not logs:
        return {'labels': [], 'usb': [], 'system': []}
    dates = [parse_dt(r['Timestamp']).date() for r in logs if parse_dt(r['Timestamp'])]
    if not dates:
        return {'labels': [], 'usb': [], 'system': []}
    day_range, d = [], min(dates)
    while d <= max(dates):
        day_range.append(d)
        d += timedelta(days=1)
    labels = [d.strftime('%b %d') for d in day_range]
    uc, sc = defaultdict(int), defaultdict(int)
    for r in logs:
        dt = parse_dt(r['Timestamp'])
        if not dt:
            continue
        l = dt.date().strftime('%b %d')
        if r['Drive'].upper() == 'SYSTEM':
            sc[l] += 1
        else:
            uc[l] += 1
    return {'labels': labels, 'usb': [uc[l] for l in labels], 'system': [sc[l] for l in labels]}

def status_breakdown():
    counts = defaultdict(int)
    for r in read_logs():
        counts[r['Status'] or 'UNKNOWN'] += 1
    return dict(counts)

# ════════════════════════════════════════════════════════════════
#  MYSQL HELPERS
# ════════════════════════════════════════════════════════════════

def safe_cursor():
    if db and cursor:
        try:
            db.ping(reconnect=True, attempts=3, delay=1)
        except Exception as e:
            logger.error(f"MySQL reconnect failed: {e}")
    return cursor

def read_network_logs():
    c = safe_cursor()
    if not c:
        return []
    try:
        c.execute("""
            SELECT attacker_ip, destination_ip, attack_type, timestamp
            FROM network_logs ORDER BY timestamp DESC LIMIT 10
        """)
        return [
            {"attacker": r[0], "destination": r[1], "type": r[2],
             "time": r[3].strftime("%Y-%m-%d %H:%M:%S") if hasattr(r[3], 'strftime') else str(r[3])}
            for r in c.fetchall()
        ]
    except Exception as e:
        logger.error(f"read_network_logs: {e}")
        return []

def read_blocked_ips():
    c = safe_cursor()
    if not c:
        return []
    try:
        c.execute("SELECT ip_address, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
        return [
            {"ip": r[0],
             "time": r[1].strftime("%Y-%m-%d %H:%M:%S") if hasattr(r[1], 'strftime') else str(r[1])}
            for r in c.fetchall()
        ]
    except Exception as e:
        logger.error(f"read_blocked_ips: {e}")
        return []

def get_network_stats():
    c = safe_cursor()
    if not c:
        return {"connections": 0, "blocked_ips": 0, "port_scans": 0, "syn_floods": 0}
    try:
        c.execute("SELECT COUNT(*) FROM network_logs")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM blocked_ips")
        blocked = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM network_logs WHERE attack_type = 'Port Scan'")
        port_scans = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM network_logs WHERE attack_type = 'SYN Flood'")
        syn_floods = c.fetchone()[0]
        return {"connections": total, "blocked_ips": blocked,
                "port_scans": port_scans, "syn_floods": syn_floods}
    except Exception as e:
        logger.error(f"get_network_stats: {e}")
        return {"connections": 0, "blocked_ips": 0, "port_scans": 0, "syn_floods": 0}

# ════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ════════════════════════════════════════════════════════════════

@app.route('/')
def dashboard():
    stats = get_stats()
    return render_template('dashboard.html',
        stats=stats,
        chart7=usb_events_chart(),
        breakdown=status_breakdown(),
        recent=list(reversed(stats['logs']))[:10])

@app.route('/usb')
def usb_monitoring():
    stats = get_stats()
    return render_template('usb.html',
        stats=stats,
        chart7=usb_events_chart(),
        logs=list(reversed(stats['logs'])),
        connected_devices=usb_manager.get_connected_devices(),
        blocked_drives=usb_manager.get_blocked_drives(),
        usb_status=usb_manager.status)

@app.route('/network')
def network_monitoring():
    return render_template('network.html',
        net_stats=get_network_stats(),
        net_logs=read_network_logs(),
        blocked_ips=read_blocked_ips())

@app.route('/system_logs')
def system_logs():
    stats = get_stats()
    return render_template('system_logs.html',
        stats=stats,
        per_day=events_per_day(),
        all_logs=list(reversed(stats['logs'])))

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route("/logs")
def logs_page():
    return redirect(url_for('system_logs'))

# ════════════════════════════════════════════════════════════════
#  USB API ROUTES
# ════════════════════════════════════════════════════════════════

@app.route('/api/start_monitor', methods=['POST'])
def api_start_monitor():
    try:
        started = usb_manager.start(scan_existing=True)
        msg = 'USB monitor started successfully' if started else 'USB monitor already running'
        return jsonify({'status': 'ok', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stop_monitor', methods=['POST'])
def api_stop_monitor():
    try:
        stopped = usb_manager.stop()
        msg = 'USB monitor stopped successfully' if stopped else 'USB monitor was not running'
        return jsonify({'status': 'ok', 'message': msg})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/usb/status')
def api_usb_status():
    return jsonify({
        'status':            usb_manager.status,
        'connected_devices': usb_manager.get_connected_devices(),
        'blocked_drives':    usb_manager.get_blocked_drives(),
    })

@app.route('/api/usb/scan', methods=['POST'])
def api_usb_scan():
    data  = request.get_json(silent=True) or {}
    drive = data.get('drive', '')
    if not drive:
        return jsonify({'status': 'error', 'message': 'drive parameter required'}), 400
    try:
        malicious, file_found = usb_manager.scan_drive(drive)
        if malicious:
            usb_manager.block_drive(drive, file_found)
            return jsonify({'status': 'ok', 'result': 'BLOCKED',
                            'message': f'Malicious file found: {file_found}'})
        return jsonify({'status': 'ok', 'result': 'SAFE', 'message': f'{drive} is safe'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    s = get_stats()
    s.pop('logs', None)
    return jsonify(s)

@app.route('/api/logs')
def api_logs():
    return jsonify(list(reversed(read_logs())))

@app.route('/api/usb_chart')
def api_usb_chart():
    return jsonify(usb_events_chart())

@app.route("/run/monitor")
def run_monitor():
    usb_manager.start(scan_existing=True)
    return redirect(url_for("dashboard"))

@app.route("/run/stop")
def run_stop():
    usb_manager.stop()
    return redirect(url_for("dashboard"))

# ════════════════════════════════════════════════════════════════
#  NETWORK IDS API ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/api/network/start", methods=["POST"])
def start_network():
    global network_process
    if network_process is None:
        script_path = os.path.join(BASE_DIR, "network", "network_engine.py")
        python_path = os.path.join(BASE_DIR, "..", "venv", "Scripts", "python.exe")
        network_process = subprocess.Popen(
            [python_path, script_path],
            cwd=os.path.join(BASE_DIR, "network")
        )
        return jsonify({"status": "ok", "message": "Network IDS started successfully"})
    return jsonify({"status": "ok", "message": "Network IDS already running"})

@app.route("/api/network/stop", methods=["POST"])
def stop_network():
    global network_process
    if network_process:
        network_process.kill()
        network_process = None
        return jsonify({"status": "ok", "message": "Network IDS stopped successfully"})
    return jsonify({"status": "ok", "message": "Network IDS not running"})

@app.route("/api/network/logs")
def network_logs():
    return jsonify({"logs": read_network_logs()})

@app.route("/api/network/blocked")
def get_blocked_ips_api():
    return jsonify({"blocked_ips": read_blocked_ips()})

@app.route("/api/network/stats")
def api_network_stats():
    return jsonify(get_network_stats())

# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(debug=False)
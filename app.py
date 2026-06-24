from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
import mysql.connector
import ipaddress
import math
import socket
try:
    from netmiko import ConnectHandler
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False

# If running with Tailscale SOCKS5 proxy, patch socket to route all TCP through it
import os as _os
_tailscale_socks5 = _os.environ.get('TAILSCALE_SOCKS5', '')
if _tailscale_socks5:
    try:
        import socks
        _socks_host, _socks_port = _tailscale_socks5.split(':')
        socks.set_default_proxy(socks.SOCKS5, _socks_host, int(_socks_port))
        socket.socket = socks.socksocket
    except Exception:
        pass

app = Flask(__name__)
app.config.from_object(Config)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'

with app.app_context():
    try:
        _conn = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        _cursor = _conn.cursor()
        for _col, _def in [
            ('gns3_host', 'VARCHAR(255) DEFAULT NULL'),
            ('gns3_port', 'INT DEFAULT 3080'),
            ('gns3_user', 'VARCHAR(255) DEFAULT NULL'),
            ('gns3_password', 'VARCHAR(255) DEFAULT NULL'),
            ('created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'),
        ]:
            try:
                _cursor.execute(f"ALTER TABLE users ADD COLUMN {_col} {_def}")
                _conn.commit()
            except mysql.connector.Error:
                pass
        _conn.close()
    except Exception:
        pass


def get_db():
    return mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )


def init_db():
    """Add GNS3 columns to users table if they don't exist yet."""
    conn = get_db()
    cursor = conn.cursor()
    for col, definition in [
        ('gns3_host', 'VARCHAR(255) DEFAULT NULL'),
        ('gns3_port', 'INT DEFAULT 3080'),
        ('gns3_user', 'VARCHAR(255) DEFAULT NULL'),
        ('gns3_password', 'VARCHAR(255) DEFAULT NULL'),
    ]:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
            conn.commit()
        except mysql.connector.Error:
            pass  # column already exists
    conn.close()


def get_user_gns3(user_id):
    """Return GNS3 connection settings for the given user."""
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT gns3_host, gns3_port, gns3_user, gns3_password FROM users WHERE id = %s",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    return {
        'host': (row.get('gns3_host') or '').strip() if row else '',
        'port': row.get('gns3_port') or 3080 if row else 3080,
        'user': (row.get('gns3_user') or '').strip() if row else '',
        'password': (row.get('gns3_password') or '').strip() if row else '',
    }


class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(row['id'], row['username'], row['role'])
    return None



@app.route('/')
def index():
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        row = cursor.fetchone()
        conn.close()
        if row and check_password_hash(row['password_hash'], password):
            login_user(User(row['id'], row['username'], row['role']))
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'viewer')",
                (username, generate_password_hash(password))
            )
            conn.commit()
            conn.close()
            flash('Account created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Username already exists.', 'error')
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) AS c FROM projects")
    stats = {'projects': cursor.fetchone()['c']}
    cursor.execute("SELECT COUNT(*) AS c FROM subnets")
    stats['subnets'] = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) AS c FROM devices")
    stats['devices'] = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) AS c FROM audit_logs")
    stats['audits'] = cursor.fetchone()['c']
    cursor.execute("SELECT * FROM projects ORDER BY created_at DESC LIMIT 5")
    recent_projects = cursor.fetchall()
    cursor.execute("SELECT * FROM subnets ORDER BY created_at DESC LIMIT 5")
    recent_subnets = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', stats=stats,
                           recent_projects=recent_projects,
                           recent_subnets=recent_subnets)



@app.route('/projects', methods=['GET', 'POST'])
@login_required
def projects():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        if current_user.role != 'admin':
            flash('Only admins can create projects.', 'error')
            conn.close()
            return redirect(url_for('projects'))
        name = request.form['name'].strip()
        description = request.form.get('description', '').strip()
        cursor.execute(
            "INSERT INTO projects (name, description, created_by) VALUES (%s, %s, %s)",
            (name, description or None, current_user.id)
        )
        conn.commit()
        flash(f'Project "{name}" created.', 'success')
        conn.close()
        return redirect(url_for('projects'))
    cursor.execute("""
        SELECT p.*, COUNT(s.id) AS subnet_count
        FROM projects p
        LEFT JOIN subnets s ON s.project_id = p.id
        GROUP BY p.id
        ORDER BY p.created_at DESC
    """)
    projects = cursor.fetchall()
    conn.close()
    return render_template('projects.html', projects=projects)



@app.route('/projects/<int:project_id>/clear/<calc_type>', methods=['POST'])
@login_required
def clear_calculation(project_id, calc_type):
    if current_user.role != 'admin':
        flash('Only admins can delete calculations.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))
    conn = get_db()
    cursor = conn.cursor()
    if calc_type == 'wlan':
        cursor.execute("DELETE FROM subnets WHERE project_id=%s AND description LIKE '[WLAN]%%'", (project_id,))
        label = 'WLAN'
    elif calc_type == 'ipv6':
        cursor.execute("DELETE FROM subnets WHERE project_id=%s AND description LIKE '[IPv6]%%'", (project_id,))
        label = 'IPv6'
    elif calc_type == 'ipv4':
        cursor.execute("DELETE FROM subnets WHERE project_id=%s AND description NOT LIKE '[WLAN]%%' AND description NOT LIKE '[IPv6]%%'", (project_id,))
        cursor.execute("DELETE FROM devices WHERE project_id=%s", (project_id,))
        label = 'IPv4'
    else:
        conn.close()
        return redirect(url_for('project_detail', project_id=project_id))
    conn.commit()
    conn.close()
    flash(f'{label} calculation cleared from project.', 'success')
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/projects/<int:project_id>')
@login_required
def project_detail(project_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM projects WHERE id = %s", (project_id,))
    project = cursor.fetchone()
    if not project:
        flash('Project not found.', 'error')
        conn.close()
        return redirect(url_for('projects'))
    cursor.execute("SELECT * FROM subnets WHERE project_id = %s ORDER BY cidr_prefix", (project_id,))
    subnets = cursor.fetchall()
    cursor.execute("SELECT * FROM devices WHERE project_id = %s AND hostname NOT LIKE 'Switch%' ORDER BY hostname", (project_id,))
    devices = cursor.fetchall()
    conn.close()
    return render_template('project_detail.html', project=project, subnets=subnets, devices=devices)


@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    if current_user.role != 'admin':
        flash('Only admins can delete projects.', 'error')
        return redirect(url_for('projects'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM subnets WHERE project_id = %s", (project_id,))
    cursor.execute("UPDATE devices SET project_id = NULL WHERE project_id = %s", (project_id,))
    cursor.execute("DELETE FROM projects WHERE id = %s", (project_id,))
    conn.commit()
    conn.close()
    flash('Project deleted.', 'success')
    return redirect(url_for('projects'))


@app.route('/subnets/<int:subnet_id>/delete', methods=['POST'])
@login_required
def delete_subnet(subnet_id):
    if current_user.role != 'admin':
        flash('Only admins can delete subnets.', 'error')
        return redirect(url_for('projects'))
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT project_id FROM subnets WHERE id = %s", (subnet_id,))
    row = cursor.fetchone()
    project_id = row['project_id'] if row else None
    cursor.execute("DELETE FROM subnets WHERE id = %s", (subnet_id,))
    conn.commit()
    conn.close()
    flash('Subnet deleted.', 'success')
    if project_id:
        return redirect(url_for('project_detail', project_id=project_id))
    return redirect(url_for('subnets'))


@app.route('/devices/<int:device_id>/delete', methods=['POST'])
@login_required
def delete_device(device_id):
    if current_user.role != 'admin':
        flash('Only admins can delete devices.', 'error')
        return redirect(url_for('projects'))
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT project_id FROM devices WHERE id = %s", (device_id,))
    row = cursor.fetchone()
    project_id = row['project_id'] if row else None
    cursor.execute("DELETE FROM devices WHERE id = %s", (device_id,))
    conn.commit()
    conn.close()
    flash('Device deleted.', 'success')
    if project_id:
        return redirect(url_for('project_detail', project_id=project_id))
    return redirect(url_for('devices'))


@app.route('/subnets')
@login_required
def subnets():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT s.*, p.name AS project_name
        FROM subnets s
        LEFT JOIN projects p ON p.id = s.project_id
        ORDER BY s.created_at DESC
    """)
    subnets = cursor.fetchall()
    conn.close()
    return render_template('subnets.html', subnets=subnets)



@app.route('/devices', methods=['GET', 'POST'])
@login_required
def devices():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        if current_user.role != 'admin':
            flash('Only admins can add devices.', 'error')
            conn.close()
            return redirect(url_for('devices'))
        console_port = request.form.get('console_port')
        cursor.execute("""
            INSERT INTO devices (hostname, ip_address, username, password, secret, project_id, console_port)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            request.form['hostname'],
            request.form['ip_address'],
            request.form.get('username') or None,
            request.form.get('password') or None,
            request.form.get('secret') or None,
            request.form.get('project_id') or None,
            int(console_port) if console_port else None
        ))
        conn.commit()
        flash(f'Device "{request.form["hostname"]}" added.', 'success')
        conn.close()
        return redirect(url_for('devices'))
    cursor.execute("""
        SELECT d.*, p.name AS project_name
        FROM devices d
        LEFT JOIN projects p ON p.id = d.project_id
        ORDER BY d.hostname
    """)
    devices = cursor.fetchall()
    cursor.execute("SELECT id, name FROM projects ORDER BY name")
    projects = cursor.fetchall()
    conn.close()
    return render_template('devices.html', devices=devices, projects=projects)



@app.route('/audit')
@login_required
def audit():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT a.*, d.hostname, p.name AS project_name
        FROM audit_logs a
        JOIN devices d ON d.id = a.device_id
        LEFT JOIN projects p ON p.id = d.project_id
        INNER JOIN (
            SELECT device_id, MAX(id) AS latest_id
            FROM audit_logs
            GROUP BY device_id
        ) latest ON a.id = latest.latest_id
        ORDER BY p.name, d.hostname
    """)
    logs = cursor.fetchall()
    conn.close()
    return render_template('audit.html', logs=logs)



def vlsm_calculate(base_network, base_cidr, host_requirements):
    network = ipaddress.IPv4Network(f"{base_network}/{base_cidr}", strict=False)

    # Separate forced bridges from LANs
    forced_bridges = [r for r in host_requirements if r.get('force_wan')]
    lan_inputs = [r for r in host_requirements if not r.get('force_wan')]

    # Sort LANs largest-first
    lan_inputs = sorted(lan_inputs, key=lambda x: x['hosts'], reverse=True)
    n = len(lan_inputs)
    num_wans = max(n - 1, 0)

    # Build LAN requirements
    lan_reqs = []
    for i, req in enumerate(lan_inputs):
        lan_reqs.append({
            'label': req['label'],
            'hosts': req['hosts'],
            'subnet_type': 'lan',
            'router_idx': i,
        })

    # Build auto WAN requirements (only if no forced bridges provided)
    wan_reqs = []
    if forced_bridges:
        for fb in forced_bridges:
            wan_reqs.append({
                'label': fb['label'],
                'hosts': 2,
                'subnet_type': 'wan',
                'router_a': fb.get('bridge_from', '?'),
                'router_b': fb.get('bridge_to', '?'),
                'named': True,
            })
    else:
        for i in range(num_wans):
            wan_reqs.append({
                'label': f'WAN{i}',
                'hosts': 2,
                'subnet_type': 'wan',
                'router_a': i,
                'router_b': i + 1,
                'named': False,
            })

    # Build label → router_name mapping for bridge resolution
    label_to_router = {req['label']: f"Router{req['router_idx']}" for req in lan_reqs}

    # VLSM: sort all largest-first
    all_reqs = sorted(lan_reqs + wan_reqs, key=lambda x: x['hosts'], reverse=True)

    results = []
    current_network = network.network_address

    for req in all_reqs:
        needed = req['hosts'] + 2
        prefix = 32 - math.ceil(math.log2(needed))
        subnet = ipaddress.IPv4Network(f"{current_network}/{prefix}", strict=False)
        hosts = list(subnet.hosts())

        if req['subnet_type'] == 'wan':
            ra, rb = req['router_a'], req['router_b']
            if req.get('named'):
                rname_a = label_to_router.get(str(ra), str(ra))
                rname_b = label_to_router.get(str(rb), str(rb))
                dev_a = {'name': rname_a, 'interface': 'Gi0/1', 'ip': str(hosts[0]), 'type': 'router'}
                dev_b = {'name': rname_b, 'interface': 'Gi0/1', 'ip': str(hosts[1]) if len(hosts) > 1 else '—', 'type': 'router'}
            else:
                dev_a = {'name': f'Router{ra}', 'interface': 'Gi0/1', 'ip': str(hosts[0]), 'type': 'router'}
                dev_b = {'name': f'Router{rb}', 'interface': 'Gi0/1', 'ip': str(hosts[1]) if len(hosts) > 1 else '—', 'type': 'router'}
            results.append({
                'label': req['label'],
                'subnet_type': 'WAN Link',
                'network_address': str(subnet.network_address),
                'subnet_mask': str(subnet.netmask),
                'cidr_prefix': prefix,
                'total_hosts': subnet.num_addresses,
                'usable_hosts': len(hosts),
                'gateway': str(hosts[0]) if hosts else None,
                'broadcast': str(subnet.broadcast_address),
                'devices': [dev_a, dev_b],
                'dhcp_range': None,
                'description': req['label'],
            })
        else:
            ri = req['router_idx']
            label = req['label']
            devices = [{'name': f'Router{ri}', 'interface': 'Gi0/0', 'ip': str(hosts[0]), 'type': 'router'}]
            if len(hosts) > 1:
                devices.append({'name': f'Server_{label}', 'interface': '—', 'ip': str(hosts[1]), 'type': 'server'})
            dhcp_range = f"{hosts[2]} – {hosts[-1]}" if len(hosts) > 2 else None
            results.append({
                'label': label,
                'subnet_type': 'LAN',
                'network_address': str(subnet.network_address),
                'subnet_mask': str(subnet.netmask),
                'cidr_prefix': prefix,
                'total_hosts': subnet.num_addresses,
                'usable_hosts': len(hosts),
                'gateway': str(hosts[0]) if hosts else None,
                'broadcast': str(subnet.broadcast_address),
                'devices': devices,
                'dhcp_range': dhcp_range,
                'description': label,
            })

        current_network = subnet.broadcast_address + 1

    return results


def build_gns3_summary(results):
    lan_subnets = [r for r in results if r['subnet_type'] == 'LAN']
    num_lan = len(lan_subnets)
    # N LAN subnets → N-1 routers (linear topology, shared between adjacent LANs)
    num_routers = num_lan  # one router per LAN subnet
    num_switches = num_lan
    num_servers = num_lan
    connections = []

    for r in results:
        if r['subnet_type'] == 'LAN':
            router = r['devices'][0]['name'] if r['devices'] else '?'
            connections.append(f"{router} (Gi0/0) → Switch_{r['label']} → Server_{r['label']} + PCs")
        elif r['subnet_type'] == 'WAN Link':
            if len(r['devices']) >= 2:
                ra = r['devices'][0]
                rb = r['devices'][1]
                connections.append(
                    f"{ra['name']} ({ra['interface']} = {ra['ip']}) ↔ {rb['name']} ({rb['interface']} = {rb['ip']}) — WAN"
                )

    return {
        'routers': num_routers,
        'switches': num_switches,
        'servers': num_servers,
        'pcs': 'As needed — connect to Switch, get IP from DHCP',
        'connections': connections,
    }


@app.route('/vlsm', methods=['GET', 'POST'])
@login_required
def vlsm():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name FROM projects ORDER BY name")
    projects = cursor.fetchall()

    results = session.get('vlsm_results')
    gns3 = session.get('vlsm_gns3')

    if request.method == 'POST':
        action = request.form.get('action', 'calculate')
        project_id = request.form.get('project_id')

        if action == 'calculate':
            base_network = request.form.get('base_network', '').strip()
            base_cidr = int(request.form.get('base_cidr', 24))
            descs = request.form.getlist('desc[]')
            hosts = request.form.getlist('hosts[]')
            bridge_descs = request.form.getlist('bridge_desc[]')
            bridge_froms = request.form.getlist('bridge_from[]')
            bridge_tos = request.form.getlist('bridge_to[]')

            host_requirements = []
            # LAN subnets
            for d, h in zip(descs, hosts):
                if h:
                    host_requirements.append({
                        'label': d.upper() if d else 'Subnet',
                        'hosts': int(h),
                        'force_wan': False,
                    })
            # Bridge (WAN) links
            for i, (bf, bt) in enumerate(zip(bridge_froms, bridge_tos)):
                bd = bridge_descs[i] if i < len(bridge_descs) else f'Bridge{i+1}'
                if bf and bt:
                    host_requirements.append({
                        'label': bd.upper() if bd else f'Bridge{i+1}',
                        'hosts': 2,
                        'force_wan': True,
                        'bridge_from': bf.upper(),
                        'bridge_to': bt.upper(),
                    })

            try:
                results = vlsm_calculate(base_network, base_cidr, host_requirements)
                gns3 = build_gns3_summary(results)
                session['vlsm_results'] = results
                session['vlsm_gns3'] = gns3
            except Exception as e:
                flash(f'Error: {e}', 'error')

        elif action == 'save' and current_user.role == 'admin':
            if not results:
                flash('Nothing to save. Please calculate first.', 'error')
            elif not project_id:
                flash('Please select a project before saving.', 'error')
            else:
                try:
                    saved_routers = set()
                    for r in results:
                        cursor.execute("""
                            INSERT INTO subnets
                            (project_id, network_address, subnet_mask, cidr_prefix,
                             total_hosts, usable_hosts, gateway, description)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            project_id, r['network_address'], r['subnet_mask'],
                            r['cidr_prefix'], r['total_hosts'], r['usable_hosts'],
                            r['gateway'], r['description']
                        ))
                        if r['subnet_type'] == 'LAN':
                            for d in r['devices']:
                                if d['name'] not in saved_routers and d['type'] == 'router':
                                    cursor.execute("""
                                        INSERT INTO devices
                                        (hostname, ip_address, device_type, project_id)
                                        VALUES (%s, %s, 'cisco_ios', %s)
                                        ON DUPLICATE KEY UPDATE hostname=VALUES(hostname)
                                    """, (d['name'], d['ip'], project_id))
                                    saved_routers.add(d['name'])
                    conn.commit()
                    session.pop('vlsm_results', None)
                    session.pop('vlsm_gns3', None)
                    flash(f'{len(results)} subnet(s) and devices saved to project.', 'success')
                    conn.close()
                    return redirect(url_for('project_detail', project_id=project_id))
                except Exception as e:
                    flash(f'Error saving: {e}', 'error')

    conn.close()
    return render_template('vlsm.html', projects=projects, results=results, gns3=gns3)


def ipv6_calculate(base_prefix, num_lans):
    """
    Splits a base IPv6 prefix into /64 LAN subnets and /127 WAN links.
    LAN: router = network+1 (::1), server = network+2 (::2).
    WAN: router_a = network+0, router_b = network+1.
    WANs are placed sequentially right after the last /64 LAN.
    """
    network = ipaddress.IPv6Network(base_prefix, strict=False)

    # Allocate /64 LAN subnets sequentially from base
    lan_results = []
    current = network.network_address
    for i in range(num_lans):
        sn = ipaddress.IPv6Network(f'{current}/64', strict=False)
        router_ip = str(sn.network_address + 1)
        server_ip = str(sn.network_address + 2)
        lan_results.append({
            'label': f'LAN{i}',
            'subnet_type': 'LAN',
            'network': f'{sn.network_address}/64',
            'prefix': 64,
            'router_name': f'Router{i}',
            'router_interface': 'Gi0/0',
            'router_ip': router_ip,
            'server_ip': server_ip,
            'cisco_router': (
                f"interface GigabitEthernet0/0\n"
                f" ipv6 address {router_ip}/64\n"
                f" ipv6 enable\n"
                f" no shutdown"
            ),
        })
        current = sn.broadcast_address + 1

    # Allocate /127 WAN links sequentially after the last /64
    wan_results = []
    for i in range(num_lans - 1):
        sn = ipaddress.IPv6Network(f'{current}/127', strict=False)
        wan_results.append({
            'label': f'WAN{i}',
            'subnet_type': 'WAN Link',
            'network': f'{sn.network_address}/127',
            'prefix': 127,
            'router_a': f'Router{i}',
            'router_a_interface': 'Gi0/1',
            'router_a_ip': str(sn.network_address),
            'router_b': f'Router{i + 1}',
            'router_b_interface': 'Gi0/1',
            'router_b_ip': str(sn.network_address + 1),
            'cisco_router_a': (
                f"interface GigabitEthernet0/1\n"
                f" ipv6 address {sn.network_address}/127\n"
                f" ipv6 enable\n"
                f" no shutdown"
            ),
            'cisco_router_b': (
                f"interface GigabitEthernet0/1\n"
                f" ipv6 address {sn.network_address + 1}/127\n"
                f" ipv6 enable\n"
                f" no shutdown"
            ),
        })
        current = sn.broadcast_address + 1

    return lan_results, wan_results


def ipv6_calculate_advanced(base_prefix, labels, types, froms, tos):
    """Advanced mode: user specifies each subnet as LAN (/64) or Bridge (/127)."""
    network = ipaddress.IPv6Network(base_prefix, strict=False)
    current = network.network_address
    lan_results = []
    wan_results = []
    bridge_from_iter = iter(froms)
    bridge_to_iter = iter(tos)
    router_idx = 0
    wan_idx = 0

    for i, (label, stype) in enumerate(zip(labels, types)):
        label = label.strip() or f'Subnet{i}'
        if stype == 'bridge':
            sn = ipaddress.IPv6Network(f'{current}/127', strict=False)
            from_name = next(bridge_from_iter, '?').strip()
            to_name = next(bridge_to_iter, '?').strip()
            wan_results.append({
                'label': f'WAN{wan_idx}',
                'subnet_type': 'WAN Link',
                'network': f'{sn.network_address}/127',
                'prefix': 127,
                'router_a': from_name,
                'router_a_interface': 'Gi0/1',
                'router_a_ip': str(sn.network_address),
                'router_b': to_name,
                'router_b_interface': 'Gi0/1',
                'router_b_ip': str(sn.network_address + 1),
                'cisco_router_a': (
                    f"interface GigabitEthernet0/1\n"
                    f" ipv6 address {sn.network_address}/127\n"
                    f" ipv6 enable\n no shutdown"
                ),
                'cisco_router_b': (
                    f"interface GigabitEthernet0/1\n"
                    f" ipv6 address {sn.network_address + 1}/127\n"
                    f" ipv6 enable\n no shutdown"
                ),
            })
            current = sn.broadcast_address + 1
            wan_idx += 1
        else:
            sn = ipaddress.IPv6Network(f'{current}/64', strict=False)
            router_ip = str(sn.network_address + 1)
            server_ip = str(sn.network_address + 2)
            lan_results.append({
                'label': label,
                'subnet_type': 'LAN',
                'network': f'{sn.network_address}/64',
                'prefix': 64,
                'router_name': f'Router{router_idx}',
                'router_interface': 'Gi0/0',
                'router_ip': router_ip,
                'server_ip': server_ip,
                'cisco_router': (
                    f"interface GigabitEthernet0/0\n"
                    f" ipv6 address {router_ip}/64\n"
                    f" ipv6 enable\n no shutdown"
                ),
            })
            current = sn.broadcast_address + 1
            router_idx += 1

    return lan_results, wan_results


@app.route('/ipv6', methods=['GET', 'POST'])
@login_required
def ipv6():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name FROM projects ORDER BY name")
    projects = cursor.fetchall()

    lan_results = session.get('ipv6_lans')
    wan_results = session.get('ipv6_wans')

    if request.method == 'POST':
        action = request.form.get('action', 'calculate')
        project_id = request.form.get('project_id')

        if action == 'calculate':
            base_prefix = request.form.get('base_prefix', '').strip()
            mode = request.form.get('mode', 'simple')
            try:
                if mode == 'advanced':
                    lan_results, wan_results = ipv6_calculate_advanced(
                        base_prefix,
                        request.form.getlist('adv_label[]'),
                        request.form.getlist('adv_type[]'),
                        request.form.getlist('adv_from[]'),
                        request.form.getlist('adv_to[]'),
                    )
                else:
                    num_lans = int(request.form.get('num_lans', 2))
                    lan_results, wan_results = ipv6_calculate(base_prefix, num_lans)
                session['ipv6_lans'] = lan_results
                session['ipv6_wans'] = wan_results
            except Exception as e:
                flash(f'Error: {e}', 'error')

        elif action == 'save' and current_user.role == 'admin':
            if not lan_results:
                flash('Nothing to save. Please calculate first.', 'error')
            elif not project_id:
                flash('Please select a project.', 'error')
            else:
                try:
                    for r in lan_results:
                        cursor.execute("""
                            INSERT INTO subnets
                            (project_id, network_address, subnet_mask, cidr_prefix,
                             total_hosts, usable_hosts, gateway, description)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            project_id,
                            r['network'],
                            'N/A (IPv6)',
                            r['prefix'],
                            0, 0,
                            r['router_ip'],
                            f"[IPv6] {r['label']}"
                        ))
                    for w in wan_results:
                        cursor.execute("""
                            INSERT INTO subnets
                            (project_id, network_address, subnet_mask, cidr_prefix,
                             total_hosts, usable_hosts, gateway, description)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            project_id,
                            w['network'],
                            'N/A (IPv6)',
                            w['prefix'],
                            0, 0,
                            w['router_a_ip'],
                            f"[IPv6] {w['label']}"
                        ))
                    conn.commit()
                    session.pop('ipv6_lans', None)
                    session.pop('ipv6_wans', None)
                    flash(f'IPv6 subnets saved to project.', 'success')
                    conn.close()
                    return redirect(url_for('project_detail', project_id=project_id))
                except Exception as e:
                    flash(f'Error saving: {e}', 'error')

    conn.close()
    return render_template('ipv6.html', projects=projects,
                           lan_results=lan_results, wan_results=wan_results)


@app.route('/devices/edit', methods=['POST'])
@login_required
def edit_device():
    if current_user.role != 'admin':
        flash('Only admins can edit devices.', 'error')
        return redirect(url_for('devices'))
    conn = get_db()
    cursor = conn.cursor()
    device_id = request.form['device_id']
    console_port = request.form.get('console_port')
    secret = request.form.get('secret')
    # Only update secret if a new one was provided
    if secret:
        cursor.execute("""
            UPDATE devices SET hostname=%s, ip_address=%s, username=%s, secret=%s,
            console_port=%s, project_id=%s WHERE id=%s
        """, (
            request.form['hostname'], request.form['ip_address'],
            request.form.get('username') or None, secret,
            int(console_port) if console_port else None,
            request.form.get('project_id') or None, device_id
        ))
    else:
        cursor.execute("""
            UPDATE devices SET hostname=%s, ip_address=%s, username=%s,
            console_port=%s, project_id=%s WHERE id=%s
        """, (
            request.form['hostname'], request.form['ip_address'],
            request.form.get('username') or None,
            int(console_port) if console_port else None,
            request.form.get('project_id') or None, device_id
        ))
    conn.commit()
    conn.close()
    flash('Device updated.', 'success')
    project_id = request.form.get('project_id')
    if project_id:
        return redirect(url_for('project_detail', project_id=project_id))
    return redirect(url_for('devices'))


@app.route('/devices/<int:device_id>/check', methods=['POST'])
@login_required
def check_device(device_id):
    if current_user.role != 'admin':
        flash('Only admins can check devices.', 'error')
        return redirect(url_for('projects'))
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
    device = cursor.fetchone()
    if not device:
        flash('Device not found.', 'error')
        conn.close()
        return redirect(url_for('projects'))

    # If console_port is set, check GNS3 console; otherwise check SSH
    gns3_host = (get_user_gns3(current_user.id).get('host') or 'localhost')
    status = 'unreachable'
    try:
        if device.get('console_port'):
            sock = socket.create_connection((gns3_host, device['console_port']), timeout=3)
        else:
            sock = socket.create_connection((device['ip_address'], 22), timeout=3)
        sock.close()
        status = 'reachable'
    except (socket.timeout, socket.error, OSError):
        status = 'unreachable'

    cursor.execute("UPDATE devices SET status = %s WHERE id = %s", (status, device_id))
    conn.commit()

    # Log to audit
    try:
        cursor.execute("""
            INSERT INTO audit_logs (device_id, checked_at, status)
            VALUES (%s, NOW(), %s)
        """, (device_id, status))
        conn.commit()
    except Exception:
        pass

    project_id = device.get('project_id')
    conn.close()
    flash(f'{device["hostname"]} is {status}.', 'success' if status == 'reachable' else 'error')
    if project_id:
        return redirect(url_for('project_detail', project_id=project_id))
    return redirect(url_for('devices'))


@app.route('/devices/<int:device_id>/deploy', methods=['POST'])
@login_required
def deploy_device(device_id):
    if current_user.role != 'admin':
        flash('Only admins can deploy configurations.', 'error')
        return redirect(url_for('projects'))
    if not NETMIKO_AVAILABLE:
        flash('Netmiko is not installed. Run: pip install netmiko', 'error')
        return redirect(url_for('projects'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
    device = cursor.fetchone()
    if not device or not device.get('console_port'):
        flash('Device not found or no console port configured.', 'error')
        conn.close()
        return redirect(url_for('projects'))

    cursor.execute(
        "SELECT * FROM subnets WHERE project_id = %s ORDER BY cidr_prefix",
        (device['project_id'],)
    )
    subnets = cursor.fetchall()
    project_id = device.get('project_id')
    conn.close()

    gns3_cfg = get_user_gns3(current_user.id)
    gns3_host = gns3_cfg.get('host') or 'localhost'

    try:
        net_connect = ConnectHandler(
            device_type='cisco_ios_telnet',
            host=gns3_host,
            port=device['console_port'],
            username=device.get('username') or '',
            password=device.get('password') or '',
            secret=device.get('secret') or '',
            global_delay_factor=4,
            fast_cli=False,
            conn_timeout=30,
            banner_timeout=30,
            auth_timeout=30,
        )
        if device.get('secret'):
            net_connect.enable()

        # Find this device's LAN subnet by matching device IP to gateway
        lan_subnets = [s for s in subnets if s.get('usable_hosts', 0) > 2
                       and not (s.get('description') or '').startswith('[WLAN]')
                       and not (s.get('description') or '').startswith('[IPv6]')]
        wan_subnets = [s for s in subnets if s.get('usable_hosts', 0) == 2
                       and not (s.get('description') or '').startswith('[IPv6]')]
        wlan_subnets = [s for s in subnets if (s.get('description') or '').startswith('[WLAN]')]
        my_lan = next((s for s in lan_subnets if s.get('gateway') == device.get('ip_address')), None)

        # Get all routers in project sorted by id to determine WAN IP order
        conn2 = get_db()
        cur2 = conn2.cursor(dictionary=True)
        cur2.execute("SELECT * FROM devices WHERE project_id = %s ORDER BY id", (device['project_id'],))
        all_devices = cur2.fetchall()
        conn2.close()
        router_devices = [d for d in all_devices if d['hostname'].lower().startswith('router')]
        my_index = next((i for i, d in enumerate(router_devices) if d['id'] == device['id']), 0)
        is_router0 = (my_index == 0)

        commands = ['no ip domain-lookup', f"hostname {device['hostname']}"]

        # Configure LAN interface
        if my_lan:
            commands += [
                'interface FastEthernet0/0',
                f"ip address {my_lan['gateway']} {my_lan['subnet_mask']}",
                'no shutdown',
                'exit',
                f"ip dhcp pool {my_lan['description'] or 'LAN'}",
                f"network {my_lan['network_address']} {my_lan['subnet_mask']}",
                f"default-router {my_lan['gateway']}",
                'exit',
            ]

        # Configure WAN interfaces and static routes (linear chain topology)
        # wan_subnets[j] connects router[j] <-> router[j+1]
        # Left WAN  (to lower-index router):  Fa1/0, gets hosts[1]
        # Right WAN (to higher-index router): Fa1/0 for Router0, Fa1/1 for others, gets hosts[0]
        def _wan_hosts(s):
            return list(ipaddress.IPv4Network(
                f"{s['network_address']}/{s['subnet_mask']}", strict=False).hosts())

        n_wan = len(wan_subnets)
        left_next_hop = None
        right_next_hop = None

        if my_index > 0 and (my_index - 1) < n_wan:
            lw = wan_subnets[my_index - 1]
            lw_hosts = _wan_hosts(lw)
            if len(lw_hosts) >= 2:
                left_next_hop = str(lw_hosts[0])
                commands += [
                    'interface FastEthernet1/0',
                    f"ip address {str(lw_hosts[1])} {lw['subnet_mask']}",
                    'no shutdown',
                    'exit',
                ]

        if my_index < n_wan:
            rw = wan_subnets[my_index]
            rw_hosts = _wan_hosts(rw)
            if len(rw_hosts) >= 2:
                right_next_hop = str(rw_hosts[1])
                rw_iface = 'FastEthernet1/0' if my_index == 0 else 'FastEthernet1/1'
                commands += [
                    f'interface {rw_iface}',
                    f"ip address {str(rw_hosts[0])} {rw['subnet_mask']}",
                    'no shutdown',
                    'exit',
                ]

        # Static routes to all other LAN subnets
        for s in lan_subnets:
            if s.get('gateway') == device.get('ip_address'):
                continue
            owner = next((d for d in router_devices if d['ip_address'] == s.get('gateway')), None)
            if not owner:
                continue
            owner_idx = next((i for i, d in enumerate(router_devices) if d['id'] == owner['id']), None)
            if owner_idx is None:
                continue
            if owner_idx < my_index and left_next_hop:
                commands.append(f"ip route {s['network_address']} {s['subnet_mask']} {left_next_hop}")
            elif owner_idx > my_index and right_next_hop:
                commands.append(f"ip route {s['network_address']} {s['subnet_mask']} {right_next_hop}")

        # Static routes to WLAN subnets (always on Router0, route left)
        for ws in wlan_subnets:
            if my_index > 0 and left_next_hop:
                commands.append(f"ip route {ws['network_address']} {ws['subnet_mask']} {left_next_hop}")

        # Configure WLAN sub-interfaces on Router0 only
        if is_router0 and wlan_subnets:
            # Bring up physical trunk interface first
            commands += [
                'interface FastEthernet1/1',
                'no ip address',
                'no shutdown',
                'exit',
            ]
            for i, ws in enumerate(wlan_subnets, start=1):
                ssid = (ws.get('description') or '')[7:]  # strip '[WLAN] '
                vlan_id = i * 10
                commands += [
                    f"interface FastEthernet1/1.{i}",
                    f"encapsulation dot1q {vlan_id}",
                    f"ip address {ws['gateway']} {ws['subnet_mask']}",
                    'no shutdown',
                    'exit',
                    f"ip dhcp pool WLAN_{ssid}",
                    f"network {ws['network_address']} {ws['subnet_mask']}",
                    f"default-router {ws['gateway']}",
                    'dns-server 8.8.8.8',
                    'exit',
                ]

        output = net_connect.send_config_set(commands, cmd_verify=False)
        net_connect.save_config()
        net_connect.disconnect()

        wlan_note = f' + {len(wlan_subnets)} WLAN SSID(s)' if is_router0 and wlan_subnets else ''
        flash(f'Configuration deployed to {device["hostname"]} successfully{wlan_note}.', 'success')
    except Exception as e:
        flash(f'Deploy failed: {e}', 'error')

    if project_id:
        return redirect(url_for('project_detail', project_id=project_id))
    return redirect(url_for('devices'))


def gns3_request(path, gns3_cfg=None):
    import urllib.request
    import base64
    import json as _json
    if gns3_cfg is None:
        gns3_cfg = {}
    host = gns3_cfg.get('host') or 'localhost'
    port = gns3_cfg.get('port') or 3080
    user = gns3_cfg.get('user') or ''
    password = gns3_cfg.get('password') or ''
    req = urllib.request.Request(f'http://{host}:{port}/v2/{path}')
    if user:
        credentials = base64.b64encode(f'{user}:{password}'.encode()).decode('ascii')
        req.add_header('Authorization', f'Basic {credentials}')
    with urllib.request.urlopen(req, timeout=10) as resp:
        return _json.loads(resp.read())


@app.route('/api/gns3/projects')
@login_required
def api_gns3_projects():
    from flask import jsonify
    try:
        cfg = get_user_gns3(current_user.id)
        projects = gns3_request('projects', gns3_cfg=cfg)
        return jsonify([{'project_id': p['project_id'], 'name': p['name']} for p in projects])
    except Exception as e:
        print(f"GNS3 projects error: {e}")
        return jsonify([])


def get_expected_config(cursor, device):
    """Build expected config lines from database for this device."""
    if not device.get('project_id') or not device.get('ip_address'):
        return []
    cursor.execute(
        "SELECT * FROM subnets WHERE project_id = %s ORDER BY cidr_prefix",
        (device['project_id'],)
    )
    subnets = cursor.fetchall()
    my_lan = next((s for s in subnets if s.get('gateway') == device.get('ip_address')
                   and not (s.get('description') or '').startswith('[WLAN]')), None)
    if not my_lan:
        return []

    lines = [
        f"interface FastEthernet0/0",
        f" ip address {my_lan['gateway']} {my_lan['subnet_mask']}",
        f"ip dhcp pool {my_lan['description'] or 'LAN'}",
        f" network {my_lan['network_address']} {my_lan['subnet_mask']}",
        f" default-router {my_lan['gateway']}",
    ]

    # Check WLAN sub-interfaces only on Router0 (first router in project)
    cursor.execute(
        "SELECT * FROM devices WHERE project_id = %s AND hostname LIKE 'Router%' ORDER BY id",
        (device['project_id'],)
    )
    routers = cursor.fetchall()
    is_router0 = routers and routers[0]['id'] == device['id']

    if is_router0:
        wlan_subnets = [s for s in subnets if (s.get('description') or '').startswith('[WLAN]')]
        for i, ws in enumerate(wlan_subnets, start=1):
            lines += [
                f"interface FastEthernet1/1.{i}",
                f" encapsulation dot1Q {i * 10}",
                f" ip address {ws['gateway']} {ws['subnet_mask']}",
                f"ip dhcp pool WLAN_{(ws['description'] or '')[7:]}",
                f" network {ws['network_address']} {ws['subnet_mask']}",
                f" default-router {ws['gateway']}",
            ]

    return lines


def get_actual_config(device, gns3_host='localhost'):
    """Pull running config from device via Netmiko."""
    net_connect = ConnectHandler(
        device_type='cisco_ios_telnet',
        host=gns3_host,
        port=device['console_port'],
        username=device.get('username') or '',
        password=device.get('password') or '',
        secret=device.get('secret') or '',
        global_delay_factor=1,
        conn_timeout=10,
        auth_timeout=10,
        banner_timeout=10,
    )
    if device.get('secret'):
        net_connect.enable()
    output = net_connect.send_command('show running-config', read_timeout=30)
    net_connect.disconnect()
    return output


def compare_configs(expected_lines, actual_config):
    """Check if expected lines appear in actual config. Returns diff string or None."""
    missing = []
    for line in expected_lines:
        if line.strip().lower() not in actual_config.lower():
            missing.append(f"MISSING: {line}")
    if missing:
        return '\n'.join(missing)
    return None


@app.route('/audit/run', methods=['POST'])
@login_required
def run_audit():
    if current_user.role != 'admin':
        flash('Only admins can run audits.', 'error')
        return redirect(url_for('audit'))

    # Fetch device list with a short-lived connection so no locks are held during Netmiko calls
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM devices WHERE console_port IS NOT NULL ORDER BY hostname")
    devices = cursor.fetchall()
    conn.close()

    gns3_host = (get_user_gns3(current_user.id).get('host') or 'localhost')

    checked = 0
    for device in devices:
        reachable = False
        try:
            sock = socket.create_connection((gns3_host, device['console_port']), timeout=2)
            sock.close()
            reachable = True
        except (socket.timeout, socket.error, OSError):
            pass

        # Compliance check (may be slow — do it before opening a DB transaction)
        audit_status = 'unreachable'
        diff_output = None
        actual_config = None
        expected_lines = []
        if reachable:
            audit_status = 'compliant'
            try:
                if NETMIKO_AVAILABLE:
                    conn_tmp = get_db()
                    cur_tmp = conn_tmp.cursor(dictionary=True)
                    expected_lines = get_expected_config(cur_tmp, device)
                    conn_tmp.close()
                    if expected_lines:
                        actual_config = get_actual_config(device, gns3_host=gns3_host)
                        diff_output = compare_configs(expected_lines, actual_config)
                        if diff_output:
                            audit_status = 'drift_detected'
            except Exception:
                pass

        # Short DB write — commit immediately to release locks
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("UPDATE devices SET status=%s WHERE id=%s",
                           ('reachable' if reachable else 'unreachable', device['id']))
            if reachable:
                cursor.execute("""
                    INSERT INTO audit_logs
                    (device_id, checked_at, status, expected_config, actual_config, diff_output)
                    VALUES (%s, NOW(), %s, %s, %s, %s)
                """, (
                    device['id'], audit_status,
                    '\n'.join(expected_lines) if expected_lines else None,
                    actual_config,
                    diff_output
                ))
            else:
                cursor.execute("""
                    INSERT INTO audit_logs (device_id, checked_at, status)
                    VALUES (%s, NOW(), %s)
                """, (device['id'], 'unreachable'))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            conn.close()

        checked += 1

    flash(f'Audit complete — {checked} device(s) checked.', 'success')
    return redirect(url_for('audit'))


@app.route('/projects/<int:project_id>/run_audit', methods=['POST'])
@login_required
def run_project_audit(project_id):
    if current_user.role != 'admin':
        flash('Only admins can run audits.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM devices WHERE project_id = %s AND console_port IS NOT NULL ORDER BY hostname", (project_id,))
    devices = cursor.fetchall()
    conn.close()

    gns3_host = (get_user_gns3(current_user.id).get('host') or 'localhost')

    checked = 0
    for device in devices:
        reachable = False
        try:
            sock = socket.create_connection((gns3_host, device['console_port']), timeout=2)
            sock.close()
            reachable = True
        except (socket.timeout, socket.error, OSError):
            pass

        audit_status = 'unreachable'
        diff_output = None
        actual_config = None
        expected_lines = []
        if reachable:
            audit_status = 'compliant'
            try:
                if NETMIKO_AVAILABLE:
                    conn_tmp = get_db()
                    cur_tmp = conn_tmp.cursor(dictionary=True)
                    expected_lines = get_expected_config(cur_tmp, device)
                    conn_tmp.close()
                    if expected_lines:
                        actual_config = get_actual_config(device, gns3_host=gns3_host)
                        diff_output = compare_configs(expected_lines, actual_config)
                        if diff_output:
                            audit_status = 'drift_detected'
            except Exception:
                pass

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("UPDATE devices SET status=%s WHERE id=%s",
                           ('reachable' if reachable else 'unreachable', device['id']))
            if reachable:
                cursor.execute("""
                    INSERT INTO audit_logs
                    (device_id, checked_at, status, expected_config, actual_config, diff_output)
                    VALUES (%s, NOW(), %s, %s, %s, %s)
                """, (device['id'], audit_status,
                      '\n'.join(expected_lines) if expected_lines else None,
                      actual_config, diff_output))
            else:
                cursor.execute("""
                    INSERT INTO audit_logs (device_id, checked_at, status)
                    VALUES (%s, NOW(), %s)
                """, (device['id'], 'unreachable'))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            conn.close()
        checked += 1

    flash(f'Audit complete — {checked} device(s) checked.', 'success')
    return redirect(url_for('audit'))


@app.route('/audit/export')
@login_required
def export_audit_csv():
    import csv, io
    from flask import Response
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT d.hostname, p.name AS project_name, a.status, a.checked_at, a.diff_output
        FROM audit_logs a
        JOIN devices d ON d.id = a.device_id
        LEFT JOIN projects p ON p.id = d.project_id
        ORDER BY a.checked_at DESC
    """)
    logs = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Device', 'Project', 'Status', 'Checked At', 'Diff'])
    for log in logs:
        writer.writerow([
            log['hostname'],
            log['project_name'] or '',
            log['status'],
            log['checked_at'].strftime('%Y-%m-%d %H:%M:%S') if log['checked_at'] else '',
            log['diff_output'] or ''
        ])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=audit_report.csv'})


@app.route('/projects/<int:project_id>/topology')
@login_required
def topology(project_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM projects WHERE id = %s", (project_id,))
    project = cursor.fetchone()
    if not project:
        flash('Project not found.', 'error')
        conn.close()
        return redirect(url_for('projects'))
    cursor.execute("SELECT * FROM subnets WHERE project_id = %s ORDER BY cidr_prefix", (project_id,))
    subnets = cursor.fetchall()
    cursor.execute("SELECT * FROM devices WHERE project_id = %s ORDER BY hostname", (project_id,))
    devices = cursor.fetchall()
    conn.close()

    lan_subnets = [s for s in subnets if s.get('usable_hosts', 0) > 2
                   and not (s.get('description') or '').startswith('[WLAN]')
                   and not (s.get('description') or '').startswith('[IPv6]')]
    wan_subnets = [s for s in subnets if s.get('usable_hosts', 0) <= 2 and s.get('usable_hosts', 0) > 0]
    wlan_subnets = [s for s in subnets if (s.get('description') or '').startswith('[WLAN]')]

    # Match routers to their LAN subnets by gateway IP
    routers = []
    for s in lan_subnets:
        router = next((d for d in devices if d['ip_address'] == s.get('gateway')), None)
        routers.append({'subnet': s, 'device': router})

    return render_template('topology.html', project=project,
                           routers=routers, wan_subnets=wan_subnets,
                           wlan_subnets=wlan_subnets)


@app.route('/audit/clear', methods=['POST'])
@login_required
def clear_audit_logs():
    if current_user.role != 'admin':
        flash('Only admins can clear audit logs.', 'error')
        return redirect(url_for('audit'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_logs")
    conn.commit()
    conn.close()
    flash('Audit logs cleared.', 'success')
    return redirect(url_for('audit'))


@app.route('/projects/<int:project_id>/link_gns3', methods=['POST'])
@login_required
def link_gns3(project_id):
    if current_user.role != 'admin':
        flash('Only admins can link GNS3 projects.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))
    gns3_project_id = request.form.get('gns3_project_id', '').strip()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE projects SET gns3_project_id = %s WHERE id = %s",
                   (gns3_project_id or None, project_id))
    conn.commit()
    conn.close()
    flash('GNS3 project linked.' if gns3_project_id else 'GNS3 link removed.', 'success')
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/api/gns3/<int:project_id>/nodes')
@login_required
def api_gns3_nodes(project_id):
    from flask import jsonify
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT gns3_project_id FROM projects WHERE id = %s", (project_id,))
        row = cursor.fetchone()
        if not row or not row.get('gns3_project_id'):
            conn.close()
            return jsonify([])
        gns3_id = row['gns3_project_id']
        cursor.execute("SELECT hostname, ip_address, console_port FROM devices WHERE project_id = %s", (project_id,))
        db_devices = {d['console_port']: d['ip_address'] for d in cursor.fetchall() if d['console_port']}
        conn.close()
        cfg = get_user_gns3(current_user.id)
        nodes = gns3_request(f'projects/{gns3_id}/nodes', gns3_cfg=cfg)

        result = []
        for n in nodes:
            ip = db_devices.get(n.get('console'), '—')
            # For VPCS nodes, get IP via Telnet
            if n.get('node_type') == 'vpcs' and n.get('status') == 'started' and n.get('console'):
                try:
                    import time as _time
                    s = socket.socket()
                    s.settimeout(2)
                    s.connect((cfg.get('host') or 'localhost', n['console']))
                    _time.sleep(0.5)
                    s.send(b'show\n')
                    _time.sleep(0.5)
                    output = s.recv(4096).decode('ascii', errors='ignore')
                    s.close()
                    for line in output.splitlines():
                        parts = line.split()
                        for part in parts:
                            if '/' in part and not part.startswith('fe80') and not part.startswith('0.0.0.0'):
                                candidate = part.split('/')[0]
                                segments = candidate.split('.')
                                if len(segments) == 4 and all(s2.isdigit() for s2 in segments):
                                    ip = candidate
                                    break
                        if ip != '—':
                            break
                except Exception:
                    pass
            result.append({
                'name': n.get('name'),
                'node_type': n.get('node_type'),
                'status': n.get('status'),
                'console': n.get('console'),
                'ip_address': ip,
            })
        return jsonify(result)
    except Exception:
        conn.close()
        return jsonify([])


@app.route('/wlan', methods=['GET', 'POST'])
@login_required
def wlan():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name FROM projects ORDER BY name")
    projects = cursor.fetchall()
    conn.close()

    results = session.get('wlan_results')

    if request.method == 'POST':
        action = request.form.get('action', 'calculate')

        if action == 'save' and current_user.role == 'admin':
            project_id = request.form.get('project_id')
            if not project_id:
                flash('Please select a project.', 'error')
            else:
                try:
                    conn = get_db()
                    cursor = conn.cursor(dictionary=True)
                    networks = request.form.getlist('save_network[]')
                    masks = request.form.getlist('save_mask[]')
                    cidrs = request.form.getlist('save_cidr[]')
                    gateways = request.form.getlist('save_gateway[]')
                    usables = request.form.getlist('save_usable[]')
                    ssids = request.form.getlist('save_ssid[]')
                    for i in range(len(networks)):
                        cursor.execute("""
                            INSERT INTO subnets
                            (project_id, network_address, subnet_mask, cidr_prefix,
                             total_hosts, usable_hosts, gateway, description)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """, (project_id, networks[i], masks[i], cidrs[i],
                              usables[i], usables[i], gateways[i],
                              f"[WLAN] {ssids[i]}"))
                    conn.commit()
                    conn.close()
                    session.pop('wlan_results', None)
                    flash(f'{len(networks)} WLAN subnet(s) saved to project.', 'success')
                    return redirect(url_for('project_detail', project_id=project_id))
                except Exception as e:
                    flash(f'Error saving: {e}', 'error')

        elif action == 'calculate':
            base_network = request.form.get('base_network', '').strip()
            base_cidr = int(request.form.get('base_cidr', 24))
            ssids = request.form.getlist('ssid[]')
            clients = request.form.getlist('clients[]')
            try:
                network = ipaddress.IPv4Network(f"{base_network}/{base_cidr}", strict=False)
                reqs = []
                for s, c in zip(ssids, clients):
                    if s.strip() and c:
                        reqs.append({'ssid': s.strip(), 'clients': int(c)})
                reqs = sorted(reqs, key=lambda x: x['clients'], reverse=True)
                current_net = network.network_address
                results = []
                for req in reqs:
                    needed = req['clients'] + 2
                    prefix = 32 - math.ceil(math.log2(needed))
                    subnet = ipaddress.IPv4Network(f"{current_net}/{prefix}", strict=False)
                    hosts = list(subnet.hosts())
                    results.append({
                        'ssid': req['ssid'],
                        'clients': req['clients'],
                        'network': str(subnet.network_address),
                        'mask': str(subnet.netmask),
                        'cidr': prefix,
                        'gateway': str(hosts[0]),
                        'dhcp_start': str(hosts[1]) if len(hosts) > 1 else '—',
                        'dhcp_end': str(hosts[-1]) if hosts else '—',
                        'dhcp_pool': len(hosts) - 1 if len(hosts) > 1 else 0,
                        'broadcast': str(subnet.broadcast_address),
                        'usable': len(hosts),
                    })
                    current_net = subnet.broadcast_address + 1
                session['wlan_results'] = results
            except Exception as e:
                flash(f'Error: {e}', 'error')

    return render_template('wlan.html', results=results, projects=projects)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        host = request.form.get('gns3_host', '').strip()
        port = request.form.get('gns3_port', '3080').strip()
        user = request.form.get('gns3_user', '').strip()
        password = request.form.get('gns3_password', '').strip()
        try:
            port = int(port)
        except ValueError:
            port = 3080
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET gns3_host=%s, gns3_port=%s, gns3_user=%s, gns3_password=%s WHERE id=%s",
            (host or None, port, user or None, password or None, current_user.id)
        )
        conn.commit()
        conn.close()
        flash('GNS3 settings saved.', 'success')
        return redirect(url_for('settings'))
    cfg = get_user_gns3(current_user.id)
    return render_template('settings.html', cfg=cfg)


@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Only admins can access this page.', 'error')
        return redirect(url_for('dashboard'))
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
def admin_set_role(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    if user_id == current_user.id:
        flash("You can't change your own role.", 'error')
        return redirect(url_for('admin_users'))
    new_role = request.form.get('role')
    if new_role not in ('admin', 'viewer'):
        flash('Invalid role.', 'error')
        return redirect(url_for('admin_users'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
    conn.commit()
    conn.close()
    flash('Role updated.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    if user_id == current_user.id:
        flash("You can't delete your own account.", 'error')
        return redirect(url_for('admin_users'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_users'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=8080)

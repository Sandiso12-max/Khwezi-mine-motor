"""Mining prototype: validation, permissions, engineering rules and SQLite storage.
All seed records are fictional. Thresholds are for education, not mine operations.
"""
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROLES = ['Administrator', 'Safety Officer', 'Mining Engineer', 'Maintenance Engineer', 'Manager']
PERMISSIONS = {
    'Administrator': {'workers', 'incidents', 'equipment', 'risks'},
    'Safety Officer': {'workers', 'incidents', 'risks'},
    'Mining Engineer': {'workers', 'incidents', 'equipment', 'risks'},
    'Maintenance Engineer': {'equipment'},
    'Manager': {'workers', 'incidents', 'equipment', 'risks'},
}
DEPARTMENTS = ['Open Pit', 'Underground', 'Processing', 'Workshop']
# Field specification: ('choice', options), ('number', minimum, maximum, default),
# ('integer', minimum, maximum, default), ('text',), ('date',), ('time',).
SCHEMAS = {
    'workers': {
        'id': ('text',), 'department': ('choice', DEPARTMENTS), 'job_role': ('text',),
        'shift': ('choice', ['Day', 'Night']), 'ppe_compliance_pct': ('number', 0., 100., 100.),
        'training_status': ('choice', ['Current', 'Expired', 'Not completed']),
        'fatigue_level': ('integer', 1, 5, 1), 'safety_observation': ('text',),
        'near_misses': ('integer', 0, 100000, 0), 'previous_incidents': ('integer', 0, 100000, 0),
        'likelihood': ('integer', 1, 5, 1), 'consequence': ('integer', 1, 5, 1),
    },
    'incidents': {
        'id': ('text',), 'date': ('date',), 'time': ('time',),
        'shift': ('choice', ['Day', 'Night']), 'location': ('text',),
        'department': ('choice', DEPARTMENTS),
        'incident_type': ('choice', ['Near miss', 'Injury', 'Equipment failure', 'Unsafe condition', 'Environmental']),
        'severity': ('choice', ['Low', 'Medium', 'High', 'Critical']),
        'injury': ('choice', ['No', 'Yes']), 'lost_time_injury': ('choice', ['No', 'Yes']),
        'cause': ('text',), 'corrective_action': ('text',),
        'status': ('choice', ['Open', 'Investigating', 'Closed']),
    },
    'equipment': {
        'id': ('text',), 'department': ('choice', DEPARTMENTS),
        'equipment_type': ('choice', ['Haul truck', 'Loader', 'Excavator', 'Drilling machine', 'Bulldozer', 'Scraper winch', 'Crusher', 'Conveyor']),
        'manufacturer': ('text',),
        'operating_hours': ('number', 0., 10000000., 100.),
        'downtime_hours': ('number', 0., 10000000., 0.),
        'temperature_c': ('number', -50., 500., 60.),
        'vibration_mm_s': ('number', 0., 1000., 2.),
        'fuel_litres': ('number', 0., 100000000., 0.),
        'brake_status': ('choice', ['Good', 'Needs inspection', 'Fault', 'Not applicable']),
        'tyre_status': ('choice', ['Good', 'Needs inspection', 'Fault', 'Not applicable']),
        'engine_status': ('choice', ['Good', 'Needs inspection', 'Fault', 'Not applicable']),
        'maintenance_status': ('choice', ['Operational', 'Scheduled', 'Under maintenance']),
        'maintenance_due': ('date',), 'maintenance_notes': ('text',),
    },
    'risks': {
        'id': ('text',), 'department': ('choice', DEPARTMENTS), 'observation': ('text',),
        'likelihood': ('integer', 1, 5, 1), 'consequence': ('integer', 1, 5, 1),
        'control_action': ('text',), 'status': ('choice', ['Open', 'Controlled', 'Closed']),
    },
}

def authorize(role, entity, write=False):
    if entity not in PERMISSIONS.get(role, set()):
        raise PermissionError('Your role does not have access to this data.')
    # The brief specifies data access; this implementation makes Manager read-only.
    if write and role == 'Manager':
        raise PermissionError('Managers have read-only access.')

def risk_class(score):
    if not 1 <= score <= 25:
        raise ValueError('Risk score must be between 1 and 25.')
    return 'Low' if score <= 4 else 'Medium' if score <= 9 else 'High' if score <= 16 else 'Critical'

def condition(value, warning, critical):
    return 'Critical' if value > critical else 'Warning' if value >= warning else 'Normal'

def availability(operating, downtime):
    if operating < 0 or downtime < 0:
        raise ValueError('Hours cannot be negative.')
    return round(100 * operating / (operating + downtime), 2) if operating + downtime else None

def validate(entity, record):
    if entity not in SCHEMAS or set(record) != set(SCHEMAS[entity]):
        raise ValueError('Record fields do not match the required schema.')
    cleaned = {}
    for name, spec in SCHEMAS[entity].items():
        value = record[name]
        kind = spec[0]
        if kind in ('number', 'integer'):
            if isinstance(value, bool):
                raise ValueError(f'{name}: a number is required.')
            number = float(value)
            if not math.isfinite(number) or not spec[1] <= number <= spec[2]:
                raise ValueError(f'{name} must be between {spec[1]} and {spec[2]}.')
            if kind == 'integer' and not number.is_integer():
                raise ValueError(f'{name} must be a whole number.')
            value = int(number) if kind == 'integer' else number
        else:
            value = str(value).strip()
            if len(value) > 2000:
                raise ValueError(f'{name} is too long (maximum 2,000 characters).')
            if kind == 'choice' and value not in spec[1]:
                raise ValueError(f'Invalid selection for {name}.')
            if kind == 'date':
                value = date.fromisoformat(value).isoformat()
            if kind == 'time':
                value = datetime.strptime(value, '%H:%M').strftime('%H:%M')
        cleaned[name] = value
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', cleaned['id']):
        raise ValueError('ID: use 1-40 letters, numbers, underscores or hyphens.')
    required = {'workers': ['job_role'], 'incidents': ['location', 'cause', 'corrective_action'],
                'equipment': ['manufacturer'], 'risks': ['observation', 'control_action']}[entity]
    if any(not cleaned[f] for f in required):
        raise ValueError('Complete these required fields: ' + ', '.join(required))
    if entity == 'incidents':
        if cleaned['date'] > date.today().isoformat():
            raise ValueError('An incident cannot be dated in the future.')
        if cleaned['lost_time_injury'] == 'Yes' and cleaned['injury'] != 'Yes':
            raise ValueError('Lost-time injury requires injury = Yes.')
        if cleaned['incident_type'] == 'Near miss' and cleaned['injury'] == 'Yes':
            raise ValueError('A near miss cannot have an injury.')
    return cleaned

def derive(entity, row, today=None):
    r = dict(row)
    today = today or date.today()
    if entity in ('workers', 'risks'):
        r['risk_score'] = r['likelihood'] * r['consequence']
        r['risk_level'] = risk_class(r['risk_score'])
    if entity == 'equipment':
        r['availability_pct'] = availability(r['operating_hours'], r['downtime_hours'])
        r['temperature_status'] = condition(r['temperature_c'], 80, 100)
        r['vibration_status'] = condition(r['vibration_mm_s'], 5, 8)
        states = [r['temperature_status'], r['vibration_status']]
        states += ['Critical' if r[x] == 'Fault' else 'Warning' if r[x] == 'Needs inspection' else 'Normal'
                   for x in ['brake_status', 'tyre_status', 'engine_status']]
        r['condition'] = max(states, key=['Normal', 'Warning', 'Critical'].index)
        due = date.fromisoformat(r['maintenance_due'])
        r['due_status'] = 'Overdue' if due < today else 'Due today' if due == today else 'Due within 7 days' if due <= today + timedelta(days=7) else 'Not due'
        r['maintenance_priority'] = 'Immediate' if r['condition'] == 'Critical' or r['due_status'] == 'Overdue' else 'Plan inspection' if r['condition'] == 'Warning' or r['due_status'] != 'Not due' else 'Routine'
    return r

def alerts_for(entity, row, today=None):
    r = derive(entity, row, today)
    alerts = []
    def add(level, parameter, value, action):
        alerts.append({'source': entity, 'record_id': r['id'], 'department': r['department'],
                       'level': level, 'parameter': parameter, 'value': str(value), 'recommended_action': action})
    if entity == 'workers':
        if r['ppe_compliance_pct'] < 100:
            add('Warning', 'PPE compliance', r['ppe_compliance_pct'], 'Address missing PPE before work.')
        if r['fatigue_level'] >= 4:
            add('High', 'Fatigue level', r['fatigue_level'], 'Refer to supervisor for fatigue assessment.')
        if r['training_status'] != 'Current':
            add('Warning', 'Safety training', r['training_status'], 'Arrange training and check task authorization.')
        if r['risk_level'] in ('High', 'Critical'):
            add(r['risk_level'], 'Worker safety risk', r['risk_score'], 'Review observation and apply controls.')
    elif entity == 'risks' and r['status'] != 'Closed' and r['risk_level'] in ('High', 'Critical'):
        add(r['risk_level'], 'Safety observation risk', r['risk_score'], r['control_action'])
    elif entity == 'incidents' and r['status'] != 'Closed' and r['severity'] in ('High', 'Critical'):
        add(r['severity'], 'Incident severity', r['severity'], r['corrective_action'])
    elif entity == 'equipment':
        for field, status in [('temperature_c', 'temperature_status'), ('vibration_mm_s', 'vibration_status')]:
            if r[status] != 'Normal':
                add(r[status], field, r[field], 'Inspect equipment and follow approved maintenance procedures.')
        for field in ['brake_status', 'tyre_status', 'engine_status']:
            if r[field] in ('Fault', 'Needs inspection'):
                add('Critical' if r[field] == 'Fault' else 'Warning', field, r[field], 'Arrange inspection and follow site isolation procedures.')
        if r['due_status'] != 'Not due':
            add('High' if r['due_status'] == 'Overdue' else 'Warning', 'Maintenance due', r['due_status'], 'Schedule maintenance; update due date after completion.')
        if r['maintenance_status'] == 'Under maintenance':
            add('Warning', 'Maintenance status', r['maintenance_status'], 'Keep unavailable until authorized return to service.')
        if r['downtime_hours'] > 24:
            add('Warning', 'Downtime hours', r['downtime_hours'], 'Investigate downtime in the reporting period.')
        if r['availability_pct'] is not None and r['availability_pct'] < 85:
            add('Warning', 'Availability %', r['availability_pct'], 'Review reliability and maintenance plan.')
    return alerts

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 200000).hex()
    return salt + ':' + digest

def password_matches(password, stored):
    return hmac.compare_digest(password_hash(password, stored.split(':')[0]), stored)

class Store:
    def __init__(self, path='data/khwezi.sqlite3'):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.executescript('''
                CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS records(entity TEXT, id TEXT, payload TEXT NOT NULL, PRIMARY KEY(entity,id));
                CREATE TABLE IF NOT EXISTS alert_events(id INTEGER PRIMARY KEY, timestamp TEXT, equipment_id TEXT, payload TEXT);
                CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT);
            ''')

    def connect(self):
        return sqlite3.connect(self.path, timeout=20)

    def bootstrap(self, demo=True, admin_password=None):
        with self.connect() as con:
            if con.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
                if not demo and (not admin_password or len(admin_password) < 12):
                    raise ValueError('Set ADMIN_PASSWORD to at least 12 characters when DEMO_MODE is false.')
                users = [('admin', admin_password or 'MineDemo2026!', 'Administrator')]
                if demo:
                    users += [(name, 'MineDemo2026!', role) for name, role in zip(
                        ['safety', 'mining', 'maintenance', 'manager'], ROLES[1:])]
                con.executemany('INSERT INTO users VALUES(?,?,?)', [(u, password_hash(p), r) for u,p,r in users])
            if demo and not con.execute("SELECT 1 FROM metadata WHERE key='seeded'").fetchone():
                for entity, records in demo_data().items():
                    for row in records:
                        row = validate(entity, row)
                        con.execute('INSERT OR IGNORE INTO records VALUES(?,?,?)', (entity, row['id'], json.dumps(row)))
                con.execute("INSERT INTO metadata VALUES('seeded','yes')")

    def login(self, username, password):
        with self.connect() as con:
            row = con.execute('SELECT password,role FROM users WHERE username=?', (username,)).fetchone()
        return row[1] if row and password_matches(password, row[0]) else None

    def role_for(self, username):
        with self.connect() as con:
            row = con.execute('SELECT role FROM users WHERE username=?', (username,)).fetchone()
        return row[0] if row else None

    def users(self, role):
        if role != 'Administrator':
            raise PermissionError('Administrator only.')
        with self.connect() as con:
            return con.execute('SELECT username,role FROM users ORDER BY username').fetchall()

    def set_user(self, role, username, password, new_role, replace=False):
        if role != 'Administrator':
            raise PermissionError('Administrator only.')
        if not re.fullmatch(r'[a-zA-Z0-9_-]{3,30}', username) or len(password) < 12 or new_role not in ROLES:
            raise ValueError('Use a 3-30 character username, a password of at least 12 characters, and a valid role.')
        with self.connect() as con:
            old = con.execute('SELECT role FROM users WHERE username=?', (username,)).fetchone()
            if old and not replace:
                raise ValueError('Username exists; choose Update to change it.')
            if replace and not old:
                raise ValueError('Username does not exist.')
            if old and old[0] == 'Administrator' and new_role != 'Administrator':
                if con.execute("SELECT COUNT(*) FROM users WHERE role='Administrator'").fetchone()[0] <= 1:
                    raise ValueError('Keep at least one administrator.')
            con.execute('INSERT OR REPLACE INTO users VALUES(?,?,?)', (username, password_hash(password), new_role))

    def rows(self, role, entity):
        authorize(role, entity)
        with self.connect() as con:
            return [json.loads(x[0]) for x in con.execute('SELECT payload FROM records WHERE entity=? ORDER BY id', (entity,))]

    def save(self, role, entity, row, update=False):
        authorize(role, entity, write=True)
        row = validate(entity, row)
        with self.connect() as con:
            exists = con.execute('SELECT 1 FROM records WHERE entity=? AND id=?', (entity,row['id'])).fetchone()
            if exists and not update:
                raise ValueError('This ID already exists. Use Edit existing record.')
            if update and not exists:
                raise ValueError('Record no longer exists.')
            con.execute('INSERT OR REPLACE INTO records VALUES(?,?,?)', (entity,row['id'],json.dumps(row)))
            # Count monitoring submissions, not page refreshes. Each save is a new observation.
            if entity == 'equipment':
                timestamp = datetime.now(timezone.utc).isoformat()
                con.execute('INSERT INTO alert_events(timestamp,equipment_id,payload) VALUES(?,?,?)',
                            (timestamp, row['id'], json.dumps(alerts_for(entity,row))))
        return row

    def history(self, role):
        authorize(role, 'equipment')
        with self.connect() as con:
            return [{'timestamp': t, 'equipment_id': e, 'alerts': json.loads(p)}
                    for t,e,p in con.execute('SELECT timestamp,equipment_id,payload FROM alert_events ORDER BY id DESC')]

    def restore(self, role, backup):
        if role != 'Administrator':
            raise PermissionError('Administrator only.')
        if set(backup) != {'version', 'records'} or backup['version'] != 1 or set(backup['records']) != set(SCHEMAS):
            raise ValueError('Invalid backup structure.')
        clean = {}
        for entity, rows in backup['records'].items():
            if not isinstance(rows, list) or len(rows) > 10000:
                raise ValueError('Each dataset must be a list of at most 10,000 records.')
            clean[entity] = [validate(entity, r) for r in rows]
            ids = [r['id'] for r in clean[entity]]
            if len(ids) != len(set(ids)):
                raise ValueError('Duplicate IDs in backup.')
        # All validation completes before a single transaction replaces data.
        with self.connect() as con:
            con.execute('DELETE FROM records')
            con.execute('DELETE FROM alert_events')
            for entity, rows in clean.items():
                con.executemany('INSERT INTO records VALUES(?,?,?)', [(entity,r['id'],json.dumps(r)) for r in rows])


def demo_data():
    today = date.today()
    data = {k: [] for k in SCHEMAS}
    for i in range(1, 17):
        data['workers'].append(dict(id=f'WRK-{i:03}', department=DEPARTMENTS[i % 4], job_role=['Operator','Technician','Miner','Supervisor'][i % 4], shift='Day' if i % 3 else 'Night', ppe_compliance_pct=80 if i % 5 == 0 else 100, training_status='Expired' if i % 7 == 0 else 'Current', fatigue_level=1+i%5, safety_observation='Check fatigue and task controls' if i%5 == 4 else 'Routine safety observation', near_misses=i%3, previous_incidents=i%2, likelihood=1+i%5, consequence=1+(i*2)%5))
    for i in range(1, 25):
        near = i % 4 == 0
        injury = not near and i % 3 == 0
        data['incidents'].append(dict(id=f'INC-{i:03}', date=(today-timedelta(days=i*2)).isoformat(), time='08:30' if i%2 else '21:15', shift='Day' if i%2 else 'Night', location=f'Zone {1+i%4}', department=DEPARTMENTS[i%4], incident_type='Near miss' if near else 'Injury' if injury else 'Unsafe condition', severity=['Low','Medium','High','Critical'][i%4], injury='Yes' if injury else 'No', lost_time_injury='Yes' if injury and i%2 else 'No', cause=['Poor housekeeping','Fatigue','Inadequate guarding','PPE non-compliance'][i%4], corrective_action='Inspect area and review task controls with supervisor.', status=['Open','Investigating','Closed'][i%3]))
    for i, kind in enumerate(SCHEMAS['equipment']['equipment_type'][1], 1):
        data['equipment'].append(dict(id=f'EQP-{i:03}', department=DEPARTMENTS[i%4], equipment_type=kind, manufacturer='Demo manufacturer', operating_hours=float(150+i*10), downtime_hours=float(i*8), temperature_c=float(65+i*6), vibration_mm_s=round(2+i*.95,2), fuel_litres=float(i*30), brake_status='Good' if i<6 else 'Not applicable', tyre_status='Good' if i<6 else 'Not applicable', engine_status='Fault' if i==8 else 'Good', maintenance_status='Under maintenance' if i==7 else 'Scheduled' if i==6 else 'Operational', maintenance_due=(today+timedelta(days=12-i*3)).isoformat(), maintenance_notes='Fictional example. Hours cover one common demonstration period.'))
    for i in range(1, 9):
        data['risks'].append(dict(id=f'RSK-{i:03}', department=DEPARTMENTS[i%4], observation=['Unprotected moving parts','Slippery access route','Fatigued operator','Missing eye protection'][i%4], likelihood=1+i%5, consequence=1+(i*2)%5, control_action='Inspect and implement task-specific controls.', status='Closed' if i==2 else 'Open'))
    return data

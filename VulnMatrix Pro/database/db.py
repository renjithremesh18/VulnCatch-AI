import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vulnmatrix.db')


class Database:
    def __init__(self):
        self.db_path = DB_PATH

    def get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self):
        with self.get_conn() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    modules TEXT NOT NULL,
                    status TEXT DEFAULT 'running',
                    score INTEGER DEFAULT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT NOT NULL,
                    extra TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            conn.commit()

    def create_scan(self, scan_id, target, modules):
        with self.get_conn() as conn:
            conn.execute(
                'INSERT INTO scans (id, target, modules, created_at) VALUES (?, ?, ?, ?)',
                (scan_id, target, json.dumps(modules), datetime.now().isoformat())
            )
            conn.commit()

    def update_scan(self, scan_id, status, score=None):
        with self.get_conn() as conn:
            conn.execute(
                'UPDATE scans SET status=?, score=?, completed_at=? WHERE id=?',
                (status, score, datetime.now().isoformat(), scan_id)
            )
            conn.commit()

    def save_finding(self, scan_id, finding):
        with self.get_conn() as conn:
            extra = {k: v for k, v in finding.items()
                     if k not in ('severity', 'category', 'description')}
            conn.execute(
                'INSERT INTO findings (scan_id, severity, category, description, extra) VALUES (?, ?, ?, ?, ?)',
                (
                    scan_id,
                    finding.get('severity', 'info'),
                    finding.get('category', 'General'),
                    finding.get('description', ''),
                    json.dumps(extra)
                )
            )
            conn.commit()

    def get_all_scans(self):
        with self.get_conn() as conn:
            rows = conn.execute(
                'SELECT id, target, status, score, created_at, completed_at '
                'FROM scans ORDER BY created_at DESC LIMIT 50'
            ).fetchall()
            return [dict(r) for r in rows]

    def get_scan_details(self, scan_id):
        with self.get_conn() as conn:
            scan = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
            if not scan:
                return None
            scan_dict = dict(scan)
            scan_dict['modules'] = json.loads(scan_dict['modules'])

            SEV_ORDER = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
            findings = conn.execute(
                'SELECT severity, category, description, extra FROM findings WHERE scan_id=?',
                (scan_id,)
            ).fetchall()

            scan_dict['findings'] = []
            for f in sorted(findings, key=lambda x: SEV_ORDER.get(x['severity'], 9)):
                fd = dict(f)
                fd['extra'] = json.loads(fd['extra']) if fd.get('extra') else {}
                scan_dict['findings'].append(fd)

            # Severity breakdown
            breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for f in scan_dict['findings']:
                sev = f.get('severity', 'info')
                breakdown[sev] = breakdown.get(sev, 0) + 1
            scan_dict['breakdown'] = breakdown

            return scan_dict

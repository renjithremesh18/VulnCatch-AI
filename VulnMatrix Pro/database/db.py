"""VulnCatch AI Platform — Enhanced Database with full platform models."""
import sqlite3
import json
import os
import hashlib
import secrets
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vulnmatrix.db')


class Database:
    def __init__(self):
        self.db_path = DB_PATH

    def get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        return conn

    def init(self):
        with self.get_conn() as conn:
            # Users table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT DEFAULT '',
                    role TEXT DEFAULT 'analyst',
                    avatar_initials TEXT DEFAULT 'U',
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            # Targets table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    type TEXT DEFAULT 'domain',
                    description TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    added_by INTEGER,
                    created_at TEXT NOT NULL,
                    last_scanned TEXT,
                    last_score INTEGER,
                    scan_count INTEGER DEFAULT 0,
                    FOREIGN KEY (added_by) REFERENCES users(id)
                )
            ''')
            # Scans table (enhanced)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    target_id INTEGER,
                    modules TEXT NOT NULL,
                    status TEXT DEFAULT 'running',
                    scan_type TEXT DEFAULT 'custom',
                    score INTEGER DEFAULT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    duration_sec INTEGER,
                    started_by INTEGER,
                    FOREIGN KEY (target_id) REFERENCES targets(id),
                    FOREIGN KEY (started_by) REFERENCES users(id)
                )
            ''')
            # Findings table (enhanced)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT NOT NULL,
                    cve_id TEXT DEFAULT '',
                    cvss_score REAL DEFAULT 0,
                    exploit_available INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'open',
                    extra TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            # Settings table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            conn.commit()

            # ── Migration: add missing columns to existing tables ────────────
            self._migrate(conn)

            # Create default admin user if none exists
            self._ensure_default_user(conn)

    def _migrate(self, conn):
        """Safely add new columns to existing tables without breaking old data."""
        migrations = [
            # scans table new columns
            ("scans",    "scan_type",          "TEXT DEFAULT 'custom'"),
            ("scans",    "duration_sec",        "INTEGER"),
            ("scans",    "target_id",           "INTEGER"),
            ("scans",    "started_by",          "INTEGER"),
            # findings table new columns
            ("findings", "cve_id",              "TEXT DEFAULT ''"),
            ("findings", "cvss_score",          "REAL DEFAULT 0"),
            ("findings", "exploit_available",   "INTEGER DEFAULT 0"),
            ("findings", "status",              "TEXT DEFAULT 'open'"),
            ("findings", "created_at",          "TEXT NOT NULL DEFAULT ''"),
        ]
        for table, column, col_def in migrations:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
                conn.commit()
            except Exception:
                # Column already exists — ignore
                pass

    def _ensure_default_user(self, conn):
        existing = conn.execute('SELECT id FROM users LIMIT 1').fetchone()
        if not existing:
            pw_hash = self._hash_password('admin123')
            conn.execute(
                'INSERT INTO users (email, password_hash, full_name, role, avatar_initials, created_at) VALUES (?,?,?,?,?,?)',
                ('admin@vulncatch.ai', pw_hash, 'Admin User', 'admin', 'AU', datetime.now().isoformat())
            )
            conn.commit()

    def _hash_password(self, password: str) -> str:
        salt = 'vulncatch_salt_2024'
        return hashlib.sha256(f'{salt}{password}'.encode()).hexdigest()

    def verify_password(self, password: str, hash_: str) -> bool:
        return self._hash_password(password) == hash_

    # ── Auth ─────────────────────────────────────────────────────────────────
    def login(self, email: str, password: str):
        with self.get_conn() as conn:
            user = conn.execute('SELECT * FROM users WHERE email=? AND is_active=1', (email,)).fetchone()
            if not user: return None
            if not self.verify_password(password, user['password_hash']): return None
            conn.execute('UPDATE users SET last_login=? WHERE id=?', (datetime.now().isoformat(), user['id']))
            conn.commit()
            return dict(user)

    def get_user(self, user_id: int):
        with self.get_conn() as conn:
            u = conn.execute('SELECT id,email,full_name,role,avatar_initials,created_at,last_login FROM users WHERE id=?', (user_id,)).fetchone()
            return dict(u) if u else None

    def update_profile(self, user_id, full_name, email):
        with self.get_conn() as conn:
            conn.execute('UPDATE users SET full_name=?, email=? WHERE id=?', (full_name, email, user_id))
            conn.commit()

    def update_password(self, user_id, new_password):
        with self.get_conn() as conn:
            h = self._hash_password(new_password)
            conn.execute('UPDATE users SET password_hash=? WHERE id=?', (h, user_id))
            conn.commit()

    # ── Targets ──────────────────────────────────────────────────────────────
    def get_all_targets(self):
        with self.get_conn() as conn:
            rows = conn.execute('SELECT * FROM targets ORDER BY created_at DESC').fetchall()
            return [dict(r) for r in rows]

    def add_target(self, name, host, type_='domain', description='', tags=None):
        with self.get_conn() as conn:
            conn.execute(
                'INSERT INTO targets (name, host, type, description, tags, created_at) VALUES (?,?,?,?,?,?)',
                (name, host, type_, description, json.dumps(tags or []), datetime.now().isoformat())
            )
            conn.commit()

    def delete_target(self, target_id):
        with self.get_conn() as conn:
            conn.execute('DELETE FROM targets WHERE id=?', (target_id,))
            conn.commit()

    def update_target_scan_info(self, host, score):
        with self.get_conn() as conn:
            conn.execute(
                'UPDATE targets SET last_scanned=?, last_score=?, scan_count=scan_count+1 WHERE host=?',
                (datetime.now().isoformat(), score, host)
            )
            conn.commit()

    # ── Scans ────────────────────────────────────────────────────────────────
    def create_scan(self, scan_id, target, modules, scan_type='custom'):
        with self.get_conn() as conn:
            conn.execute(
                'INSERT INTO scans (id, target, modules, scan_type, created_at) VALUES (?,?,?,?,?)',
                (scan_id, target, json.dumps(modules), scan_type, datetime.now().isoformat())
            )
            conn.commit()

    def update_scan(self, scan_id, status, score=None):
        with self.get_conn() as conn:
            completed = datetime.now().isoformat()
            # Calculate duration
            scan = conn.execute('SELECT created_at FROM scans WHERE id=?', (scan_id,)).fetchone()
            duration = None
            if scan:
                try:
                    start = datetime.fromisoformat(scan['created_at'])
                    duration = int((datetime.now() - start).total_seconds())
                except Exception:
                    pass
            conn.execute(
                'UPDATE scans SET status=?, score=?, completed_at=?, duration_sec=? WHERE id=?',
                (status, score, completed, duration, scan_id)
            )
            conn.commit()

    def get_all_scans(self):
        with self.get_conn() as conn:
            rows = conn.execute(
                'SELECT id, target, status, score, scan_type, created_at, completed_at, duration_sec '
                'FROM scans ORDER BY created_at DESC LIMIT 100'
            ).fetchall()
            return [dict(r) for r in rows]

    def get_scan_details(self, scan_id):
        with self.get_conn() as conn:
            scan = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
            if not scan: return None
            scan_dict = dict(scan)
            try: scan_dict['modules'] = json.loads(scan_dict['modules'])
            except: scan_dict['modules'] = []

            SEV_ORDER = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
            findings = conn.execute(
                'SELECT id, severity, category, description, cve_id, cvss_score, exploit_available, status, extra, created_at FROM findings WHERE scan_id=?',
                (scan_id,)
            ).fetchall()

            scan_dict['findings'] = []
            for f in sorted(findings, key=lambda x: SEV_ORDER.get(x['severity'], 9)):
                fd = dict(f)
                try: fd['extra'] = json.loads(fd['extra']) if fd.get('extra') else {}
                except: fd['extra'] = {}
                scan_dict['findings'].append(fd)

            breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for f in scan_dict['findings']:
                sev = f.get('severity', 'info')
                breakdown[sev] = breakdown.get(sev, 0) + 1
            scan_dict['breakdown'] = breakdown
            return scan_dict

    # ── Findings ─────────────────────────────────────────────────────────────
    def save_finding(self, scan_id, finding):
        with self.get_conn() as conn:
            extra = {k: v for k, v in finding.items()
                     if k not in ('severity', 'category', 'description', 'cve_id', 'cvss_score')}
            conn.execute(
                'INSERT INTO findings (scan_id, severity, category, description, cve_id, cvss_score, extra, created_at) VALUES (?,?,?,?,?,?,?,?)',
                (
                    scan_id,
                    finding.get('severity', 'info'),
                    finding.get('category', 'General'),
                    finding.get('description', ''),
                    finding.get('cve_id', ''),
                    finding.get('cvss_score', 0),
                    json.dumps(extra),
                    datetime.now().isoformat(),
                )
            )
            conn.commit()

    def get_all_findings(self, limit=200):
        with self.get_conn() as conn:
            rows = conn.execute(
                '''SELECT f.id, f.severity, f.category, f.description, f.cve_id, f.cvss_score,
                          f.exploit_available, f.status, f.created_at, s.target
                   FROM findings f JOIN scans s ON f.scan_id = s.id
                   ORDER BY f.created_at DESC LIMIT ?''',
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_dashboard_stats(self):
        with self.get_conn() as conn:
            total_scans    = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
            total_targets  = conn.execute('SELECT COUNT(*) FROM targets').fetchone()[0]
            total_findings = conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
            critical       = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical'").fetchone()[0]
            high           = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='high'").fetchone()[0]
            medium         = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='medium'").fetchone()[0]
            low            = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='low'").fetchone()[0]
            open_f         = conn.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0]
            resolved_f     = conn.execute("SELECT COUNT(*) FROM findings WHERE status='resolved'").fetchone()[0]
            # Average score of last 10 scans
            scores = conn.execute("SELECT score FROM scans WHERE score IS NOT NULL ORDER BY created_at DESC LIMIT 10").fetchall()
            avg_score = int(sum(r[0] for r in scores) / len(scores)) if scores else 0
            # Recent scans
            recent_scans = conn.execute(
                'SELECT id, target, status, score, scan_type, created_at, duration_sec FROM scans ORDER BY created_at DESC LIMIT 5'
            ).fetchall()
            # Recent findings
            recent_findings = conn.execute(
                '''SELECT f.severity, f.category, f.description, s.target, f.created_at
                   FROM findings f JOIN scans s ON f.scan_id=s.id
                   ORDER BY f.created_at DESC LIMIT 10'''
            ).fetchall()
            # Severity trend (last 7 scans)
            trend_scans = conn.execute(
                "SELECT id, target, score, created_at FROM scans WHERE score IS NOT NULL ORDER BY created_at DESC LIMIT 7"
            ).fetchall()
            return {
                'total_scans': total_scans, 'total_targets': total_targets,
                'total_findings': total_findings, 'critical': critical,
                'high': high, 'medium': medium, 'low': low,
                'open': open_f, 'resolved': resolved_f,
                'security_score': avg_score,
                'recent_scans': [dict(r) for r in recent_scans],
                'recent_findings': [dict(r) for r in recent_findings],
                'trend_scans': [dict(r) for r in reversed(trend_scans)],
            }

    # ── Settings ─────────────────────────────────────────────────────────────
    def get_setting(self, key, default=''):
        with self.get_conn() as conn:
            row = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
            return row['value'] if row else default

    def set_setting(self, key, value):
        with self.get_conn() as conn:
            conn.execute(
                'INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?,?,?)',
                (key, value, datetime.now().isoformat())
            )
            conn.commit()

    def get_all_settings(self):
        with self.get_conn() as conn:
            rows = conn.execute('SELECT key, value FROM settings').fetchall()
            return {r['key']: r['value'] for r in rows}

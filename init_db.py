import sqlite3

connection = sqlite3.connect("database.db")

connection.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    college_id TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

connection.execute("""
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    incident_type TEXT NOT NULL,
    description TEXT NOT NULL,
    incident_date TEXT,
    location TEXT,
    clicked_link INTEGER DEFAULT 0,
    credentials_entered INTEGER DEFAULT 0,
    priority TEXT DEFAULT 'LOW',
    status TEXT DEFAULT 'SUBMITTED',
    assigned_to INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")

connection.execute("""
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_type TEXT,
    file_size INTEGER,
    file_hash TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (incident_id) REFERENCES incidents(id)
)
""")

connection.execute("""
CREATE TABLE IF NOT EXISTS case_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (incident_id) REFERENCES incidents(id),
    FOREIGN KEY (admin_id) REFERENCES users(id)
)
""")

connection.execute("""
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    incident_id INTEGER,
    action TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
)
""")

connection.execute("""
CREATE TABLE IF NOT EXISTS internal_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    note TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (incident_id) REFERENCES incidents(id),
    FOREIGN KEY (admin_id) REFERENCES users(id)
)
""")

connection.commit()
connection.close()

print("Database initialized successfully!")
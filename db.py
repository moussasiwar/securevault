import sqlite3

DB_PATH = "securevault.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with open("schema.sql", encoding="utf-8") as f:
        conn = get_db()
        conn.executescript(f.read())
        conn.commit()
        conn.close()

if __name__ == "__main__":
    init_db()
    print("Base initialisee.")
import sqlite3 as sql
import bcrypt
from flask import g, current_app


def newUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    try:
        cur.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed)
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False


def getUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE email = ?", (email,))
    result = cur.fetchone()
    con.close()
    if result is None:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), result[0])


def get_db():
    if "db" not in g:
        db_path = current_app.config.get["DATABASE"]
        g.db = sql.connect(db_path)
        g.db.row_factory = sql.Row
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def getLogs():
    db = get_db()
    cur = db.execute("SELECT * FROM logs ORDER BY created DESC")
    rows = cur.fetchall()
    return [dict(r) for r in rows]


# def getUsers():
#     con = sql.connect("databaseFiles/database.db")
#     cur = con.cursor()
#     cur.execute("SELECT * FROM id7-tusers")
#     con.close()
#     return cur

import sqlite3


def search_users(query):
    # VULNERABLE: direct string interpolation — SQL injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    return cursor.fetchall()


def safe_search_users(query):
    # SAFE: parameterized query — protected against SQL injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (query,))
    return cursor.fetchall()


def get_user_by_id(user_id):
    # VULNERABLE: integer injection possible
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
    return cursor.fetchone()


def delete_user(username):
    # VULNERABLE: deletion without parameterization
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE name = '{username}'")
    conn.commit()

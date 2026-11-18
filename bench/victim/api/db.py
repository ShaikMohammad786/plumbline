import sqlite3

conn = sqlite3.connect(":memory:")
cursor = conn.cursor()


def get_user_by_name(username: str):
    # Planted: SEC003 SQL injection via f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return cursor.execute(query).fetchall()


def get_item_by_name(item_name: str):
    # Planted: SEC003 SQL injection via %-formatting
    return cursor.execute("SELECT * FROM items WHERE name = '%s'" % item_name).fetchall()


# --- DECOYS ---

def get_product_safe(product_id: int):
    # Decoy: Safe parameterized SQL query with placeholder
    return cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()


def get_orders_by_user_safe(user_id: int):
    # Decoy: Safe parameterized query
    return cursor.execute("SELECT * FROM orders WHERE user_id = :uid", {"uid": user_id}).fetchall()

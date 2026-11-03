import sqlite3


def get_db_connection():
    connection = sqlite3.connect("database.db")
    connection.row_factory = sqlite3.Row

    # Enable foreign key support
    connection.execute("PRAGMA foreign_keys = ON")

    return connection



def current_user_is_admin(user_id):
    """Check the user's current role in the database."""
    if user_id is None:
        return False

    connection = get_db_connection()
    try:
        user = connection.execute(
            "SELECT role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        return user is not None and user["role"] == "admin"
    finally:
        connection.close()


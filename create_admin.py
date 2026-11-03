import getpass
import sqlite3

from werkzeug.security import generate_password_hash

MIN_PASSWORD_LENGTH = 12   # same rule as the registration form

name = input("Admin name [Security Administrator]: ").strip() or "Security Administrator"
college_id = input("Admin ID [ADMIN001]: ").strip() or "ADMIN001"
email = input("Admin email: ").strip()

if "@" not in email:
    raise SystemExit("Please enter a valid email address.")


password = getpass.getpass(f"Password (at least {MIN_PASSWORD_LENGTH} characters): ")
if len(password) < MIN_PASSWORD_LENGTH:
      raise SystemExit(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
if password != getpass.getpass("Repeat password: "):
    raise SystemExit("Passwords do not match.")

password_hash = generate_password_hash(password)
connection = sqlite3.connect("database.db")

try:
    existing = connection.execute(
         "SELECT id FROM users WHERE email = ?", (email,)
         ).fetchone()

    if existing:
        answer = input("That email already exists. Reset its password and make it admin? [y/N]: ")
        
        if answer.strip().lower() != "y":
            raise SystemExit("No changes made.")
        
        connection.execute(
             "UPDATE users SET password_hash = ?, role = 'admin' WHERE id = ?",
             (password_hash, existing[0]),
             )
        
        print("Administrator password reset.")
        
    else:
        connection.execute(
               "INSERT INTO users (name, college_id, email, password_hash, role) "
               "VALUES (?, ?, ?, ?, 'admin')",
               (name, college_id, email, password_hash),
           )
        print("Administrator account created.")
        
        connection.commit()

except sqlite3.IntegrityError:
       raise SystemExit("That admin ID or email is already used by another account.")

finally:
       connection.close()
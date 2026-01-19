"""
auth.py - User Authentication Module for Nirikshan

I built this module to handle all user authentication for my GRC platform.
It uses MySQL to store user accounts and Werkzeug for secure password hashing.

Author: Me
Project: Nirikshan (Final Year Project)
"""

import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash

# Database connection settings - you'll need to update these for your setup
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "admin",
    "password": "mysql@toor",  
    "database": "auditor",
    "auth_plugin": "mysql_native_password"
}

def get_connection():
    """Creates and returns a connection to my MySQL database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print("Database connection error:", e)
        return None


# =============================================================================
# User Registration
# =============================================================================
def create_user(username: str, password: str, role: str = "Staff"):
    """
    Registers a new user in the system.
    I use Werkzeug's password hashing to store passwords securely - never store plain text!
    """
    if not username or not password:
        return {"success": False, "message": "Username and password required"}

    # Hash the password before storing it
    hashed_password = generate_password_hash(password)

    conn = get_connection()
    if conn is None:
        return {"success": False, "message": "Database connection failed"}

    try:
        with conn.cursor() as cur:
            # First check if username is already taken
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                return {"success": False, "message": "Username already exists"}

            # Create the new user account
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username, hashed_password, role)
            )
            conn.commit()

        return {"success": True, "message": "Account created successfully"}

    except Exception as e:
        return {"success": False, "message": f"Database error: {e}"}

    finally:
        conn.close()


# =============================================================================
# Login Validation
# =============================================================================
def validate_login(username: str, password: str, role: str = None) -> bool:
    """
    Checks if the username and password are correct.
    Can also verify the user has a specific role if needed.
    """
    conn = get_connection()
    if conn is None:
        return False

    try:
        with conn.cursor(dictionary=True) as cur:
            cur.execute(
                "SELECT username, password_hash, role FROM users WHERE username = %s",
                (username,)
            )
            user = cur.fetchone()
            if not user:
                return False

            # Verify the password against the stored hash
            if not check_password_hash(user["password_hash"], password):
                return False

            # If a specific role is required, check that too
            if role and role != user["role"]:
                return False

            return True

    except Exception:
        return False

    finally:
        conn.close()


# =============================================================================
# Get All Users (for admin dashboard)
# =============================================================================
def get_all_users():
    """Returns a list of all registered users for the admin panel."""
    conn = get_connection()
    if conn is None:
        return []

    try:
        with conn.cursor(dictionary=True) as cur:
            cur.execute("SELECT username, role, created_at FROM users ORDER BY created_at DESC")
            return cur.fetchall()

    finally:
        conn.close()


# =============================================================================
# Delete User Account
# =============================================================================
def delete_user(username: str):
    """Removes a user account from the system."""
    conn = get_connection()
    if conn is None:
        return {"success": False, "message": "Database connection failed"}

    try:
        with conn.cursor() as cur:
            # Make sure the user exists before trying to delete
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if not cur.fetchone():
                return {"success": False, "message": "User does not exist"}

            cur.execute("DELETE FROM users WHERE username = %s", (username,))
            conn.commit()
            return {"success": True, "message": "User deleted successfully"}

    except Exception as e:
        return {"success": False, "message": f"Database error: {e}"}

    finally:
        conn.close()

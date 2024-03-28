import sqlite3
import hashlib
import os
import binascii

class PasswordHasher:
    """
    Class for managing passwords in SQLite database.

    Args:
        database_name (str, optional): Name of the SQLite database file. Defaults to 'passwords.db'.

    Attributes:
        conn (sqlite3.Connection): Object representing the connection to the SQLite database.
        cursor (sqlite3.Cursor): Object representing the cursor for executing SQL commands.
    """
    def __init__(self, database_name='passwords.db'):
        """
        Initializes the PasswordManager object.

        Args:
            database_name (str, optional): Name of the SQLite database file. Defaults to 'passwords.db'.
        """
        self.conn = sqlite3.connect(database_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY AUTOINCREMENT,
                            password_hash TEXT NOT NULL, salt TEXT NOT NULL)''')
        self.conn.commit()

    def hash_password(self, password, salt=""):
        """
        Hashes the password using PBKDF2-HMAC-SHA256 algorithm.

        Args:
            password (str): Password to hash.
            salt (str, optional): Salt used for hashing. Random salt is generated if not provided.

        Returns:
            tuple: A tuple containing the hashed password and the salt used.
        """
        if salt == "":
            salt = os.urandom(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return password_hash, salt

    def insert_password(self, password):
        """
        Inserts the hashed password into the database.

        Args:
            password (str): Password to insert.
        """
        password_hash, salt = self.hash_password(password)
        self.cursor.execute('''INSERT INTO passwords (password_hash, salt) VALUES (?, ?)''',
                        (password_hash.hex(), salt.hex()))
        self.conn.commit()

    def verify_password(self, id, password):
        """
        Verifies if the provided password is correct for the given ID.

        Args:
            id (int): ID of the password in the database.
            password (str): Password to verify.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        self.cursor.execute('''SELECT password_hash, salt FROM passwords WHERE id = ?''', (id,))
        row = self.cursor.fetchone()
        if row:
            stored_password_hash = bytes.fromhex(row[0])
            salt = bytes.fromhex(row[1])
            entered_password_hash, dump = self.hash_password(password, salt)
            if entered_password_hash == stored_password_hash:
                return True
        return False

    def close_connection(self):
        """
        Closes the connection to the database.
        """
        self.conn.close()

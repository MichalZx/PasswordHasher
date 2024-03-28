import sqlite3
import hashlib
import os
import binascii

def connect_database(database_name='passwords.db'):
    """
    Connects to the SQLite database with the specified name or creates a new one if it doesn't exist.

    Args:
        database_name (str, optional): The name of the SQLite database. Defaults to 'passwords.db'.

    Returns:
        sqlite3.Connection: A connection object representing the database connection.
    """
    conn = sqlite3.connect(database_name)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT NOT NULL, salt TEXT NOT NULL)''')
    conn.commit()
    return conn

def hash_password(password, salt):
    """
    Hashes the password using a given salt.

    Args:
        password (str): The password to be hashed.
        salt (str): The salt used for hashing the password.

    Returns:
        tuple: A tuple containing the final hashed password and the salt used.
    """
    if salt == "":
        salt = os.urandom(32)
    password_hash0 = hashlib.sha256(password.encode() + salt).hexdigest()
    password_hash1 = hashlib.sha256(password_hash0.encode() + salt + password.encode()).hexdigest()
    final_hash = hashlib.sha256(password_hash0.encode() + password_hash1.encode()).hexdigest()
    return final_hash, salt

def insert_password(hash, salt):
    """
    Inserts the hashed password and its corresponding salt into the database.

    Args:
        hash (str): The hashed password to be inserted.
        salt (str): The salt used for hashing the password.
    """
    cursor.execute('''INSERT INTO passwords (password_hash, salt) VALUES (?, ?)''',
                   (hash, binascii.hexlify(salt).decode()))
    conn.commit()

def verify_password(id, password):
    """
    Verifies if the provided password matches the stored hashed password for the given ID.

    Args:
        id (int): The ID corresponding to the password to be verified.
        password (str): The password to be verified.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    cursor.execute('''SELECT password_hash, salt FROM passwords WHERE id = ?''', (id,))
    row = cursor.fetchone()
    if row:
        stored_password_hash = row[0]
        salt = binascii.unhexlify(row[1])
        entered_password_hash, dump = hash_password(password, salt)
        if entered_password_hash == stored_password_hash:
            return True
    return False

if __name__ == "__main__":
    conn = connect_database()
    cursor = conn.cursor()

    password = input("Input password: ")
    password2 = input("Input password again: ")
    if password2 == password:
        hash, salt = hash_password(password, "")
        insert_password(hash, salt)
    else:
        print("Passwords do not match!")
    try:
        id = int(input("Input ID: "))
        pass_check = input("Input password: ")
        if verify_password(id, pass_check):
            print("Password is correct")
        else:
            print("Password is not correct")
    except ValueError:
        print("Input is not a number!")

    conn.close()

# Creates a root account with a random password. Can also be used to reset the root password.
# If the database does not exist it is created too

import bcrypt
import sqlite3
import secrets
import sys
import os.path
from os import path
import collections
from config import *

if not path.exists(DATABASE):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    query = open('schema.sql', 'r')
    c.executescript(query.read())
    conn.commit()
    query.close()
    print("Initialized database")
else:
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

admin_username = 'nick'

"""
Returns a named tuple containing a clear-text password and the corresponding bcrypt hash.
"""
Pass = collections.namedtuple('Pass', ['text', 'hash'])
def random_password(length=16):
    p = secrets.token_urlsafe(length).encode('utf-8')
    hashed = bcrypt.hashpw(p, bcrypt.gensalt())
    return Pass(p.decode(), hashed)


#Check if the root account already exists
c.execute("SELECT * FROM users WHERE username=?", (admin_username,))

if(c.fetchone() != None):
    # root user exists
    print("Admin user '" + admin_username + "' already exists.")
    input = input("Would you like to overwrite this user? (yes/no): ")
    if(input != 'yes'):
        print("Goodbye")
        conn.close()
        sys.exit()
    else:
        #Update the db
        new_pass = random_password()
        c.execute("UPDATE users SET password=? WHERE username=?", (new_pass.hash,admin_username))
        conn.commit()
        print("PLEASE SAVE THE FOLLOWING INFORMATION!")
        print("Username:    "+admin_username)
        print("Password:    " + new_pass.text)
else:
    # root user does not exist
    password = random_password()
    c.execute('INSERT INTO users (username, password, display_name, permissions_level) VALUES (?, ?, ?, "1");', (admin_username, password.hash, admin_username))
    conn.commit()
    print("PLEASE SAVE THE FOLLOWING INFORMATION!")
    print("Username:    " + admin_username)
    print("Password:    " + password.text)

conn.close()

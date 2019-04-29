# Creates a root account with a random password. Can also be used to reset the root password. 

import bcrypt
import sqlite3
import random
import sys
import collections
from config import *

conn = sqlite3.connect(DATABASE)
c = conn.cursor()

"""
Returns a named tuple containing a clear-text password and the corresponding bcrypt hash.
"""
Pass = collections.namedtuple('Pass', ['text', 'hash'])
def random_password(length=16):
    s = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?"
    p = "".join(random.sample(s,length)).encode('utf-8')
    hashed = bcrypt.hashpw(p, bcrypt.gensalt())
    return Pass(p.decode(), hashed)


#Check if the root account already exists
c.execute('SELECT * FROM users WHERE username="root";')

if(c.fetchone() != None):
    # root user exists
    print("Root user already exists.")
    input = input("Would you like to overwrite this user? (yes/no): ")
    if(input != 'yes'):
        print("Goodbye")
        conn.close()
        sys.exit()
    else:
        #Update the db
        new_pass = random_password()
        c.execute("UPDATE users SET password=? WHERE username='root';", (new_pass.hash,))
        conn.commit()
        print("PLEASE SAVE THE FOLLOWING INFORMATION!")
        print("Username:    root")
        print("Password:    " + new_pass.text)
else:
    # root user does not exist
    password = random_password()
    c.execute('INSERT INTO users (username, password, display_name, permissions_level) VALUES ("root", ?, "root", "3");', (password.hash,))
    conn.commit()
    print("PLEASE SAVE THE FOLLOWING INFORMATION!")
    print("Username:    root")
    print("Password:    " + password.text)

conn.close()

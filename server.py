from flask import Flask, session, request, render_template, redirect, url_for, g
import bcrypt
import sqlite3
import os
import gnupg
from datetime import datetime
from pprint import pprint
from verifyPackage import download
import requests
import json
import time
from config import *
from utilities import *

# Please note, this application most likely has security issues and should
# not be assumed to be secure in its current state.

app = Flask(__name__)
if PRODUCTION:
    app.config['SECRET_KEY'] = os.urandom(24)
else:
    app.config['SECRET_KEY'] = 'gNYGBERDFGeurfh98re6xhdfjvdnkusxfhiuy'
app.debug = True

# Print Timestamps
#https://stackoverflow.com/a/28673279
#https://stackoverflow.com/a/3682808
@app.template_filter('ctime')
def timectime(s):
    try:
        return datetime.utcfromtimestamp(int(s)).strftime('%m-%d-%Y')
    except Exception as e:
        return "Never"

# Global database getter
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # g._database.set_trace_callback(print)
    return db

# Global gpg getter
def get_gpg():
    gpg = getattr(g, '_gpg', None)
    if gpg is None:
        gpg = g._gpg = gnupg.GPG(gnupghome=GPG_home)
    return gpg

# Web Login
@app.route('/login', methods=['POST', 'GET'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        if(username != '' and password != ''):
            c = get_db().cursor()

            user = (username,)
            c.execute('SELECT * FROM users WHERE username=?;', user)
            result = c.fetchone()

            # Check password anyways for security reasons
            if(result):
                if bcrypt.checkpw(password, result[2]):
                    session['username'] = result[1]
                    session['user_id'] = result[0]
                    session['permissions_level'] = result[4]
                else:
                    error = 'Invalid credentials'
            else:
                # Dummy check for timing reasons
                hash = b'$2a$12$XNJU.L80D1lQ8jt5tSPwm.E6Wa8IC7WkSiJG5ukci9nsXNeUs32aS'
                password = 'dummyValue'.encode('utf-8')
                bcrypt.checkpw(password, hash)
                error = 'Invalid credentials'

        else:
            return "Please enter a username and password"
    if(session.get('username')):
        return redirect(url_for('dashboard'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    if session.get('username'):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM lookup_history ORDER BY id DESC LIMIT 10;")
        rows = c.fetchall()
        return render_template('index.html', username=session.get('username'), lookup_history=rows)
    else:
        return redirect(url_for('login'))

@app.route('/keys', methods=['POST', 'GET'])
def keys():
    if request.method == 'GET':
        if session.get('username'):
            # User should be logged in
            return render_template('keys.html', username=session.get('username'), keys=get_gpg().list_keys())
        else:
            return redirect(url_for('login'))

@app.route('/application_keys', methods=['POST', 'GET'])
def application_keys():
    error = ""
    if request.method == 'GET':
        if session.get('username'):
            # User should be logged in
            user_id = session.get('user_id', None)
            if user_id is not None:
                c = get_db().cursor()
                # Be careful about changing this. It affects api_keys.html
                c.execute('SELECT applications.id, applications.name, users.display_name, users.permissions_level, users.id, applications.api_key FROM applications INNER JOIN users on applications.owner_id=users.id;')
                rows = c.fetchall()
            return render_template('api_keys.html', username=session.get('username'), permissions_level=session.get('permissions_level'), applications=rows, user_id=user_id)
        else:
            return redirect(url_for('login'))
    if request.method == 'POST':
        if session.get('username'):
            user_id = session.get('user_id', None)
            app_name = request.form.get('app_name')
            if user_id is not None:
                c = get_db().cursor()
                try:
                    c.execute('INSERT INTO applications (name, owner_id, api_key) VALUES (?, ?, ?);', (app_name, user_id, generate_api_key()))
                    print("Inserting " + app_name)
                    get_db().commit()
                except sqlite3.IntegrityError as e:
                    print("An error occurred:", e.args[0])
                    error = "An application with that name already exists"

            # Now act like a get request
            ser_id = session.get('user_id', None)
            if user_id is not None:
                c = get_db().cursor()
                # Be careful about changing this. It affects api_keys.html
                c.execute('SELECT applications.id, applications.name, users.display_name, users.permissions_level, users.id, applications.api_key FROM applications INNER JOIN users on applications.owner_id=users.id;')
                rows = c.fetchall()
            return render_template('api_keys.html', username=session.get('username'), permissions_level=session.get('permissions_level'), applications=rows, user_id=user_id, error=error)

@app.route('/deleteApp', methods=['POST'])
def deleteApp():
    if session.get('username'):
        app_id = request.form.get('app_id')
        user_id = session['user_id']
        permissions_level = session['permissions_level']

        c = get_db().cursor()
        c.execute('DELETE FROM applications \
            WHERE id IN (SELECT applications.id FROM users \
            INNER JOIN applications ON applications.owner_id=users.id \
            WHERE (users.permissions_level >= ? OR owner_id=?) \
            AND applications.id=?);', (permissions_level, user_id, app_id))
        get_db().commit()

        return redirect(url_for('application_keys'))


@app.route('/checkPackage', methods=['POST', 'GET'])
def checkPackage():
    error = ""
    result = {}
    if request.method == 'GET':
        if session.get('username'):
            # User should be logged in
            return render_template('checkPackage.html', username=session.get('username'))
        else:
            return redirect(url_for('login'))
    if request.method == 'POST':
        if session.get('username'):
            # User should be logged in
            package_name = request.form.get('packageName')

            r = requests.get(URL + package_name + '/json/')

            if(r.status_code == 200):
                data = json.loads(r.text)
                num_releases = len(data['releases'])
                latest_version = data['info']['version']

                if data['releases'][latest_version][0]['has_sig'] == True:
                    result = download(data['releases'][latest_version][0]['url'], latest_version)
                else:
                    result['error'] = "Package has no signature"

            elif(r.status_code == 404):
                error = ("Package not found")
            else:
                error = ("Something went wrong")

            if result.get('error'):
                lookup_result = result['error']
            else:
                lookup_result = result.get('verified_status')

            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO lookup_history (package_name, package_version, username, timestamp, result) VALUES (?,?,?,?,?)", (package_name, latest_version, session.get('username'), int(time.time()), lookup_result))
            conn.commit()

            return render_template('checkPackage.html', username=session.get('username'), error=error, result=result, name=package_name)
        else:
            return redirect(url_for('login'))

@app.route('/uploadKey', methods=['POST', 'GET'])
def uploadKey():
    error = None
    info = None
    if request.method == 'GET':
        if session.get('username'):
            # User should be logged in
            return render_template('addKey.html', username=session.get('username'))
        else:
            return redirect(url_for('login'))
    elif request.method == 'POST':
        if session.get('username'):
            data = request.form.get('pubkey')
            if(data is not ""):
                result = get_gpg().import_keys(data)
                if result.imported == 0:
                    error = result.results[0]['text']
                elif result.imported == 1:
                    short_id = result.fingerprints[0][-16:]
                    info = "Imported " + short_id
            else:
                error = "Please input a PGP public key"
            return render_template('addKey.html', username=session.get('username'), error=error, info=info)
        else:
            return redirect(url_for('login'))

@app.route('/deleteKey', methods=['POST'])
def deleteKey():
    if session.get('username'):
        keyID = request.form.get('keyID')
        result = str(get_gpg().delete_keys(keyID))
        print(result)

        return redirect(url_for('keys'))

# /verify/<name>/<version>
# API call to check a package
# Version is optional and defaults to the most recent
# X-Auth-Token should be set to an API key and is a required header
@app.route('/api/verify/<name>', defaults={'version': None})
@app.route('/api/verify/<name>/<version>', methods=['GET'])
def verify(name, version):
    result = {}
    if request.headers.get('X-Auth-Token'):
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM applications WHERE api_key=?', (request.headers.get('X-Auth-Token'),))
        row = c.fetchone()

        if row is not None:
            # Requestor information
            app_id = row[0]
            app_name = row[1]

            package_name = name
            r = requests.get(URL + package_name + '/json/')

            if(r.status_code == 200):
                data = json.loads(r.text)
                latest_version = data['info']['version']

                # If no version passed use most recent
                if version == None:
                    version = latest_version

                if data['releases'].get(version) == None:
                    result['error'] = "Version not found"
                else:
                    if data['releases'][version][0]['has_sig'] == True:
                        result = download(data['releases'][version][0]['url'], version)
                        result['version'] = version
                        result['latest_version'] = latest_version
                    else:
                        result['error'] = "Package has no signature"

            elif(r.status_code == 404):
                result['error'] = "Package not found"
            else:
                result['error'] = "Something went wrong"

            if result.get('error'):
                lookup_result = result['error']
            else:
                lookup_result = result.get('verified_status')

            c.execute("INSERT INTO lookup_history (package_name, package_version, app_name, timestamp, result) VALUES (?,?,?,?,?)", (package_name, version, app_name, int(time.time()), lookup_result))
            conn.commit()
            return json.dumps(result)
        else:
            result['error'] = "auth_error"
            return json.dumps(result)
    else:
        result['error'] = "auth_error"
        return json.dumps(result)


if __name__ == '__main__':
    app.run(debug=True)

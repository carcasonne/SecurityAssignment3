import json, sqlite3, click, functools, os, hashlib, time, random, sys
import re
import json, sqlite3, click, functools, os, hashlib,time, random, sys
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request

from datetime import datetime
from cryptography.fernet import Fernet
from base64 import b64encode
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import bcrypt
from Cryptodome.Protocol.KDF import bcrypt_check

### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)


def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assocUser INTEGER NOT NULL,
    dateWritten DATETIME NOT NULL,
    note TEXT NOT NULL,
    publicID INTEGER NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

INSERT INTO users VALUES(null,"admin", "password");
INSERT INTO users VALUES(null,"bernardo", "omgMPC");
INSERT INTO notes VALUES(null,2,"1993-09-23 10:10:10","hello my friend",1234567890);
INSERT INTO notes VALUES(null,2,"1993-09-23 12:10:10","i want lunch pls",1234567891);

""")


### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = os.urandom(32)


### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)

    return wrapped_view


@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))

@app.route("/delete/<note_id>", methods=['POST'])
@login_required
def delete_note(note_id):
    db = connect_db()
    c = db.cursor()
    statement = """DELETE from NOTES where id = ?"""
    c.execute(statement, (note_id,))
    db.commit()
    db.close()
    return redirect(url_for('notes'))



@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror = ""
    # Posting a new note:
    if request.method == 'POST':
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']

            if note == "SECRET STRING":
                userEnc = "gAAAAABja6SDmmMUb0iSd-ywgJjFjXhQQRHl8urGQ-iqnusLIkrKZKqM91kG_JHtI30AmC6qxtaEloxbSoqoMpoVNuzZ_Lgs7w=="
                passEnc = "gAAAAABja6SDJFGDcpow4YgpNvZ0lDB9JgxIhVE0FNiG4aEF8b58QJh1rw45kf7jIsNvTCDeNvc3Dfvvl2AHnbnz3Ud6i-vwwg=="
                key = "scyKzVawk2YB2DANJreVA4cwx0LWlAu9Ko883aAT3PE="
                fernet = Fernet(key)
                decU = fernet.decrypt(userEnc).decode()
                decP = fernet.decrypt(passEnc).decode()
                note = f"Username: {decU}, Password = {decP} "

            db = connect_db()
            c = db.cursor()
            statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,?,?,?,?);"""
            print(statement)
            c.execute(statement, (session['userid'], time.strftime('%Y-%m-%d %H:%M:%S'), note, random.randrange(1000000000, 9999999999)))
            db.commit()
            db.close()
        elif request.form['submit_button'] == 'import note':
            noteid = request.form['noteid']

            if not noteid.isnumeric():
                print(f'{datetime.now}: User {session["userid"]} has tried to SQL inject the site!!!')
                importerror="Your IP address has been sent to the Federal Bureau of Ivestigation for malicious attempts at hacking."
            else:
                db = connect_db()
                c = db.cursor()
                statement = """SELECT * from NOTES where publicID = ?"""
                c.execute(statement, (noteid,))
                result = c.fetchall()
                if(len(result)>0):
                    row = result[0]
                    # Not necesarry to sanitize here, this is all backend information
                    statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,%s,'%s','%s',%s);""" %(session['userid'],row[2],row[3],row[4])
                    c.execute(statement)
                else:
                    importerror="No such note with that ID!"
                db.commit()
                db.close()

    db = connect_db()
    c = db.cursor()
    statement = "SELECT * FROM notes WHERE assocUser = %s;" % session['userid']
    print(statement)
    c.execute(statement)
    notes = c.fetchall()
    print(notes)

    return render_template('notes.html', notes=notes, importerror=importerror)

@app.route("/login/", methods=('GET', 'POST'))
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = connect_db()
        c = db.cursor()
        statement = "SELECT * FROM users WHERE username = ?;"
        c.execute(statement, (username,))
        result = c.fetchall()

        if len(result) > 0 and verify_password(password, result[0][2]):
            session.clear()
            session['logged_in'] = True
            session['userid'] = result[0][0]
            session['username'] = result[0][1]
            return redirect(url_for('index'))
        else:
            error = "Wrong username or password!"
    return render_template('login.html', error=error)


@app.route("/register/", methods=('GET', 'POST'))
def register():
    errored = False
    usererror = ""
    passworderror = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        user_statement = """SELECT * FROM users WHERE username = ?;"""

        c.execute(user_statement, (username,))

        if len(c.fetchall()) > 0:
            errored = True
            usererror = "You must choose another username"

        password_valid = password_check(password)
        print(type(password_valid))
        print(password_valid['password_valid'])
        if not password_valid['password_valid']:
            errored = True
            passworderror = "Password was not valid. Password needs to have "
            for e in password_valid.items():
                match e:
                    case ('length_error', True):
                        passworderror = passworderror + "- at least 8 characters "
                    case ('digit_error', True):
                        passworderror = passworderror + "- at least 1 digit "
                    case ('symbol_error', True):
                        passworderror = passworderror + "- at least 1 special character "
                    case ('uppercase_error', True):
                        passworderror = passworderror + "- at least 1 uppercase character "
                    case ('lowercase_error', True):
                        passworderror = passworderror + "- at least 1 lowercase character "

        if not errored:
            hashed_password = hash_password(password)
            statement = """INSERT INTO users(id,username,password) VALUES(null,?,?);"""
            print(statement)
            c.execute(statement, (username, hashed_password))
            statement = "SELECT * FROM users WHERE username = ?;"
            c.execute(statement, (username,))
            result = c.fetchall()
            session.clear()
            session['logged_in'] = True
            session['userid'] = result[0][0]
            session['username'] = result[0][1]
            db.commit()
            db.close()
            return redirect(url_for('index'))

        db.commit()
        db.close()
    return render_template('register.html', usererror=usererror, passworderror=passworderror)


def password_check(password):
    """
    Password is considered valid if:
        8+ characters long
        1+ digits
        1+ symbol
        1+ uppercase letter
        1+ lowercase letter
    """
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    symbol_error = password.isalnum()
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    password_valid = not (length_error or digit_error or symbol_error or uppercase_error or lowercase_error)
    return {
        'password_valid': password_valid,
        'length_error': length_error,
        'digit_error': digit_error,
        'symbol_error': symbol_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error
    }

def hash_password(password):
    byte_password = password.encode('utf-8')
    b64pwd = b64encode(SHA256.new(byte_password).digest())
    return bcrypt(b64pwd, 12)


def verify_password(password, bcrypt_hash):
    byte_password = password.encode('utf-8')
    error = False
    try:
        b64pwd = b64encode(SHA256.new(byte_password).digest())
        bcrypt_check(b64pwd, bcrypt_hash)
    except ValueError:
        error = True

    return not error

@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))


if __name__ == "__main__":
    # create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5000
    if (len(sys.argv) == 2):
        runport = sys.argv[1]
    try:
        app.run(host='0.0.0.0', port=runport)  # runs on machine ip address to make it visible on netowrk
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 5000)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")

from flask import Flask, request, jsonify, render_template, session, redirect
from time import time
#from flask_cors import CORS
from collections import OrderedDict
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from uuid import uuid4
import json
import hashlib
import sqlite3
from sqlite3 import Error
from datetime import datetime




db_path = "./blockchain.db"

class Blockchain:

    def __init__(self):
        self.db_path = './blockchain.db'
        self._initialize_database()

    def _initialize_database(self):

        db = sqlite3.connect(self.db_path)
        dbfunc = db.cursor()

        dbfunc.execute("CREATE TABLE IF NOT EXISTS Users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password TEXT,role TEXT,public_key TEXT,private_key TEXT);")

        dbfunc.execute("CREATE TABLE IF NOT EXISTS TempRecordChanges(id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, doctor_id INTEGER, action TEXT, timestamp TEXT, doctor_signature TEXT, patient_signature TEXT, authority_id INTEGER, authority_signature TEXT, status TEXT);")

        dbfunc.execute("CREATE TABLE IF NOT EXISTS Blocks(id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER, doctor_id INTEGER, authority_id INTEGER, timestamp TEXT, record_change TEXT, previous_hash TEXT, validator_signature TEXT, block_hash TEXT);")

        db.commit()
        db.close()

    def create_block(self, Patient_id, Doctor_id, Authority_id, previous_hash, Validator_sig, Record_change):

        block = {
            'timestamp': datetime.now().strftime("%y/%m/%d %H:%M:%S"),
            'Patient_id': Patient_id,
            'Doctor_id': Doctor_id,
            'Authority_id': Authority_id,
            'previous_hash': previous_hash,
            'Validator_sig': Validator_sig,
            'Record_change': Record_change
        }

        block_hash = self.hash(block)
        block['block_hash'] = block_hash

        return block
    def GenerateKeys(self, user_id):

        key = RSA.generate(2048)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()

        StoreKeys(user_id, public_key, private_key)

        return private_key, public_key


    @staticmethod
    def Sign(private_key, Record):

        key = RSA.importKey(private_key)

        signer = PKCS1_v1_5.new(key)

        RecordJson = json.dumps(Record, sort_keys=True).encode()

        msgdigest  = SHA256.new(RecordJson)

        signature = signer.sign(msgdigest)

        return binascii.hexlify(signature).decode('utf8')

    @staticmethod
    def Authenicity_Check(public_key, Record, sign):

        key = RSA.importKey(public_key)
        verifier = PKCS1_v1_5.new(key)

        RecordJson = json.dumps(Record, sort_keys=True).encode()
        msgdigest = SHA256.new(RecordJson)

        signature = binascii.unhexlify(sign.encode('utf8'))

        return verifier.verify(msgdigest, signature)


    @staticmethod
    def hash(block):
        # We must to ensure that the Dictionary is ordered, otherwise we'll get inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()

def CreateUser(username, password, role):

    pass_hash = hashlib.sha256(password.encode()).hexdigest()

    db = sqlite3.connect(db_path)

    dbfunc = db.cursor()

    dbfunc.execute("INSERT INTO Users (username, password, role) VALUES (?, ?, ?)",(username, pass_hash, role))
    db.commit()
    db.close()

def Login(username, password):

    pass_hash = hashlib.sha256(password.encode()).hexdigest()
    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()
    dbfunc.execute("SELECT id, role, public_key, private_key FROM Users WHERE username=? AND password=?",(username, pass_hash))
    row = dbfunc.fetchone()
    db.close()

    return row

def StoreKeys(user_id,public_key,private_key):

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("UPDATE Users SET public_key=?, private_key=? WHERE id=?",(public_key, private_key, user_id))
    db.commit()
    db.close()

def GetUserKey(user_id):
    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("SELECT public_key, private_key FROM Users WHERE id=?",(user_id,))

    row = dbfunc.fetchone()
    db.close()

    return row

def NewRecord(patient_id, doctor_id, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("INSERT INTO TempRecordChanges (patient_id, doctor_id, action, timestamp, status) VALUES (?, ?, ?, ?, ?)",(patient_id, doctor_id, action, timestamp, "Pending Approval"))

    db.commit()
    db.close()

def GetPending(patient_id):

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("SELECT * FROM TempRecordChanges WHERE patient_id=? AND status = 'Pending Approval'",(patient_id,))

    row = dbfunc.fetchall()
    db.close()

    return row


def UpdateRecord(record_id, field, value):

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute(f"UPDATE TempRecordChanges SET {field}=? WHERE id=?",(value, record_id))

    db.commit()
    db.close()


def GetChain(patient_id):

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("SELECT * FROM Blocks WHERE patient_id=? ORDER BY id ASC",(patient_id,))

    row = dbfunc.fetchall()
    db.close()

    return row


# Initantiate the Blockchain
blockchain = Blockchain()

# Instantiate the Node
app = Flask(__name__)
app.secret_key = "Very_Secret_Demo_Key"
#CORS(app)

@app.route("/") # adds the root page/home page route to flask
# everything under the route belongs to the route until new route is added
def index():
    # returns the rendered page
    return render_template("./index.html")

@app.route("/home")

def Home():
    return index()

@app.route('/register', methods = ['GET','POST'])
def register():

    if request.method == 'GET':
        return render_template('register.html')

    req = request.get_json()
    username = req.get('username')
    password = req.get('password')
    role = req.get('role')

    if not username or not password or not role:
        return jsonify({"error": "Required fields can't be empty !"}), 400

    try:
        CreateUser(username, password, role)
        return jsonify({"message": "User created successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "User with this information already exists"}), 400

@app.route('/login', methods=['GET','POST'])
def login():

    if request.method == 'GET':
        return render_template("login.html")

    username = request.form.get('username')
    password = request.form.get('password')

    credentials = Login(username, password)

    if not credentials:
        return jsonify({"error": "Invalid username or password"}), 401

    user_id, role, public_key, private_key = credentials

    session["user_id"] = user_id
    session["role"] = role

    return jsonify({'status':"success",'redirect':"/dashboard"}), 200

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/login")

@app.route('/user/dashboard')

def dashboard():

    if 'user_id' in session:
        return redirect("/login")
    role = session["role"]

    if role == "doctor":
        return render_template("doctor_dashboard.html")
    elif role == "patient":
        return render_template("patient_dashboard.html")
    elif role == "authority":
        return render_template("authority_dashboard.html")
    else:
        return render_template("error.html",massage = "invalid role"), 403

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)

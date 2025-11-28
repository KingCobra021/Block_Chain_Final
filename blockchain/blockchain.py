from flask import Flask, request, jsonify, render_template, session, redirect
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import json
import hashlib
import sqlite3
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

def GetPending(user_id, role):

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    if role == "doctor" or role == "patient":
        sql = f"SELECT * FROM TempRecordChanges WHERE {role}_id=? AND status = 'Pending Approval'"
        dbfunc.execute(sql,(user_id,))
    elif role == "authority":
        dbfunc.execute("SELECT * FROM TempRecordChanges WHERE status='Pending Approval'")
    else:
        db.close()
        return []

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

def GetRecord(record_id):

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("SELECT * FROM TempRecordChanges WHERE id=?",(record_id,))

    row = dbfunc.fetchone()
    db.close()

    return row

def LastHash(patient_id):
    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("SELECT block_hash FROM Blocks WHERE patient_id=? ORDER BY id DESC LIMIT 1",(patient_id,))

    row = dbfunc.fetchone()
    db.close()

    if row is None:
        return "GENESIS"

    return row[0]


def WriteBlock(block):

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("""INSERT INTO Blocks (patient_id,doctor_id,authority_id,timestamp,record_change,previous_hash,validator_signature,block_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            block["Patient_id"],
            block["Doctor_id"],
            block["Authority_id"],
            block["timestamp"],
            json.dumps(block["Record_change"]),
            block["previous_hash"],
            block["Validator_sig"],
            block["block_hash"],
        )
    )

    db.commit()
    db.close()

def PoA(record_id, authority_id):

    record = GetRecord(record_id)

    if not record:
        return False, "Record doesn't exist!"

    (id,patient_id,doctor_id,action,timestamp,doctor_sig,patient_sig,auth_id,authority_sig,status) = record


    keys = GetUserKey(authority_id)

    if not keys:
        return False, "Athority  keys doesn't exist!."

    auth_pub, auth_priv = keys

    if status != "Pending Approval":
        return False, "Record not pending."

    if not doctor_sig:
        return False, "Doctor has not signed this record."

    if not patient_sig:
        return False, "Patient has not signed this record."

    if not auth_priv:
        return False, "Authority private key doesn't exist!"

    change = {
        "record_id": record_id,
        "patient_id": patient_id,
        "doctor_id": doctor_id,
        "action": action,
        "timestamp": timestamp
    }
    last_hash = LastHash(patient_id)

    validator_sig = blockchain.Sign(auth_priv, change)

    block = blockchain.create_block(Patient_id=patient_id,Doctor_id=doctor_id,Authority_id=authority_id,previous_hash=last_hash,Validator_sig=validator_sig,Record_change=change)

    WriteBlock(block)

    UpdateRecord(record_id, "status", "Approved")
    UpdateRecord(record_id, "authority_id", authority_id)
    UpdateRecord(record_id, "authority_signature", validator_sig)

    return True, "Record Approved!"



def SignRecord(record_id, user_id, role):


    record = GetRecord(record_id)

    if not record:
        return False, "Record doesn't exist!"

    (id,patient_id,doctor_id,action,timestamp,doctor_sig,patient_sig,auth_id,auth_sig,status) = record

    if status != "Pending Approval":
        return False, "Record not pending."

    change = {
        "record_id": record_id,
        "patient_id": patient_id,
        "doctor_id": doctor_id,
        "action": action,
        "timestamp": timestamp
    }

    keys = GetUserKey(user_id)

    if not keys:
        return False, "User has no keys. Generate a key pair first."

    pub_key, priv_key = keys

    if not priv_key:
        return False, "User private key is missing."

    signature = blockchain.Sign(priv_key, change)

    if role == "doctor":
        if doctor_id != user_id:
            return False, "Unauthorized action!"

        if doctor_sig:
            return False, "Already signed."

        UpdateRecord(record_id, "doctor_signature", signature)

        return True, "Doctor signature added."

    elif role == "patient":
        if patient_id != user_id:
            return False, "Unauthorized action!"

        if patient_sig:
            return False, "Already signed."

        UpdateRecord(record_id, "patient_signature", signature)
        return True, "Patient signature added."

    else:
        return False, "Invalid role for signing."


def GetUserId(username):

    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()

    dbfunc.execute("SELECT id FROM users WHERE username = ? AND role = 'patient' ",(username,))

    row = dbfunc.fetchone()
    db.close()

    if row is None:
        return None

    id = row[0]

    return id

def GetUsername(user_id):
    db = sqlite3.connect(db_path)
    dbfunc = db.cursor()
    dbfunc.execute("SELECT username FROM Users WHERE id = ?", (user_id,))
    row = dbfunc.fetchone()
    db.close()
    if not row:
        return None
    username = row[0]
    return username


# Initantiate the Blockchain
blockchain = Blockchain()

# Instantiate the Node
app = Flask(__name__)
app.secret_key = "Very_Secret_Demo_Key"
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

    return jsonify({'status':"success",'redirect':"/user/dashboard"}), 200

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/login")

@app.route('/user/dashboard')

def dashboard():

    if 'user_id' not in session:
        return redirect("/login")
    role = session["role"]

    if role == "doctor":
        return render_template("doctor_dashboard.html")
    elif role == "patient":
        return render_template("patient_dashboard.html")
    elif role == "authority":
        return render_template("authority_dashboard.html")


@app.route('/user/generate_key', methods = ['POST'])
def generate_key():

    if 'user_id' not in session:
        return jsonify({"error": "Not Logged in!"}), 403
    user_id = session["user_id"]

    private_key,public_key = blockchain.GenerateKeys(user_id)


    return jsonify({"message":"Key pair generated successfully.","public_key":public_key}), 200


@app.route('/doctor/new_record', methods = ['GET', 'POST'])
def new_record():
    if "user_id" not in session:
        return redirect("/login")

    if session["role"] != "doctor":
        return jsonify({"error": "You are not authorized to perform this action!"}), 403

    if request.method == 'GET':
        return render_template("record_change.html")

    patient_username = request.form.get("patient_username")
    action = request.form.get("action")
    doctor_id = session["user_id"]

    if not patient_username or not action:
        return jsonify({"error": "Required fields can't be empty !"}), 400

    patient_id = GetUserId(patient_username)

    if patient_id is None:
        return jsonify({"error": "Patient not found."}), 404

    NewRecord(patient_id, doctor_id, action)

    return jsonify({"message": "New record pending approval."}), 200


@app.route('/records/pending', methods=['GET'])
def pending_records():

    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    role = session["role"]

    records = GetPending(user_id, role)

    return render_template("pending_records.html", records=records)
@app.route('/records/sign', methods=['POST'])
def sign_record():

    if "user_id" not in session:
        return jsonify({"error": "Not logged in!"}), 403

    user_id = session["user_id"]
    role = session["role"]

    row = request.get_json()
    record_id = row.get("record_id")

    if not record_id:
        return jsonify({"error": "Record not found!"}), 400

    success, reason = SignRecord(int(record_id), user_id, role)

    if not success:
        return jsonify({"error": reason}), 400

    return jsonify({"message": reason}), 200

@app.route('/records/approve', methods=['POST'])
def approve_record():
    if "user_id" not in session or session.get("role") != "authority":
        return jsonify({"error": "Not authorized"}), 403

    data = request.get_json()
    record_id = data.get("record_id")

    if not record_id:
        return jsonify({"error": "record_id is required"}), 400

    success, reason = PoA(int(record_id), session["user_id"])

    if not success:
        return jsonify({"error": reason}), 400

    return jsonify({"message": reason}), 200
@app.route('/chain/<int:patient_id>', methods=['GET'])
def view_chain(patient_id):

    if "user_id" not in session:
        return redirect("/login")

    chain = GetChain(patient_id)

    return jsonify({"patient_id": patient_id,"chain": chain}), 200
@app.route('/user/id', methods=['GET'])
def get_id(username):

    if not username:
        return redirect("User Doesn't exist.")

    user_id = GetUserId(username)

    if user_id is None:
        return jsonify({"error": "User doesn't exist."}), 404

    return jsonify({"user_id": user_id}), 200


@app.route('/records/history', methods=['GET'])
def records_history():

    if "user_id" not in session:
        return jsonify({"error": "Not logged in!"}), 403

    role = session["role"]
    user_id = session["user_id"]

    if role == "patient":
        patient_id = user_id

    elif role == "doctor":
        patient_username = request.args.get("patient_username")
        if not patient_username:
            return jsonify({"error": "patient_username is required for doctors."}), 400

        patient_id = GetUserId(patient_username)
        if patient_id is None:
            return jsonify({"error": "Patient username not found or not a patient."}), 404

    else:
        return jsonify({"error": "This role cannot view history."}), 403

    rows = GetChain(patient_id)

    history = []
    for row in rows:

        history.append({
            "block_id": row[0],
            "patient_id": row[1],
            "doctor_id": row[2],
            "authority_id": row[3],
            "timestamp": row[4],
            "record_change": json.loads(row[5]) if row[5] else None,
            "previous_hash": row[6],
            "validator_signature": row[7],
            "block_hash": row[8],
        })

    patient_username = GetUsername(patient_id)

    return jsonify({"patient_id": patient_id,"patient_username": patient_username,"history": history}), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)

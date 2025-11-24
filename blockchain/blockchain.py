
from flask import Flask, request, jsonify, render_template
from time import time
from flask_cors import CORS
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





class Blockchain:

    def __init__(self):
        self.db_path = './blockchain.db'
        self._initialize_database()

    def create_block(self, Patient_id, Authority_id, previous_hash, Validator_sig, Record_change):

        block = {
            'timestamp': datetime.now().strftime("%y/%m/%d %H:%M:%S"),
            'Patient_id': Patient_id,
            'Authority_id': Authority_id,
            'previous_hash': previous_hash,
            'Validator_sig': Validator_sig,
            'Record_change': Record_change
        }

        block_hash = self.hash(block)
        block['block_hash'] = block_hash

        return block
    def GenerateKeys(self):

        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

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

        signature = binascii.unhexlify(sign.decode('utf8'))

        return verifier.verify(msgdigest, signature)


    @staticmethod
    def hash(block):
        # We must to ensure that the Dictionary is ordered, otherwise we'll get inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()



# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate the Node
app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/configure')
def configure():
    return render_template('./configure.html')


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200



if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)

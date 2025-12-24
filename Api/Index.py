from flask import Flask, request, jsonify
import requests, hashlib, base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

SECRET_SEED = "APIMPDS$9712Q"
IV_STR = "AP4123IMPDS@12768F"
API_URL = "http://impds.nic.in/impdsmobileapi/api/getrationcard"
TOKEN = "91f01a0a96c526d28e4d0c1189e80459"
USER_AGENT = "Dalvik/2.1.0"
ACCESS_KEY = "paidchx"

def get_md5_hex(s):
    return hashlib.md5(s.encode("iso-8859-1")).hexdigest()

def generate_session_id():
    return "28" + datetime.now().strftime("%Y%m%d%H%M%S")

def encrypt_payload(aadhaar, session_id):
    key_material = get_md5_hex(get_md5_hex(SECRET_SEED) + session_id)
    key = hashlib.sha256(key_material.encode()).digest()[:16]
    iv = IV_STR.encode()[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(aadhaar.encode(), AES.block_size)
    enc = cipher.encrypt(padded)
    return base64.b64encode(base64.b64encode(enc)).decode()

@app.route("/")
def home():
    return jsonify({"status": "API running"})

@app.route("/fetch")
def fetch():
    key = request.args.get("key")
    aadhaar = request.args.get("aadhaar")

    if key != ACCESS_KEY:
        return jsonify({"error": "Invalid key"}), 401

    if not aadhaar or not aadhaar.isdigit() or len(aadhaar) != 12:
        return jsonify({"error": "Invalid Aadhaar"}), 400

    session_id = generate_session_id()
    encrypted = encrypt_payload(aadhaar, session_id)

    payload = {
        "id": encrypted,
        "idType": "U",
        "userName": "IMPDS",
        "token": TOKEN,
        "sessionId": session_id
    }

    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json"
    }

    r = requests.post(API_URL, json=payload, headers=headers, timeout=10)
    return jsonify(r.json())

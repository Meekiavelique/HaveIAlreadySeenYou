import os
import json
from collections import defaultdict
from flask import url_for
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'ip_to_usernames.db')
AUTH_KEYS_FILE = os.path.join(BASE_DIR, 'auth_keys.json')
engine = create_engine(f'sqlite:///{DB_FILE}')
Session = sessionmaker(bind=engine)
Base = declarative_base()

class IPToUsername(Base):
    __tablename__ = 'iptopseudo'
    id = Column(Integer, primary_key=True)
    ip_address = Column(String)
    username = Column(String)
    auth_key = Column(String)

Base.metadata.create_all(engine)
session = Session()

if os.path.exists(AUTH_KEYS_FILE):
    with open(AUTH_KEYS_FILE, 'r') as f:
        ADMIN_AUTH_KEYS = json.load(f)
else:
    ADMIN_AUTH_KEYS = {}
    with open(AUTH_KEYS_FILE, 'w') as f:
        json.dump(ADMIN_AUTH_KEYS, f)

iptopseudo = defaultdict(list)
for record in session.query(IPToUsername).all():
    iptopseudo[record.ip_address].append(record.username)

def register_key():
    new_auth_key = secrets.token_hex(16)
    ADMIN_AUTH_KEYS[new_auth_key] = True
    with open(AUTH_KEYS_FILE, 'w') as f:
        json.dump(ADMIN_AUTH_KEYS, f)
    print(f"Nouvelle clé : {new_auth_key}")

def check_ip(auth_key, username, ip_address):
    if auth_key not in ADMIN_AUTH_KEYS:
        print("Clé inconnu !")
        return

    iptopseudo[ip_address].append(username)
    session.add(IPToUsername(ip_address=ip_address, username=username, auth_key=auth_key))
    session.commit()

    usernames = iptopseudo[ip_address]
    print(f"Pseudos: {', '.join(usernames)}")

def run_web_app():
    from flask import Flask, request, jsonify, render_template
    app = Flask(__name__)

    @app.route('/')
    def index():
        font_path = url_for('static', filename='fonts/mc.ttf')
        return render_template('index.html', font_path=font_path)

    @app.route('/check_ip', methods=['POST'])
    def check_ip_web():
        auth_key = request.form.get('auth_key')
        username = request.form.get('username')
        ip_address = request.form.get('ip_address')

        if auth_key not in ADMIN_AUTH_KEYS:
            return jsonify({'error': "Clé d'authentification invalide"}), 401

        iptopseudo[ip_address].append(username)
        session.add(IPToUsername(ip_address=ip_address, username=username, auth_key=auth_key))
        session.commit()

        usernames = iptopseudo[ip_address]
        return jsonify({'Pseudos': usernames})

    app.run(host='0.0.0.0', port=5000, debug=True)

action = input("(register / web / quit) : ")
while action != 'quit':
    if action == 'register':
        register_key()
    elif action == 'web':
        run_web_app()
    else:
        print("Réssaie ! (register / web / quit) ")
    action = input("(register / web / quit) : ")
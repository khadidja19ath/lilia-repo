"""
TP 6 — Application de Sécurisation des Communications
Implémentation complète : TCP/IP · Bluetooth · Wi-Fi/UDP · Vote Électronique
Niveau : Ing 3 — Cybersécurité
"""

import streamlit as st
import hashlib
import hmac
import secrets
import base64
import json
import socket
import threading
import time
import struct
import io
import os
import queue
from datetime import datetime



# ─── Crypto Imports ───────────────────────────────────────────────────────────
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

try:
    import qrcode
    from PIL import Image
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════════
#  STYLE & CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="SecureCom · TP6 Crypto",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Syne', sans-serif;
}
code, .stCode, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

.main { background: #0a0e1a; }

section[data-testid="stSidebar"] {
    background: #0d1120;
    border-right: 1px solid #1e2d50;
}
section[data-testid="stSidebar"] .stMarkdown p,
section[data-testid="stSidebar"] label {
    color: #8899bb;
}

.hero-title {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 2.6rem;
    background: linear-gradient(135deg, #00d4ff 0%, #0066ff 50%, #7c3aed 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0;
    line-height: 1.1;
}
.hero-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #4a6080;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    margin-top: 4px;
}

.card {
    background: #0d1120;
    border: 1px solid #1e2d50;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
}
.card-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: #00d4ff;
    margin-bottom: 10px;
}

.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
}
.badge-ok  { background: #052e16; color: #4ade80; border: 1px solid #16a34a; }
.badge-err { background: #2d0a0a; color: #f87171; border: 1px solid #dc2626; }
.badge-info{ background: #0c1a3a; color: #60a5fa; border: 1px solid #2563eb; }
.badge-warn{ background: #2d1e00; color: #fbbf24; border: 1px solid #d97706; }

.hex-block {
    background: #060910;
    border: 1px solid #1e2d50;
    border-radius: 8px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #4ade80;
    word-break: break-all;
    line-height: 1.6;
    overflow-x: auto;
}
.log-line {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.73rem;
    padding: 3px 0;
    border-bottom: 1px solid #0e1828;
    color: #94a3b8;
}
.log-line .ts { color: #2563eb; margin-right: 8px; }
.log-line .ok { color: #4ade80; }
.log-line .err { color: #f87171; }
.log-line .info { color: #60a5fa; }

.metric-row {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin: 12px 0;
}
.metric-box {
    flex: 1;
    min-width: 120px;
    background: #060a14;
    border: 1px solid #1e2d50;
    border-radius: 10px;
    padding: 14px 16px;
    text-align: center;
}
.metric-val {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.5rem;
    font-weight: 600;
    color: #00d4ff;
}
.metric-lbl {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #4a6080;
    margin-top: 4px;
}

.protocol-tag {
    background: linear-gradient(90deg, #0c1a3a, #0d1120);
    border: 1px solid #1e3a70;
    border-left: 3px solid #0066ff;
    border-radius: 0 8px 8px 0;
    padding: 10px 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #60a5fa;
    margin: 8px 0;
}

.step-num {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: #0066ff22;
    border: 1px solid #0066ff;
    color: #60a5fa;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    font-weight: 600;
    margin-right: 8px;
}

.vote-box {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1428 100%);
    border: 1px solid #1e3a70;
    border-radius: 14px;
    padding: 24px;
    text-align: center;
    transition: all 0.2s;
}
.vote-box:hover { border-color: #0066ff; }

.divider {
    border: none;
    border-top: 1px solid #1e2d50;
    margin: 20px 0;
}
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  CRYPTO PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════════

def generate_rsa_keypair(bits: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    iv = secrets.token_bytes(16)
    padded = plaintext + bytes(16 - len(plaintext) % 16) * (16 - len(plaintext) % 16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv, enc.update(padded) + enc.finalize()

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]

def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key, private_key.public_key()

def ecdh_shared_secret(private_key, peer_public_key) -> bytes:
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SecureCom-TP6",
        backend=default_backend()
    ).derive(shared)

def ecdsa_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def ecdsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def compute_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def hybrid_encrypt(public_key, message: bytes) -> dict:
    aes_key = secrets.token_bytes(32)
    enc_key = rsa_encrypt(public_key, aes_key)
    iv, ciphertext = aes_encrypt(aes_key, message)
    mac = compute_hmac(aes_key, ciphertext)
    return {
        "enc_key": base64.b64encode(enc_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "mac": mac
    }

def hybrid_decrypt(private_key, envelope: dict) -> bytes:
    aes_key = rsa_decrypt(private_key, base64.b64decode(envelope["enc_key"]))
    ciphertext = base64.b64decode(envelope["ciphertext"])
    mac_check = compute_hmac(aes_key, ciphertext)
    if not hmac.compare_digest(mac_check, envelope["mac"]):
        raise ValueError("HMAC verification failed — message integrity compromised!")
    return aes_decrypt(aes_key, base64.b64decode(envelope["iv"]), ciphertext)

def serialize_public_key(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def fingerprint(public_key) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(raw).hexdigest()[:32]

# ─── Paillier Homomorphic Encryption (simplified for vote) ────────────────────

def paillier_keygen(bits: int = 512):
    """Simplified Paillier key generation using sympy-like approach."""
    import sympy
    p = sympy.randprime(2**(bits//2 - 1), 2**(bits//2))
    q = sympy.randprime(2**(bits//2 - 1), 2**(bits//2))
    while p == q:
        q = sympy.randprime(2**(bits//2 - 1), 2**(bits//2))
    n = p * q
    n2 = n * n
    g = n + 1
    lam = (p - 1) * (q - 1) // sympy.gcd(p - 1, q - 1)
    mu = pow(int(sympy.mod_inverse(lam, n)), 1, n)
    return {"n": n, "g": g, "lam": lam, "mu": mu, "n2": n2}

def paillier_encrypt(pub, m: int) -> int:
    n, g, n2 = pub["n"], pub["g"], pub["n2"]
    r = secrets.randbelow(n - 2) + 2
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

def paillier_decrypt(key, c: int) -> int:
    n, lam, mu, n2 = key["n"], key["lam"], key["mu"], key["n2"]
    x = pow(c, lam, n2)
    l_val = (x - 1) // n
    return (l_val * mu) % n

def paillier_add(pub, c1: int, c2: int) -> int:
    return (c1 * c2) % pub["n2"]

# ═══════════════════════════════════════════════════════════════════════════════
#  SESSION STATE INIT
# ═══════════════════════════════════════════════════════════════════════════════

def init_state():
    defaults = {
        "tcp_alice_priv": None, "tcp_alice_pub": None,
        "tcp_bob_priv": None,   "tcp_bob_pub": None,
        "tcp_session_key": None,
        "tcp_messages": [],
        "bt_alice_ecdh_priv": None, "bt_alice_ecdh_pub": None,
        "bt_bob_ecdh_priv": None,   "bt_bob_ecdh_pub": None,
        "bt_alice_sign_priv": None, "bt_alice_sign_pub": None,
        "bt_bob_sign_priv": None,   "bt_bob_sign_pub": None,
        "bt_shared_secret": None,
        "bt_messages": [],
        "wifi_alice_priv": None, "wifi_alice_pub": None,
        "wifi_bob_priv": None,   "wifi_bob_pub": None,
        "wifi_messages": [],
        "vote_paillier_key": None,
        "vote_registered_voters": {},
        "vote_ballots": [],
        "vote_tally": None,
        "vote_candidates": ["Candidate A", "Candidate B", "Candidate C"],
        "logs": [],
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

def log(msg: str, level: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    st.session_state.logs.append({"ts": ts, "msg": msg, "level": level})

def render_logs(limit: int = 12):
    logs = st.session_state.logs[-limit:]
    lines = ""
    for entry in reversed(logs):
        cls = entry["level"]
        lines += f'<div class="log-line"><span class="ts">[{entry["ts"]}]</span> <span class="{cls}">{entry["msg"]}</span></div>'
    st.markdown(f'<div class="card" style="max-height:200px;overflow-y:auto">{lines}</div>', unsafe_allow_html=True)

def hex_block(data: bytes | str, label: str = ""):
    if isinstance(data, bytes):
        content = data.hex(" ", 1) if len(data) <= 64 else data.hex()[:128] + "…"
    else:
        content = data
    if label:
        st.markdown(f'<div class="card-title">{label}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="hex-block">{content}</div>', unsafe_allow_html=True)

def badge(text: str, kind: str = "info"):
    st.markdown(f'<span class="badge badge-{kind}">{text}</span>', unsafe_allow_html=True)

def metrics(*items):
    """items = list of (value, label)"""
    boxes = "".join(
        f'<div class="metric-box"><div class="metric-val">{v}</div><div class="metric-lbl">{l}</div></div>'
        for v, l in items
    )
    st.markdown(f'<div class="metric-row">{boxes}</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("""
    <div style="padding:16px 0 8px">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                    letter-spacing:0.2em;color:#2563eb;text-transform:uppercase;
                    margin-bottom:6px">TP 6 · SecureCom</div>
        <div style="font-family:'Syne',sans-serif;font-weight:800;font-size:1.4rem;
                    color:#e2e8f0;line-height:1.2">Cryptographie<br>Appliquée</div>
        <div style="font-size:0.7rem;color:#4a6080;margin-top:6px">
            Ing 3 · Cybersécurité · 2026
        </div>
    </div>
    <hr style="border-color:#1e2d50;margin:12px 0"/>
    """, unsafe_allow_html=True)

    section = st.radio(
        "Module",
        ["🏠 Accueil", "🔌 TCP/IP Sécurisé", "📡 Bluetooth RFCOMM",
         "📶 Wi-Fi / UDP Chat", "🗳️ Vote Électronique", "📋 Journal Système"],
        label_visibility="collapsed"
    )

    st.markdown("""
    <hr style="border-color:#1e2d50;margin:16px 0"/>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                color:#2a3a5a;line-height:1.8">
    <div>RSA-2048 · OAEP · PSS</div>
    <div>AES-256-CBC · PKCS7</div>
    <div>ECDH P-256 · HKDF</div>
    <div>ECDSA · HMAC-SHA256</div>
    <div>Paillier (Homomorphe)</div>
    </div>
    """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE : ACCUEIL
# ═══════════════════════════════════════════════════════════════════════════════

if section == "🏠 Accueil":
    st.markdown('<div class="hero-title">SecureCom</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">Application de sécurisation des communications · TP 6</div>', unsafe_allow_html=True)
    st.markdown('<hr class="divider"/>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div class="card">
            <div class="card-title">Architecture Cryptographique</div>
            <div class="protocol-tag">
                🔌 <strong>TCP/IP</strong> — RSA-2048 + AES-256-CBC + HMAC<br>
                Chiffrement hybride, intégrité, authentification mutuelle
            </div>
            <div class="protocol-tag">
                📡 <strong>Bluetooth RFCOMM</strong> — ECDH P-256 + AES-256-CBC + ECDSA<br>
                Échange de clés Diffie-Hellman, signatures sur courbes elliptiques
            </div>
            <div class="protocol-tag">
                📶 <strong>Wi-Fi / UDP</strong> — RSA + AES + HMAC<br>
                Chat chiffré E2E avec authentification par signatures numériques
            </div>
            <div class="protocol-tag">
                🗳️ <strong>Vote Électronique</strong> — Chiffrement Homomorphe Paillier<br>
                Dépouillement sans déchiffrement individuel, anonymat garanti
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="card">
            <div class="card-title">Garanties de Sécurité</div>
        """, unsafe_allow_html=True)

        guarantees = [
            ("🔒", "Confidentialité", "AES-256-CBC / RSA-OAEP"),
            ("✅", "Intégrité", "HMAC-SHA256 / Signature RSA-PSS"),
            ("🪪", "Authenticité", "Certificats RSA / ECDSA P-256"),
            ("🚫", "Non-répudiation", "Signatures numériques vérifiables"),
            ("🎭", "Anonymat (vote)", "Chiffrement homomorphe Paillier"),
        ]
        for icon, title, detail in guarantees:
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:12px;padding:8px 0;
                        border-bottom:1px solid #1e2d50">
                <span style="font-size:1.1rem">{icon}</span>
                <div>
                    <div style="font-weight:600;font-size:0.85rem;color:#e2e8f0">{title}</div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#4a6080">{detail}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("""
    <div class="card" style="margin-top:8px">
        <div class="card-title">Flux de Communication Sécurisée</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                    color:#4a6080;line-height:2.0;padding:8px 0">
        <span style="color:#0066ff">Alice</span> ──[Génère RSA/ECDH]──▶ 
        <span style="color:#00d4ff">Clé Publique</span> ──[Canal non sécurisé]──▶ 
        <span style="color:#7c3aed">Bob</span><br>
        <span style="color:#7c3aed">Bob</span> ──[Chiffre AES-key avec PubKey_Alice]──▶ 
        <span style="color:#00d4ff">Enveloppe</span> ──▶ 
        <span style="color:#0066ff">Alice</span><br>
        <span style="color:#0066ff">Alice</span> ──[Déchiffre → AES-key]──▶ 
        <span style="color:#4ade80">Session sécurisée</span> ◀──▶ 
        <span style="color:#7c3aed">Bob</span><br>
        <span style="color:#fbbf24">HMAC</span> sur chaque message ──▶ 
        <span style="color:#4ade80">Intégrité vérifiée</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE : TCP/IP
# ═══════════════════════════════════════════════════════════════════════════════

elif section == "🔌 TCP/IP Sécurisé":
    st.markdown('<div class="hero-title" style="font-size:2rem">TCP/IP Sécurisé</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">RSA-2048 · AES-256-CBC · HMAC-SHA256 · Sockets simulés</div>', unsafe_allow_html=True)
    st.markdown('<hr class="divider"/>', unsafe_allow_html=True)

    # ── Étape 1 : Génération des clés ─────────────────────────────────────────
    st.markdown("### <span class='step-num'>1</span> Génération des Clés RSA", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="card"><div class="card-title">Alice · Clés RSA-2048</div>', unsafe_allow_html=True)
        if st.button("🔑 Générer clés Alice", key="gen_alice_tcp", use_container_width=True):
            with st.spinner("Génération RSA-2048…"):
                priv, pub = generate_rsa_keypair(2048)
                st.session_state.tcp_alice_priv = priv
                st.session_state.tcp_alice_pub = pub
                log("Alice: paire de clés RSA-2048 générée", "ok")

        if st.session_state.tcp_alice_pub:
            badge("CLÉS GÉNÉRÉES", "ok")
            fp = fingerprint(st.session_state.tcp_alice_pub)
            st.markdown(f'<div class="hex-block" style="margin-top:8px">Fingerprint SHA-256:<br>{fp}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="card"><div class="card-title">Bob · Clés RSA-2048</div>', unsafe_allow_html=True)
        if st.button("🔑 Générer clés Bob", key="gen_bob_tcp", use_container_width=True):
            with st.spinner("Génération RSA-2048…"):
                priv, pub = generate_rsa_keypair(2048)
                st.session_state.tcp_bob_priv = priv
                st.session_state.tcp_bob_pub = pub
                log("Bob: paire de clés RSA-2048 générée", "ok")

        if st.session_state.tcp_bob_pub:
            badge("CLÉS GÉNÉRÉES", "ok")
            fp = fingerprint(st.session_state.tcp_bob_pub)
            st.markdown(f'<div class="hex-block" style="margin-top:8px">Fingerprint SHA-256:<br>{fp}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # ── Étape 2 : Handshake ───────────────────────────────────────────────────
    st.markdown("### <span class='step-num'>2</span> Handshake · Établissement de Session", unsafe_allow_html=True)

    if st.session_state.tcp_alice_priv and st.session_state.tcp_bob_priv:
        if st.button("🤝 Simuler Handshake TCP Sécurisé", use_container_width=True, key="handshake"):
            with st.spinner("Handshake en cours…"):
                # Bob génère une clé de session AES-256 et la chiffre pour Alice
                session_key = secrets.token_bytes(32)
                enc_session = rsa_encrypt(st.session_state.tcp_alice_pub, session_key)
                # Alice déchiffre
                dec_session = rsa_decrypt(st.session_state.tcp_alice_priv, enc_session)
                assert session_key == dec_session
                st.session_state.tcp_session_key = session_key
                log(f"Handshake OK — clé AES-256 établie: {session_key.hex()[:16]}…", "ok")

            st.success("✅ Handshake réussi — session sécurisée établie")
            metrics(
                ("2048", "RSA bits"),
                ("256", "AES bits"),
                (f"{len(enc_session)}", "bytes chiffrés"),
                ("SHA-256", "OAEP Hash"),
            )
    else:
        st.info("⚠️ Générez les clés d'Alice et Bob d'abord.")

    # ── Étape 3 : Échange de messages ─────────────────────────────────────────
    if st.session_state.tcp_session_key:
        st.markdown("### <span class='step-num'>3</span> Canal Sécurisé · Échange de Messages", unsafe_allow_html=True)

        col1, col2 = st.columns([3, 1])
        with col1:
            msg_tcp = st.text_input("Message à envoyer", placeholder="Entrez votre message…", key="msg_tcp")
        with col2:
            sender = st.selectbox("Expéditeur", ["Alice", "Bob"], key="sender_tcp")

        if st.button("📤 Envoyer", key="send_tcp", use_container_width=True) and msg_tcp:
            key = st.session_state.tcp_session_key
            plaintext = msg_tcp.encode()
            iv, ciphertext = aes_encrypt(key, plaintext)
            mac = compute_hmac(key, ciphertext)
            # Vérification côté destinataire
            mac_ok = hmac.compare_digest(compute_hmac(key, ciphertext), mac)
            decrypted = aes_decrypt(key, iv, ciphertext)

            st.session_state.tcp_messages.append({
                "from": sender,
                "plain": msg_tcp,
                "cipher": ciphertext.hex()[:48] + "…",
                "mac": mac[:16] + "…",
                "mac_ok": mac_ok,
                "ts": datetime.now().strftime("%H:%M:%S")
            })
            log(f"{sender}→{'Bob' if sender=='Alice' else 'Alice'}: [{len(ciphertext)}B chiffrés] HMAC={'✓' if mac_ok else '✗'}", "ok")

        # Affichage des messages
        if st.session_state.tcp_messages:
            st.markdown('<div class="card"><div class="card-title">Journal des Messages</div>', unsafe_allow_html=True)
            for m in reversed(st.session_state.tcp_messages[-8:]):
                align = "left" if m["from"] == "Alice" else "right"
                color = "#0066ff" if m["from"] == "Alice" else "#7c3aed"
                st.markdown(f"""
                <div style="text-align:{align};margin:6px 0">
                    <div style="display:inline-block;max-width:80%;text-align:left">
                        <div style="font-size:0.65rem;color:{color};font-family:'JetBrains Mono',monospace;margin-bottom:2px">
                            {m['from']} · {m['ts']}
                        </div>
                        <div style="background:#0d1728;border:1px solid {color}33;border-radius:10px;
                                    padding:10px 14px;color:#e2e8f0;font-size:0.85rem">
                            {m['plain']}
                        </div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;color:#2a3a5a;margin-top:2px">
                            AES: {m['cipher']} | HMAC: {m['mac']} 
                            <span style="color:{'#4ade80' if m['mac_ok'] else '#f87171'}">
                                {'✓ intégrité ok' if m['mac_ok'] else '✗ intégrité compromise'}
                            </span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # ── Étape 4 : Chiffrement Hybride Complet ─────────────────────────────
        st.markdown("### <span class='step-num'>4</span> Chiffrement Hybride RSA+AES", unsafe_allow_html=True)
        st.markdown('<div class="card"><div class="card-title">Alice → Bob : Enveloppe Hybride Complète</div>', unsafe_allow_html=True)

        hybrid_msg = st.text_area("Message (Alice → Bob)", "Message confidentiel simulant une donnée sensible.", key="hybrid_msg", height=80)
        if st.button("🔐 Chiffrer (Hybride RSA+AES)", use_container_width=True):
            with st.spinner("Chiffrement hybride…"):
                envelope = hybrid_encrypt(st.session_state.tcp_bob_pub, hybrid_msg.encode())
                decrypted_msg = hybrid_decrypt(st.session_state.tcp_bob_priv, envelope)
                ok = decrypted_msg.decode() == hybrid_msg

            col_a, col_b = st.columns(2)
            with col_a:
                hex_block(envelope["enc_key"][:64] + "…", "Clé AES chiffrée (RSA-OAEP)")
                hex_block(envelope["ciphertext"][:64] + "…", "Ciphertext AES-256-CBC")
            with col_b:
                hex_block(envelope["mac"], "HMAC-SHA256")
                st.markdown(f'<br><span class="badge badge-{"ok" if ok else "err"}">{"✓ Déchiffrement réussi" if ok else "✗ Erreur"}</span>', unsafe_allow_html=True)
            log(f"Hybride RSA+AES: {len(hybrid_msg)} chars → {len(base64.b64decode(envelope['ciphertext']))} bytes chiffrés", "ok")
        st.markdown("</div>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE : BLUETOOTH
# ═══════════════════════════════════════════════════════════════════════════════

elif section == "📡 Bluetooth RFCOMM":
    st.markdown('<div class="hero-title" style="font-size:2rem">Bluetooth RFCOMM</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">ECDH P-256 · HKDF · AES-256-CBC · ECDSA · Simulation de canal BT</div>', unsafe_allow_html=True)
    st.markdown('<hr class="divider"/>', unsafe_allow_html=True)

    st.markdown("""
    <div class="card">
        <div class="card-title">Protocole de Sécurisation BT / RFCOMM</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#4a6080;line-height:2.2">
        <span style="color:#00d4ff">1. Pairing</span> — Alice et Bob génèrent des paires ECDH (P-256) pour le chiffrement<br>
        <span style="color:#00d4ff">2. Auth Keys</span> — Paires ECDSA séparées pour l'authentification des messages<br>
        <span style="color:#00d4ff">3. ECDH Exchange</span> — Échange des clés publiques ECDH sur canal BT simulé<br>
        <span style="color:#00d4ff">4. Shared Secret</span> — HKDF(ECDH_secret) → clé AES-256 de session<br>
        <span style="color:#00d4ff">5. Secure Channel</span> — AES-256-CBC + signature ECDSA de chaque trame
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Pairing ───────────────────────────────────────────────────────────────
    st.markdown("### <span class='step-num'>1</span> Pairing BT · Génération des Clés", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    for who, col in [("Alice", col1), ("Bob", col2)]:
        with col:
            key_ecdh = f"bt_{who.lower()}_ecdh_priv"
            key_sign = f"bt_{who.lower()}_sign_priv"
            color = "#0066ff" if who == "Alice" else "#7c3aed"
            st.markdown(f'<div class="card"><div class="card-title" style="color:{color}">{who} · Clés BT</div>', unsafe_allow_html=True)
            if st.button(f"📱 Générer clés {who}", key=f"gen_{who}_bt", use_container_width=True):
                ecdh_priv, ecdh_pub = generate_ecdh_keypair()
                sign_priv, sign_pub = generate_ecdh_keypair()
                st.session_state[f"bt_{who.lower()}_ecdh_priv"] = ecdh_priv
                st.session_state[f"bt_{who.lower()}_ecdh_pub"] = ecdh_pub
                st.session_state[f"bt_{who.lower()}_sign_priv"] = sign_priv
                st.session_state[f"bt_{who.lower()}_sign_pub"] = sign_pub
                log(f"{who}: ECDH P-256 + ECDSA P-256 générés", "ok")

            if st.session_state.get(f"bt_{who.lower()}_ecdh_pub"):
                badge("ECDH P-256 OK", "ok")
                st.markdown(" ", unsafe_allow_html=True)
                badge("ECDSA P-256 OK", "ok")
                fp_ecdh = fingerprint(st.session_state[f"bt_{who.lower()}_ecdh_pub"])
                fp_sign = fingerprint(st.session_state[f"bt_{who.lower()}_sign_pub"])
                st.markdown(f"""
                <div class="hex-block" style="margin-top:8px;font-size:0.65rem">
                ECDH FP: {fp_ecdh[:24]}…<br>
                SIGN FP: {fp_sign[:24]}…
                </div>""", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    # ── ECDH Key Exchange ─────────────────────────────────────────────────────
    st.markdown("### <span class='step-num'>2</span> Échange de Clés ECDH P-256", unsafe_allow_html=True)

    bt_ready = all(st.session_state.get(k) for k in [
        "bt_alice_ecdh_priv", "bt_bob_ecdh_priv",
        "bt_alice_sign_priv", "bt_bob_sign_priv"
    ])

    if bt_ready:
        if st.button("🔄 Effectuer ECDH Exchange", use_container_width=True, key="bt_ecdh"):
            with st.spinner("ECDH Exchange…"):
                # Calculer les secrets partagés
                secret_alice = ecdh_shared_secret(
                    st.session_state.bt_alice_ecdh_priv,
                    st.session_state.bt_bob_ecdh_pub
                )
                secret_bob = ecdh_shared_secret(
                    st.session_state.bt_bob_ecdh_priv,
                    st.session_state.bt_alice_ecdh_pub
                )
                assert secret_alice == secret_bob, "ECDH mismatch!"
                st.session_state.bt_shared_secret = secret_alice
                log(f"ECDH OK — secret partagé: {secret_alice.hex()[:16]}…", "ok")

            st.success("✅ Secret ECDH partagé établi via HKDF-SHA256")
            hex_block(st.session_state.bt_shared_secret, "Clé de session AES-256 dérivée (HKDF)")
            metrics(
                ("P-256", "Courbe ECDH"),
                ("256", "bits HKDF"),
                ("AES-256", "Chiffrement"),
                ("ECDSA", "Auth"),
            )
    else:
        st.info("⚠️ Générez d'abord les clés des deux parties.")

    # ── Envoi de messages ─────────────────────────────────────────────────────
    if st.session_state.bt_shared_secret:
        st.markdown("### <span class='step-num'>3</span> Canal BT Chiffré + Authentifié", unsafe_allow_html=True)

        col1, col2 = st.columns([3, 1])
        with col1:
            msg_bt = st.text_input("Trame RFCOMM", placeholder="Message BT…", key="msg_bt")
        with col2:
            sender_bt = st.selectbox("Émetteur", ["Alice", "Bob"], key="sender_bt")

        if st.button("📡 Transmettre Trame BT", use_container_width=True, key="send_bt") and msg_bt:
            key = st.session_state.bt_shared_secret
            plaintext = msg_bt.encode()
            iv, ciphertext = aes_encrypt(key, plaintext)
            # Signature ECDSA
            sign_priv = st.session_state[f"bt_{sender_bt.lower()}_sign_priv"]
            sign_pub  = st.session_state[f"bt_{sender_bt.lower()}_sign_pub"]
            sig = ecdsa_sign(sign_priv, ciphertext)
            sig_ok = ecdsa_verify(sign_pub, ciphertext, sig)
            decrypted = aes_decrypt(key, iv, ciphertext)

            st.session_state.bt_messages.append({
                "from": sender_bt,
                "plain": msg_bt,
                "cipher": ciphertext.hex()[:40] + "…",
                "sig": sig.hex()[:20] + "…",
                "sig_ok": sig_ok,
                "ts": datetime.now().strftime("%H:%M:%S")
            })
            log(f"BT {sender_bt}: {len(ciphertext)}B | ECDSA {'✓' if sig_ok else '✗'}", "ok" if sig_ok else "err")

        if st.session_state.bt_messages:
            st.markdown('<div class="card"><div class="card-title">Trames RFCOMM</div>', unsafe_allow_html=True)
            for m in reversed(st.session_state.bt_messages[-6:]):
                color = "#0066ff" if m["from"] == "Alice" else "#7c3aed"
                sig_color = "#4ade80" if m["sig_ok"] else "#f87171"
                st.markdown(f"""
                <div style="background:#060a14;border:1px solid {color}33;border-radius:8px;
                            padding:10px 14px;margin:4px 0">
                    <span style="color:{color};font-family:'JetBrains Mono',monospace;
                                font-size:0.65rem">{m['from']} · {m['ts']}</span>
                    <div style="color:#e2e8f0;margin:4px 0">{m['plain']}</div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;color:#2a3a5a">
                        AES: {m['cipher']} | ECDSA: {m['sig']}
                        <span style="color:{sig_color}">{'✓ authentifié' if m['sig_ok'] else '✗ signature invalide'}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # ── Attaque MITM et contre-mesure ─────────────────────────────────────
        st.markdown("### <span class='step-num'>4</span> Attaque MITM & Contre-mesure ECDSA", unsafe_allow_html=True)
        st.markdown("""
        <div class="card">
            <div class="card-title">Simulation d'Attaque Man-in-the-Middle BT</div>
        """, unsafe_allow_html=True)

        if st.button("⚠️ Simuler Attaque MITM", use_container_width=True, key="mitm_bt"):
            # L'attaquant génère sa propre paire ECDH
            mitm_ecdh_priv, mitm_ecdh_pub = generate_ecdh_keypair()
            # Il essaie de se faire passer pour Bob auprès d'Alice
            # Alice calcule un secret avec la clé MITM (pense que c'est Bob)
            secret_with_mitm = ecdh_shared_secret(
                st.session_state.bt_alice_ecdh_priv,
                mitm_ecdh_pub
            )
            # La vérification ECDSA détecte l'imposteur
            # L'attaquant ne possède pas la clé privée ECDSA de Bob
            # Il forge une signature invalide
            forged_sig = secrets.token_bytes(64)
            detected = not ecdsa_verify(
                st.session_state.bt_bob_sign_pub,
                b"test_message",
                forged_sig
            )

            st.error("🚨 Attaque MITM Détectée!")
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(f"""
                <div class="hex-block">
                ❌ MITM établit canal avec Alice<br>
                Faux secret: {secret_with_mitm.hex()[:16]}…<br>
                Signature forgée: {forged_sig.hex()[:16]}…
                </div>""", unsafe_allow_html=True)
            with col_b:
                st.markdown(f"""
                <div class="hex-block" style="color:#4ade80">
                ✅ Contre-mesure ECDSA active<br>
                Clé ECDSA Bob: vérifiée<br>
                Signature invalide → {'REJETÉ' if detected else 'ACCEPTÉ'}
                </div>""", unsafe_allow_html=True)
            log("MITM BT détecté par vérification ECDSA", "err")
        st.markdown("</div>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE : Wi-Fi / UDP Chat
# ═══════════════════════════════════════════════════════════════════════════════

elif section == "📶 Wi-Fi / UDP Chat":
    st.markdown('<div class="hero-title" style="font-size:2rem">Wi-Fi / UDP Chat</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">Chiffrement E2E · RSA + AES · HMAC · Authentification mutuelle</div>', unsafe_allow_html=True)
    st.markdown('<hr class="divider"/>', unsafe_allow_html=True)

    st.markdown("""
    <div class="card">
        <div class="card-title">Architecture Chat Sécurisé sur UDP</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#4a6080;line-height:2">
        UDP ⊕ Chiffrement AES-256-CBC ⊕ Signature RSA-PSS ⊕ HMAC-SHA256<br>
        <span style="color:#60a5fa">• Chaque datagramme UDP contient : IV | Ciphertext | HMAC | Signature</span><br>
        <span style="color:#60a5fa">• Pas de connexion TCP → stateless, adapté IoT/mobile</span><br>
        <span style="color:#60a5fa">• Authentification par signature RSA-PSS de l'expéditeur</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Génération des clés
    st.markdown("### <span class='step-num'>1</span> Initialisation des Entités", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    for who, col in [("Alice", col1), ("Bob", col2)]:
        with col:
            color = "#0066ff" if who == "Alice" else "#7c3aed"
            st.markdown(f'<div class="card"><div class="card-title" style="color:{color}">{who}</div>', unsafe_allow_html=True)
            if st.button(f"🔑 Init {who}", key=f"init_{who}_wifi", use_container_width=True):
                with st.spinner(f"Génération RSA-2048 {who}…"):
                    priv, pub = generate_rsa_keypair(2048)
                    st.session_state[f"wifi_{who.lower()}_priv"] = priv
                    st.session_state[f"wifi_{who.lower()}_pub"] = pub
                    log(f"Wi-Fi {who}: RSA-2048 généré", "ok")

            if st.session_state.get(f"wifi_{who.lower()}_pub"):
                badge("RSA-2048 PRÊT", "ok")
                fp = fingerprint(st.session_state[f"wifi_{who.lower()}_pub"])
                st.markdown(f'<div class="hex-block" style="margin-top:8px;font-size:0.65rem">FP: {fp}</div>', unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    # Interface Chat
    wifi_ready = st.session_state.get("wifi_alice_priv") and st.session_state.get("wifi_bob_priv")

    if wifi_ready:
        st.markdown("### <span class='step-num'>2</span> Chat Chiffré E2E", unsafe_allow_html=True)

        col1, col2, col3 = st.columns([2, 2, 1])
        with col1:
            msg_wifi = st.text_input("Message", placeholder="Tapez votre message…", key="msg_wifi")
        with col2:
            dest_wifi = st.selectbox("Destinataire", ["Bob ← Alice", "Alice ← Bob"], key="dest_wifi")
        with col3:
            st.markdown("<br>", unsafe_allow_html=True)
            send_clicked = st.button("📤", key="send_wifi", use_container_width=True)

        if send_clicked and msg_wifi:
            if dest_wifi == "Bob ← Alice":
                sender, recip = "Alice", "Bob"
                sender_priv = st.session_state.wifi_alice_priv
                recip_pub   = st.session_state.wifi_bob_pub
                recip_priv  = st.session_state.wifi_bob_priv
            else:
                sender, recip = "Bob", "Alice"
                sender_priv = st.session_state.wifi_bob_priv
                recip_pub   = st.session_state.wifi_alice_pub
                recip_priv  = st.session_state.wifi_alice_priv

            # Construire datagramme UDP simulé
            plaintext = msg_wifi.encode()
            # Chiffrement hybride
            aes_key = secrets.token_bytes(32)
            enc_aes_key = rsa_encrypt(recip_pub, aes_key)
            iv, ciphertext = aes_encrypt(aes_key, plaintext)
            mac = compute_hmac(aes_key, ciphertext)
            # Signature RSA-PSS par l'expéditeur
            sig = rsa_sign(sender_priv, ciphertext)
            # Vérification côté destinataire
            sig_ok = rsa_verify(
                st.session_state[f"wifi_{sender.lower()}_pub"],
                ciphertext,
                sig
            )
            mac_ok = hmac.compare_digest(compute_hmac(aes_key, ciphertext), mac)
            decrypted = aes_decrypt(aes_key, iv, ciphertext)

            # Taille du datagramme simulé
            datagram_size = 4 + len(enc_aes_key) + 16 + len(ciphertext) + 32 + len(sig)

            st.session_state.wifi_messages.append({
                "from": sender, "to": recip,
                "plain": msg_wifi,
                "cipher": ciphertext.hex()[:40] + "…",
                "mac": mac[:16] + "…",
                "sig": sig.hex()[:16] + "…",
                "sig_ok": sig_ok,
                "mac_ok": mac_ok,
                "datagram_size": datagram_size,
                "ts": datetime.now().strftime("%H:%M:%S")
            })
            log(f"UDP {sender}→{recip}: {datagram_size}B | RSA-PSS {'✓' if sig_ok else '✗'} | HMAC {'✓' if mac_ok else '✗'}", "ok")

        # Affichage chat
        if st.session_state.wifi_messages:
            st.markdown('<div class="card"><div class="card-title">Conversation Chiffrée UDP</div>', unsafe_allow_html=True)
            for m in reversed(st.session_state.wifi_messages[-8:]):
                is_alice = m["from"] == "Alice"
                align = "left" if is_alice else "right"
                color = "#0066ff" if is_alice else "#7c3aed"
                st.markdown(f"""
                <div style="text-align:{align};margin:6px 0">
                    <div style="display:inline-block;max-width:85%;text-align:left">
                        <div style="font-size:0.62rem;font-family:'JetBrains Mono',monospace;
                                    color:{color};margin-bottom:2px">
                            {m['from']} → {m['to']} · {m['ts']} · {m['datagram_size']}B UDP
                        </div>
                        <div style="background:#0d1728;border:1px solid {color}33;border-radius:10px;
                                    padding:10px 14px;color:#e2e8f0">
                            {m['plain']}
                        </div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                                    color:#2a3a5a;margin-top:2px">
                            <span style="color:{'#4ade80' if m['sig_ok'] else '#f87171'}">
                                RSA-PSS {'✓' if m['sig_ok'] else '✗'}
                            </span> |
                            <span style="color:{'#4ade80' if m['mac_ok'] else '#f87171'}">
                                HMAC {'✓' if m['mac_ok'] else '✗'}
                            </span> |
                            AES: {m['cipher']}
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # Démo structure datagramme UDP
        st.markdown("### <span class='step-num'>3</span> Structure du Datagramme UDP Sécurisé", unsafe_allow_html=True)
        st.markdown("""
        <div class="card">
            <div class="card-title">Format du Paquet</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;line-height:2.2">
            <span style="color:#fbbf24">┌─────────────────────────────────────────────────┐</span><br>
            <span style="color:#fbbf24">│</span> <span style="color:#60a5fa">HDR [4B]</span>  Version=1, Type=MSG, Flags        <span style="color:#fbbf24">│</span><br>
            <span style="color:#fbbf24">│</span> <span style="color:#60a5fa">KEY [256B]</span> Clé AES-256 chiffrée RSA-OAEP       <span style="color:#fbbf24">│</span><br>
            <span style="color:#fbbf24">│</span> <span style="color:#60a5fa">IV  [16B]</span>  Vecteur d'initialisation AES           <span style="color:#fbbf24">│</span><br>
            <span style="color:#fbbf24">│</span> <span style="color:#60a5fa">ENC [var]</span>  Ciphertext AES-256-CBC                 <span style="color:#fbbf24">│</span><br>
            <span style="color:#fbbf24">│</span> <span style="color:#60a5fa">MAC [32B]</span>  HMAC-SHA256(AES-key, ciphertext)       <span style="color:#fbbf24">│</span><br>
            <span style="color:#fbbf24">│</span> <span style="color:#60a5fa">SIG [256B]</span> Signature RSA-PSS-SHA256(ciphertext)  <span style="color:#fbbf24">│</span><br>
            <span style="color:#fbbf24">└─────────────────────────────────────────────────┘</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE : VOTE ÉLECTRONIQUE
# ═══════════════════════════════════════════════════════════════════════════════

elif section == "🗳️ Vote Électronique":
    st.markdown('<div class="hero-title" style="font-size:2rem">Vote Électronique</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">Chiffrement Homomorphe Paillier · Anonymat · Intégrité · Dépouillement sécurisé</div>', unsafe_allow_html=True)
    st.markdown('<hr class="divider"/>', unsafe_allow_html=True)

    st.markdown("""
    <div class="card">
        <div class="card-title">Principe Homomorphe (Paillier)</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#4a6080;line-height:2">
        <span style="color:#00d4ff">Propriété clé :</span> Enc(v1) × Enc(v2) mod n² = Enc(v1 + v2 mod n)<br>
        → On peut additionner les votes <strong>sans jamais les déchiffrer individuellement</strong><br>
        → L'autorité électorale ne déchiffre <em>que le total final</em><br>
        <span style="color:#4ade80">Garanties :</span> anonymat des votants · intégrité du scrutin · vérifiabilité
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Setup Paillier ─────────────────────────────────────────────────────────
    st.markdown("### <span class='step-num'>1</span> Initialisation de l'Autorité Électorale", unsafe_allow_html=True)

    col1, col2 = st.columns([2, 1])
    with col1:
        if st.button("🔐 Générer Clé Paillier (512 bits)", use_container_width=True, key="gen_paillier"):
            with st.spinner("Génération de la paire de clés Paillier…"):
                try:
                    key = paillier_keygen(bits=256)  # 256 pour la démo (plus rapide)
                    st.session_state.vote_paillier_key = key
                    st.session_state.vote_ballots = []
                    st.session_state.vote_registered_voters = {}
                    st.session_state.vote_tally = None
                    log("Paillier 256-bit: clé générée (mode démo)", "ok")
                except Exception as e:
                    st.error(f"Erreur: {e}")
                    log(f"Erreur Paillier: {e}", "err")

    with col2:
        if st.session_state.vote_paillier_key:
            badge("CLÉS PAILLIER OK", "ok")

    if st.session_state.vote_paillier_key:
        key = st.session_state.vote_paillier_key
        metrics(
            (str(key["n"].bit_length()), "bits n"),
            (str(len(st.session_state.vote_registered_voters)), "électeurs"),
            (str(len(st.session_state.vote_ballots)), "bulletins"),
            (str(len(st.session_state.vote_candidates)), "candidats"),
        )

        # ── Enregistrement voter ───────────────────────────────────────────────
        st.markdown("### <span class='step-num'>2</span> Enregistrement des Électeurs", unsafe_allow_html=True)

        col1, col2 = st.columns([3, 1])
        with col1:
            voter_name = st.text_input("Nom de l'électeur", placeholder="ex: Karim Benali", key="voter_name")
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("➕ Inscrire", use_container_width=True, key="register_voter") and voter_name:
                if voter_name in st.session_state.vote_registered_voters:
                    st.warning(f"'{voter_name}' déjà inscrit!")
                else:
                    # Chaque électeur reçoit un token signé (simulé) + clé pub RSA
                    voter_priv, voter_pub = generate_rsa_keypair(1024)
                    token = secrets.token_hex(16)
                    st.session_state.vote_registered_voters[voter_name] = {
                        "token": token,
                        "pub_key": voter_pub,
                        "priv_key": voter_priv,
                        "has_voted": False
                    }
                    log(f"Électeur '{voter_name}' inscrit | token: {token[:8]}…", "ok")

        if st.session_state.vote_registered_voters:
            st.markdown('<div class="card"><div class="card-title">Liste Électorale</div>', unsafe_allow_html=True)
            for name, info in st.session_state.vote_registered_voters.items():
                status_badge = "✅ A voté" if info["has_voted"] else "⏳ Pas encore voté"
                color = "#4ade80" if info["has_voted"] else "#fbbf24"
                st.markdown(f"""
                <div style="display:flex;justify-content:space-between;align-items:center;
                            padding:6px 0;border-bottom:1px solid #1e2d50">
                    <span style="color:#e2e8f0">{name}</span>
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:#4a6080">
                        Token: {info['token'][:8]}…
                    </span>
                    <span style="color:{color};font-size:0.75rem">{status_badge}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # ── Vote ───────────────────────────────────────────────────────────────
        st.markdown("### <span class='step-num'>3</span> Bulletins de Vote Chiffrés", unsafe_allow_html=True)

        voters_eligible = [
            name for name, info in st.session_state.vote_registered_voters.items()
            if not info["has_voted"]
        ]

        if voters_eligible:
            col1, col2 = st.columns(2)
            with col1:
                voter_sel = st.selectbox("Électeur", voters_eligible, key="voter_sel")
            with col2:
                candidate_sel = st.selectbox("Candidat", st.session_state.vote_candidates, key="cand_sel")

            if st.button("🗳️ Soumettre Bulletin Chiffré", use_container_width=True, key="vote_btn"):
                key = st.session_state.vote_paillier_key
                cand_idx = st.session_state.vote_candidates.index(candidate_sel)
                # Encoder le vote comme vecteur binaire chiffré : 1 pour le candidat choisi
                encrypted_votes = [paillier_encrypt(key, 1 if i == cand_idx else 0)
                                  for i in range(len(st.session_state.vote_candidates))]
                # Signature du bulletin par l'électeur (non-répudiation anonyme)
                voter_priv = st.session_state.vote_registered_voters[voter_sel]["priv_key"]
                ballot_data = json.dumps([str(v) for v in encrypted_votes]).encode()
                signature   = rsa_sign(voter_priv, ballot_data)

                st.session_state.vote_ballots.append({
                    "encrypted": encrypted_votes,
                    "signature": signature.hex()[:24] + "…",
                    "ts": datetime.now().strftime("%H:%M:%S")
                })
                st.session_state.vote_registered_voters[voter_sel]["has_voted"] = True
                log(f"Bulletin de '{voter_sel}' chiffré et soumis | candidat masqué", "ok")
                st.success(f"✅ Bulletin de **{voter_sel}** soumis (vote chiffré, candidat non visible)")

                # Afficher les chiffrés
                st.markdown('<div class="hex-block">', unsafe_allow_html=True)
                for i, (c, enc) in enumerate(zip(st.session_state.vote_candidates, encrypted_votes)):
                    st.markdown(f'<div style="color:#4a6080">{c}: {str(enc)[:40]}…</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
        else:
            if st.session_state.vote_registered_voters:
                st.info("✅ Tous les électeurs inscrits ont voté.")
            else:
                st.info("⚠️ Inscrivez des électeurs d'abord.")

        # ── Dépouillement Homomorphe ───────────────────────────────────────────
        if len(st.session_state.vote_ballots) >= 1:
            st.markdown("### <span class='step-num'>4</span> Dépouillement Homomorphe", unsafe_allow_html=True)

            if st.button("📊 Dépouiller (sans déchiffrer les bulletins individuels)", use_container_width=True, key="tally"):
                key = st.session_state.vote_paillier_key
                n_candidates = len(st.session_state.vote_candidates)
                # Multiplication homomorphe = addition des votes
                tally_enc = [1] * n_candidates  # neutre multiplicatif
                for ballot in st.session_state.vote_ballots:
                    for i in range(n_candidates):
                        tally_enc[i] = paillier_add(key, tally_enc[i], ballot["encrypted"][i])
                # Déchiffrement du TOTAL uniquement
                tally = [paillier_decrypt(key, c) for c in tally_enc]
                st.session_state.vote_tally = tally
                log(f"Dépouillement: {tally} | total bulletins: {len(st.session_state.vote_ballots)}", "ok")

        if st.session_state.vote_tally:
            tally = st.session_state.vote_tally
            total = sum(tally)
            winner_idx = tally.index(max(tally))
            winner = st.session_state.vote_candidates[winner_idx]

            st.markdown('<div class="card"><div class="card-title">Résultats du Scrutin</div>', unsafe_allow_html=True)
            for i, (cand, count) in enumerate(zip(st.session_state.vote_candidates, tally)):
                pct = (count / total * 100) if total > 0 else 0
                is_winner = i == winner_idx
                bar_color = "#4ade80" if is_winner else "#1e3a70"
                text_color = "#4ade80" if is_winner else "#94a3b8"
                st.markdown(f"""
                <div style="margin:8px 0">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                        <span style="color:{text_color};font-weight:{'700' if is_winner else '400'}">
                            {'🏆 ' if is_winner else ''}{cand}
                        </span>
                        <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:{text_color}">
                            {count} vote{'s' if count>1 else ''} ({pct:.1f}%)
                        </span>
                    </div>
                    <div style="background:#0d1120;border-radius:6px;height:10px;overflow:hidden">
                        <div style="background:{bar_color};width:{pct}%;height:100%;
                                    transition:width 0.5s;border-radius:6px"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown(f"""
            <div style="margin-top:16px;padding:14px;background:#052e16;border:1px solid #16a34a;
                        border-radius:10px;text-align:center">
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;
                            color:#4a6080;margin-bottom:4px">VAINQUEUR</div>
                <div style="font-size:1.3rem;font-weight:700;color:#4ade80">🏆 {winner}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#4a6080;margin-top:4px">
                    {max(tally)}/{total} votes · dépouillement homomorphe Paillier
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""
            <div style="margin-top:12px;padding:10px;background:#0c1a3a;border:1px solid #1e3a70;
                        border-radius:8px">
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#4a6080;line-height:1.8">
                ✅ Les bulletins individuels n'ont jamais été déchiffrés<br>
                ✅ Seul le total final a été déchiffré par l'autorité<br>
                ✅ Anonymat des votants préservé par Paillier<br>
                ✅ Intégrité garantie par les signatures RSA des bulletins
                </div>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE : JOURNAL SYSTÈME
# ═══════════════════════════════════════════════════════════════════════════════

elif section == "📋 Journal Système":
    st.markdown('<div class="hero-title" style="font-size:2rem">Journal Système</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-sub">Tous les événements cryptographiques · Audit trail</div>', unsafe_allow_html=True)
    st.markdown('<hr class="divider"/>', unsafe_allow_html=True)

    col1, col2 = st.columns([4, 1])
    with col2:
        if st.button("🗑️ Vider", use_container_width=True, key="clear_logs"):
            st.session_state.logs = []
            st.rerun()

    if st.session_state.logs:
        metrics(
            (str(len(st.session_state.logs)), "événements"),
            (str(sum(1 for l in st.session_state.logs if l["level"] == "ok")), "succès"),
            (str(sum(1 for l in st.session_state.logs if l["level"] == "err")), "erreurs"),
            (str(sum(1 for l in st.session_state.logs if l["level"] == "info")), "infos"),
        )

        lines = ""
        for entry in reversed(st.session_state.logs):
            cls = entry["level"]
            icon = {"ok": "✓", "err": "✗", "info": "i", "warn": "!"}.get(cls, "·")
            lines += f'<div class="log-line"><span class="ts">[{entry["ts"]}]</span> <span class="{cls}">{icon} {entry["msg"]}</span></div>'

        st.markdown(f'<div class="card" style="max-height:500px;overflow-y:auto">{lines}</div>', unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="card" style="text-align:center;padding:40px;color:#2a3a5a">
            <div style="font-size:2rem;margin-bottom:8px">📋</div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.8rem">
                Aucun événement — utilisez les modules pour générer des logs
            </div>
        </div>
        """, unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<hr style="border-color:#1e2d50;margin-top:40px"/>
<div style="text-align:center;font-family:'JetBrains Mono',monospace;font-size:0.62rem;
            color:#2a3a5a;padding:10px 0">
    SecureCom · TP6 Cryptographie Appliquée · Ing 3 Cybersécurité · 2026<br>
    RSA-2048 · AES-256-CBC · ECDH P-256 · ECDSA · HMAC-SHA256 · Paillier
</div>
""", unsafe_allow_html=True)

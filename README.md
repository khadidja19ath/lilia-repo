# 🔐 SecureCom — TP6 Cryptographie Appliquée

Application interactive de sécurisation des communications, développée dans le cadre du TP 6 — Ing 3 Cybersécurité.

---

## 📋 Description

SecureCom est une application **Streamlit** qui simule et démontre plusieurs protocoles de communication sécurisée à travers une interface visuelle moderne. Elle couvre quatre modules cryptographiques indépendants.

---

## 🧩 Modules

### 🔌 TCP/IP Sécurisé
- Génération de paires de clés **RSA-2048**
- Handshake simulé avec échange de clé de session
- Chiffrement des messages via **AES-256-CBC**
- Vérification d'intégrité par **HMAC-SHA256**
- Chiffrement hybride complet **RSA + AES**

### 📡 Bluetooth RFCOMM
- Échange de clés **ECDH P-256** avec dérivation **HKDF**
- Chiffrement des trames via **AES-256-CBC**
- Authentification par signatures **ECDSA P-256**
- Simulation d'attaque **MITM** et contre-mesure ECDSA

### 📶 Wi-Fi / UDP Chat
- Chat chiffré **End-to-End** sans connexion TCP
- Datagrammes UDP contenant : `IV | Ciphertext | HMAC | Signature RSA-PSS`
- Authentification mutuelle par **RSA-PSS-SHA256**
- Adapté aux environnements IoT / mobile

### 🗳️ Vote Électronique
- Chiffrement homomorphe **Paillier**
- Dépouillement sans déchiffrement individuel des bulletins
- Enregistrement des électeurs avec tokens et clés **RSA-1024**
- Résultats vérifiables avec anonymat garanti

---

## 🛡️ Garanties de Sécurité

| Propriété | Mécanisme |
|---|---|
| Confidentialité | AES-256-CBC / RSA-OAEP |
| Intégrité | HMAC-SHA256 / RSA-PSS |
| Authenticité | Certificats RSA / ECDSA P-256 |
| Non-répudiation | Signatures numériques vérifiables |
| Anonymat (vote) | Chiffrement homomorphe Paillier |

---

## ⚙️ Installation

### Prérequis
- Python 3.10+
- pip

### Installer les dépendances

```bash
pip install streamlit cryptography sympy
```

Optionnel (pour les QR codes) :
```bash
pip install qrcode pillow
```

### Lancer l'application

```bash
streamlit run app.py
```

---

## 📁 Structure du Projet

```
.
├── app.py          # Application principale Streamlit
└── README.md       # Ce fichier
```

---

## 🔧 Technologies Utilisées

- **Streamlit** — Interface utilisateur
- **cryptography** — RSA, AES, ECDH, ECDSA, HKDF
- **sympy** — Génération des nombres premiers pour Paillier
- **hashlib / hmac** — HMAC-SHA256
- **secrets** — Génération sécurisée des clés et tokens

---

## 📚 Concepts Cryptographiques Couverts

- Chiffrement asymétrique RSA (OAEP, PSS)
- Chiffrement symétrique AES-CBC avec padding PKCS7
- Échange de clés Diffie-Hellman sur courbes elliptiques (ECDH)
- Signatures numériques ECDSA et RSA-PSS
- Dérivation de clés HKDF-SHA256
- Chiffrement homomorphe Paillier
- Protocole de handshake et session sécurisée

---

## 👨‍🎓 Contexte Académique

> TP 6 · Sécurisation des Communications  
> Niveau : Ingénieur 3ème année · Spécialité Cybersécurité · 2026

---

## ⚠️ Avertissement

Ce projet est développé à **des fins pédagogiques uniquement**. Les paramètres cryptographiques (taille des clés Paillier réduite à 256 bits en mode démo) sont volontairement allégés pour la rapidité d'exécution. Ne pas utiliser en production.

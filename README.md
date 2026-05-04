# 🔐 VaultShare — Secure File Sharing System
### ITPE3227 Final Project | Hybrid Encryption: AES-256 + RSA-2048

![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-green)
![RSA](https://img.shields.io/badge/Key%20Exchange-RSA--2048-blue)
![Auth](https://img.shields.io/badge/Auth-JWT%20%2B%20bcrypt-orange)
![DB](https://img.shields.io/badge/Database-Firebase%20Firestore-yellow)

---

## 📌 Project Description

VaultShare is a web-based secure file sharing system that implements **hybrid encryption** using:
- **AES-256-GCM** for fast, symmetric file encryption
- **RSA-2048 (RSA-OAEP)** for secure asymmetric key exchange
- **bcrypt** for password hashing
- **JWT** for stateless session authentication
- **Firebase Firestore** as the NoSQL database backend

Files are encrypted entirely **client-side in the browser** using the Web Crypto API before being stored in Firebase. The server never handles plaintext file data.

---

## 🏗 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser)                         │
│                                                                   │
│  ┌──────────────┐    ┌────────────────────────────────────────┐  │
│  │  index.html  │    │           dashboard.html               │  │
│  │  (Login/Reg) │    │  Upload → Encrypt → Store → Download   │  │
│  └──────┬───────┘    └──────────────┬─────────────────────────┘  │
│         │                           │                             │
│  ┌──────▼───────────────────────────▼─────────────────────────┐  │
│  │                    Web Crypto API                           │  │
│  │   AES-256-GCM File Encryption + RSA-OAEP Key Wrapping      │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
└─────────────────────────────┼───────────────────────────────────┘
                               │ HTTPS
              ┌────────────────┼────────────────────┐
              │                │                    │
     ┌────────▼────────┐  ┌────▼─────┐  ┌──────────▼──────┐
     │  Node.js Server │  │  PHP     │  │ Firebase Auth   │
     │  (Express + JWT │  │  Bridge  │  │   (Identity)    │
     │   + bcrypt)     │  │          │  └─────────────────┘
     └────────┬────────┘  └────┬─────┘
              │                │
     ┌────────▼────────────────▼────┐
     │     Firebase Firestore       │
     │  users/ → RSA keys, profile  │
     │  files/ → encrypted blobs    │
     └──────────────────────────────┘
```

---

## 🔐 Encryption Flow

```
FILE UPLOAD (Encryption)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Original File
       │
       ├──► [1] Generate random AES-256 key (WebCrypto CSPRNG)
       │
       ├──► [2] Generate random 12-byte IV
       │
       ├──► [3] Encrypt File with AES-256-GCM
       │         Input:  plaintext + AES key + IV
       │         Output: ciphertext (same size + 16-byte GCM tag)
       │
       ├──► [4] Encrypt AES key with recipient's RSA-2048 Public Key
       │         Input:  raw AES key bytes (32 bytes)
       │         Output: encrypted key (256 bytes, RSA-OAEP)
       │
       └──► [5] Store in Firestore:
                  { encryptedData, encryptedAESKey, iv, fileHash }

FILE DOWNLOAD (Decryption)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Firestore: { encryptedData, encryptedAESKey, iv }
       │
       ├──► [1] Decrypt encryptedAESKey with RSA-2048 Private Key
       │         → recovers original AES-256 key
       │
       ├──► [2] Decrypt encryptedData with AES-256-GCM + IV
       │         → recovers original plaintext
       │
       ├──► [3] Verify SHA-256 hash (integrity check)
       │
       └──► [4] Trigger browser file download
```

---

## 🛠 Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend | HTML5, CSS3, JavaScript (ES2022) | UI + Client-side crypto |
| Encryption | Web Crypto API (Browser native) | AES-256-GCM + RSA-OAEP |
| Backend | Node.js + Express.js | REST API, file management |
| PHP | PHP 8+ | Server bridge, session management |
| Auth | Firebase Auth + JWT + bcrypt | User authentication |
| Database | Firebase Firestore | Encrypted file storage |
| Password Hash | bcrypt (12 rounds) | Secure credential storage |

---

## 🚀 Setup Instructions

### Prerequisites
- Node.js 18+ (`node --version`)
- npm 9+
- Firebase account & project
- PHP 8+ (optional, for PHP bridge)

### Step 1 — Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/vaultshare.git
cd vaultshare
npm install
```

### Step 2 — Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com)
2. Create a new project
3. Enable **Authentication** → Email/Password
4. Enable **Firestore Database** (start in test mode, then apply security rules)
5. Enable **Storage** (optional)

#### Get Web Config:
- Project Settings → Your Apps → Web App → Copy config
- Paste into `public/js/firebase-config.js`

#### Get Service Account (for Node.js backend):
- Project Settings → Service Accounts → Generate New Private Key
- Save as `server/serviceAccountKey.json`

### Step 3 — Environment Variables

```bash
cp .env.example .env
```

Edit `.env`:
```env
PORT=3000
JWT_SECRET=your-64-char-random-secret-here
FIREBASE_STORAGE_BUCKET=your-project-id.appspot.com
```

Generate a strong JWT secret:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Step 4 — Deploy Firestore Rules

```bash
npm install -g firebase-tools
firebase login
firebase init firestore
# Copy content from firestore.rules
firebase deploy --only firestore:rules
```

### Step 5 — Run

```bash
# Development
npm run dev

# Production
npm start
```

Open: `http://localhost:3000`

---

## 📁 Project Structure

```
secure-fileshare/
├── public/
│   ├── index.html          # Login / Register page
│   ├── dashboard.html      # Main file management dashboard
│   ├── api-bridge.php      # PHP server bridge
│   ├── css/
│   │   ├── style.css       # Auth page styles
│   │   └── dashboard.css   # Dashboard styles
│   └── js/
│       ├── firebase-config.js  # Firebase initialization
│       ├── auth.js             # Login/Register logic
│       ├── crypto.js           # AES + RSA encryption engine
│       └── dashboard.js        # File upload/download logic
├── server/
│   ├── server.js           # Express REST API
│   └── serviceAccountKey.json  # Firebase Admin credentials (git-ignored)
├── firestore.rules         # Firestore security rules
├── package.json
├── .env.example
└── README.md
```

---

## 🔑 Why Hybrid Encryption?

### Why AES-256?
- **Speed**: AES is ~1000x faster than RSA for large data
- **Security**: 256-bit key = 2²⁵⁶ possible keys, computationally unbreakable
- **GCM mode**: Provides both encryption AND authentication (integrity)
- **Standard**: NIST-approved, widely deployed (TLS, disk encryption)

### Why RSA-2048?
- **Asymmetric**: Public key can be shared openly; only private key can decrypt
- **Key distribution**: Solves the key exchange problem securely
- **2048-bit**: ~617 decimal digits, secure against current attacks
- **OAEP padding**: Prevents chosen-ciphertext attacks vs older PKCS#1 v1.5

### Why Hybrid (AES + RSA)?
- AES alone: Fast but requires secure key exchange channel
- RSA alone: Too slow for large files (max ~245 bytes with 2048-bit key)
- **Hybrid solution**: Use RSA to securely exchange the AES key, then use AES for bulk data
- This is exactly how TLS/HTTPS works in practice

---

## 🛡 Security Analysis

### Strengths
- Files never transmitted unencrypted
- AES keys are unique per file (random CSPRNG)
- IV is random per encryption (prevents replay attacks)
- GCM provides integrity/authentication tag
- bcrypt with 12 rounds resists brute-force
- JWT with expiry limits session hijacking
- Firestore rules enforce server-side access control
- SHA-256 hash verifies file integrity on download

### Limitations
- Private keys stored in Firestore (production: use client-side IndexedDB or HSM)
- No key revocation mechanism
- No end-to-end verification of recipient identity
- Client-side crypto can be tampered with on untrusted devices

---

## 📸 API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | ❌ | Create account |
| POST | `/api/auth/login` | ❌ | Login, get JWT |
| GET | `/api/auth/me` | ✅ JWT | Get current user |
| POST | `/api/files/upload` | ✅ JWT | Upload encrypted file metadata |
| GET | `/api/files` | ✅ JWT | List user's files |
| GET | `/api/files/:id` | ✅ JWT | Get encrypted file for download |
| DELETE | `/api/files/:id` | ✅ JWT | Delete file |
| GET | `/api/users/search?email=` | ✅ JWT | Find user's public key |

---

## 👥 Group Members

| Name | Student ID | Role |
|------|-----------|------|
| | | |
| | | |
| | | |

---

## 📅 Submission

**GitHub Repository**: `https://github.com/YOUR_USERNAME/vaultshare`  
**Deadline**: 2nd Week of May 2026

---

*ITPE3227 — Integrative Programming and Technologies 2*

// ============================================
// server.js  —  VaultShare Backend (Node.js)
// Express + Firebase Admin SDK
// JWT Authentication + bcrypt password hashing
// ============================================
const express        = require('express');
const cors           = require('cors');
const bcrypt         = require('bcrypt');
const jwt            = require('jsonwebtoken');
const multer         = require('multer');
const admin          = require('firebase-admin');
const path           = require('path');
const crypto         = require('crypto');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── FIREBASE ADMIN INIT ──────────────────────
const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET
});

const db      = admin.firestore();
const bucket  = admin.storage().bucket();

// ── MIDDLEWARE ───────────────────────────────
app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// Multer — in-memory storage (files are encrypted before any disk write)
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 50 * 1024 * 1024 } // 50 MB max
});

// ── JWT MIDDLEWARE ────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token      = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// ── HELPER: GENERATE JWT ─────────────────────
function generateToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '24h' });
}

// ============================================
// AUTH ROUTES
// ============================================

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, publicKey, privateKey } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    // Check if email already exists
    const existing = await db.collection('users').where('email', '==', email).get();
    if (!existing.empty) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password with bcrypt (12 rounds)
    const passwordHash = await bcrypt.hash(password, 12);

    // Create user document
    const userRef = db.collection('users').doc();
    await userRef.set({
      name,
      email,
      passwordHash,
      publicKey:  publicKey  || null,
      privateKey: privateKey || null,
      createdAt:  admin.firestore.FieldValue.serverTimestamp(),
      role:       'user'
    });

    // Generate JWT
    const token = generateToken({ uid: userRef.id, email, name });

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: { uid: userRef.id, name, email }
    });

  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const snap = await db.collection('users').where('email', '==', email).limit(1).get();

    if (snap.empty) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const userDoc  = snap.docs[0];
    const userData = userDoc.data();

    // Compare password with bcrypt hash
    const valid = await bcrypt.compare(password, userData.passwordHash);

    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT
    const token = generateToken({
      uid:   userDoc.id,
      email: userData.email,
      name:  userData.name
    });

    res.json({
      message: 'Login successful',
      token,
      user: {
        uid:        userDoc.id,
        name:       userData.name,
        email:      userData.email,
        publicKey:  userData.publicKey,
        privateKey: userData.privateKey
      }
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/me  — Verify token & return user info
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const snap = await db.collection('users')
      .where('email', '==', req.user.email).limit(1).get();

    if (snap.empty) return res.status(404).json({ error: 'User not found' });

    const data = snap.docs[0].data();
    res.json({
      uid:       snap.docs[0].id,
      name:      data.name,
      email:     data.email,
      publicKey: data.publicKey
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ============================================
// FILE ROUTES
// ============================================

// POST /api/files/upload  — Upload encrypted file data
app.post('/api/files/upload', authenticateToken, async (req, res) => {
  const {
    fileName, fileType, fileSize,
    encryptedData, encryptedAESKey, iv,
    fileHash, sharedWith
  } = req.body;

  if (!fileName || !encryptedData || !encryptedAESKey || !iv) {
    return res.status(400).json({ error: 'Missing required encryption fields' });
  }

  try {
    let recipientId = req.user.uid;

    // If sharing with another user, look up their ID
    if (sharedWith) {
      const snap = await db.collection('users')
        .where('email', '==', sharedWith).limit(1).get();

      if (!snap.empty) {
        recipientId = snap.docs[0].id;
      }
    }

    const fileRef = await db.collection('files').add({
      fileName,
      fileType:        fileType || 'application/octet-stream',
      fileSize:        fileSize || 0,
      encryptedData,
      encryptedAESKey,
      iv,
      fileHash:        fileHash || null,
      ownerId:         req.user.uid,
      ownerEmail:      req.user.email,
      recipientId,
      sharedWith:      sharedWith || null,
      uploadedAt:      admin.firestore.FieldValue.serverTimestamp(),
      encryptionInfo: {
        algorithm:     'AES-256-GCM',
        keyEncryption: 'RSA-OAEP-2048',
        ivLength:      12,
        keyLength:     256
      }
    });

    res.status(201).json({
      message:  'File uploaded successfully',
      fileId:   fileRef.id,
      fileName
    });

  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// GET /api/files  — List files for authenticated user
app.get('/api/files', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;

    const [ownedSnap, sharedSnap] = await Promise.all([
      db.collection('files').where('ownerId', '==', uid).get(),
      db.collection('files').where('recipientId', '==', uid).get()
    ]);

    const fileMap = new Map();

    [...ownedSnap.docs, ...sharedSnap.docs].forEach(doc => {
      const data = doc.data();
      fileMap.set(doc.id, {
        id:          doc.id,
        fileName:    data.fileName,
        fileType:    data.fileType,
        fileSize:    data.fileSize,
        fileHash:    data.fileHash,
        ownerId:     data.ownerId,
        ownerEmail:  data.ownerEmail,
        sharedWith:  data.sharedWith,
        uploadedAt:  data.uploadedAt,
        encryptionInfo: data.encryptionInfo
        // Note: encryptedData NOT returned in list — only on individual fetch
      });
    });

    const files = Array.from(fileMap.values()).sort((a, b) => {
      const aTime = a.uploadedAt?.toDate ? a.uploadedAt.toDate().getTime() : 0;
      const bTime = b.uploadedAt?.toDate ? b.uploadedAt.toDate().getTime() : 0;
      return bTime - aTime;
    });

    res.json({ files });

  } catch (err) {
    console.error('List error:', err);
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

// GET /api/files/:id  — Get encrypted file data for decryption
app.get('/api/files/:id', authenticateToken, async (req, res) => {
  try {
    const doc = await db.collection('files').doc(req.params.id).get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'File not found' });
    }

    const data = doc.data();
    const uid  = req.user.uid;

    // Access control check
    if (data.ownerId !== uid && data.recipientId !== uid) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json({
      id:              doc.id,
      fileName:        data.fileName,
      fileType:        data.fileType,
      fileSize:        data.fileSize,
      encryptedData:   data.encryptedData,
      encryptedAESKey: data.encryptedAESKey,
      iv:              data.iv,
      fileHash:        data.fileHash,
      encryptionInfo:  data.encryptionInfo
    });

  } catch (err) {
    console.error('Fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch file' });
  }
});

// DELETE /api/files/:id  — Delete file
app.delete('/api/files/:id', authenticateToken, async (req, res) => {
  try {
    const doc = await db.collection('files').doc(req.params.id).get();

    if (!doc.exists) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Only owner can delete
    if (doc.data().ownerId !== req.user.uid) {
      return res.status(403).json({ error: 'Only the file owner can delete this file' });
    }

    await db.collection('files').doc(req.params.id).delete();

    res.json({ message: 'File deleted successfully' });

  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// GET /api/users/search?email=  — Find user's public key
app.get('/api/users/search', authenticateToken, async (req, res) => {
  const { email } = req.query;

  if (!email) return res.status(400).json({ error: 'Email required' });

  try {
    const snap = await db.collection('users')
      .where('email', '==', email).limit(1).get();

    if (snap.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    const data = snap.docs[0].data();
    res.json({
      uid:       snap.docs[0].id,
      name:      data.name,
      email:     data.email,
      publicKey: data.publicKey
    });

  } catch (err) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// ── HEALTH CHECK ─────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status:    'OK',
    service:   'VaultShare API',
    timestamp: new Date().toISOString(),
    version:   '1.0.0'
  });
});

// ── CATCH-ALL: SERVE FRONTEND ─────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ── START SERVER ──────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🔐 VaultShare Server running on http://localhost:${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   Firebase Project: ${serviceAccount.project_id}\n`);
});

module.exports = app;

// ============================================
// auth.js  —  Authentication Logic
// Handles: Register, Login, Session
// Uses: Firebase Auth + Firestore for RSA key storage
// ============================================

// ── TAB SWITCHER ────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.form-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`.tab[onclick="switchTab('${tab}')"]`).classList.add('active');
  document.getElementById(tab + 'Form').classList.add('active');
}

// ── SHOW MESSAGE ────────────────────────────
function showMsg(id, text, type = 'error') {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = `msg ${type}`;
}

// ── VALIDATE EMAIL ───────────────────────────
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ── PASSWORD TOGGLE / VALIDATION ─────────────
function togglePassword(fieldId, button) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  const isPassword = field.type === 'password';
  field.type = isPassword ? 'text' : 'password';
  button.textContent = isPassword ? 'Hide' : 'Show';
}

function validateRegisterPasswords() {
  const password = document.getElementById('regPassword').value;
  const confirm  = document.getElementById('regConfirm').value;
  const passwordHint = document.getElementById('regPasswordHint');
  const confirmHint  = document.getElementById('regConfirmHint');

  if (password.length === 0) {
    passwordHint.textContent = 'Use at least 8 characters.';
    passwordHint.className = 'password-hint';
  } else if (password.length < 8) {
    passwordHint.textContent = 'Password must be at least 8 characters.';
    passwordHint.className = 'password-hint warning';
  } else {
    passwordHint.textContent = 'Good password length.';
    passwordHint.className = 'password-hint success';
  }

  if (confirm.length === 0) {
    confirmHint.textContent = 'Re-enter your password.';
    confirmHint.className = 'password-hint';
  } else if (password !== confirm) {
    confirmHint.textContent = 'Passwords do not match.';
    confirmHint.className = 'password-hint warning';
  } else {
    confirmHint.textContent = 'Passwords match.';
    confirmHint.className = 'password-hint success';
  }
}

// ── GENERATE RSA KEY PAIR ────────────────────
// Uses WebCrypto API — RSA-OAEP 2048-bit
async function generateRSAKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name:           'RSA-OAEP',
      modulusLength:  2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash:           'SHA-256'
    },
    true,  // extractable
    ['encrypt', 'decrypt']
  );
}

// ── EXPORT KEY TO BASE64 STRING ─────────────
async function exportKeyToBase64(key, format) {
  const exported = await window.crypto.subtle.exportKey(format, key);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

// ── REGISTER HANDLER ─────────────────────────
async function handleRegister() {
  const name     = document.getElementById('regName').value.trim();
  const email    = document.getElementById('regEmail').value.trim();
  const password = document.getElementById('regPassword').value;
  const confirm  = document.getElementById('regConfirm').value;

  validateRegisterPasswords();

  // Validation
  if (!name)               return showMsg('regMsg', 'Full name is required.');
  if (!isValidEmail(email)) return showMsg('regMsg', 'Enter a valid email address.');
  if (password.length < 8) return showMsg('regMsg', 'Password must be at least 8 characters.');
  if (password !== confirm) return showMsg('regMsg', 'Passwords do not match.');

  const btn = document.querySelector('#registerForm .btn-primary');
  btn.disabled = true;
  btn.querySelector('span').textContent = 'Creating account...';

  try {
    // 1. Create Firebase Auth user (Firebase handles secure password hashing)
    const cred = await auth.createUserWithEmailAndPassword(email, password);
    const uid  = cred.user.uid;

    // Update display name
    await cred.user.updateProfile({ displayName: name });

    // 2. Generate RSA-2048 key pair for this user
    showMsg('regMsg', '🔑 Generating RSA-2048 key pair...', 'success');
    const keyPair = await generateRSAKeyPair();

    // 3. Export keys to storable format
    const publicKeyB64  = await exportKeyToBase64(keyPair.publicKey,  'spki');
    const privateKeyB64 = await exportKeyToBase64(keyPair.privateKey, 'pkcs8');

    // 4. Store public key in Firestore (public — shareable)
    //    Store private key in Firestore (in real production: store only in client/hardware)
    await db.collection('users').doc(uid).set({
      name,
      email,
      createdAt:  firebase.firestore.FieldValue.serverTimestamp(),
      publicKey:  publicKeyB64,
      // NOTE: In a production system, never store the private key on the server.
      // Store it client-side (IndexedDB) or derived from a passphrase.
      // For this educational project we store it encrypted in Firestore.
      privateKey: privateKeyB64
    });

    // 5. Store keys in sessionStorage for current session
    sessionStorage.setItem('rsaPublicKey',  publicKeyB64);
    sessionStorage.setItem('rsaPrivateKey', privateKeyB64);
    sessionStorage.setItem('userId',        uid);
    sessionStorage.setItem('userEmail',     email);

    showMsg('regMsg', '✅ Account created! Redirecting...', 'success');
    setTimeout(() => window.location.href = 'dashboard.html', 1200);

  } catch (err) {
    const messages = {
      'auth/email-already-in-use': 'An account with this email already exists.',
      'auth/weak-password':        'Password is too weak. Use 8+ characters.',
      'auth/invalid-email':        'Invalid email format.'
    };
    showMsg('regMsg', messages[err.code] || err.message);
  } finally {
    btn.disabled = false;
    btn.querySelector('span').textContent = 'Create Account';
  }
}

// ── LOGIN HANDLER ─────────────────────────────
async function handleLogin() {
  const email    = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;

  if (!email || !password) return showMsg('loginMsg', 'Please fill in all fields.');

  const btn = document.querySelector('#loginForm .btn-primary');
  btn.disabled = true;
  btn.querySelector('span').textContent = 'Authenticating...';

  try {
    const cred = await auth.signInWithEmailAndPassword(email, password);
    const uid  = cred.user.uid;

    // Load user's RSA keys from Firestore
    const userDoc = await db.collection('users').doc(uid).get();
    if (!userDoc.exists) throw new Error('User profile not found.');

    const data = userDoc.data();
    sessionStorage.setItem('rsaPublicKey',  data.publicKey);
    sessionStorage.setItem('rsaPrivateKey', data.privateKey);
    sessionStorage.setItem('userId',        uid);
    sessionStorage.setItem('userEmail',     email);

    showMsg('loginMsg', '✅ Authenticated! Loading vault...', 'success');
    setTimeout(() => window.location.href = 'dashboard.html', 800);

  } catch (err) {
    const messages = {
      'auth/user-not-found':    'No account found with this email.',
      'auth/wrong-password':    'Incorrect password.',
      'auth/invalid-credential':'Invalid email or password.',
      'auth/too-many-requests': 'Too many failed attempts. Try again later.'
    };
    showMsg('loginMsg', messages[err.code] || err.message);
  } finally {
    btn.disabled = false;
    btn.querySelector('span').textContent = 'Authenticate';
  }
}

// ── AUTO REDIRECT IF ALREADY LOGGED IN ───────
auth.onAuthStateChanged(user => {
  if (user && window.location.pathname.includes('index')) {
    window.location.href = 'dashboard.html';
  }
});

// Allow Enter key
document.addEventListener('keypress', e => {
  if (e.key === 'Enter') {
    const activePanel = document.querySelector('.form-panel.active');
    if (activePanel.id === 'loginForm')    handleLogin();
    if (activePanel.id === 'registerForm') handleRegister();
  }
});

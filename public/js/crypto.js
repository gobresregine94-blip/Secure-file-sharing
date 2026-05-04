// ============================================
// crypto.js  —  Hybrid Encryption Engine
// AES-256-GCM  +  RSA-OAEP-2048
//
// ENCRYPTION FLOW:
//   File → AES-256 key (random) → Encrypted file blob
//          AES key → RSA Public Key → Encrypted AES key
//          Store: [encrypted file] + [encrypted AES key] + [IV]
//
// DECRYPTION FLOW:
//   Encrypted AES key → RSA Private Key → AES key
//   Encrypted file + AES key + IV → Original file
// ============================================

const CryptoEngine = (() => {

  // ── IMPORT RSA PUBLIC KEY FROM BASE64 ──────
  async function importPublicKey(base64) {
    const binaryDer = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return await window.crypto.subtle.importKey(
      'spki',
      binaryDer.buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
  }

  // ── IMPORT RSA PRIVATE KEY FROM BASE64 ─────
  async function importPrivateKey(base64) {
    const binaryDer = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return await window.crypto.subtle.importKey(
      'pkcs8',
      binaryDer.buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    );
  }

  // ── GENERATE RANDOM AES-256 KEY ─────────────
  async function generateAESKey() {
    return await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,       // extractable so we can encrypt it with RSA
      ['encrypt', 'decrypt']
    );
  }

  // ── EXPORT AES KEY TO RAW BYTES ─────────────
  async function exportAESKey(key) {
    return await window.crypto.subtle.exportKey('raw', key);
  }

  // ── IMPORT AES KEY FROM RAW BYTES ──────────
  async function importAESKey(rawKey) {
    return await window.crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ── ENCRYPT FILE WITH AES-256-GCM ──────────
  // Returns: { ciphertext: ArrayBuffer, iv: Uint8Array }
  async function encryptFile(fileBuffer, aesKey) {
    // 12-byte random IV (recommended for AES-GCM)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      fileBuffer
    );

    return { ciphertext, iv };
  }

  // ── DECRYPT FILE WITH AES-256-GCM ──────────
  async function decryptFile(ciphertext, aesKey, iv) {
    return await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ciphertext
    );
  }

  // ── ENCRYPT AES KEY WITH RSA PUBLIC KEY ────
  // Converts the raw AES key bytes → RSA-encrypted blob
  async function encryptAESKeyWithRSA(aesKey, rsaPublicKeyB64) {
    const rawAESKey   = await exportAESKey(aesKey);
    const rsaPublicKey = await importPublicKey(rsaPublicKeyB64);

    const encryptedKey = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      rsaPublicKey,
      rawAESKey
    );

    // Return as Base64 string for Firestore storage
    return btoa(String.fromCharCode(...new Uint8Array(encryptedKey)));
  }

  // ── DECRYPT AES KEY WITH RSA PRIVATE KEY ───
  async function decryptAESKeyWithRSA(encryptedKeyB64, rsaPrivateKeyB64) {
    const encryptedKey  = Uint8Array.from(atob(encryptedKeyB64), c => c.charCodeAt(0));
    const rsaPrivateKey = await importPrivateKey(rsaPrivateKeyB64);

    const rawAESKey = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      rsaPrivateKey,
      encryptedKey
    );

    return await importAESKey(rawAESKey);
  }

  // ── MAIN: FULL ENCRYPT FILE ─────────────────
  // Returns everything needed to store in Firestore
  async function encryptFileForUpload(fileBuffer, rsaPublicKeyB64, onStep) {
    const log = [];
    const stepCallback = typeof onStep === 'function' ? onStep : () => {};

    stepCallback(1, 'Generating random AES-256 key...');
    log.push(`[STEP 1] Generating AES-256 key (256-bit, random, WebCrypto CSPRNG)`);

    const aesKey = await generateAESKey();
    log.push(`[STEP 1] ✓ AES key generated`);

    stepCallback(2, 'Encrypting file with AES-256-GCM...');
    log.push(`[STEP 2] Encrypting file data with AES-256-GCM`);
    log.push(`[STEP 2] File size: ${fileBuffer.byteLength} bytes`);

    const { ciphertext, iv } = await encryptFile(fileBuffer, aesKey);
    const ivB64              = btoa(String.fromCharCode(...iv));
    log.push(`[STEP 2] ✓ File encrypted — ciphertext size: ${ciphertext.byteLength} bytes`);
    log.push(`[STEP 2] IV (Base64): ${ivB64}`);

    stepCallback(3, 'Encrypting AES key with RSA-2048...');
    log.push(`[STEP 3] Encrypting AES key using RSA-OAEP-2048 with recipient's public key`);

    const encryptedAESKeyB64 = await encryptAESKeyWithRSA(aesKey, rsaPublicKeyB64);
    log.push(`[STEP 3] ✓ AES key encrypted (RSA-OAEP output: 256 bytes → Base64)`);

    // Convert ciphertext to Base64 for Firestore storage
    const ciphertextB64 = btoa(
      String.fromCharCode(...new Uint8Array(ciphertext))
    );

    log.push(`[COMPLETE] Hybrid encryption successful`);
    log.push(`[COMPLETE] Storing: encrypted_file + encrypted_aes_key + iv`);

    return {
      ciphertextB64,
      encryptedAESKeyB64,
      ivB64,
      log
    };
  }

  // ── MAIN: FULL DECRYPT FILE ─────────────────
  async function decryptFileForDownload(ciphertextB64, encryptedAESKeyB64, ivB64, rsaPrivateKeyB64) {
    // 1. Decrypt the AES key using RSA private key
    const aesKey = await decryptAESKeyWithRSA(encryptedAESKeyB64, rsaPrivateKeyB64);

    // 2. Restore IV and ciphertext from Base64
    const iv         = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));

    // 3. Decrypt file
    const plaintext = await decryptFile(ciphertext.buffer, aesKey, iv);

    return plaintext;
  }

  // ── COMPUTE SHA-256 HASH OF FILE ────────────
  // For integrity verification
  async function computeFileHash(buffer) {
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    const hashArray  = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── FORMAT BYTES ────────────────────────────
  function formatBytes(bytes) {
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1024*1024)  return (bytes/1024).toFixed(1) + ' KB';
    return (bytes/(1024*1024)).toFixed(1) + ' MB';
  }

  // Public API
  return {
    encryptFileForUpload,
    decryptFileForDownload,
    computeFileHash,
    formatBytes
  };

})();

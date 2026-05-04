// ============================================
// dashboard.js
// Handles: file queue, encryption upload, listing, download
// Uses: Firebase Auth/Firestore + CryptoEngine
// ============================================

let pendingFiles = [];
let currentUserId = null;
let currentUserEmail = null;
let rsaPublicKey = null;
let rsaPrivateKey = null;

document.addEventListener('DOMContentLoaded', () => {
  auth.onAuthStateChanged(async (user) => {
    if (!user) {
      window.location.href = 'index.html';
      return;
    }

    currentUserId = user.uid;
    currentUserEmail = user.email || '';

    const usernameEl = document.getElementById('navUsername');
    if (usernameEl) usernameEl.textContent = currentUserEmail;

    await loadUserKeys(user.uid);
    await loadFiles();
    updateStorageDisplay([]);
  });
});

async function loadUserKeys(uid) {
  // Try session first
  rsaPublicKey = sessionStorage.getItem('rsaPublicKey');
  rsaPrivateKey = sessionStorage.getItem('rsaPrivateKey');

  if (rsaPublicKey && rsaPrivateKey) return;

  const docRef = db.collection('users').doc(uid);
  const doc = await docRef.get();

  let data = doc.exists ? doc.data() : null;

  // ✅ If keys exist in Firestore
  if (data?.publicKey && data?.privateKey) {
    rsaPublicKey = data.publicKey;
    rsaPrivateKey = data.privateKey;
  } else {
    // 🔥 AUTO-GENERATE KEYS
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    // Convert to Base64 safely
    function toBase64(buffer) {
      let binary = '';
      const bytes = new Uint8Array(buffer);
      const chunkSize = 0x8000;

      for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
      }

      return btoa(binary);
    }

    rsaPublicKey = toBase64(publicKeyBuffer);
    rsaPrivateKey = toBase64(privateKeyBuffer);

    //  SAVE TO FIRESTORE
    await docRef.set({
      publicKey: rsaPublicKey,
      privateKey: rsaPrivateKey
    }, { merge: true });
  }

  //  SAVE TO SESSION
  sessionStorage.setItem('rsaPublicKey', rsaPublicKey);
  sessionStorage.setItem('rsaPrivateKey', rsaPrivateKey);
}

async function handleLogout() {
  sessionStorage.clear();
  await auth.signOut();
  window.location.href = 'index.html';
}

function handleFileSelect(event) {
  addFilesToQueue(Array.from(event.target.files || []));
}

function handleDrop(event) {
  event.preventDefault();
  document.getElementById('uploadZone')?.classList.remove('drag-over');
  addFilesToQueue(Array.from(event.dataTransfer?.files || []));
}

function addFilesToQueue(files) {
  files.forEach((file) => {
    const exists = pendingFiles.some(
      (f) => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified
    );
    if (!exists) pendingFiles.push(file);
  });

  renderFileQueue();
}

function removeFromQueue(index) {
  pendingFiles.splice(index, 1);
  renderFileQueue();
}

function renderFileQueue() {
  const container = document.getElementById('fileQueue');
  const controls = document.getElementById('uploadControls');
  if (!container || !controls) return;

  container.innerHTML = '';

  if (!pendingFiles.length) {
    controls.style.display = 'none';
    return;
  }

  controls.style.display = 'flex';

  pendingFiles.forEach((file, index) => {
    const row = document.createElement('div');
    row.className = 'file-queue-item';

    const icon = document.createElement('div');
    icon.className = 'file-queue-icon';
    icon.textContent = 'F';

    const name = document.createElement('div');
    name.className = 'file-queue-name';
    name.textContent = file.name;

    const size = document.createElement('div');
    size.className = 'file-queue-size';
    size.textContent = CryptoEngine.formatBytes(file.size);

    const removeBtn = document.createElement('button');
    removeBtn.className = 'file-queue-remove';
    removeBtn.type = 'button';
    removeBtn.textContent = 'x';
    removeBtn.addEventListener('click', () => removeFromQueue(index));

    row.appendChild(icon);
    row.appendChild(name);
    row.appendChild(size);
    row.appendChild(removeBtn);
    container.appendChild(row);
  });
}

function resetUploadProgress() {
  for (let i = 1; i <= 5; i += 1) {
    const stepEl = document.getElementById(`step${i}`);
    if (!stepEl) continue;
    stepEl.classList.remove('active');
    stepEl.classList.remove('done');
  }
  setProgress(0);
  setProgressMsg('');
}

function setStep(stepNumber, status) {
  const stepEl = document.getElementById(`step${stepNumber}`);
  if (!stepEl) return;

  stepEl.classList.remove('active');
  stepEl.classList.remove('done');
  if (status === 'active' || status === 'done') {
    stepEl.classList.add(status);
  }
}

function setProgress(percent) {
  const bar = document.getElementById('progressBar');
  if (bar) bar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
}

function setProgressMsg(message) {
  const msg = document.getElementById('progressMsg');
  if (msg) msg.textContent = message || '';
}

async function uploadFiles() {
  if (!pendingFiles.length) return;

  if (!rsaPublicKey || !rsaPrivateKey) {
    alert('RSA keys are missing. Please sign out and sign in again.');
    return;
  }

  const progressDiv = document.getElementById('uploadProgress');
  if (progressDiv) progressDiv.style.display = 'block';

  try {
    const shareTarget = document.getElementById('shareTarget')?.value.trim() || '';
    let targetUserId = currentUserId;
    let targetPublicKey = rsaPublicKey;

    if (shareTarget) {
      const snap = await db.collection('users')
        .where('email', '==', shareTarget)
        .limit(1)
        .get();

      if (snap.empty) throw new Error('Recipient email not found.');

      const userDoc = snap.docs[0];
      const userData = userDoc.data() || {};
      if (!userData.publicKey) throw new Error('Recipient has no public key.');

      targetUserId = userDoc.id;
      targetPublicKey = userData.publicKey;
    }

    for (let i = 0; i < pendingFiles.length; i += 1) {
      const file = pendingFiles[i];
      resetUploadProgress();
      setProgressMsg(`Encrypting ${file.name} (${i + 1}/${pendingFiles.length})...`);
      await uploadSingleFile(file, targetPublicKey, targetUserId, shareTarget || null);
    }

    pendingFiles = [];
    renderFileQueue();
    setProgressMsg('Upload complete.');
    await loadFiles();

  } catch (err) {
    console.error(err);
    alert(`Upload failed: ${err.message}`);
  } finally {
    if (progressDiv) {
      setTimeout(() => {
        progressDiv.style.display = 'none';
        resetUploadProgress();
      }, 1200);
    }
  }
}

async function uploadSingleFile(file, recipientPublicKey, recipientUid, sharedWith) {
  const buffer = await file.arrayBuffer();
  const fileHash = await CryptoEngine.computeFileHash(buffer);

  const encrypted = await CryptoEngine.encryptFileForUpload(
    buffer,
    recipientPublicKey,
    (step, msg) => {
      if (step > 1) setStep(step - 1, 'done');
      setStep(step, 'active');
      setProgress(step * 20);
      setProgressMsg(msg);
    }
  );

  setStep(3, 'done');
  setStep(4, 'active');
  setProgress(80);
  setProgressMsg('Uploading to Firestore...');

  await db.collection('files').add({
    fileName: file.name,
    fileType: file.type || 'application/octet-stream',
    fileSize: file.size,
    encryptedData: encrypted.ciphertextB64,
    encryptedAESKey: encrypted.encryptedAESKeyB64,
    iv: encrypted.ivB64,
    fileHash,
    ownerId: currentUserId,
    ownerEmail: currentUserEmail,
    recipientId: recipientUid,
    sharedWith: sharedWith,
    uploadedAt: firebase.firestore.FieldValue.serverTimestamp()
  });

  setStep(4, 'done');
  setStep(5, 'active');
  setProgress(100);
  setProgressMsg(`Uploaded ${file.name} successfully.`);
}

async function loadFiles() {
  const tbody = document.getElementById('filesList');
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Loading files...</td></tr>';

  try {
    const [owned, shared] = await Promise.all([
      db.collection('files').where('ownerId', '==', currentUserId).get(),
      db.collection('files').where('recipientId', '==', currentUserId).get()
    ]);

    const map = new Map();
    [...owned.docs, ...shared.docs].forEach((doc) => {
      map.set(doc.id, { id: doc.id, ...doc.data() });
    });

    const files = Array.from(map.values()).sort((a, b) => {
      const aTime = a.uploadedAt?.toDate ? a.uploadedAt.toDate().getTime() : 0;
      const bTime = b.uploadedAt?.toDate ? b.uploadedAt.toDate().getTime() : 0;
      return bTime - aTime;
    });

    if (!files.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No files found.</td></tr>';
      updateStorageDisplay([]);
      return;
    }

    tbody.innerHTML = '';

    files.forEach((file) => {
      const row = document.createElement('tr');

      const nameCell = document.createElement('td');
      nameCell.textContent = file.fileName || 'Untitled';

      const sizeCell = document.createElement('td');
      sizeCell.textContent = CryptoEngine.formatBytes(file.fileSize || 0);

      const uploadedCell = document.createElement('td');
      uploadedCell.textContent = formatUploadedDate(file.uploadedAt);

      const ownerCell = document.createElement('td');
      ownerCell.textContent = file.ownerId === currentUserId ? 'You' : (file.ownerEmail || 'Shared');

      const actionCell = document.createElement('td');
      const actionWrap = document.createElement('div');
      actionWrap.className = 'action-btns';

      const decryptBtn = document.createElement('button');
      decryptBtn.className = 'btn-action btn-download';
      decryptBtn.type = 'button';
      decryptBtn.textContent = 'Decrypt';
      decryptBtn.addEventListener('click', () => downloadFile(file.id));
      actionWrap.appendChild(decryptBtn);

      if (file.ownerId === currentUserId) {
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn-action btn-delete';
        deleteBtn.type = 'button';
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', () => deleteFile(file.id, file.fileName || 'this file'));
        actionWrap.appendChild(deleteBtn);
      }

      actionCell.appendChild(actionWrap);

      row.appendChild(nameCell);
      row.appendChild(sizeCell);
      row.appendChild(uploadedCell);
      row.appendChild(ownerCell);
      row.appendChild(actionCell);

      tbody.appendChild(row);
    });

    updateStorageDisplay(files);
  } catch (err) {
    console.error(err);
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Failed to load files.</td></tr>';
  }
}

async function deleteFile(fileId, fileName) {
  const confirmed = window.confirm(`Delete "${fileName}" permanently?`);
  if (!confirmed) return;

  try {
    await db.collection('files').doc(fileId).delete();
    await loadFiles();
  } catch (err) {
    console.error(err);
    alert(`Delete failed: ${err.message}`);
  }
}

async function downloadFile(fileId) {
  try {
    if (!rsaPrivateKey) throw new Error('Private key not found in session.');

    const doc = await db.collection('files').doc(fileId).get();
    if (!doc.exists) throw new Error('File not found.');

    const file = doc.data() || {};

    const plaintext = await CryptoEngine.decryptFileForDownload(
      file.encryptedData,
      file.encryptedAESKey,
      file.iv,
      rsaPrivateKey
    );

    const blob = new Blob([plaintext], { type: file.fileType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = file.fileName || 'download.bin';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error(err);
    alert(`Decrypt failed: ${err.message}`);
  }
}

function updateStorageDisplay(files = []) {
  const totalBytes = files.reduce((sum, f) => sum + (f.fileSize || 0), 0);
  const maxBytes = 50 * 1024 * 1024;

  const bar = document.getElementById('storageFill');
  const text = document.getElementById('storageText');

  if (bar) bar.style.width = `${Math.min((totalBytes / maxBytes) * 100, 100)}%`;
  if (text) text.textContent = `${CryptoEngine.formatBytes(totalBytes)} used`;
}

function formatUploadedDate(ts) {
  if (!ts || !ts.toDate) return '-';
  const date = ts.toDate();
  return date.toLocaleString();
}

function exportKeys() {
  if (!rsaPublicKey || !rsaPrivateKey) {
    alert('No keys available in this session.');
    return;
  }

  const payload = {
    userId: currentUserId,
    email: currentUserEmail,
    exportedAt: new Date().toISOString(),
    publicKey: rsaPublicKey,
    privateKey: rsaPrivateKey
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'secure-fileshare-keys.json';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.style.display = 'none';
}

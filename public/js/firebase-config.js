// ============================================
// firebase-config.js
// Firebase configuration with Compat SDK
// Using global firebase object from CDN
// ============================================

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyAAzbAdq3a0sYrb2CkDwbo5U4u2prTUgRo",
  authDomain: "fileshare-5a45c.firebaseapp.com",
  projectId: "fileshare-5a45c",
  storageBucket: "fileshare-5a45c.firebasestorage.app",
  messagingSenderId: "21898232226",
  appId: "1:21898232226:web:f7c7644824799337cdb2fb",
  measurementId: "G-SNPXS1T4PY"
};

// Initialize Firebase (using compat SDK)
firebase.initializeApp(firebaseConfig);

// Expose global references for use in auth.js and dashboard.js
const auth = firebase.auth();
const db   = firebase.firestore();


// Only available on dashboard (storage SDK loaded there)
let storage;
try { storage = firebase.storage(); } catch(e) {}

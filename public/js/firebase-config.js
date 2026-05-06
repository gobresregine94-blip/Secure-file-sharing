// ============================================
// firebase-config.js
// Firebase configuration with Compat SDK
// Using global firebase object from CDN
// ============================================

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBCfvFAhEbBJlHKLJz7dWGAehLIIjE8wwI",
  authDomain: "fileshare-83308.firebaseapp.com",
  projectId: "fileshare-83308",
  storageBucket: "fileshare-83308.firebasestorage.app",
  messagingSenderId: "86234713315",
  appId: "1:86234713315:web:f23f7280d3d728759689d6",
  measurementId: "G-F6K4FRFDNP"
};

// Initialize Firebase (using compat SDK)
firebase.initializeApp(firebaseConfig);

// Expose global references for use in auth.js and dashboard.js
const auth = firebase.auth();
const db   = firebase.firestore();


// Only available on dashboard (storage SDK loaded there)
let storage;
try { storage = firebase.storage(); } catch(e) {}

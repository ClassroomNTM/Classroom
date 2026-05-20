/**
 * auth-guard.js — Shared authentication & authorization module
 *
 * ▸ ดึง role จาก Firestore เพียง 1 ครั้ง → cache ใน sessionStorage (TTL 30 นาที)
 * ▸ ป้องกัน user เข้าหน้าที่ไม่มีสิทธิ์ (redirect กลับ submit.html)
 * ▸ Export: initAuth(options) → { user, role, name }
 *
 * options: {
 *   requireAdmin?: boolean   — ถ้า true → user ถูก redirect ไป submit.html
 *   adminOnly?:   boolean   — alias ของ requireAdmin
 *   onReady?: (ctx) => void  — callback หลัง auth สำเร็จ
 * }
 */

import { initializeApp, getApps } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import {
  getAuth, onAuthStateChanged, signOut
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

// ── Firebase config (เปลี่ยนที่นี่ที่เดียว) ──────────────────────────────
const FIREBASE_CONFIG = {
  apiKey:            "AIzaSyCBXMi3sy-3iDDzHDXVvlmaa6szcmnFbwQ",
  authDomain:        "classroom-93c8b.firebaseapp.com",
  projectId:         "classroom-93c8b",
  storageBucket:     "classroom-93c8b.firebasestorage.app",
  messagingSenderId: "659092749098",
  appId:             "1:659092749098:web:36f249557c4badc088fc53",
  measurementId:     "G-EXJVCH9Z4S"
};

// ── Pages accessible by role ─────────────────────────────────────────────
// user สามารถเข้าได้เฉพาะหน้านี้
const USER_ALLOWED_PAGES = ["submit.html"];
const ADMIN_HOME = "dashboard.html";
const USER_HOME  = "submit.html";

// ── Cache TTL: 30 minutes ────────────────────────────────────────────────
const ROLE_CACHE_TTL = 30 * 60 * 1000;
const CACHE_KEY = "_authCache";

// ── Init Firebase (singleton) ────────────────────────────────────────────
const app  = getApps().length ? getApps()[0] : initializeApp(FIREBASE_CONFIG);
const auth = getAuth(app);
const db   = getFirestore(app);

// Expose for other modules that need db/auth
export { app, auth, db };

// ── Cache helpers ────────────────────────────────────────────────────────
function getCached() {
  try {
    const raw = sessionStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    if (Date.now() - obj.ts > ROLE_CACHE_TTL) {
      sessionStorage.removeItem(CACHE_KEY);
      return null;
    }
    return obj; // { ts, uid, role, name }
  } catch { return null; }
}

function setCached(uid, role, name) {
  sessionStorage.setItem(CACHE_KEY, JSON.stringify({ ts: Date.now(), uid, role, name }));
}

function clearCache() {
  sessionStorage.removeItem(CACHE_KEY);
}

// ── Fetch user profile from Firestore (1 read per session) ──────────────
async function fetchUserProfile(firebaseUser) {
  const cached = getCached();
  // ถ้า cache ยังใช้ได้และเป็น uid เดิม → ไม่อ่าน Firestore
  if (cached && cached.uid === firebaseUser.uid) {
    return { role: cached.role, name: cached.name };
  }

  // อ่าน Firestore 1 ครั้ง
  const snap = await getDoc(doc(db, "users", firebaseUser.uid));
  let role, name;

  if (snap.exists()) {
    const data = snap.data();
    role = data.role || "user";
    name = data.displayName || firebaseUser.displayName || firebaseUser.email;
  } else {
    // ผู้ใช้ใหม่ผ่าน Google → สร้าง doc อัตโนมัติ (1 write)
    role = "user";
    name = firebaseUser.displayName || firebaseUser.email;
    await setDoc(doc(db, "users", firebaseUser.uid), {
      displayName: name,
      email:       firebaseUser.email,
      role:        "user",
      provider:    firebaseUser.providerData[0]?.providerId || "google.com",
      createdAt:   serverTimestamp()
    });
  }

  setCached(firebaseUser.uid, role, name);
  return { role, name };
}

// ── Page access check ────────────────────────────────────────────────────
function currentPage() {
  return window.location.pathname.split("/").pop() || "index.html";
}

function enforceAccess(role) {
  const page = currentPage();
  if (role === "admin") return; // admin เข้าได้ทุกหน้า
  // user → ต้องอยู่ใน allowed list
  if (!USER_ALLOWED_PAGES.includes(page)) {
    window.location.replace(USER_HOME);
  }
}

// ── Google Apps Script URL ───────────────────────────────────────────────
const GAS_URL = "https://script.google.com/macros/s/AKfycbxarf3f9nPgFImUgxv9wkeCZcEfEOO-a79va2-T7E4RoNinBIZdQt_3e9qStx3_gHuPeg/exec";

// ── logAction — บันทึกลง Google Sheet (ใช้ได้ทุกหน้า) ──────────────────
export async function logAction(actionType, description, detail = {}, status = "success", errorMsg = "") {
  try {
    const cached = getCached();
    const payload = {
      userId:    cached?.uid   || auth.currentUser?.uid   || "",
      userName:  cached?.name  || auth.currentUser?.displayName || "",
      userEmail: auth.currentUser?.email || "",
      userRole:  cached?.role  || "user",
      actionType,
      description,
      detail,
      status,
      errorMsg,
      timestamp: new Date().toISOString()
    };
    fetch(GAS_URL, {
      method:  "POST",
      headers: { "Content-Type": "text/plain" },
      body:    JSON.stringify(payload)
    }).catch(e => console.warn("logAction failed:", e));
  } catch (e) {
    console.warn("logAction error:", e);
  }
}

// ── Logout helper ────────────────────────────────────────────────────────
export async function doLogout() {
  await logAction("logout", "ออกจากระบบ", {}, "success");
  clearCache();
  await signOut(auth);
  window.location.href = "index.html";
}

// ── Main export ──────────────────────────────────────────────────────────
/**
 * initAuth(options)
 *  options.requireAdmin — redirect user → submit.html  (ใช้ใน admin-only pages)
 *  options.onReady(ctx) — called with { user, role, name } after auth
 */
export function initAuth(options = {}) {
  return new Promise((resolve) => {
    onAuthStateChanged(auth, async (user) => {
      if (!user) {
        clearCache();
        window.location.href = "index.html";
        return;
      }

      const { role, name } = await fetchUserProfile(user);

      // ── Access control ──
      if (options.requireAdmin && role !== "admin") {
        window.location.replace(USER_HOME);
        return;
      }
      enforceAccess(role);

      // ── Render topbar UI ──
      const avatarEl   = document.getElementById("avatarEl");
      const userNameEl = document.getElementById("userNameEl");
      const roleBadgeEl = document.getElementById("roleBadgeEl");
      const adminNavItem = document.getElementById("adminNavItem");

      if (avatarEl)    avatarEl.textContent    = name.charAt(0).toUpperCase();
      if (userNameEl)  userNameEl.textContent  = name;
      if (roleBadgeEl) {
        roleBadgeEl.textContent = role === "admin" ? "Admin" : "User";
        roleBadgeEl.className   = "role-badge " + (role === "admin" ? "role-admin" : "role-user");
      }

      // Admin-only nav items
      if (adminNavItem) {
        adminNavItem.style.display = role === "admin" ? "flex" : "none";
      }

      // Hide non-submit nav for user role
      if (role !== "admin") {
        document.querySelectorAll(".nav-item[data-admin]").forEach(el => {
          el.style.display = "none";
        });
      }

      const ctx = { user, role, name, db, auth };
      if (options.onReady) options.onReady(ctx);
      resolve(ctx);
    });
  });
}

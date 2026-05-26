"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { createClient } from "@supabase/supabase-js";

// ── LUCIDE ICONS ─────────────────────────────────────────────────────────────
import {
  Clipboard, Eye, EyeOff, Pencil, Trash2, X, Lock, Unlock,
  LogOut, Fingerprint, Zap, KeyRound, Settings, FileText,
  LayoutDashboard, FolderOpen, ClipboardList,
  Copy, FileLock2, Save, ShieldCheck, AlertTriangle,
} from "lucide-react";

// ── VERSION ───────────────────────────────────────────────────────────────────
const APP_VERSION = "1.4.3";

// ── CLIENTE SUPABASE SINGLETON ────────────────────────────────────────────────
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
);

// ── CRYPTO ENGINE (Web Crypto API, zero-knowledge) ───────────────────────────
const crypto_engine = {
  async deriveKey(masterPassword, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw", enc.encode(masterPassword), "PBKDF2", false, ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },
  async encrypt(text, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, key, enc.encode(text)
    );
    const buf = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    buf.set(iv, 0);
    buf.set(new Uint8Array(ciphertext), iv.byteLength);
    return btoa(String.fromCharCode(...buf));
  },
  async decrypt(b64, key) {
    try {
      const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      const iv = buf.slice(0, 12);
      const data = buf.slice(12);
      const plain = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
      return new TextDecoder().decode(plain);
    } catch { return null; }
  }
};

// ── SUPABASE DATA LAYER ───────────────────────────────────────────────────────
const SALT = "teamvault-org-salt-v1";
let _cryptoKey = null;
let _currentUser = null;

// Estado reactivo en memoria (cache local)
let _store = { collections: [], secrets: [], audit: [] };

const VAULT_VERIFIER_KEY = "tv_vault_verifier";
const VAULT_VERIFIER_PLAIN = "teamvault-ok";

async function initCrypto(master) {
  const key = await crypto_engine.deriveKey(master, SALT);
  const stored = localStorage.getItem(VAULT_VERIFIER_KEY);

  if (!stored) {
    // Primera vez: guardar verificador encriptado con esta clave
    const verifier = await crypto_engine.encrypt(VAULT_VERIFIER_PLAIN, key);
    localStorage.setItem(VAULT_VERIFIER_KEY, verifier);
    _cryptoKey = key;
    return true;
  }

  // Siguientes veces: desencriptar el verificador para validar la clave
  const result = await crypto_engine.decrypt(stored, key);
  if (result !== VAULT_VERIFIER_PLAIN) {
    _cryptoKey = null;
    return false; // clave incorrecta
  }

  _cryptoKey = key;
  return true;
}

// ── WEBAUTHN / PASSKEY ENGINE ─────────────────────────────────────────────────
const PASSKEY_LS_KEY   = "tv_passkey_enc";
const PASSKEY_CRED_KEY = "tv_passkey_cred";

const passkey = {
  isSupported() {
    return !!(window.PublicKeyCredential &&
      navigator.credentials?.create &&
      navigator.credentials?.get);
  },
  isRegistered() {
    return !!(localStorage.getItem(PASSKEY_LS_KEY) && localStorage.getItem(PASSKEY_CRED_KEY));
  },
  _b64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  },
  _fromB64url(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
  },
  async _deriveWrapKey(rawId) {
    const km = await window.crypto.subtle.importKey("raw", rawId, "PBKDF2", false, ["deriveKey"]);
    return window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: new TextEncoder().encode("tv-passkey-wrap-v1"), iterations: 100000, hash: "SHA-256" },
      km, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  },
  async register(masterPassword, userName) {
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    const userId    = window.crypto.getRandomValues(new Uint8Array(16));
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: "TeamVault", id: window.location.hostname },
        user: { id: userId, name: userName, displayName: userName },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred" },
        timeout: 60000,
      },
    });
    const rawId   = new Uint8Array(cred.rawId);
    const wrapKey = await this._deriveWrapKey(rawId);
    const iv      = window.crypto.getRandomValues(new Uint8Array(12));
    const ct      = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, new TextEncoder().encode(masterPassword));
    const combined = new Uint8Array(iv.byteLength + ct.byteLength);
    combined.set(iv, 0); combined.set(new Uint8Array(ct), iv.byteLength);
    localStorage.setItem(PASSKEY_LS_KEY,   btoa(String.fromCharCode(...combined)));
    localStorage.setItem(PASSKEY_CRED_KEY, this._b64url(cred.rawId));
  },
  async unlock() {
    const credIdB64 = localStorage.getItem(PASSKEY_CRED_KEY);
    const encB64    = localStorage.getItem(PASSKEY_LS_KEY);
    if (!credIdB64 || !encB64) throw new Error("No hay passkey registrada");
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: window.crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: this._fromB64url(credIdB64) }],
        userVerification: "required",
        timeout: 60000,
      },
    });
    const wrapKey = await this._deriveWrapKey(new Uint8Array(assertion.rawId));
    const combined = Uint8Array.from(atob(encB64), c => c.charCodeAt(0));
    const plain   = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: combined.slice(0, 12) }, wrapKey, combined.slice(12));
    return new TextDecoder().decode(plain);
  },
  clear() {
    localStorage.removeItem(PASSKEY_LS_KEY);
    localStorage.removeItem(PASSKEY_CRED_KEY);
  },
};

// ── COLECCIONES ───────────────────────────────────────────────────────────────
async function loadCollections(userId) {
  // Primero obtenemos las collection_ids a las que pertenece el usuario
  const { data: memberships } = await supabase
    .from("collection_members")
    .select("collection_id")
    .eq("user_id", userId);

  if (!memberships || memberships.length === 0) {
    // Si no tiene membresías, cargamos las que creó él (owner)
    const { data } = await supabase
      .from("collections")
      .select("*")
      .eq("owner_id", userId)
      .order("created_at", { ascending: true });
    _store.collections = data || [];
    return _store.collections;
  }

  const ids = memberships.map(m => m.collection_id);
  const { data } = await supabase
    .from("collections")
    .select("*")
    .in("id", ids)
    .order("created_at", { ascending: true });
  _store.collections = data || [];
  return _store.collections;
}

// Usa función SECURITY DEFINER (sin abrir tablas)
async function createCollection(name, icon, color, userId) {
  const { data, error } = await supabase.rpc("create_collection_with_member", {
    p_name:  name,
    p_icon:  icon  || "📁",
    p_color: color || "#7C3AED",
  });
  if (error) throw error;
  await loadCollections(userId);
  return data; // retorna el UUID de la nueva colección
}

// ── SECRETOS ──────────────────────────────────────────────────────────────────
async function loadSecrets(userId) {
  if (_store.collections.length === 0) {
    _store.secrets = [];
    return [];
  }
  const colIds = _store.collections.map(c => c.id);
  const { data, error } = await supabase
    .from("secrets")
    .select("*")
    .in("collection_id", colIds)
    .order("updated_at", { ascending: false });

  if (error) { console.error("loadSecrets error:", error); _store.secrets = []; return []; }

  // Mapear campos de BD a los que usa la UI (col → collection_id)
  _store.secrets = (data || []).map(s => ({
    ...s,
    col: s.collection_id,
  }));
  return _store.secrets;
}

async function decryptSecret(s) {
  if (!_cryptoKey) return { ...s, value: "[sin clave maestra]", user: "", notes: "" };
  const value = await crypto_engine.decrypt(s.enc_value, _cryptoKey);
  const user  = s.enc_user  ? await crypto_engine.decrypt(s.enc_user,  _cryptoKey) : "";
  const notes = s.enc_notes ? await crypto_engine.decrypt(s.enc_notes, _cryptoKey) : "";
  return { ...s, value: value || "[error al desencriptar]", user: user || "", notes: notes || "" };
}

async function saveSecret(data, userId) {
  if (!_cryptoKey) throw new Error("No hay clave maestra");
  if (!data.col) throw new Error("Colección no definida");

  const enc_value = await crypto_engine.encrypt(data.value || "", _cryptoKey);
  const enc_user  = data.user  ? await crypto_engine.encrypt(data.user,  _cryptoKey) : null;
  const enc_notes = data.notes ? await crypto_engine.encrypt(data.notes, _cryptoKey) : null;
  const now = new Date().toISOString().split("T")[0];

  const payload = {
    collection_id: data.col,
    type: data.type,
    name: data.name,
    enc_value,
    enc_user,
    enc_notes,
    updated_at: now,
    //created_by: userId,
  };

  let result;
  if (data.id) {
    // Update
    const { data: updated, error } = await supabase
      .from("secrets")
      .update({ ...payload })
      .eq("id", data.id)
      .select()
      .single();
    if (error) throw error;
    result = updated;
  } else {
    // Insert
    const { data: inserted, error } = await supabase
      .from("secrets")
      .insert({ ...payload, created_at: now })
      .select()
      .single();
    if (error) throw error;
    result = inserted;
  }

  await addAudit(userId, data.id ? "update" : "create", data.name, true);
  await loadSecrets(userId);
  return { ...result, col: result.collection_id };
}

async function deleteSecret(id, userId) {
  const s = _store.secrets.find(x => x.id === id);
  const { error } = await supabase.from("secrets").delete().eq("id", id);
  if (error) throw error;
  if (s) await addAudit(userId, "delete", s.name, true);
  await loadSecrets(userId);
}

// ── AUDITORÍA ─────────────────────────────────────────────────────────────────
async function loadAudit(userId) {
  const { data } = await supabase
    .from("audit_log")
    .select("*")
    .order("ts", { ascending: false })
    .limit(50);
  _store.audit = data || [];
  return _store.audit;
}

async function addAudit(userId, action, target, ok) {
  const { data: { user } } = await supabase.auth.getUser();
  await supabase.from("audit_log").insert({
    user_id: userId,
    user_email: user?.email || "desconocido",
    action,
    target_name: target,
    ok,
  });
  // Actualizar cache local sin recargar todo
  _store.audit.unshift({
    id: "tmp-" + Date.now(),
    user_email: user?.email || "desconocido",
    action,
    target_name: target,
    ok,
    ts: new Date().toISOString(),
  });
  if (_store.audit.length > 50) _store.audit.pop();
}

// ── CARGA INICIAL ─────────────────────────────────────────────────────────────
async function loadAll(userId) {
  await loadCollections(userId);
  await Promise.all([
    loadSecrets(userId),
    loadAudit(userId),
  ]);
}

// ── TYPE CONFIG ──────────────────────────────────────────────────────────────
const TYPE_META = {
  api:        { label: "API Key",    icon: <Zap      size={16} />, color: "#7C3AED", bg: "#EDE9FE" },
  credential: { label: "Credencial", icon: <KeyRound size={16} />, color: "#0369A1", bg: "#E0F2FE" },
  config:     { label: "Config",     icon: <Settings size={16} />, color: "#059669", bg: "#D1FAE5" },
  file:       { label: "Documento",  icon: <FileText size={16} />, color: "#B45309", bg: "#FEF3C7" },
};

// ── HELPERS ──────────────────────────────────────────────────────────────────
function timeAgo(ts) {
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "ahora mismo";
  if (m < 60) return `hace ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `hace ${h}h`;
  return `hace ${Math.floor(h / 24)}d`;
}

function mask(val) {
  if (!val) return "••••••••";
  return val.slice(0, 4) + "••••••••" + val.slice(-4);
}

// ── STYLES ──────────────────────────────────────────────────────────────────
const THEMES = {
  dark: {
    bg: "#0F0F13",
    surface: "#18181F",
    surface2: "#1E1E28",
    surface3: "#252530",
    border: "rgba(255,255,255,0.07)",
    border2: "rgba(255,255,255,0.12)",
    text: "#F0EEF8",
    muted: "#8B8A9E",
    accent: "#7C5CFC",
    accentDim: "rgba(124,92,252,0.15)",
    accentBorder: "rgba(124,92,252,0.4)",
    danger: "#EF4444",
    success: "#10B981",
    warn: "#F59E0B",
  },
  light: {
    bg: "#F4F3FA",
    surface: "#FFFFFF",
    surface2: "#F0EFF8",
    surface3: "#E8E7F3",
    border: "rgba(0,0,0,0.08)",
    border2: "rgba(0,0,0,0.14)",
    text: "#1A1826",
    muted: "#6B6880",
    accent: "#7C5CFC",
    accentDim: "rgba(124,92,252,0.10)",
    accentBorder: "rgba(124,92,252,0.35)",
    danger: "#DC2626",
    success: "#059669",
    warn: "#D97706",
  },
};

// G starts as dark (default); replaced at runtime by themed components
let G = THEMES.dark;

function makeCSS(theme) {
  const T = THEMES[theme] || THEMES.dark;
  return `
  @import url('https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,400;0,500;1,400&family=Outfit:wght@300;400;500;600;700&display=swap');

  * { box-sizing: border-box; margin: 0; padding: 0; }

  .tv-root {
    font-family: 'Outfit', sans-serif;
    background: ${T.bg};
    color: ${T.text};
    min-height: 100vh;
    font-size: 14px;
    line-height: 1.5;
  }

  /* scrollbar */
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: ${T.border2}; border-radius: 99px; }

  /* login */
  .tv-login {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: ${T.bg};
    position: relative;
    overflow: hidden;
  }
  .tv-login::before {
    content: '';
    position: absolute;
    width: 600px; height: 600px;
    background: radial-gradient(circle, rgba(124,92,252,0.12) 0%, transparent 70%);
    top: -100px; left: 50%; transform: translateX(-50%);
    pointer-events: none;
  }
  .tv-login-card {
    background: ${T.surface};
    border: 1px solid ${T.border2};
    border-radius: 20px;
    padding: 48px 40px;
    width: 100%;
    max-width: 380px;
    position: relative;
    z-index: 1;
  }
  @media (max-width: 440px) {
    .tv-login { padding: 16px; align-items: flex-start; padding-top: 40px; }
    .tv-login-card { padding: 32px 20px; border-radius: 16px; }
  }
  .tv-login-logo {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 32px;
  }
  .tv-login-logo-icon {
    width: 40px; height: 40px;
    background: ${T.accent};
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
  }
  .tv-login-logo-name {
    font-size: 20px; font-weight: 700; letter-spacing: -0.3px;
  }
  .tv-login-logo-sub {
    font-size: 11px; color: ${T.muted}; font-weight: 400;
  }
  .tv-login h2 { font-size: 22px; font-weight: 600; margin-bottom: 6px; }
  .tv-login p { color: ${T.muted}; font-size: 13px; margin-bottom: 28px; }
  .tv-field { margin-bottom: 14px; }
  .tv-label { font-size: 12px; color: ${T.muted}; margin-bottom: 6px; font-weight: 500; letter-spacing: 0.02em; }
  .tv-input {
    width: 100%;
    background: ${T.surface2};
    border: 1px solid ${T.border2};
    border-radius: 10px;
    padding: 10px 14px;
    color: ${T.text};
    font-family: 'Outfit', sans-serif;
    font-size: 14px;
    outline: none;
    transition: border-color 0.15s;
  }
  .tv-input:focus { border-color: ${T.accent}; }
  .tv-input::placeholder { color: ${T.muted}; }
  .tv-btn {
    width: 100%;
    background: ${T.accent};
    color: #fff;
    border: none;
    border-radius: 10px;
    padding: 11px;
    font-family: 'Outfit', sans-serif;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.15s, transform 0.1s;
    margin-top: 6px;
  }
  .tv-btn:hover { opacity: 0.9; }
  .tv-btn:active { transform: scale(0.98); }
  .tv-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  /* Google sign-in button - official style */
  .tv-btn-google {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    background: #fff;
    color: #3c4043;
    border: 1px solid #dadce0;
    border-radius: 10px;
    padding: 11px 16px;
    font-family: 'Roboto', 'Outfit', sans-serif;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s, box-shadow 0.15s;
    margin-top: 6px;
    letter-spacing: 0.01em;
  }
  .tv-btn-google:hover { background: #f8f9fa; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }
  .tv-btn-google:active { background: #f1f3f4; }
  .tv-btn-google:disabled { opacity: 0.6; cursor: not-allowed; }
  .tv-btn-ghost {
    background: ${T.surface2};
    border: 1px solid ${T.border2};
    color: ${T.text};
  }
  .tv-btn-ghost:hover { background: ${T.surface3}; opacity: 1; }
  .tv-btn-danger {
    background: rgba(239,68,68,0.15);
    border: 1px solid rgba(239,68,68,0.3);
    color: ${T.danger};
  }
  .tv-btn-danger:hover { background: rgba(239,68,68,0.25); opacity:1; }

  .tv-hint {
    font-size: 11px; color: ${T.muted};
    background: ${T.surface2};
    border: 1px solid ${T.border};
    border-radius: 8px;
    padding: 10px 12px;
    margin-top: 16px;
    line-height: 1.6;
  }
  .tv-hint strong { color: ${T.text}; }

  /* layout */
  .tv-layout { display: flex; height: 100vh; overflow: hidden; max-width: 100vw; }

  /* sidebar */
  .tv-sidebar {
    width: 220px;
    flex-shrink: 0;
    background: ${T.surface};
    border-right: 1px solid ${T.border};
    display: flex;
    flex-direction: column;
    padding: 20px 0;
    overflow-y: auto;
  }
  .tv-sidebar-logo {
    display: flex; align-items: center; gap: 9px;
    padding: 0 18px 20px;
    border-bottom: 1px solid ${T.border};
    margin-bottom: 12px;
  }
  .tv-sidebar-logo-icon {
    width: 32px; height: 32px;
    background: ${T.accent};
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px;
  }
  .tv-sidebar-logo-txt { font-size: 15px; font-weight: 700; letter-spacing: -0.2px; }
  .tv-nav-section { padding: 0 10px; margin-bottom: 4px; }
  .tv-nav-label { font-size: 10px; color: ${T.muted}; letter-spacing: 0.08em; font-weight: 600; padding: 8px 8px 4px; text-transform: uppercase; }
  .tv-nav-item {
    display: flex; align-items: center; gap: 9px;
    padding: 8px 10px;
    border-radius: 8px;
    cursor: pointer;
    color: ${T.muted};
    font-size: 13px; font-weight: 500;
    transition: all 0.12s;
    margin-bottom: 1px;
  }
  .tv-nav-item:hover { background: ${T.surface2}; color: ${T.text}; }
  .tv-nav-item.active { background: ${T.accentDim}; color: ${T.text}; }
  .tv-nav-item .nav-icon { font-size: 16px; width: 20px; text-align: center; flex-shrink: 0; }
  .tv-nav-badge {
    margin-left: auto;
    background: ${T.accent};
    color: #fff;
    font-size: 10px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 99px;
    min-width: 18px;
    text-align: center;
  }
  .tv-sidebar-bottom {
    margin-top: auto;
    padding: 12px 10px 0;
    border-top: 1px solid ${T.border};
  }
  .tv-user-chip {
    display: flex; align-items: center; gap: 9px;
    padding: 8px 10px;
    border-radius: 8px;
    cursor: pointer;
  }
  .tv-avatar {
    width: 28px; height: 28px;
    border-radius: 50%;
    background: ${T.accent};
    display: flex; align-items: center; justify-content: center;
    font-size: 11px; font-weight: 700;
    flex-shrink: 0;
  }
  .tv-avatar-name { font-size: 12px; font-weight: 500; }
  .tv-avatar-role { font-size: 10px; color: ${T.muted}; }
  .tv-enc-badge {
    display: flex; align-items: center; gap: 6px;
    padding: 8px 10px;
    margin-top: 6px;
    background: rgba(16,185,129,0.08);
    border: 1px solid rgba(16,185,129,0.2);
    border-radius: 8px;
    font-size: 11px;
    color: ${T.success};
  }

  /* main */
  .tv-main { flex: 1; overflow-y: auto; display: flex; flex-direction: column; }

  /* topbar */
  .tv-topbar {
    padding: 20px 28px 0;
    display: flex; align-items: center; gap: 12px;
    flex-shrink: 0;
  }
  .tv-search {
    flex: 1;
    display: flex; align-items: center; gap: 8px;
    background: ${T.surface};
    border: 1px solid ${T.border2};
    border-radius: 10px;
    padding: 9px 14px;
    transition: border-color 0.15s;
  }
  .tv-search:focus-within { border-color: ${T.accentBorder}; }
  .tv-search input {
    background: none; border: none; outline: none;
    color: ${T.text}; font-family: 'Outfit', sans-serif; font-size: 13px;
    flex: 1; min-width: 0;
  }
  .tv-search input::placeholder { color: ${T.muted}; }
  .tv-topbar-btn {
    display: flex; align-items: center; gap: 7px;
    padding: 8px 16px;
    border-radius: 10px;
    font-family: 'Outfit', sans-serif;
    font-size: 13px; font-weight: 600;
    cursor: pointer; border: none;
    transition: all 0.12s;
    white-space: nowrap;
  }
  .tv-topbar-btn-primary {
    background: ${T.accent};
    color: #fff;
  }
  .tv-topbar-btn-primary:hover { opacity: 0.88; }

  /* content */
  .tv-content { padding: 20px 28px 28px; flex: 1; }

  /* stats */
  .tv-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
  .tv-stat {
    background: ${T.surface};
    border: 1px solid ${T.border};
    border-radius: 12px;
    padding: 16px;
  }
  .tv-stat-label { font-size: 11px; color: ${T.muted}; margin-bottom: 6px; font-weight: 500; }
  .tv-stat-val { font-size: 26px; font-weight: 700; letter-spacing: -0.5px; }
  .tv-stat-sub { font-size: 11px; color: ${T.muted}; margin-top: 3px; }

  /* filters */
  .tv-filters { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .tv-chip {
    display: flex; align-items: center; gap: 5px;
    padding: 5px 12px;
    border-radius: 99px;
    border: 1px solid ${T.border2};
    background: transparent;
    color: ${T.muted};
    font-family: 'Outfit', sans-serif;
    font-size: 12px; font-weight: 500;
    cursor: pointer;
    transition: all 0.12s;
  }
  .tv-chip:hover { border-color: ${T.accent}; color: ${T.text}; }
  .tv-chip.active { background: ${T.accentDim}; border-color: ${T.accentBorder}; color: ${T.text}; }

  /* section header */
  .tv-section-hd { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .tv-section-title { font-size: 13px; font-weight: 600; color: ${T.muted}; letter-spacing: 0.04em; text-transform: uppercase; }

  /* secret cards */
  .tv-secret-card {
    display: flex; align-items: center; gap: 14px;
    background: ${T.surface};
    border: 1px solid ${T.border};
    border-radius: 12px;
    padding: 14px 16px;
    margin-bottom: 6px;
    cursor: pointer;
    transition: all 0.12s;
    position: relative;
    overflow: hidden;
  }
  .tv-secret-card:hover { border-color: ${T.border2}; background: ${T.surface2}; }
  .tv-secret-card.selected { border-color: ${T.accentBorder}; background: ${T.accentDim}; }
  .tv-type-icon {
    width: 36px; height: 36px;
    border-radius: 9px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
    flex-shrink: 0;
  }
  .tv-secret-name { font-size: 14px; font-weight: 600; flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .tv-secret-meta { font-size: 11px; color: ${T.muted}; margin-top: 2px; }
  .tv-type-badge {
    font-size: 10px; font-weight: 600;
    padding: 3px 9px;
    border-radius: 99px;
    flex-shrink: 0;
  }
  .tv-masked {
    font-family: 'DM Mono', monospace;
    font-size: 12px; color: ${T.muted};
    background: ${T.surface2};
    padding: 4px 10px;
    border-radius: 6px;
    flex-shrink: 0;
    max-width: 160px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .tv-card-actions { display: flex; gap: 6px; flex-shrink: 0; }
  .tv-icon-btn {
    width: 30px; height: 30px;
    background: ${T.surface2};
    border: 1px solid ${T.border2};
    border-radius: 7px;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer;
    color: ${T.muted};
    font-size: 14px;
    transition: all 0.12s;
    flex-shrink: 0;
  }
  .tv-icon-btn:hover { background: ${T.surface3}; color: ${T.text}; border-color: ${T.border2}; }

  /* bottom grid */
  .tv-bottom-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 20px; }
  .tv-panel {
    background: ${T.surface};
    border: 1px solid ${T.border};
    border-radius: 12px;
    padding: 16px;
  }
  .tv-panel-title { font-size: 12px; font-weight: 600; color: ${T.muted}; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 12px; }
  .tv-member-row {
    display: flex; align-items: center; gap: 10px;
    padding: 7px 0;
    border-bottom: 1px solid ${T.border};
  }
  .tv-member-row:last-child { border-bottom: none; }
  .tv-member-name { font-size: 13px; font-weight: 500; flex: 1; }
  .tv-role { font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 99px; }
  .tv-role-admin { background: rgba(124,92,252,0.15); color: #A78BFA; }
  .tv-role-editor { background: rgba(3,105,161,0.15); color: #60A5FA; }
  .tv-role-viewer { background: rgba(255,255,255,0.06); color: ${T.muted}; }

  .tv-audit-row {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 7px 0;
    border-bottom: 1px solid ${T.border};
  }
  .tv-audit-row:last-child { border-bottom: none; }
  .tv-audit-dot { width: 7px; height: 7px; border-radius: 50%; margin-top: 5px; flex-shrink: 0; }
  .tv-audit-text { font-size: 12px; color: ${T.muted}; line-height: 1.5; }
  .tv-audit-user { color: ${T.text}; font-weight: 600; }
  .tv-audit-time { font-size: 10px; color: ${T.muted}; margin-top: 2px; }

  /* modal overlay */
  .tv-overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.65);
    display: flex; align-items: center; justify-content: center;
    z-index: 1000;
    padding: 20px;
  }
  .tv-modal {
    background: ${T.surface};
    border: 1px solid ${T.border2};
    border-radius: 16px;
    width: 100%;
    max-width: 520px;
    max-height: 90vh;
    overflow-y: auto;
    padding: 28px;
    position: relative;
  }
  .tv-modal-title { font-size: 18px; font-weight: 700; margin-bottom: 6px; }
  .tv-modal-sub { font-size: 13px; color: ${T.muted}; margin-bottom: 22px; }
  .tv-modal-close {
    position: absolute; top: 20px; right: 20px;
    background: ${T.surface2}; border: 1px solid ${T.border2};
    border-radius: 7px; width: 30px; height: 30px;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer; color: ${T.muted}; font-size: 16px;
  }
  .tv-modal-close:hover { color: ${T.text}; }
  .tv-modal-actions { display: flex; gap: 10px; margin-top: 24px; }
  .tv-modal-actions .tv-btn { width: auto; flex: 1; padding: 10px; }

  /* detail view value */
  .tv-value-box {
    background: ${T.surface2};
    border: 1px solid ${T.border2};
    border-radius: 10px;
    padding: 12px 14px;
    font-family: 'DM Mono', monospace;
    font-size: 13px;
    color: ${T.text};
    word-break: break-all;
    white-space: pre-wrap;
    max-height: 200px;
    overflow-y: auto;
    position: relative;
  }
  .tv-value-box.blurred { filter: blur(5px); user-select: none; }

  .tv-select {
    width: 100%;
    background: ${T.surface2};
    border: 1px solid ${T.border2};
    border-radius: 10px;
    padding: 10px 14px;
    color: ${T.text};
    font-family: 'Outfit', sans-serif;
    font-size: 14px;
    outline: none;
    appearance: none;
  }
  .tv-select:focus { border-color: ${T.accent}; }
  .tv-textarea {
    width: 100%;
    background: ${T.surface2};
    border: 1px solid ${T.border2};
    border-radius: 10px;
    padding: 10px 14px;
    color: ${T.text};
    font-family: 'DM Mono', monospace;
    font-size: 13px;
    outline: none;
    resize: vertical;
    min-height: 100px;
  }
  .tv-textarea:focus { border-color: ${T.accent}; }

  .tv-copy-toast {
    position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
    background: ${T.success};
    color: #fff;
    padding: 10px 20px;
    border-radius: 99px;
    font-size: 13px; font-weight: 600;
    z-index: 2000;
    animation: slideUp 0.2s ease;
  }
  @keyframes slideUp {
    from { opacity: 0; transform: translateX(-50%) translateY(10px); }
    to   { opacity: 1; transform: translateX(-50%) translateY(0); }
  }

  .tv-error { color: ${T.danger}; font-size: 12px; margin-top: 6px; }
  .tv-divider { border: none; border-top: 1px solid ${T.border}; margin: 16px 0; }
  .tv-input-row { display: flex; gap: 10px; }
  .tv-input-row .tv-field { flex: 1; }

  /* collections view */
  .tv-col-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .tv-col-card {
    background: ${T.surface};
    border: 1px solid ${T.border};
    border-radius: 12px;
    padding: 16px;
    cursor: pointer;
    transition: all 0.12s;
  }
  .tv-col-card:hover { border-color: ${T.border2}; }
  .tv-col-card.selected { border-color: ${T.accentBorder}; background: ${T.accentDim}; }
  .tv-col-icon { font-size: 28px; margin-bottom: 8px; }
  .tv-col-name { font-size: 14px; font-weight: 600; }
  .tv-col-count { font-size: 11px; color: ${T.muted}; margin-top: 2px; }

  /* audit page */
  .tv-audit-full-row {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 14px;
    background: ${T.surface};
    border: 1px solid ${T.border};
    border-radius: 10px;
    margin-bottom: 6px;
  }

  /* ── MOBILE DRAWER ── */
  .tv-hamburger {
    display: none;
    align-items: center; justify-content: center;
    width: 36px; height: 36px;
    background: ${T.surface};
    border: 1px solid ${T.border2};
    border-radius: 9px;
    cursor: pointer;
    color: ${T.text};
    flex-shrink: 0;
  }
  .tv-drawer-overlay {
    display: none;
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.6);
    z-index: 200;
  }
  .tv-drawer-overlay.open { display: block; }
  .tv-drawer {
    position: fixed; top: 0; left: 0; bottom: 0;
    width: 260px;
    background: ${T.surface};
    border-right: 1px solid ${T.border2};
    z-index: 201;
    display: flex; flex-direction: column;
    padding: 20px 0;
    transform: translateX(-100%);
    transition: transform 0.22s ease;
  }
  .tv-drawer.open { transform: translateX(0); }

  @media (max-width: 700px) {
    /* ocultar sidebar desktop, mostrar hamburguesa */
    .tv-sidebar { display: none; }
    .tv-hamburger { display: flex; }

    /* layout sin desbordamiento */
    .tv-root { overflow-x: hidden; }
    .tv-layout { overflow-x: hidden; }
    .tv-main { overflow-x: hidden; min-width: 0; }

    /* topbar */
    .tv-topbar { padding: 12px 12px 0; gap: 8px; }
    .tv-topbar-btn { padding: 8px 10px; font-size: 12px; }

    /* contenido */
    .tv-content { padding: 12px 12px 20px; }

    /* stats: 2 columnas */
    .tv-stats { grid-template-columns: repeat(2, 1fr); gap: 8px; margin-bottom: 16px; }
    .tv-stat { padding: 12px; }
    .tv-stat-val { font-size: 22px; }

    /* bottom grid: 1 columna */
    .tv-bottom-grid { grid-template-columns: 1fr; }

    /* ocultar elementos que desbordan en cards */
    .tv-masked { display: none; }
    .tv-type-badge { display: none; }

    /* cards más compactas */
    .tv-secret-card { padding: 10px 12px; gap: 10px; }

    /* modal: pantalla completa en móvil */
    .tv-overlay { padding: 0; align-items: flex-end; }
    .tv-modal {
      max-width: 100%;
      border-radius: 16px 16px 0 0;
      max-height: 92vh;
      padding: 20px 16px;
    }

    /* colecciones: 2 columnas */
    .tv-col-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }

    /* search input no desborde */
    .tv-search { min-width: 0; }
    .tv-search input { min-width: 0; width: 100%; }

    /* input-row apilado */
    .tv-input-row { flex-direction: column; }

    /* audit rows wrap */
    .tv-audit-full-row { flex-wrap: wrap; }
  /* theme toggle */
  .tv-theme-toggle {
    display: flex; align-items: center; gap: 8px;
    padding: 7px 10px;
    border-radius: 8px;
    cursor: pointer;
    color: ${T.muted};
    font-size: 12px; font-weight: 500;
    background: ${T.surface2};
    border: 1px solid ${T.border2};
    font-family: 'Outfit', sans-serif;
    transition: all 0.12s;
    width: 100%;
    margin-top: 6px;
  }
  .tv-theme-toggle:hover { color: ${T.text}; border-color: ${T.accent}; }

  }
`;
}

// ── COMPONENTS ───────────────────────────────────────────────────────────────

function Toast({ msg }) {
  if (!msg) return null;
  return <div className="tv-copy-toast">{msg}</div>;
}

function CopyBtn({ value, onToast }) {
  return (
    <button className="tv-icon-btn" title="Copiar" onClick={e => {
      e.stopPropagation();
      navigator.clipboard?.writeText(value).catch(() => {});
      onToast("✓ Copiado al portapapeles");
    }}><Clipboard size={14} /></button>
  );
}

function DetailModal({ secret, collections, onClose, onDelete, onEdit, onToast, userId, vaultLocked }) {
  const [revealed, setRevealed] = useState(false);
  const [dec, setDec] = useState(null);
  const [loading, setLoading] = useState(true);
  const col = collections.find(c => c.id === secret.col);
  const meta = TYPE_META[secret.type] || TYPE_META.api;

  useEffect(() => {
    decryptSecret(secret).then(d => { setDec(d); setLoading(false); });
    addAudit(userId, "read", secret.name, true);
  }, [secret.id]);

  return (
    <div className="tv-overlay" onClick={onClose}>
      <div className="tv-modal" onClick={e => e.stopPropagation()}>
        <button className="tv-modal-close" onClick={onClose}>✕</button>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <div className="tv-type-icon" style={{ background: meta.bg, color: meta.color, display: "flex", alignItems: "center", justifyContent: "center" }}>{meta.icon}</div>
          <div>
            <div className="tv-modal-title" style={{ marginBottom: 2 }}>{secret.name}</div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="tv-type-badge" style={{ background: meta.bg, color: meta.color }}>{meta.label}</span>
              {col && <span style={{ fontSize: 11, color: G.muted }}>{col.icon} {col.name}</span>}
            </div>
          </div>
        </div>
        <hr className="tv-divider" />
        {loading ? (
          <div style={{ color: G.muted, fontSize: 13, padding: "20px 0" }}>Desencriptando...</div>
        ) : dec ? (
          <>
            {dec.user && (
              <div className="tv-field">
                <div className="tv-label">Usuario / Email</div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  {/* Usuario: siempre visible, solo copiable */}
                  <div className="tv-value-box" style={{ flex: 1 }}>{dec.user}</div>
                  <CopyBtn value={dec.user} onToast={onToast} />
                </div>
              </div>
            )}
            <div className="tv-field">
              <div className="tv-label">{secret.type === "config" ? "Contenido" : "Valor / Contraseña"}</div>
              <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                {/* Contraseña: oculta por defecto, revelar para copiar */}
                <div className="tv-value-box" style={{ flex: 1, filter: revealed ? "none" : "blur(5px)", userSelect: revealed ? "auto" : "none" }}>{dec.value}</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <button className="tv-icon-btn" title={revealed ? "Ocultar" : "Revelar"} onClick={() => setRevealed(r => !r)}>{revealed ? <EyeOff size={14} /> : <Eye size={14} />}</button>
                  {revealed && <CopyBtn value={dec.value} onToast={onToast} />}
                </div>
              </div>
              {!revealed && <div style={{ fontSize: 11, color: G.muted, marginTop: 6 }}>Pulsa el ojo para revelar</div>}
            </div>
            {dec.notes && (
              <div className="tv-field">
                <div className="tv-label">Notas</div>
                <div style={{ fontSize: 13, color: G.muted, lineHeight: 1.6, background: G.surface2, padding: "10px 14px", borderRadius: 8 }}>{dec.notes}</div>
              </div>
            )}
            <hr className="tv-divider" />
            <div style={{ display: "flex", gap: 16, fontSize: 11, color: G.muted }}>
              <span>Creado: {secret.created_at}</span>
              <span>Actualizado: {secret.updated_at}</span>
            </div>
          </>
        ) : (
          <div style={{ color: G.danger, fontSize: 13 }}>Error al desencriptar.</div>
        )}
        <div className="tv-modal-actions">
          {!vaultLocked && (
            <button className="tv-btn tv-btn-danger" onClick={() => { onDelete(secret.id); onClose(); }} style={{ padding: "10px", width: "auto", flex: 1 }}><Trash2 size={14} style={{display:"inline",marginRight:4}} />Eliminar</button>
          )}
          {!vaultLocked && (
            <button className="tv-btn tv-btn-ghost" onClick={() => { onClose(); onEdit(secret); }} style={{ padding: "10px", width: "auto", flex: 1 }}><Pencil size={14} style={{display:"inline",marginRight:4}} />Editar</button>
          )}
          <button className="tv-btn tv-btn-ghost" onClick={onClose} style={{ padding: "10px", width: "auto", flex: 1 }}>Cerrar</button>
        </div>
      </div>
    </div>
  );
}

// ── SECRET MODAL (crear y editar) ─────────────────────────────────────────────
function SecretModal({ collections, onClose, onSave, onToast, userId, editSecret }) {
  const isEdit = !!editSecret;
  const [form, setForm] = useState({ col: collections[0]?.id || "", type: "credential", name: "", user: "", value: "", notes: "" });
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(isEdit);
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  // Si es edición, desencriptamos y pre-cargamos el formulario
  useEffect(() => {
    if (!isEdit) return;
    decryptSecret(editSecret).then(dec => {
      setForm({
        id: editSecret.id,
        col: editSecret.col,
        type: editSecret.type,
        name: editSecret.name,
        user: dec.user || "",
        value: dec.value || "",
        notes: dec.notes || "",
      });
      setLoading(false);
    });
  }, []);

  const handleSave = async () => {
    if (!form.name.trim()) { setErr("El nombre es obligatorio"); return; }
    if (!form.value.trim()) { setErr("El valor no puede estar vacío"); return; }
    if (!_cryptoKey) { setErr("Introduce primero la contraseña maestra"); return; }
    setSaving(true);
    try {
      await saveSecret(form, userId);
      onToast(isEdit ? "✓ Secreto actualizado" : "✓ Secreto guardado y encriptado en Supabase");
      onSave();
      onClose();
    } catch (e) {
      setErr("Error al guardar: " + e.message);
    }
    setSaving(false);
  };

  return (
    <div className="tv-overlay" onClick={onClose}>
      <div className="tv-modal" onClick={e => e.stopPropagation()}>
        <button className="tv-modal-close" onClick={onClose}>✕</button>
        <div className="tv-modal-title">{isEdit ? <><Pencil size={16} style={{display:"inline",marginRight:6,verticalAlign:"middle"}} />Editar secreto</> : "Nuevo secreto"}</div>
        <div className="tv-modal-sub">{isEdit ? "Modifica los datos. Se re-encriptará en tu navegador." : "Se encriptará en tu navegador antes de guardarse en Supabase"}</div>
        {loading ? (
          <div style={{ color: G.muted, fontSize: 13, padding: "20px 0" }}>Desencriptando datos...</div>
        ) : (<>
        <div className="tv-input-row">
          <div className="tv-field">
            <div className="tv-label">Colección</div>
            <select className="tv-select" value={form.col} onChange={e => set("col", e.target.value)}>
              {collections.map(c => <option key={c.id} value={c.id}>{c.icon} {c.name}</option>)}
            </select>
          </div>
          <div className="tv-field">
            <div className="tv-label">Tipo</div>
            <select className="tv-select" value={form.type} onChange={e => set("type", e.target.value)}>
              {Object.entries(TYPE_META).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
          </div>
        </div>
        <div className="tv-field">
          <div className="tv-label">Nombre</div>
          <input className="tv-input" placeholder="ej: MySQL producción" value={form.name} onChange={e => set("name", e.target.value)} />
        </div>
        {form.type === "credential" && (
          <div className="tv-field">
            <div className="tv-label">Usuario / Email</div>
            <input className="tv-input" placeholder="usuario@dominio.com" value={form.user} onChange={e => set("user", e.target.value)} />
          </div>
        )}
        <div className="tv-field">
          <div className="tv-label">{form.type === "config" ? "Contenido (JSON, YAML, texto...)" : "Valor / Contraseña / Key"}</div>
            {form.type === "config" ? (
              <textarea className="tv-textarea" placeholder='{"key": "value"}' value={form.value} onChange={e => set("value", e.target.value)} rows={5} />
            ) : (
              <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                <input
                  className="tv-input"
                  type={form.showValue ? "text" : "password"}
                  placeholder="••••••••••••••••"
                  value={form.value}
                  onChange={e => set("value", e.target.value)}
                  style={{ paddingRight: 40, fontFamily: form.showValue ? "inherit" : "monospace" }}
                />
                <button
                  type="button"
                  onMouseDown={() => set("showValue", true)}
                  onMouseUp={() => set("showValue", false)}
                  onMouseLeave={() => set("showValue", false)}
                  style={{
                    position: "absolute", right: 10,
                    background: "none", border: "none",
                    cursor: "pointer", fontSize: 16,
                    color: "#8B8A9E", padding: "4px",
                    userSelect: "none",
                  }}
                >
                  {form.showValue ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            )}        </div>
        <div className="tv-field">
          <div className="tv-label">Notas (opcional)</div>
          <input className="tv-input" placeholder="Contexto, host, instrucciones..." value={form.notes} onChange={e => set("notes", e.target.value)} />
        </div>
        {err && <div className="tv-error">{err}</div>}
        <div className="tv-modal-actions">
          <button className="tv-btn tv-btn-ghost" onClick={onClose} style={{ padding: "10px", width: "auto", flex: 1 }}>Cancelar</button>
          <button className="tv-btn" onClick={handleSave} disabled={saving} style={{ padding: "10px", width: "auto", flex: 2 }}>
            {saving ? "Encriptando y guardando..." : isEdit ? <><Save size={14} style={{display:"inline",marginRight:6}} />Guardar cambios</> : <><ShieldCheck size={14} style={{display:"inline",marginRight:6}} />Guardar encriptado</>}
          </button>
        </div>
        </>)}
      </div>
    </div>
  );
}

// ── NEW COLLECTION MODAL ──────────────────────────────────────────────────────
function NewCollectionModal({ onClose, onSave, onToast, userId }) {
  const ICONS = ["📁","🚌","🖥️","🏠","🔧","🌐","🗄️","🔐","📊","⚙️","🚀","💡"];
  const [form, setForm] = useState({ name: "", icon: "📁", color: "#7C3AED" });
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSave = async () => {
    if (!form.name.trim()) { setErr("El nombre es obligatorio"); return; }
    setSaving(true);
    try {
      await createCollection(form.name, form.icon, form.color, userId);
      onToast("✓ Colección creada");
      onSave();
      onClose();
    } catch (e) {
      setErr("Error: " + e.message);
    }
    setSaving(false);
  };

  return (
    <div className="tv-overlay" onClick={onClose}>
      <div className="tv-modal" onClick={e => e.stopPropagation()}>
        <button className="tv-modal-close" onClick={onClose}>✕</button>
        <div className="tv-modal-title">Nueva colección</div>
        <div className="tv-modal-sub">Agrupa secretos por proyecto o sistema</div>
        <div className="tv-field">
          <div className="tv-label">Nombre</div>
          <input className="tv-input" placeholder="ej: Infraestructura IT" value={form.name} onChange={e => set("name", e.target.value)} autoFocus />
        </div>
        <div className="tv-field">
          <div className="tv-label">Icono</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {ICONS.map(ic => (
              <button key={ic} onClick={() => set("icon", ic)} style={{
                fontSize: 22, padding: "6px 10px", borderRadius: 8, cursor: "pointer",
                background: form.icon === ic ? G.accentDim : G.surface2,
                border: `1px solid ${form.icon === ic ? G.accentBorder : G.border2}`,
              }}>{ic}</button>
            ))}
          </div>
        </div>
        {err && <div className="tv-error">{err}</div>}
        <div className="tv-modal-actions">
          <button className="tv-btn tv-btn-ghost" onClick={onClose} style={{ padding: "10px", width: "auto", flex: 1 }}>Cancelar</button>
          <button className="tv-btn" onClick={handleSave} disabled={saving} style={{ padding: "10px", width: "auto", flex: 2 }}>
            {saving ? "Creando..." : "✓ Crear colección"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── SECRET CARD ───────────────────────────────────────────────────────────────
function SecretCard({ secret, collections, onSelect, onEdit, onToast, onDelete, userId, vaultLocked }) {
  const meta = TYPE_META[secret.type] || TYPE_META.api;
  const col = collections.find(c => c.id === secret.col);

  return (
    <div className="tv-secret-card" onClick={() => onSelect(secret)}>
      <div className="tv-type-icon" style={{ background: meta.bg, color: meta.color, display: "flex", alignItems: "center", justifyContent: "center" }}>{meta.icon}</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="tv-secret-name">{secret.name}</div>
        <div className="tv-secret-meta">{col ? `${col.icon} ${col.name}` : ""} · {timeAgo(secret.updated_at)}</div>
      </div>
      <span className="tv-type-badge" style={{ background: meta.bg, color: meta.color }}>{meta.label}</span>
      <div className="tv-masked">{mask(secret.enc_value)}</div>
      <div className="tv-card-actions" onClick={e => e.stopPropagation()}>
        {!vaultLocked && (
          <button className="tv-icon-btn" title="Copiar valor" onClick={async () => {
            const d = await decryptSecret(secret);
            navigator.clipboard?.writeText(d.value || "").catch(() => {});
            await addAudit(userId, "copy", secret.name, true);
            onToast("✓ Valor copiado");
          }}><Clipboard size={14} /></button>
        )}
        {!vaultLocked && (
          <button className="tv-icon-btn" title="Editar" onClick={() => onEdit(secret)}><Pencil size={14} /></button>
        )}
        <button className="tv-icon-btn" title="Ver detalle" onClick={() => onSelect(secret)}><Eye size={14} /></button>
      </div>
    </div>
  );
}

// ── MASTER KEY MODAL ──────────────────────────────────────────────────────────
function MasterKeyModal({ onUnlock, userName }) {
  const [master, setMaster] = useState("");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [passkeySupported]  = useState(() => typeof window !== "undefined" && passkey.isSupported());
  const [passkeyRegistered, setPasskeyRegistered] = useState(() => typeof window !== "undefined" && passkey.isRegistered());
  const [showManual, setShowManual] = useState(false);

  useEffect(() => {
    if (passkeyRegistered) handlePasskeyUnlock();
  }, []);

  const handlePasskeyUnlock = async () => {
    setLoading(true); setErr("");
    try {
      const masterPwd = await passkey.unlock();
      const ok = await initCrypto(masterPwd);
      if (ok) {
        onUnlock();
      } else {
        setShowManual(true);
        setErr("❌ La clave biométrica no coincide. Introduce la contraseña manualmente.");
      }
    } catch (e) {
      setShowManual(true);
      setErr("Verificación biométrica cancelada. Introduce la clave manualmente.");
    }
    setLoading(false);
  };

  const handleUnlock = async () => {
    if (master.length < 4) { setErr("Mínimo 4 caracteres"); return; }
    setLoading(true); setErr("");
    try {
      const ok = await initCrypto(master);
      if (!ok) {
        setErr("❌ Contraseña incorrecta. No puede acceder al vault.");
        setLoading(false);
        return;
      }
      // Clave correcta: registrar passkey si es posible
      if (passkeySupported && !passkeyRegistered) {
        try {
          await passkey.register(master, userName || "usuario");
          setPasskeyRegistered(true);
        } catch {
          // Registro opcional, no bloquear si falla o cancela
        }
      }
      onUnlock();
    } catch (e) {
      setErr("Error al verificar la clave");
    }
    setLoading(false);
  };

  const handleForgetPasskey = () => {
    passkey.clear();
    setPasskeyRegistered(false);
    setShowManual(true);
    setErr("");
  };

  // Vista: passkey registrada y no se ha pedido manual
  if (passkeyRegistered && !showManual) {
    return (
      <div className="tv-overlay">
        <div className="tv-modal" style={{ textAlign: "center" }}>
          <div className="tv-modal-title" style={{ justifyContent: "center", display: "flex", alignItems: "center", gap: 8 }}>
            Desbloquear Vault
          </div>
          <div className="tv-modal-sub">Usa tu huella, Face ID o PIN del dispositivo</div>
          {loading ? (
            <div style={{ color: G.muted, fontSize: 13, padding: "24px 0" }}>Esperando verificación biométrica...</div>
          ) : (
            <button className="tv-btn" onClick={handlePasskeyUnlock} style={{ marginBottom: 10 }}>
              <Fingerprint size={16} style={{display:"inline",marginRight:8}} />Verificar identidad
            </button>
          )}
          {err && (
            <div style={{ marginTop: 8, padding: "10px 12px", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, color: G.danger, fontSize: 12 }}>
              {err}
            </div>
          )}
          <div style={{ marginTop: 16 }}>
            <button onClick={handleForgetPasskey} style={{ background: "none", border: "none", color: G.muted, fontSize: 11, cursor: "pointer", textDecoration: "underline" }}>
              Usar contraseña maestra
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Vista: formulario manual (primera vez o fallback)
  return (
    <div className="tv-overlay">
      <div className="tv-modal">
        <div className="tv-modal-title">🔒 Contraseña maestra</div>
        <div className="tv-modal-sub">
          {passkeySupported && !passkeyRegistered
            ? "Al desbloquear, podrás activar el acceso biométrico para la próxima vez."
            : "Necesaria para encriptar y desencriptar los secretos."}
        </div>
        <div className="tv-field">
          <div className="tv-label">Contraseña maestra del equipo</div>
          <input className="tv-input" type="password" placeholder="••••••••••••" value={master}
            onChange={e => setMaster(e.target.value)} onKeyDown={e => e.key === "Enter" && handleUnlock()} autoFocus />
        </div>
        {err && (
          <div style={{ marginTop: 8, padding: "10px 12px", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, color: G.danger, fontSize: 12 }}>
            {err}
          </div>
        )}
        <div className="tv-modal-actions" style={{ marginTop: 16 }}>
          <button className="tv-btn" onClick={handleUnlock} disabled={loading} style={{ padding: "10px", width: "auto", flex: 1 }}>
            {loading
              ? "Verificando..."
              : passkeySupported && !passkeyRegistered
                ? <><Fingerprint size={14} style={{display:"inline",marginRight:6}} />Desbloquear y activar biometría</>
                : <><Unlock size={14} style={{display:"inline",marginRight:6}} />Desbloquear</>
            }
          </button>
        </div>
        {passkeyRegistered && (
          <div style={{ marginTop: 12, textAlign: "center" }}>
            <button onClick={handleForgetPasskey} style={{ background: "none", border: "none", color: G.muted, fontSize: 11, cursor: "pointer", textDecoration: "underline" }}>
              Olvidar biometría en este dispositivo
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── PAGES ─────────────────────────────────────────────────────────────────────
function DashboardPage({ collections, secrets, audit, onToast, onRefresh, userId, isSuperAdmin }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);
  const [showNew, setShowNew] = useState(false);
  const [editing, setEditing] = useState(null);
  const vaultLocked = !_cryptoKey;

  const filtered = secrets.filter(s => {
    if (filter !== "all" && s.type !== filter) return false;
    if (search && !s.name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const handleDelete = async (id) => {
    await deleteSecret(id, userId);
    onRefresh();
  };

  return (
    <>
      <div className="tv-topbar">
        <div className="tv-search">
          <span style={{ color: G.muted }}>🔍</span>
          <input placeholder="Buscar secretos, configs, claves..." value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <button
          className="tv-topbar-btn tv-topbar-btn-primary"
          onClick={() => vaultLocked ? onToast("⚠ Desbloquea el vault primero") : setShowNew(true)}
          title={vaultLocked ? "Desbloquea el vault para crear secretos" : ""}
          style={vaultLocked ? { opacity: 0.5 } : {}}
        >+ Nuevo secreto</button>
      </div>
      <div className="tv-content">
        <div className="tv-stats">
          <div className="tv-stat">
            <div className="tv-stat-label">Total secretos</div>
            <div className="tv-stat-val">{secrets.length}</div>
            <div className="tv-stat-sub">En {collections.length} colecciones</div>
          </div>
          <div className="tv-stat">
            <div className="tv-stat-label">Colecciones</div>
            <div className="tv-stat-val">{collections.length}</div>
            <div className="tv-stat-sub">Activas</div>
          </div>
          <div className="tv-stat">
            <div className="tv-stat-label">Accesos hoy</div>
            <div className="tv-stat-val" style={{ color: G.accent }}>
              {audit.filter(a => new Date(a.ts).toDateString() === new Date().toDateString()).length}
            </div>
            <div className="tv-stat-sub">En el log</div>
          </div>
          <div className="tv-stat">
            <div className="tv-stat-label">Encriptación</div>
            <div className="tv-stat-val" style={{ color: _cryptoKey ? G.success : G.warn, fontSize: 16, paddingTop: 4 }}>
              {_cryptoKey ? "AES-256" : "Sin clave"}
            </div>
            <div className="tv-stat-sub">{_cryptoKey ? "Zero-knowledge activa" : "Solo lectura"}</div>
          </div>
        </div>

        <div className="tv-filters">
          {[["all","Todos"], ["api","API Keys"], ["credential","Credenciales"], ["config","Configs"], ["file","Documentos"]].map(([k,l]) => (
            <button key={k} className={`tv-chip ${filter === k ? "active" : ""}`} onClick={() => setFilter(k)}>{l}</button>
          ))}
        </div>

        <div className="tv-section-hd">
          <div className="tv-section-title">{filtered.length} secreto{filtered.length !== 1 ? "s" : ""}</div>
        </div>

        {filtered.length === 0 ? (
          <div style={{ color: G.muted, fontSize: 13, padding: "32px 0", textAlign: "center" }}>
            {search ? "No hay resultados para tu búsqueda" : "No hay secretos todavía. Crea el primero."}
          </div>
        ) : filtered.map(s => (
          <SecretCard key={s.id} secret={s} collections={collections} onSelect={setSelected} onEdit={setEditing} onToast={onToast} onDelete={handleDelete} userId={userId} vaultLocked={vaultLocked} />
        ))}

        <div className="tv-bottom-grid">
          {isSuperAdmin && (
          <div className="tv-panel">
            <div className="tv-panel-title">Auditoría reciente</div>
            {audit.slice(0, 6).map((a, i) => (
              <div key={a.id || i} className="tv-audit-row">
                <div className="tv-audit-dot" style={{ background: a.ok ? G.success : G.danger }}></div>
                <div>
                  <div className="tv-audit-text">
                    <span className="tv-audit-user">{a.user_email?.split("@")[0] || "usuario"}</span>
                    {" "}{a.action === "read" ? "accedió a" : a.action === "update" ? "actualizó" : a.action === "create" ? "creó" : a.action === "copy" ? "copió" : "eliminó"}
                    {" "}"{a.target_name}"
                    {!a.ok && <span style={{ color: G.danger }}> denegado</span>}
                  </div>
                  <div className="tv-audit-time">{timeAgo(a.ts)}</div>
                </div>
              </div>
            ))}
            {audit.length === 0 && <div style={{ color: G.muted, fontSize: 12, padding: "8px 0" }}>Sin actividad todavía</div>}
          </div>
          )}
          <div className="tv-panel">
            <div className="tv-panel-title">Por tipo</div>
            {Object.entries(TYPE_META).map(([k, v]) => {
              const count = secrets.filter(s => s.type === k).length;
              return (
                <div key={k} style={{ display: "flex", alignItems: "center", gap: 10, padding: "7px 0", borderBottom: `1px solid ${G.border}` }}>
                  <span style={{ color: v.color, display: "flex", alignItems: "center" }}>{v.icon}</span>
                  <span style={{ flex: 1, fontSize: 13 }}>{v.label}</span>
                  <span style={{ fontSize: 13, fontWeight: 600, color: count > 0 ? G.text : G.muted }}>{count}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
      {selected && <DetailModal secret={selected} collections={collections} onClose={() => setSelected(null)} onDelete={handleDelete} onEdit={setEditing} onToast={onToast} userId={userId} vaultLocked={vaultLocked} />}
      {showNew && <SecretModal collections={collections} onClose={() => setShowNew(false)} onSave={onRefresh} onToast={onToast} userId={userId} />}
      {editing && <SecretModal collections={collections} onClose={() => setEditing(null)} onSave={onRefresh} onToast={onToast} userId={userId} editSecret={editing} />}
    </>
  );
}

function AuditPage({ audit }) {
  const actIcon = {
    read:   <Eye size={14} />,
    update: <Pencil size={14} />,
    create: <FileLock2 size={14} />,
    delete: <Trash2 size={14} />,
    copy:   <Clipboard size={14} />,
  };
  return (
    <div className="tv-content">
      <div className="tv-section-hd" style={{ marginBottom: 16 }}>
        <div className="tv-section-title">Log de auditoría completo</div>
      </div>
      {audit.map((a, i) => (
        <div key={a.id || i} className="tv-audit-full-row">
          <div style={{ fontSize: 18 }}>{actIcon[a.action] || "•"}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13 }}>
              <span style={{ fontWeight: 600 }}>{a.user_email?.split("@")[0] || "usuario"}</span>
              {" "}<span style={{ color: G.muted }}>{a.action}</span>
              {" "}→ <span style={{ color: G.text }}>"{a.target_name}"</span>
              {!a.ok && <span style={{ color: G.danger, marginLeft: 8 }}> DENEGADO</span>}
            </div>
            <div style={{ fontSize: 11, color: G.muted, marginTop: 2 }}>{new Date(a.ts).toLocaleString("es-ES")}</div>
          </div>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: a.ok ? G.success : G.danger, flexShrink: 0 }}></div>
        </div>
      ))}
      {audit.length === 0 && <div style={{ color: G.muted, fontSize: 13, padding: "32px 0", textAlign: "center" }}>Sin registros todavía</div>}
    </div>
  );
}

function CollectionsPage({ collections, secrets, audit, onRefresh, onToast, userId }) {
  const [selCol, setSelCol] = useState(null);
  const [selected, setSelected] = useState(null);
  const [showNew, setShowNew] = useState(false);
  const [editing, setEditing] = useState(null);
  const vaultLocked = !_cryptoKey;

  const colSecrets = selCol ? secrets.filter(s => s.col === selCol) : secrets;

  const handleDelete = async (id) => {
    await deleteSecret(id, userId);
    onRefresh();
  };

  return (
    <>
      <div className="tv-topbar">
        <div className="tv-search"><span style={{ color: G.muted }}>📁</span><span style={{ color: G.muted, fontSize: 13 }}>Colecciones</span></div>
        <button
          className="tv-topbar-btn tv-topbar-btn-primary"
          onClick={() => vaultLocked ? onToast("⚠ Desbloquea el vault primero") : setShowNew(true)}
          title={vaultLocked ? "Desbloquea el vault para crear colecciones" : ""}
          style={vaultLocked ? { opacity: 0.5 } : {}}
        >+ Nueva colección</button>
      </div>
      <div className="tv-content">
        <div className="tv-col-grid">
          {collections.map(c => (
            <div key={c.id} className={`tv-col-card ${selCol === c.id ? "selected" : ""}`} onClick={() => setSelCol(selCol === c.id ? null : c.id)}>
              <div className="tv-col-icon">{c.icon}</div>
              <div className="tv-col-name">{c.name}</div>
              <div className="tv-col-count">{secrets.filter(s => s.col === c.id).length} secretos</div>
            </div>
          ))}
          {collections.length === 0 && (
            <div style={{ color: G.muted, fontSize: 13, gridColumn: "1/-1", padding: "20px 0" }}>
              No hay colecciones todavía. Crea la primera.
            </div>
          )}
        </div>
        <div className="tv-section-hd">
          <div className="tv-section-title">{selCol ? collections.find(c => c.id === selCol)?.name : "Todos los secretos"} · {colSecrets.length}</div>
        </div>
        {colSecrets.map(s => (
          <SecretCard key={s.id} secret={s} collections={collections} onSelect={setSelected} onEdit={setEditing} onToast={onToast} onDelete={handleDelete} userId={userId} vaultLocked={vaultLocked} />
        ))}
        {colSecrets.length === 0 && <div style={{ color: G.muted, fontSize: 13, padding: "32px 0", textAlign: "center" }}>Sin secretos en esta colección</div>}
      </div>
      {selected && <DetailModal secret={selected} collections={collections} onClose={() => setSelected(null)} onDelete={handleDelete} onEdit={setEditing} onToast={onToast} userId={userId} vaultLocked={vaultLocked} />}
      {showNew && <NewCollectionModal onClose={() => setShowNew(false)} onSave={onRefresh} onToast={onToast} userId={userId} />}
      {editing && <SecretModal collections={collections} onClose={() => setEditing(null)} onSave={onRefresh} onToast={onToast} userId={userId} editSecret={editing} />}
    </>
  );
}

// ── LOGIN SCREEN ──────────────────────────────────────────────────────────────
function LoginScreen({ onLogin }) {
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session?.user) {
        onLogin({ name: session.user.email.split("@")[0], email: session.user.email, id: session.user.id });
      }
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === "SIGNED_IN" && session?.user) {
        onLogin({ name: session.user.email.split("@")[0], email: session.user.email, id: session.user.id });
      }
    });

    const params = new URLSearchParams(window.location.search);
    if (params.get("error") === "no-autorizado") {
      setErr("Email no autorizado para acceder a TeamVault");
    }

    return () => subscription.unsubscribe();
  }, []);

  const handleGoogle = async () => {
    setLoading(true);
    setErr("");
    const { error } = await supabase.auth.signInWithOAuth({
      provider: "google",
      options: {
        redirectTo: window.location.origin,
        queryParams: { access_type: "offline", prompt: "consent" },
      },
    });
    if (error) { setErr(error.message); setLoading(false); }
  };

  return (
    <div className="tv-login">
      <div className="tv-login-card">
        <div className="tv-login-logo">
          <div className="tv-login-logo-icon"><Lock size={20} color="#fff" /></div>
          <div>
            <div className="tv-login-logo-name">TeamVault</div>
            <div className="tv-login-logo-sub">Gestión segura de secretos</div>
          </div>
        </div>
        <h2>Acceder</h2>
        <p style={{ color: "#8B8A9E", fontSize: 13, marginBottom: 28 }}>
          Usa tu cuenta Google del equipo para entrar
        </p>
        {err && <div className="tv-error" style={{ marginBottom: 12 }}>{err}</div>}
        <button className="tv-btn-google" onClick={handleGoogle} disabled={loading}>
          {!loading && (
            <svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg" style={{ flexShrink: 0 }}>
              <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.875 2.684-6.615z" fill="#4285F4"/>
              <path d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.258c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z" fill="#34A853"/>
              <path d="M3.964 10.707A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.707V4.961H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.039l3.007-2.332z" fill="#FBBC05"/>
              <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.961L3.964 7.293C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335"/>
            </svg>
          )}
          <span>{loading ? "Redirigiendo a Google..." : "Continuar con Google"}</span>
        </button>
      </div>
    </div>
  );
}

// ── APP ROOT ──────────────────────────────────────────────────────────────────
export default function TeamVaultApp() {
  const [user, setUser] = useState(null);
  const [page, setPage] = useState("dashboard");
  const [toast, setToast] = useState("");
  const [tick, setTick] = useState(0);
  const [dataReady, setDataReady] = useState(false);
  // true = vault desbloqueado y app visible; false = pantalla de clave maestra
  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  const [collections, setCollections] = useState([]);
  const [secrets, setSecrets] = useState([]);
  const [audit, setAudit] = useState([]);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem("tv_theme") || "dark"; } catch { return "dark"; } });
  const [isSuperAdmin, setIsSuperAdmin] = useState(false);
  const toastTimer = useRef(null);

  const fetchRole = useCallback(async () => {
    try {
      const res = await fetch("/api/me");
      if (!res.ok) return;
      const { role } = await res.json();
      setIsSuperAdmin(role === "superadmin");
    } catch { /* si falla, queda como member */ }
  }, []);

  // Keep G in sync with theme so all child components using G get the right colors
  G = THEMES[theme] || THEMES.dark;
  const css = makeCSS(theme);
  const toggleTheme = () => setTheme(t => { const next = t === "dark" ? "light" : "dark"; try { localStorage.setItem("tv_theme", next); } catch {} return next; });

  const showToast = useCallback((msg) => {
    setToast(msg);
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(""), 2200);
  }, []);

  const refresh = useCallback(async () => {
    if (!user) return;
    await loadAll(user.id);
    setCollections([..._store.collections]);
    setSecrets([..._store.secrets]);
    setAudit([..._store.audit]);
    setTick(t => t + 1);
  }, [user]);

  useEffect(() => {
    if (!user) return;
    setDataReady(false);
    setVaultUnlocked(false);
    setIsSuperAdmin(false);
    _cryptoKey = null;
    Promise.all([
      loadAll(user.id),
      fetchRole(),
    ]).then(() => {
      setCollections([..._store.collections]);
      setSecrets([..._store.secrets]);
      setAudit([..._store.audit]);
      setDataReady(true);
    });
  }, [user, fetchRole]);

  const NAV = [
    { id: "dashboard", icon: <LayoutDashboard size={16} />, label: "Dashboard" },
    { id: "collections", icon: <FolderOpen size={16} />, label: "Colecciones" },
    ...(isSuperAdmin ? [{ id: "audit", icon: <ClipboardList size={16} />, label: "Auditoría" }] : []),
  ];

  const navigateTo = (id) => { setPage(id); setDrawerOpen(false); };

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    _cryptoKey = null;
    setUser(null);
    setDrawerOpen(false);
  };

  // Contenido del panel de navegación (reutilizado en sidebar y drawer)
  const NavContent = () => (
    <>
      <div className="tv-sidebar-logo">
        <div className="tv-sidebar-logo-icon"><Lock size={16} color="#fff" /></div>
        <div className="tv-sidebar-logo-txt">TeamVault</div>
      </div>
      <div className="tv-nav-section">
        <div className="tv-nav-label">Menú</div>
        {NAV.map(n => (
          <div key={n.id} className={`tv-nav-item ${page === n.id ? "active" : ""}`} onClick={() => navigateTo(n.id)}>
            <span className="nav-icon">{n.icon}</span>
            {n.label}
            {n.id === "audit" && audit.length > 0 && <span className="tv-nav-badge">{audit.length}</span>}
          </div>
        ))}
      </div>
      <div className="tv-sidebar-bottom">
        <div className="tv-user-chip">
          <div className="tv-avatar">{user.name.slice(0,2).toUpperCase()}</div>
          <div>
            <div className="tv-avatar-name">{user.name}</div>
            <div className="tv-avatar-role">{user.email}</div>
          </div>
        </div>
        <div className="tv-enc-badge">
          {_cryptoKey ? <><Lock size={12} style={{display:"inline",marginRight:4}} />AES-256-GCM activo</> : <><Unlock size={12} style={{display:"inline",marginRight:4}} />Sin clave maestra</>}
        </div>
        <button className="tv-theme-toggle" onClick={toggleTheme}>
          {theme === "dark" ? "☀ Modo claro" : "🌙 Modo oscuro"}
        </button>
        <div className="tv-nav-item" style={{ marginTop: 6, color: G.accent }} onClick={handleSignOut}>
          <LogOut size={15} style={{display:"inline",marginRight:6}} />Salir
        </div>
        <div style={{ padding: "8px 10px 0", fontSize: 10, color: "#7C5CFC", opacity: 1, letterSpacing: "0.04em" }}>
          v{APP_VERSION}
        </div>
      </div>
    </>
  );

  // Paso 1: sin usuario → pantalla de login Google
  if (!user) return (
    <>
      <style>{css}</style>
      <div className="tv-root">
        <LoginScreen onLogin={u => setUser(u)} />
      </div>
    </>
  );

  // Paso 2: usuario logueado pero vault bloqueado → pantalla de clave maestra (full screen)
  if (!vaultUnlocked) return (
    <>
      <style>{css}</style>
      <div className="tv-root">
        <MasterKeyModal
          userName={user?.email || "usuario"}
          onUnlock={() => { setVaultUnlocked(true); showToast("✓ Vault desbloqueado"); }}
        />
      </div>
    </>
  );

  // Paso 3: usuario logueado + vault desbloqueado → app completa
  return (
    <>
      <style>{css}</style>
      <div className="tv-root">
        {/* Drawer móvil */}
        <div className={`tv-drawer-overlay ${drawerOpen ? "open" : ""}`} onClick={() => setDrawerOpen(false)} />
        <nav className={`tv-drawer ${drawerOpen ? "open" : ""}`}>
          <NavContent />
        </nav>

        <div className="tv-layout">
          {/* Sidebar desktop */}
          <nav className="tv-sidebar">
            <NavContent />
          </nav>

          <main className="tv-main">
            {/* Topbar con hamburguesa en móvil */}
            {dataReady && (
              <div style={{ display: "flex", alignItems: "center", padding: "12px 12px 0", gap: 8 }}>
                <button className="tv-hamburger" onClick={() => setDrawerOpen(true)} aria-label="Menú">
                  <svg width="18" height="14" viewBox="0 0 18 14" fill="none">
                    <rect y="0" width="18" height="2" rx="1" fill="currentColor"/>
                    <rect y="6" width="18" height="2" rx="1" fill="currentColor"/>
                    <rect y="12" width="18" height="2" rx="1" fill="currentColor"/>
                  </svg>
                </button>
                <span style={{ fontSize: 13, fontWeight: 600, color: G.muted }}>
                  {NAV.find(n => n.id === page)?.icon} {NAV.find(n => n.id === page)?.label}
                </span>
              </div>
            )}

            {!dataReady ? (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", flex: 1, color: G.muted, fontSize: 14 }}>
                Cargando datos de Supabase...
              </div>
            ) : (
              <>
                {page === "dashboard" && <DashboardPage key={tick} collections={collections} secrets={secrets} audit={audit} onToast={showToast} onRefresh={refresh} userId={user.id} isSuperAdmin={isSuperAdmin} />}
                {page === "collections" && <CollectionsPage key={tick} collections={collections} secrets={secrets} audit={audit} onRefresh={refresh} onToast={showToast} userId={user.id} />}
                {page === "audit" && isSuperAdmin && <AuditPage key={tick} audit={audit} />}
              </>
            )}
          </main>
        </div>
        {toast && <Toast msg={toast} />}
      </div>
    </>
  );
}
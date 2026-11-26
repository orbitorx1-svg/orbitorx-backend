/**
 * orbitorx-auth.js  —  Firebase Admin + custom-token endpoint  (ESM version)
 * ---------------------------------------------------------------------------
 * server.js already uses `import`, so this file is ESM too. Keep both files
 * in the repo root.
 *
 * What it does
 *   1) saveOtp(mobile, otp)   -> stores the OTP in Firestore (otp_verify/<mobile>)
 *                                with a 10 minute expiry.
 *   2) POST /auth/custom-token -> { mobile, otp } verify karta hai aur Firebase
 *                                custom token deta hai. App us token se
 *                                signInWithCustomToken() karega, phir Firestore
 *                                ko request.auth.uid mil jayega.
 *   3) GET  /auth/ping         -> sanity check.
 *
 * Setup
 *   npm install firebase-admin
 *   Render > Environment > Secret Files:
 *     Filename   : firebase-key.json
 *     Mount path : /etc/secrets/firebase-key.json
 * ---------------------------------------------------------------------------
 */

import fs from 'fs';
import admin from 'firebase-admin';

const KEY_PATH = process.env.FIREBASE_KEY_PATH || '/etc/secrets/firebase-key.json';
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'orbitorx';
const OTP_COLLECTION = 'otp_verify';
const OTP_TTL_MIN = 10;
const MAX_TRIES = 5;

function loadCredential() {
  if (process.env.FIREBASE_KEY_JSON) {
    try { return admin.credential.cert(JSON.parse(process.env.FIREBASE_KEY_JSON)); }
    catch (e) { console.error('[auth] FIREBASE_KEY_JSON parse failed:', e.message); }
  }
  if (fs.existsSync(KEY_PATH)) {
    try { return admin.credential.cert(JSON.parse(fs.readFileSync(KEY_PATH, 'utf8'))); }
    catch (e) { console.error('[auth] key file read failed:', e.message); }
  }
  console.error('[auth] No Firebase key found at ' + KEY_PATH);
  return undefined;
}

if (!admin.apps.length) {
  admin.initializeApp({ credential: loadCredential(), projectId: PROJECT_ID });
}

const db = () => admin.firestore();

export function cleanMobile(mobile) {
  return String(mobile || '').replace(/\D/g, '').slice(-10);
}

/** Firebase uid that never changes for a given phone number. */
export function uidFor(mobile) {
  return 'u' + cleanMobile(mobile);
}

/** Save a freshly generated OTP (called from /api/generate-auto-otp). */
export async function saveOtp(mobile, otp, ttlMin = OTP_TTL_MIN) {
  const m = cleanMobile(mobile);
  if (m.length !== 10 || !otp) throw new Error('bad mobile/otp');
  await db().collection(OTP_COLLECTION).doc(m).set({
    otp: String(otp),
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + ttlMin * 60 * 1000,
    tries: 0,
  });
  return true;
}

/** Check an OTP. Returns true once, then the record is deleted. */
export async function verifyOtp(mobile, otp) {
  const m = cleanMobile(mobile);
  if (m.length !== 10 || !otp) return false;
  const ref = db().collection(OTP_COLLECTION).doc(m);
  const snap = await ref.get();
  if (!snap.exists) return false;

  const d = snap.data() || {};
  if (Number(d.expiresAt || 0) < Date.now()) { await ref.delete().catch(() => {}); return false; }
  if (Number(d.tries || 0) >= MAX_TRIES) { await ref.delete().catch(() => {}); return false; }

  if (String(d.otp) !== String(otp).trim()) {
    await ref.update({ tries: (Number(d.tries) || 0) + 1 }).catch(() => {});
    return false;
  }

  await ref.delete().catch(() => {});
  return true;
}

/** Create a Firebase custom token for a verified mobile number. */
export async function createTokenForMobile(mobile) {
  const m = cleanMobile(mobile);
  if (m.length !== 10) throw new Error('bad mobile');
  return admin.auth().createCustomToken(uidFor(m), {
    phone: '+91' + m,
    provider: 'orbitorx-otp',
  });
}

/** Mount the routes on the existing express app. */
export function mountAuth(app) {
  app.get('/auth/ping', (_req, res) => {
    res.json({ ok: true, project: PROJECT_ID, adminReady: admin.apps.length > 0 });
  });

  app.post('/auth/custom-token', async (req, res) => {
    try {
      const body = req.body || {};
      const mobile = cleanMobile(body.mobile);
      const otp = String(body.otp || '').trim();

      if (mobile.length !== 10 || !otp) {
        return res.status(400).json({ error: 'mobile and otp are required' });
      }

      const ok = await verifyOtp(mobile, otp);
      if (!ok) return res.status(401).json({ error: 'invalid or expired otp' });

      const token = await createTokenForMobile(mobile);
      return res.json({ token, uid: uidFor(mobile) });
    } catch (err) {
      console.error('[auth] custom-token error:', err);
      return res.status(500).json({ error: 'server error' });
    }
  });
}

export { admin };

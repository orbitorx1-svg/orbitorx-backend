/**
 * orbitorx-auth.js  —  Firebase Admin + custom-token endpoint  (ESM, crash-safe)
 * ---------------------------------------------------------------------------
 * v2 changes
 *   - Agar Firebase key na mile to server CRASH nahi hoga.
 *     Baaki routes (rapidoreach etc.) normal chalte rahenge.
 *   - /auth/ping batayega ki key mili ya nahi.
 *   - /auth/custom-token 503 dega jab tak key na lage.
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

let adminReady = false;
let adminError = '';

function loadCredential() {
  try {
    if (process.env.FIREBASE_KEY_JSON) {
      return admin.credential.cert(JSON.parse(process.env.FIREBASE_KEY_JSON));
    }
    if (fs.existsSync(KEY_PATH)) {
      return admin.credential.cert(JSON.parse(fs.readFileSync(KEY_PATH, 'utf8')));
    }
    adminError = 'key file not found at ' + KEY_PATH;
    return null;
  } catch (e) {
    adminError = 'key load failed: ' + e.message;
    return null;
  }
}

try {
  if (!admin.apps.length) {
    const cred = loadCredential();
    if (cred) {
      admin.initializeApp({ credential: cred, projectId: PROJECT_ID });
      adminReady = true;
      console.log('[auth] Firebase Admin ready');
    } else {
      console.error('[auth] Firebase Admin NOT ready —', adminError);
    }
  } else {
    adminReady = true;
  }
} catch (e) {
  adminReady = false;
  adminError = 'initializeApp failed: ' + e.message;
  console.error('[auth] initializeApp failed:', e.message);
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
  if (!adminReady) throw new Error('firebase admin not ready: ' + adminError);
  await db().collection(OTP_COLLECTION).doc(m).set({
    otp: String(otp),
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + ttlMin * 60 * 1000,
    tries: 0,
  });
  return true;
}

/**
 * The app writes the OTP to `users_auth` (mobile, otp, timestamp) and the admin
 * sends it to the user. So the real check happens here, on the server.
 */
async function verifyFromUsersAuth(m, otp) {
  // data me dono format hain: "+91XXXXXXXXXX" aur "XXXXXXXXXX"
  let snap = await db().collection('users_auth')
    .where('mobile', 'in', ['+91' + m, m]).get();
  if (snap.empty) {
    snap = await db().collection('users_auth')
      .where('mobile', '==', '+91 ' + m).get();
  }
  if (snap.empty) return false;

  let best = null;
  snap.forEach((d) => {
    const v = d.data() || {};
    if (!best || String(v.timestamp || '') > String(best.timestamp || '')) best = v;
  });
  if (!best) return false;
  if (String(best.otp || '') !== String(otp).trim()) return false;

  const t = Date.parse(best.timestamp || '') || 0;
  if (t && Date.now() - t > 15 * 60 * 1000) return false;   // 15 minute validity
  return true;
}

/** Check an OTP. Returns true once, then the record is deleted. */
export async function verifyOtp(mobile, otp) {
  const m = cleanMobile(mobile);
  if (m.length !== 10 || !otp) return false;
  if (!adminReady) return false;

  try {
    if (await verifyFromUsersAuth(m, otp)) return true;
  } catch (e) {
    console.error('[auth] users_auth check failed:', e.message);
  }

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
  if (!adminReady) throw new Error('firebase admin not ready: ' + adminError);
  return admin.auth().createCustomToken(uidFor(m), {
    phone: '+91' + m,
    provider: 'orbitorx-otp',
  });
}

/** Mount the routes on the existing express app. */
export function mountAuth(app) {
  app.get('/auth/ping', (_req, res) => {
    res.json({
      ok: true,
      build: 'v7',
      project: PROJECT_ID,
      adminReady,
      error: adminReady ? '' : adminError,
      keyPath: KEY_PATH,
    });
  });

  /* POST /auth/admin-token — admin panel ke liye token (admin:true claim) */
  app.post('/auth/admin-token', async (req, res) => {
    try {
      if (!adminReady) return res.status(503).json({ error: 'server not configured' });
      const body = req.body || {};
      const email = String(body.email || '').trim().toLowerCase();
      const pass = String(body.password || '');
      const A_EMAIL = (process.env.ADMIN_EMAIL || 'developer@orbitorx.com').toLowerCase();
      const A_PASS = process.env.ADMIN_PASSWORD || 'Orbitorx@2026';

      if (!email || email !== A_EMAIL || pass !== A_PASS) {
        return res.status(401).json({ error: 'invalid credentials' });
      }
      const uid = 'admin-' + Buffer.from(email).toString('hex').slice(0, 12);
      const token = await admin.auth().createCustomToken(uid, { admin: true, email });
      return res.json({ token, uid });
    } catch (err) {
      console.error('[auth] admin-token error:', err);
      return res.status(500).json({ error: 'server error', detail: String(err.message || err) });
    }
  });

  /* GET /auth/selftest — Firestore aur token dono check karta hai */
  app.get('/auth/selftest', async (_req, res) => {
    const out = { build: 'v7', adminReady, adminError };
    try {
      const snap = await db().collection('users_auth').limit(3).get();
      out.usersAuth = 'ok, docs=' + snap.size;
      const sample = [];
      snap.forEach((d) => {
        const v = d.data() || {};
        sample.push({ mobile: v.mobile || null, hasOtp: !!v.otp, timestamp: v.timestamp || null });
      });
      out.sample = sample;
    } catch (e) {
      out.usersAuth = 'ERR: ' + e.message;
      out.usersAuthCode = e.code || '';
    }
    try {
      const t = await createTokenForMobile('9999999999');
      out.customToken = 'ok, len=' + String(t).length;
    } catch (e) {
      out.customToken = 'ERR: ' + e.message;
      out.customTokenCode = e.code || '';
    }
    res.json(out);
  });

  app.post('/auth/custom-token', async (req, res) => {
    try {
      if (!adminReady) {
        return res.status(503).json({ error: 'server not configured', detail: adminError });
      }
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
      return res.status(500).json({
        error: 'server error',
        detail: String((err && err.message) || err),
        code: String((err && err.code) || ''),
      });
    }
  });
}

export { admin };

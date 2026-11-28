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
      build: 'v17',
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

  /* POST /notify — admin panel se push notification bhejne ke liye */
  app.post('/notify', async (req, res) => {
    try {
      if (!adminReady) return res.status(503).json({ error: 'server not configured' });

      const auth = String(req.headers.authorization || '');
      const idToken = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!idToken) return res.status(401).json({ error: 'missing token' });

      let dec;
      try { dec = await admin.auth().verifyIdToken(idToken); }
      catch (e) { return res.status(401).json({ error: 'invalid token' }); }
      const _isAdmin = dec && (dec.admin === true || String(dec.uid || '').indexOf('admin-') === 0);
      if (!_isAdmin) return res.status(403).json({ error: 'admin only', uid: String((dec && dec.uid) || '') });

      const body = req.body || {};
      const m = cleanMobile(body.mobile);
      const title = String(body.title || '').trim();
      const text = String(body.body || body.message || '').trim();
      if (m.length !== 10 || !title) return res.status(400).json({ error: 'mobile and title required' });

      const tokens = new Set();
      try {
        const q = await db().collection('fcm_tokens').where('mobile', 'in', ['+91' + m, m]).get();
        q.forEach((d) => { const v = d.data() || {}; if (v.token) tokens.add(v.token); });
      } catch (e) { console.warn('[notify] query failed:', e.message); }
      try {
        const docRef = await db().collection('fcm_tokens').doc('u' + m).get();
        if (docRef.exists) { const v = docRef.data() || {}; if (v.token) tokens.add(v.token); }
      } catch (e) {}

      if (!tokens.size) return res.json({ sent: 0, reason: 'no tokens for this user' });

      const img = String(body.image || body.imageUrl || '').trim();
      const notif = { title: title, body: text || 'Tap to open OrbitorX' };
      const data = { title: title, body: text || '', url: String(body.url || '/') };
      if (img) { notif.image = img; data.image = img; }
      const msg = {
        tokens: Array.from(tokens),
        notification: notif,
        data: data,
        webpush: {
          notification: Object.assign({
            icon: 'https://orbitorx.online/icons/icon-192.png',
            badge: 'https://orbitorx.online/icons/icon-192.png',
          }, img ? { image: img } : {}),
          fcmOptions: { link: 'https://orbitorx.online/' },
        },
      };
      const r = await admin.messaging().sendEachForMulticast(msg);
      return res.json({ sent: r.successCount, failed: r.failureCount });
    } catch (err) {
      console.error('[notify] error:', err);
      return res.status(500).json({ error: 'server error', detail: String(err.message || err) });
    }
  });

  /* POST /notify-admin — user ka koi action admin ko push kare */
  app.post('/notify-admin', async (req, res) => {
    try {
      if (!adminReady) return res.status(503).json({ error: 'server not configured' });

      const auth = String(req.headers.authorization || '');
      const idToken = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!idToken) return res.status(401).json({ error: 'missing token' });

      let dec;
      try { dec = await admin.auth().verifyIdToken(idToken); }
      catch (e) { return res.status(401).json({ error: 'invalid token' }); }

      const body = req.body || {};
      const title = String(body.title || 'OrbitorX').slice(0, 80);
      const text = String(body.body || body.message || '').slice(0, 200);

      const snap = await db().collection('fcm_tokens').get();
      const tokens = [];
      snap.forEach((d) => {
        const v = d.data() || {};
        const uid = String(v.uid || d.id || '');
        if (v.token && uid.indexOf('admin-') === 0) tokens.push(v.token);
      });
      if (!tokens.length) return res.json({ sent: 0, reason: 'no admin tokens' });

      const r = await admin.messaging().sendEachForMulticast({
        tokens,
        notification: { title, body: text || 'New activity' },
        data: { title, body: text, url: '/' },
      });
      return res.json({ sent: r.successCount, failed: r.failureCount });
    } catch (err) {
      console.error('[notify-admin] error:', err);
      return res.status(500).json({ error: 'server error', detail: String(err.message || err) });
    }
  });

  /* ---------- PUBSCALE OFFERWALL CALLBACK ---------- */
  const pubscaleHandler = async (req, res) => {
    try {
      if (!adminReady) return res.status(503).send('not configured');
      const q = Object.assign({}, req.query, req.body || {});

      const userId = String(q.user_id || q.userId || '').trim();
      const value = Number(q.value || q.reward || 0);
      const token = String(q.token || q.transaction_id || '').trim();
      const key = String(q.key || '').trim();

      const EXPECT = String(process.env.PUBSCALE_CALLBACK_KEY || '');
      if (EXPECT && key !== EXPECT) return res.status(401).send('bad key');
      if (!userId || !value) return res.status(400).send('bad params');

      const dedupeId = token || (userId + '_' + value + '_' + Math.floor(Date.now() / 60000));
      const dedupeRef = db().collection('pubscale_callbacks').doc(dedupeId);
      const seen = await dedupeRef.get();
      if (seen.exists) return res.status(200).send('duplicate');

      const snap = await db().collection('user_profiles').where('customUserID', '==', userId).limit(1).get();
      if (snap.empty) {
        await dedupeRef.set({ q: q, status: 'no_user', at: new Date().toISOString() });
        return res.status(200).send('no user');
      }

      const rate = Number(process.env.PUBSCALE_COIN_VALUE || 0.8);   // rupees per coin
      const rupees = Math.round(value * rate * 100) / 100;
      const userRef = snap.docs[0].ref;

      await db().runTransaction(async (t) => {
        const fresh = await t.get(userRef);
        const d = (fresh.exists && fresh.data()) || {};
        const bal = Number(d.balance || 0);
        t.update(userRef, { balance: Math.round((bal + rupees) * 100) / 100 });
        t.set(db().collection('user_transactions').doc(), {
          transactionID: token || dedupeId,
          mobile: d.mobile || '',
          email: d.email || '',
          customUserID: userId,
          userName: d.fullName || '',
          type: 'credit',
          source: 'pubscale_offerwall',
          title: 'Offerwall Reward',
          amount: rupees,
          coins: value,
          status: 'Success',
          timestamp: new Date().toISOString(),
        });
      });

      await dedupeRef.set({ q: q, status: 'credited', rupees: rupees, at: new Date().toISOString() });
      return res.status(200).send('OK');
    } catch (err) {
      console.error('[pubscale] error:', err);
      return res.status(500).send('error');
    }
  };
  app.get('/pubscale-callback', pubscaleHandler);
  app.post('/pubscale-callback', pubscaleHandler);

  /* POST /notify-bulk — admin sab users ya chune hue users ko bheje */
  app.post('/notify-bulk', async (req, res) => {
    try {
      if (!adminReady) return res.status(503).json({ error: 'server not configured' });

      const auth = String(req.headers.authorization || '');
      const idToken = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!idToken) return res.status(401).json({ error: 'missing token' });
      let dec;
      try { dec = await admin.auth().verifyIdToken(idToken); }
      catch (e) { return res.status(401).json({ error: 'invalid token' }); }
      const _isAdmin = dec && (dec.admin === true || String(dec.uid || '').indexOf('admin-') === 0);
      if (!_isAdmin) return res.status(403).json({ error: 'admin only', uid: String((dec && dec.uid) || '') });

      const b = req.body || {};
      const title = String(b.title || '').trim().slice(0, 90);
      const text = String(b.body || b.message || '').trim().slice(0, 300);
      const img = String(b.image || '').trim();
      if (!title) return res.status(400).json({ error: 'title required' });

      const wantAll = b.all === true;
      const wanted = new Set((Array.isArray(b.mobiles) ? b.mobiles : []).map((x) => cleanMobile(x)).filter(Boolean));
      const wantedEmails = new Set((Array.isArray(b.emails) ? b.emails : []).map((x) => String(x || '').trim().toLowerCase()).filter(Boolean));

      const snap = await db().collection('fcm_tokens').get();
      const tokens = [];
      snap.forEach((d) => {
        const v = d.data() || {};
        if (!v.token) return;
        if (wantAll) { tokens.push(v.token); return; }
        const m = cleanMobile(v.mobile || d.id || '');
        if (m && wanted.has(m)) { tokens.push(v.token); return; }
        const em = String(v.email || '').trim().toLowerCase();
        if (em && wantedEmails.has(em)) { tokens.push(v.token); }
      });
      if (!tokens.length) return res.json({ sent: 0, failed: 0, reason: 'no matching tokens' });

      const notif = { title: title, body: text || 'Open OrbitorX' };
      const data = { title: title, body: text || '', url: '/' };
      if (img) { notif.image = img; data.image = img; }

      let sent = 0, failed = 0;
      for (let i = 0; i < tokens.length; i += 500) {
        const chunk = tokens.slice(i, i + 500);
        const r = await admin.messaging().sendEachForMulticast({
          tokens: chunk,
          notification: notif,
          data: data,
          webpush: {
            notification: Object.assign({
              icon: 'https://orbitorx.online/icons/icon-192.png',
              badge: 'https://orbitorx.online/icons/icon-192.png',
            }, img ? { image: img } : {}),
            fcmOptions: { link: 'https://orbitorx.online/' },
          },
        });
        sent += r.successCount; failed += r.failureCount;
      }
      return res.json({ sent: sent, failed: failed, tokens: tokens.length });
    } catch (err) {
      console.error('[notify-bulk] error:', err);
      return res.status(500).json({ error: 'server error', detail: String(err.message || err) });
    }
  });

  /* GET /auth/selftest — Firestore aur token dono check karta hai */
  app.get('/auth/selftest', async (_req, res) => {
    const out = { build: 'v17', adminReady, adminError };
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
    /* FCM send permission check (dry run — koi notification nahi jayegi) */
    try {
      await admin.messaging().send({
        token: 'dry-run-test-token',
        notification: { title: 't', body: 't' },
      }, true);
      out.fcm = 'ok (dry run)';
    } catch (e) {
      out.fcm = 'ERR: ' + String((e && e.code) || '') + ' ' + String((e && e.message) || e);
    }
    /* token count + asli test push (pehle token par) */
    try {
      const snap2 = await db().collection('fcm_tokens').get();
      out.fcmTokens = snap2.size;
      /* sabse NAYA token use karo (jo abhi register hua ho) */
      let firstTok = null, firstDoc = null, bestAt = '';
      snap2.forEach((d) => {
        const v = d.data() || {};
        if (!v.token) return;
        const at = String(v.updatedAt || '');
        if (!firstTok || at > bestAt) { firstTok = v.token; firstDoc = d.id; bestAt = at; }
      });
      out.firstTokenDoc = firstDoc || null;
      if (firstTok) {
        try {
          const r2 = await admin.messaging().send({
            token: firstTok,
            notification: { title: 'OrbitorX test', body: 'Push test from selftest' },
          });
          out.realPush = 'ok: ' + String(r2).slice(0, 40);
        } catch (e) {
          out.realPush = 'ERR: ' + String((e && e.code) || '') + ' ' + String((e && e.message) || e).slice(0, 160);
        }
      } else {
        out.realPush = 'no token found';
      }
    } catch (e) {
      out.fcmTokens = 'ERR: ' + e.message;
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

import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const APP_ID = process.env.RAPIDOREACH_APP_ID || 'LqVvhW4ElAN';
const APP_KEY = process.env.RAPIDOREACH_APP_KEY || 'e77a1cb9ed3fed066bf7fb8ed3bbee42';
const APP_SECRET = process.env.RAPIDOREACH_APP_SECRET || '9070d178139ae2b099cacaf4dab18fe1';

app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'orbitorx-backend' });
});

app.get('/api/rapidoreach-url', (req, res) => {
  const userId = String(req.query.userId || '').trim();
  if (!userId) {
    return res.status(400).json({ error: 'userId is required' });
  }

  const rawString = `${userId}-${APP_ID}-${APP_KEY}`;
  const checksum = crypto.createHash('md5').update(rawString).digest('hex');
  const uid = `${userId}-${APP_ID}-${checksum}`;
  const offerwallUrl = `https://www.rapidoreach.com/ofw/?userId=${encodeURIComponent(uid)}`;

  return res.json({ uid, offerwallUrl });
});

const processedTxns = new Set();

function handleCallback(req, res) {
  const data = { ...req.query, ...req.body };

  const rawUserId = String(data.userId || data.user_id || data.uid || '').trim();
  const txId = String(data.transactionId || data.transaction_id || data.txId || '').trim();
  const status = String(data.status || '').trim();
  const reward = Number(data.reward ?? data.amount ?? data.vc ?? 0);
  const internalUserId = rawUserId.includes('-') ? rawUserId.split('-')[0] : rawUserId;

  if (txId && processedTxns.has(txId)) {
    return res.status(200).send('OK');
  }
  if (txId) {
    processedTxns.add(txId);
  }

  console.log('Callback received:', {
    internalUserId,
    rawUserId,
    txId,
    status,
    reward,
  });

  return res.status(200).send('OK');
}

app.get('/api/rapidoreach-callback', handleCallback);
app.post('/api/rapidoreach-callback', handleCallback);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

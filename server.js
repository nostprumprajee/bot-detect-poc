// server.js
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const path = require('path');

const APP_SECRET = "super_secret_key_change_me";

const app = express();
app.use(bodyParser.json({ limit: "500kb" }));
app.use(express.static(path.join(__dirname, "public")));

/* In-memory stores for POC */
const fingerprints = new Map();
const telemetryStore = new Map();

/* HMAC token */
function signToken(payload, ttl = 60) {
  const data = {
    ...payload,
    exp: Date.now() + ttl * 1000
  };
  const msg = JSON.stringify(data);
  const sig = crypto.createHmac('sha256', APP_SECRET).update(msg).digest('hex');
  return Buffer.from(msg).toString('base64') + "." + sig;
}

function verifyToken(token) {
  try {
    const [b64, sig] = token.split(".");
    const msg = Buffer.from(b64, 'base64').toString();
    const expected = crypto.createHmac('sha256', APP_SECRET).update(msg).digest('hex');
    if (expected !== sig) return null;
    const data = JSON.parse(msg);
    if (Date.now() > data.exp) return null;
    return data;
  } catch (e) {
    return null;
  }
}

/* Receive fingerprint */
app.post("/api/fingerprint", (req, res) => {
  const { fp, basic, canvasHash, audioHash } = req.body;
  if (!fp) return res.json({ ok: false });

  const now = Date.now();
  const rec = fingerprints.get(fp) || { firstSeen: now, count: 0, lastSeen: 0 };
  rec.count += 1;
  rec.lastSeen = now;
  rec.basic = basic;
  rec.canvasHash = canvasHash;
  rec.audioHash = audioHash;
  fingerprints.set(fp, rec);

  const token = signToken({ fp });

  console.log("FP received:", fp);

  res.json({ ok: true, token });
});

/* Receive telemetry */
app.post("/api/telemetry", (req, res) => {
  const sid = req.headers["x-session-id"] || "anon";
  const events = req.body.events || [];

  const arr = telemetryStore.get(sid) || [];
  arr.push(...events);

  if (arr.length > 2000) arr.splice(0, arr.length - 2000);

  telemetryStore.set(sid, arr);

  res.json({ ok: true });
});

/* Score calculation */
function scoreTelemetry(events = []) {
  if (!events.length) return 0.2;

  let last = null;
  let deltas = [];
  let clicks = 0;

  for (const e of events) {
    if (e.type === "click") clicks++;
    if (last) deltas.push(e.t - last.t);
    last = e;
  }

  let score = 1.0;

  const avgDelta = deltas.reduce((a, b) => a + b, 0) / (deltas.length || 1);

  if (avgDelta < 20) score -= 0.6;
  else if (avgDelta < 80) score -= 0.2;

  if (clicks === 0 && events.length > 50) score -= 0.3;

  return Math.max(0, Math.min(1, score));
}

/* Endpoint to assess */
app.get("/api/assess", (req, res) => {
  const token = req.headers["x-auth-token"];
  const verified = verifyToken(token);
  if (!verified) return res.json({ action: "invalid_token" });

  const sid = req.headers["x-session-id"] || "anon";
  const events = telemetryStore.get(sid) || [];

  const score = scoreTelemetry(events);

  let action = "allow";
  if (score < 0.3) action = "block";
  else if (score < 0.6) action = "challenge";

  res.json({ action, score, eventCount: events.length });
});

/* Start */
app.listen(3000, () => {
  console.log("POC bot detection server running on http://localhost:3000");
});

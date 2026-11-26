
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
app.use(cors()); // Erlaubt Anfragen aus PenguinMod (Browser)
app.use(express.json());

// Speicher im RAM (für Dauer-Speicherung binden wir später eine Datenbank an)
// Struktur: username -> { passwordHash, token, tokenExpiresAt, createdAt }
const users = new Map();

// Hilfsfunktion: Neuen zufälligen Token erzeugen (gültig für 48 Stunden)
const TOKEN_TTL_MS = 48 * 60 * 60 * 1000;

function createSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Middleware: Prüft bei geschützten Routen, ob ein gültiger Token mitgeschickt wurde
function requireAuth(req, res, next) {
  const token = req.body?.token || req.headers['authorization'];

  if (!token) {
    // Keine Antwort mit Daten – Zugriff verweigert
    return res.status(401).json({ ok: false, error: 'NO_TOKEN' });
  }

  let matchedUser = null;
  let matchedUsername = null;

  for (const [username, userData] of users.entries()) {
    if (userData.token === token) {
      matchedUser = userData;
      matchedUsername = username;
      break;
    }
  }

  if (!matchedUser) {
    return res.status(401).json({ ok: false, error: 'INVALID_TOKEN' });
  }

  // Prüfen, ob die 48 Stunden abgelaufen sind
  if (Date.now() > matchedUser.tokenExpiresAt) {
    matchedUser.token = null;
    matchedUser.tokenExpiresAt = 0;
    return res.status(401).json({ ok: false, error: 'TOKEN_EXPIRED' });
  }

  // Nutzer für den nächsten Schritt merken
  req.user = { username: matchedUsername, data: matchedUser };
  next();
}

// ---------------------------------------------------------
// 1. ÖFFENTLICHE AUTH-ENDPUNKTE (nur für Login / Registrierung)
// ---------------------------------------------------------

// Schritt 1 beim Login: Prüfen, ob Username existiert
app.post('/check-user', (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  if (!username) {
    return res.status(400).json({ ok: false, exists: false });
  }

  const exists = users.has(username);
  return res.json({ ok: true, exists });
});

// Neuen Account registrieren
app.post('/register', async (req, res) => {
  const rawUsername = String(req.body?.username || '').trim();
  const username = rawUsername.toLowerCase();
  const password = String(req.body?.password || '');

  if (username.length < 3 || username.length > 20) {
    return res.status(400).json({ ok: false, error: 'USERNAME_LENGTH' });
  }
  if (password.length < 4) {
    return res.status(400).json({ ok: false, error: 'PASSWORD_TOO_SHORT' });
  }
  if (users.has(username)) {
    return res.status(409).json({ ok: false, error: 'USERNAME_TAKEN' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const token = createSessionToken();
  const tokenExpiresAt = Date.now() + TOKEN_TTL_MS;

  users.set(username, {
    displayName: rawUsername,
    passwordHash,
    token,
    tokenExpiresAt,
    createdAt: Date.now()
  });

  return res.json({
    ok: true,
    username: rawUsername,
    token,
    expiresInHours: 48
  });
});

// Schritt 2 beim Login: Passwort prüfen -> neuen Token geben (alter wird sofort ungültig!)
app.post('/login', async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  const user = users.get(username);
  if (!user) {
    return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND' });
  }

  const passwordValid = await bcrypt.compare(password, user.passwordHash);
  if (!passwordValid) {
    return res.status(401).json({ ok: false, error: 'WRONG_PASSWORD' });
  }

  // Neuer Token überschreibt den alten -> alter Login fliegt sofort raus
  const newToken = createSessionToken();
  user.token = newToken;
  user.tokenExpiresAt = Date.now() + TOKEN_TTL_MS;

  return res.json({
    ok: true,
    username: user.displayName,
    token: newToken,
    expiresInHours: 48
  });
});

// ---------------------------------------------------------
// 2. GESCHÜTZTE ENDPUNKTE (gehen NUR mit gültigem Token!)
// ---------------------------------------------------------

// Test-Endpunkt: Prüft, ob der gespeicherte Token noch gültig ist
app.post('/me', requireAuth, (req, res) => {
  res.json({
    ok: true,
    username: req.user.data.displayName,
    expiresAt: req.user.data.tokenExpiresAt
  });
});

// Alle anderen unbekannten Requests ohne Token abblocken
app.use((req, res) => {
  res.status(403).end(); // Antwortet ohne Daten
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`RE-CHAT Server läuft auf Port ${PORT}`);
});

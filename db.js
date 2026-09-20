const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username     TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    upload_count INTEGER NOT NULL DEFAULT 0,
    blocked      INTEGER NOT NULL DEFAULT 0,
    block_reason TEXT
  );

  CREATE TABLE IF NOT EXISTS uploads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    owner       TEXT NOT NULL,
    repo        TEXT NOT NULL,
    file_count  INTEGER NOT NULL,
    skipped     INTEGER NOT NULL DEFAULT 0,
    commit_sha  TEXT,
    public_repo INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL
  );
`);

const now = () => new Date().toISOString();

function upsertUser(username) {
  const row = db.prepare('SELECT username FROM users WHERE username = ?').get(username);
  if (row) {
    db.prepare('UPDATE users SET last_seen = ? WHERE username = ?').run(now(), username);
  } else {
    db.prepare('INSERT INTO users (username, created_at, last_seen) VALUES (?, ?, ?)')
      .run(username, now(), now());
  }
}

function isBlocked(username) {
  const row = db.prepare('SELECT blocked, block_reason FROM users WHERE username = ?').get(username);
  return row && row.blocked ? row : null;
}

function logUpload(username, owner, repo, fileCount, skipped, commitSha, publicRepo) {
  db.prepare('INSERT INTO uploads (username, owner, repo, file_count, skipped, commit_sha, public_repo, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(username, owner, repo, fileCount, skipped, commitSha || null, publicRepo ? 1 : 0, now());
  db.prepare('UPDATE users SET upload_count = upload_count + 1 WHERE username = ?').run(username);
}

function userStats(username) {
  return db.prepare('SELECT upload_count, created_at, last_seen FROM users WHERE username = ?').get(username);
}

function recentUploads(username, limit = 15) {
  return db.prepare(
    'SELECT * FROM uploads WHERE username = ? ORDER BY created_at DESC LIMIT ?'
  ).all(username, limit);
}

function totalUploads() {
  return db.prepare('SELECT COUNT(*) AS n FROM uploads').get().n;
}

function totalUsers() {
  return db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
}

module.exports = { upsertUser, isBlocked, logUpload, userStats, recentUploads, totalUploads, totalUsers };
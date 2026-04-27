const { Pool } = require('pg');
require('dotenv').config();

const connectionString = process.env.DATABASE_URL_LOCAL || process.env.DATABASE_URL;

const pool = new Pool({
  connectionString,
  ssl: connectionString && (connectionString.includes('localhost') || connectionString.includes('127.0.0.1')) ? false : { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

// A wrapper to make 'pg' compatible with existing 'sqlite3' code
const db = {
  run: (sql, params, callback) => {
    let pgSql = sql;
    let i = 1;
    pgSql = pgSql.replace(/\?/g, () => `$${i++}`);
    pool.query(pgSql, params, (err, res) => {
      if (callback) {
        // sqlite3 binds `this.changes`
        const context = res ? { changes: res.rowCount } : {};
        callback.call(context, err);
      }
    });
  },
  get: (sql, params, callback) => {
    let pgSql = sql;
    let i = 1;
    pgSql = pgSql.replace(/\?/g, () => `$${i++}`);
    pool.query(pgSql, params, (err, res) => {
      if (callback) callback(err, res && res.rows.length > 0 ? res.rows[0] : null);
    });
  },
  all: (sql, params, callback) => {
    let pgSql = sql;
    let i = 1;
    pgSql = pgSql.replace(/\?/g, () => `$${i++}`);
    pool.query(pgSql, params, (err, res) => {
      if (callback) callback(err, res ? res.rows : []);
    });
  }
};

const initDb = async () => {
  const usersSchema = `
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_verified BOOLEAN DEFAULT FALSE,
      verified_at TEXT
    );
  `;

  const documentsSchema = `
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      size INTEGER NOT NULL,
      path TEXT NOT NULL,
      uploaded_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
  `;

  const queryHistorySchema = `
    CREATE TABLE IF NOT EXISTS query_history (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      query TEXT NOT NULL,
      response TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
  `;

  const documentChunksSchema = `
    CREATE TABLE IF NOT EXISTS document_chunks (
      id TEXT PRIMARY KEY,
      doc_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      content TEXT NOT NULL,
      embedding vector(384),
      FOREIGN KEY (doc_id) REFERENCES documents (id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
  `;

  try {
    console.log('Connecting to PostgreSQL...');
    const client = await pool.connect();
    try {
      console.log('Connection established, running schema initialization...');
      await client.query('BEGIN');
      await client.query('CREATE EXTENSION IF NOT EXISTS vector;');
      
      // Run each schema part
      await client.query(usersSchema);
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_at TEXT;');
      
      await client.query(documentsSchema);
      await client.query(queryHistorySchema);
      await client.query(documentChunksSchema);
      
      await client.query('COMMIT');
      console.log('PostgreSQL database tables and pgvector initialized.');
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('Error during schema initialization:', e.message);
      // Don't exit here, let the app try to run
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('CRITICAL: Database connection failed:', err.message);
    if (err.code === 'ECONNRESET') {
      console.error('Connection reset by peer. This is often a network or firewall issue.');
    }
  }
};

module.exports = { db, initDb, pool };

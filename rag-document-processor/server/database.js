const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/medrag'
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
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
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
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('CREATE EXTENSION IF NOT EXISTS vector;');
      await client.query(usersSchema);
      await client.query(documentsSchema);
      await client.query(queryHistorySchema);
      await client.query(documentChunksSchema);
      await client.query('COMMIT');
      console.log('PostgreSQL database tables and pgvector initialized.');
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('Error creating PostgreSQL tables:', e.message);
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Connected to PostgreSQL failed:', err.message);
  }
};

module.exports = { db, initDb, pool };

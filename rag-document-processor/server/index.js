const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const { simpleParser } = require('mailparser');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { db, initDb, pool } = require('./database');

let pineconeClient = null;
let pineconeIndex = null;
const { RecursiveCharacterTextSplitter } = require('langchain/text_splitter');
// pipeline dynamically imported later
const axios = require('axios');

// Helper function for cosine similarity
function cosineSimilarity(vecA, vecB) {
  if (!Array.isArray(vecA) || !Array.isArray(vecB) || vecA.length !== vecB.length) {
    return 0;
  }

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < vecA.length; i++) {
    dotProduct += vecA[i] * vecB[i];
    normA += vecA[i] * vecA[i];
    normB += vecB[i] * vecB[i];
  }

  if (normA === 0 || normB === 0) return 0;

  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

// Load environment variables
dotenv.config();

console.log('--- Environment Check ---');
if (process.env.GEMINI_API_KEY) {
  console.log('GEMINI_API_KEY: FOUND (ends in ...' + process.env.GEMINI_API_KEY.slice(-4) + ')');
} else {
  console.error('GEMINI_API_KEY: NOT FOUND IN .env');
}
console.log('-------------------------');

const app = express();
const PORT = 3001;

// Middleware
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-default-secret-key';

// --- NODEMAILER SETUP ---
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

const sendCongratsEmail = (email, username) => {
  mailer.sendMail({
    from: process.env.MAIL_FROM,
    to: email,
    subject: '🎉 Welcome to AskDocs — Account Verified!',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 560px; margin: auto; background: #0f172a; color: #e2e8f0; border-radius: 12px; overflow: hidden;">
        <div style="background: linear-gradient(135deg, #4f46e5, #7c3aed); padding: 32px; text-align: center;">
          <h1 style="margin: 0; font-size: 28px; color: #fff;">🎉 You're In!</h1>
        </div>
        <div style="padding: 32px;">
          <p style="font-size: 18px;">Hi <strong>${username}</strong>,</p>
          <p>Your email has been verified and your <strong>AskDocs</strong> account is now fully activated. Welcome aboard!</p>
          <p>You can now upload documents and ask intelligent AI-powered questions about them.</p>
          <div style="margin: 32px 0; text-align: center;">
            <a href="http://localhost:5173" style="background: #4f46e5; color: #fff; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 16px;">
              Open AskDocs →
            </a>
          </div>
          <p style="font-size: 12px; color: #64748b;">If you didn't create this account, you can safely ignore this email.</p>
        </div>
      </div>
    `
  }, (err) => {
    if (err) console.error('Failed to send congrats email:', err.message);
    else console.log(`Congrats email sent to ${email}`);
  });
};

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Helper: decode & validate a Firebase ID token (JWT)
const decodeFirebaseToken = (token) => {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
  const { email, name, email_verified, iss, exp } = payload;
  if (Date.now() / 1000 > exp) throw new Error('Token has expired');
  if (!iss.startsWith('https://securetoken.google.com/')) throw new Error('Token not issued by Firebase');
  return { email, name, email_verified };
};

// --- AUTH ROUTES ---

// Unified Firebase auth endpoint (handles both Google OAuth and email/password)
app.post('/api/auth/firebase', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token is required' });

  try {
    const { email, name, email_verified } = decodeFirebaseToken(token);

    if (!email_verified) {
      return res.status(403).json({ error: 'Please verify your email first. Check your inbox for a verification link.' });
    }

    if (!email.endsWith('@gmail.com') && !email.endsWith('@googlemail.com')) {
      return res.status(403).json({ error: 'Only @gmail.com accounts are allowed.' });
    }

    const displayName = name || email.split('@')[0];

    const findSql = 'SELECT * FROM users WHERE email = ?';
    db.get(findSql, [email], (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });

      if (user) {
        // Existing user — check if this is first verified login (send congrats email)
        if (!user.is_verified) {
          const verifiedAt = new Date().toISOString();
          db.run('UPDATE users SET is_verified = TRUE, verified_at = ? WHERE id = ?', [verifiedAt, user.id], () => {
            sendCongratsEmail(user.email, user.username || displayName);
          });
        }
        const jwtToken = jwt.sign({ id: user.id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
        return res.json({ token: jwtToken, user: { id: user.id, email: user.email, username: user.username } });
      } else {
        // New user — create account (Google sign-up path or email already verified on first use)
        const id = uuidv4();
        const mockPasswordHash = 'OAUTH_USER_' + uuidv4();
        const verifiedAt = new Date().toISOString();
        const insertSql = 'INSERT INTO users (id, username, email, password_hash, is_verified, verified_at) VALUES (?, ?, ?, ?, TRUE, ?)';

        db.run(insertSql, [id, displayName, email, mockPasswordHash, verifiedAt], function (insertErr) {
          if (insertErr) {
            console.error('Failed to insert Firebase user:', insertErr.message);
            return res.status(500).json({ error: 'Failed to create account' });
          }
          sendCongratsEmail(email, displayName);
          const jwtToken = jwt.sign({ id, email, username: displayName }, JWT_SECRET, { expiresIn: '8h' });
          res.status(201).json({ token: jwtToken, user: { id, email, username: displayName } });
        });
      }
    });
  } catch (error) {
    console.error('Firebase token processing failed:', error.message);
    res.status(401).json({ error: error.message });
  }
});

// Legacy email/password signup (creates DB record; Firebase handles email verification)
app.post('/api/auth/signup', (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) {
    return res.status(400).json({ error: 'Email, username, and password are required' });
  }
  const salt = bcrypt.genSaltSync(10);
  const password_hash = bcrypt.hashSync(password, salt);
  const id = uuidv4();
  const sql = 'INSERT INTO users (id, username, email, password_hash, is_verified) VALUES (?, ?, ?, ?, FALSE)';
  db.run(sql, [id, username, email, password_hash], function (err) {
    if (err) {
      console.error('Signup error:', err.message);
      if (err.message.includes('unique') || err.message.includes('already exists')) {
        return res.status(409).json({ error: 'Email or Username may already be in use.' });
      }
      return res.status(500).json({ error: 'A database error occurred during signup.' });
    }
    res.status(201).json({ message: 'User created successfully' });
  });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const sql = 'SELECT id, email, username FROM users WHERE id = ?';
  db.get(sql, [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  });
});

app.put('/api/auth/profile', authenticateToken, (req, res) => {
  const { currentPassword, newPassword, newUsername } = req.body;
  const userId = req.user.id;

  if (!currentPassword) {
    return res.status(400).json({ error: 'Current password is required to make changes.' });
  }

  const sql = 'SELECT * FROM users WHERE id = ?';
  db.get(sql, [userId], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });

    const isMatch = bcrypt.compareSync(currentPassword, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Incorrect current password.' });
    }

    const updates = [];
    const params = [];

    if (newUsername && newUsername !== user.username) {
      updates.push('username = ?');
      params.push(newUsername);
    }

    if (newPassword && newPassword.length > 0) {
      const salt = bcrypt.genSaltSync(10);
      updates.push('password_hash = ?');
      params.push(bcrypt.hashSync(newPassword, salt));
    }

    if (updates.length === 0) {
      return res.json({ message: 'No changes made.' });
    }

    params.push(userId);
    const updateSql = "UPDATE users SET " + updates.join(', ') + " WHERE id = ?";
    db.run(updateSql, params, function (updateErr) {
      if (updateErr) return res.status(500).json({ error: 'Failed to update profile.' });
      const newJwtToken = jwt.sign({ id: user.id, email: user.email, username: newUsername || user.username }, JWT_SECRET, { expiresIn: '8h' });
      res.json({ message: 'Profile updated successfully', token: newJwtToken, user: { id: user.id, email: user.email, username: newUsername || user.username } });
    });
  });
});


// Global variables for RAG pipeline
let vectorStore;
let isRAGInitialized = false;



// Ensure uploads directory exists
const uploadsDir = path.resolve(__dirname, 'uploads');
try {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }
} catch (e) {
  console.error('Failed to ensure uploads directory exists:', e);
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const filename = `${Date.now()}-${safeName}`;
    cb(null, filename);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: function (req, file, cb) {
    const allowedTypes = ['application/pdf', 'text/plain', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'message/rfc822'];
    const allowedExtensions = ['.pdf', '.txt', '.docx', '.eml'];
    const fileExtension = path.extname(file.originalname).toLowerCase();

    if (allowedTypes.includes(file.mimetype) || allowedExtensions.includes(fileExtension)) {
      return cb(null, true);
    }
    return cb(new Error('Unsupported file type. Please upload PDF, TXT, DOCX, or EML files only.'));
  }
});

// Initialize RAG pipeline
async function initializeRAG() {
  try {
    console.log('Initializing RAG pipeline...');
    console.log('Using pgvector for vector store.');

    textSplitter = new RecursiveCharacterTextSplitter({
      chunkSize: 1000,
      chunkOverlap: 200,
    });

    // Initialize embeddings model
    try {
      const transformers = await import('@xenova/transformers');
      const pipeline = transformers.pipeline;
      embedder = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2');
      console.log('Embedding model loaded successfully');
    } catch (error) {
      console.log('Failed to load embedding model, using fallback.', error);
      embedder = null;
    }

    const embedQuery = async (text) => {
      if (typeof text !== 'string') text = String(text || '');
      if (embedder) {
        try {
          const output = await embedder(text, { pooling: 'mean', normalize: true });
          return Array.from(output.data);
        } catch (error) {
          console.log('Embedding failed, using fallback.', error);
        }
      }
      const hash = text.split('').reduce((a, b) => (((a << 5) - a) + b.charCodeAt(0)) & 0xFFFFFFFF, 0);
      return new Array(384).fill(0).map((_, i) => Math.sin(hash + i) * 0.1);
    };

    embeddings = {
      embedQuery: embedQuery,
      embedDocuments: (documents) => Promise.all(documents.map(doc => embedQuery(doc))),
    };

    // Vector store abstraction using pgvector
    vectorStore = {
      addDocuments: async (docsToAdd) => {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          for (const d of docsToAdd) {
            const embedding = await embeddings.embedQuery(d.pageContent);
            const chunkId = uuidv4();
            const embeddingStr = `[${embedding.join(',')}]`;
            await client.query(
              'INSERT INTO document_chunks (id, doc_id, user_id, content, embedding) VALUES ($1, $2, $3, $4, $5)',
              [chunkId, d.metadata.docId, d.metadata.userId, d.pageContent, embeddingStr]
            );
          }
          await client.query('COMMIT');
        } catch (e) {
          await client.query('ROLLBACK');
          console.error('Failed to insert chunks to pgvector:', e);
        } finally {
          client.release();
        }
      },
      similaritySearch: async (query, k) => {
        const queryEmbedding = await embeddings.embedQuery(query);
        const embeddingStr = `[${queryEmbedding.join(',')}]`;
        const sql = `
          SELECT content, doc_id, user_id
          FROM document_chunks
          ORDER BY embedding <=> $1
          LIMIT $2;
        `;
        const result = await pool.query(sql, [embeddingStr, k]);
        return result.rows.map(row => ({
          pageContent: row.content,
          metadata: { docId: row.doc_id, userId: row.user_id }
        }));
      }
    };

    console.log('RAG pipeline initialized successfully');
    isRAGInitialized = true;


  } catch (error) {
    console.error('Error initializing RAG pipeline:', error);
    throw error;
  }
}

// Helper to extract text from uploaded file
async function extractTextFromFile(filePath, mimetype) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.pdf' || mimetype.includes('pdf')) {
    return (await pdfParse(fs.readFileSync(filePath))).text || '';
  }
  if (ext === '.txt' || mimetype.includes('text')) {
    return fs.readFileSync(filePath, 'utf8');
  }
  if (ext === '.docx' || mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
    return (await mammoth.extractRawText({ path: filePath })).value || '';
  }
  if (ext === '.eml' || mimetype === 'message/rfc822') {
    const mail = await simpleParser(fs.createReadStream(filePath));
    return [mail.subject || '', mail.text || '', mail.html || ''].join('\n');
  }
  return fs.readFileSync(filePath, 'utf8');
}

// --- SECURED API ROUTES ---

// Documents API
app.get('/api/documents', authenticateToken, (req, res) => {
  const sql = 'SELECT id, name, type, size, uploaded_at as uploadedAt FROM documents WHERE user_id = ?';
  db.all(sql, [req.user.id], (err, rows) => {
    if (err) {
      console.error('Error fetching documents:', err.message);
      return res.status(500).json({ error: 'Failed to retrieve documents' });
    }
    res.json(rows);
  });
});

app.get('/api/documents/:id/content', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT * FROM documents WHERE id = ? AND user_id = ?';
  db.get(sql, [id, req.user.id], async (err, doc) => {
    if (err || !doc) {
      return res.status(404).json({ error: 'Document not found or access denied' });
    }
    try {
      const textContent = await extractTextFromFile(doc.path, doc.type);
      res.json({ content: textContent });
    } catch (e) {
      console.error('Failed to read document content:', e.message);
      res.status(500).json({ error: 'Failed to read document content' });
    }
  });
});

app.delete('/api/documents/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const findSql = 'SELECT path FROM documents WHERE id = ? AND user_id = ?';

  db.get(findSql, [id, req.user.id], (err, doc) => {
    if (err || !doc) {
      return res.status(404).json({ error: 'Document not found or access denied' });
    }
    const deleteSql = 'DELETE FROM documents WHERE id = ?';
    db.run(deleteSql, [id], function (err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to delete document from database' });
      }
      if (doc.path && fs.existsSync(doc.path)) {
        fs.unlinkSync(doc.path);
      }
      res.json({ success: true });
    });
  });
});

app.post('/api/documents/upload', authenticateToken, upload.single('document'), async (req, res) => {
  try {
    if (!isRAGInitialized) return res.status(503).json({ error: 'RAG pipeline not yet initialized' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const { originalname, mimetype, size, path: storedPath } = req.file;
    const textContent = await extractTextFromFile(storedPath, mimetype);
    const docId = uuidv4();
    const userId = req.user.id;
    const uploadedAt = new Date().toISOString();

    const sql = 'INSERT INTO documents (id, user_id, name, type, size, path, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.run(sql, [docId, userId, originalname, mimetype, size, storedPath, uploadedAt], async function (err) {
      if (err) {
        console.error('DB Error on upload:', err.message);
        return res.status(500).json({ error: 'Failed to save document metadata' });
      }
      try {
        const chunks = await textSplitter.splitDocuments([
          { pageContent: textContent, metadata: { source: storedPath, docId, userId } }
        ]);
        await vectorStore.addDocuments(chunks);
        res.status(201).json({ id: docId, name: originalname, type: mimetype, size, uploadedAt });
      } catch (indexError) {
        console.error('Indexing error on upload:', indexError.message);
        res.status(500).json({ error: 'Failed to index document' });
      }
    });
  } catch (error) {
    console.error('Upload failed:', error);
    res.status(500).json({ error: error.message || 'Failed to upload document' });
  }
});

// Process query endpoint
app.post('/api/process-query', authenticateToken, async (req, res) => {
  try {
    if (!isRAGInitialized) return res.status(503).json({ error: 'RAG pipeline not yet initialized' });

    const { query } = req.body;
    if (!query) return res.status(400).json({ error: 'Query is required' });

    console.log('Processing query:', query);

    const userDocsSql = 'SELECT id FROM documents WHERE user_id = ?';
    const userDocIds = await new Promise((resolve, reject) => {
      db.all(userDocsSql, [req.user.id], (err, rows) => {
        if (err) reject(err);
        else resolve(rows.map(r => r.id));
      });
    });

    if (userDocIds.length === 0) {
      return res.json({
        answer: "No documents have been uploaded yet. Please upload your documents first.",
        relevant_quotes: [],
        confidence: "low"
      });
    }

    console.log(`Searching for query: "${query}"`);
    const allSearchResults = await vectorStore.similaritySearch(query, 10);
    console.log(`Found ${allSearchResults.length} total matches`);

    const searchResults = allSearchResults.filter(result => userDocIds.includes(result.metadata.docId)).slice(0, 5);
    console.log(`Filtered to ${searchResults.length} user documents`);

    const context = searchResults.map(doc => doc.pageContent).join('\n\n');

    if (!context.trim()) {
      return res.json({
        answer: "Could not find relevant information in your documents to answer this question.",
        relevant_quotes: [],
        confidence: "low"
      });
    }

    // Truncate context to max 3000 chars to stay within free-tier token limits
    const truncatedContext = context.length > 3000 ? context.substring(0, 3000) + '...' : context;
    console.log(`Sending ${truncatedContext.length} chars of context to LLM`);

    const ragPrompt = `You are an intelligent document analysis assistant. Your goal is to be as helpful as possible, using the provided document context to answer the user's question.

    Instructions:
    1. Analyze the Document Context below carefully.
    2. Answer the user's question accurately based ONLY on the provided context.
    3. If the answer is not in the context, explicitly state that you cannot find the answer in the provided documents.
    4. Always be polite and professional.

    Document Context:
    ${truncatedContext}

    User Question: ${query}

    Format your response as a JSON object with the strict structure: { "answer": "...", "relevant_quotes": ["..."], "confidence": "high/medium/low" }`;

    let finalResponse;
    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) throw new Error('GEMINI_API_KEY is not configured in .env');

      const geminiResponse = await axios.post(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=${apiKey}`,
        {
          contents: [{ parts: [{ text: ragPrompt }] }],
          generationConfig: { temperature: 0.2, maxOutputTokens: 2048 }
        },
        { headers: { 'Content-Type': 'application/json' } }
      );

      // Validate response structure
      if (!geminiResponse.data?.candidates?.[0]?.content?.parts?.[0]?.text) {
        throw new Error('Invalid response structure from Gemini API');
      }

      const responseText = geminiResponse.data.candidates[0].content.parts[0].text;
      console.log('Raw Gemini response:', responseText);

      // Try to extract JSON from the response (sometimes it's wrapped in markdown code blocks)
      let jsonText = responseText.trim();
      if (jsonText.startsWith('```json')) {
        jsonText = jsonText.replace(/```json\n?/g, '').replace(/```\n?$/g, '').trim();
      } else if (jsonText.startsWith('```')) {
        jsonText = jsonText.replace(/```\n?/g, '').trim();
      }

      // Parse JSON with error handling
      let parsedResponse;
      try {
        parsedResponse = JSON.parse(jsonText);
      } catch (parseError) {
        console.error('JSON parse error:', parseError);
        console.error('Failed to parse text:', jsonText);
        throw new Error('Failed to parse AI response as JSON');
      }

      // Build the final response with proper field mapping
      finalResponse = {
        answer: parsedResponse.answer || 'Could not generate a specific answer. Please try rephrasing.',
        relevant_quotes: parsedResponse.relevant_quotes || [],
        confidence: parsedResponse.confidence || 'medium'
      };

    } catch (e) {
      console.error('LLM response generation failed:', e.message);
      if (e.response) {
        console.error('API Error Response Status:', e.response.status);
        console.error('API Error Response Data:', JSON.stringify(e.response.data, null, 2));
      } else {
        console.error('Error details:', e);
      }


      // Provide a clear, user-friendly error based on the error type
      let userFacingAnswer;
      if (e.response?.status === 429) {
        const retryInfo = e.response?.data?.error?.details?.find(d => d['@type']?.includes('RetryInfo'));
        const delay = retryInfo?.retryDelay || 'a few minutes';
        userFacingAnswer = `⚠️ AI API quota limit reached. The Gemini free tier has a daily request limit that has been exhausted. Please try again in ${delay === 'a few minutes' ? 'a few minutes' : delay} or tomorrow when the quota resets.`;
      } else if (!apiKey) {
        userFacingAnswer = '⚠️ AI is not configured. Please contact the administrator.';
      } else {
        userFacingAnswer = '⚠️ The AI encountered an unexpected error. Please try rephrasing your question.';
      }
      finalResponse = {
        answer: userFacingAnswer,
        relevant_quotes: [],
        confidence: 'low'
      };
    }

    const historyId = uuidv4();
    const historySql = 'INSERT INTO query_history (id, user_id, query, response, timestamp) VALUES (?, ?, ?, ?, ?)';
    db.run(historySql, [historyId, req.user.id, query, JSON.stringify(finalResponse), new Date().toISOString()], (err) => {
      if (err) console.error('Failed to save query history:', err.message);
    });

    res.json(finalResponse);

  } catch (error) {
    console.error('Error processing query:', error.response?.data || error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Query History API
app.get('/api/query-history', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM query_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10';
  db.all(sql, [req.user.id], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve query history' });
    }
    const history = rows.map(row => {
      try {
        return { ...row, response: JSON.parse(row.response) };
      } catch (e) {
        return { ...row, response: { Justification: 'Error: Could not parse response.' } };
      }
    });
    res.json(history);
  });
});

app.delete('/api/query-history/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM query_history WHERE id = ? AND user_id = ?';
  db.run(sql, [id, req.user.id], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete history item' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'History item not found or access denied' });
    }
    res.json({ success: true });
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', ragInitialized: isRAGInitialized });
});

// Start server
async function startServer() {
  try {
    await initDb();
    await initializeRAG();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
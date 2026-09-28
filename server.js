require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// Security & Middleware
app.use(helmet({ contentSecurityPolicy: false })); // Disabled CSP to allow CDN scripts in this standalone setup
app.use(cors());
app.use(express.json({ limit: '50kb' }));
app.use(express.static('public'));

// Rate Limiting
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 200, message: 'Too many requests' });
app.use('/api/', apiLimiter);

// Database Setup
const dbPath = path.join(__dirname, 'shiver.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (code TEXT PRIMARY KEY, signPub TEXT, boxPub TEXT, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, recipientCode TEXT, ephemeralPub TEXT, nonce TEXT, ciphertext TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipientCode)`);
});

// API Routes
app.post('/api/users', (req, res) => {
    const { code, signPub, boxPub } = req.body;
    if (!code || !signPub || !boxPub || code.length !== 10) return res.status(400).send('Invalid payload');
    
    db.run(`INSERT OR IGNORE INTO users (code, signPub, boxPub) VALUES (?, ?, ?)`, [code, signPub, boxPub], (err) => {
        if (err) return res.status(500).send('DB Error');
        res.json({ success: true });
    });
});

app.get('/api/users/:code', (req, res) => {
    const code = req.params.code;
    db.get(`SELECT signPub, boxPub FROM users WHERE code = ?`, [code], (err, row) => {
        if (err) return res.status(500).send('DB Error');
        if (!row) return res.status(404).json({ error: 'User not found' });
        res.json(row);
    });
});

app.post('/api/messages', (req, res) => {
    const { recipientCode, ephemeralPub, nonce, ciphertext } = req.body;
    if (!recipientCode || !ephemeralPub || !nonce || !ciphertext) return res.status(400).send('Invalid');

    db.run(`INSERT INTO messages (recipientCode, ephemeralPub, nonce, ciphertext) VALUES (?, ?, ?, ?)`,
        [recipientCode, ephemeralPub, nonce, ciphertext],
        function(err) {
            if (err) return res.status(500).send('DB Error');
            const msgObj = { id: this.lastID, recipientCode, ephemeralPub, nonce, ciphertext, timestamp: new Date().getTime() };
            io.to(recipientCode).emit('message', msgObj);
            res.json({ success: true });
        }
    );
});

app.get('/api/messages/:code', (req, res) => {
    db.all(`SELECT id, recipientCode, ephemeralPub, nonce, ciphertext, timestamp FROM messages WHERE recipientCode = ? ORDER BY id ASC`,
        [req.params.code], (err, rows) => {
            if (err) return res.status(500).send('DB Error');
            res.json(rows);
        }
    );
});

// WebSockets
io.on('connection', (socket) => {
    socket.on('subscribe', (code) => {
        if (typeof code === 'string' && code.length === 10) socket.join(code);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Shiver server listening on port ${PORT}`);
});

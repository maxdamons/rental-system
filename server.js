const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET_KEY = 'super-secret-rental-key-2026'; // Used for JWT Tokens

// --- DATABASE SETUP (SQLite) ---
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error(err.message);
    else console.log('Connected to the real SQLite database.');
});

db.serialize(() => {
    // Create Tables
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, name TEXT, email TEXT, phone TEXT, role TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS agreements (id INTEGER PRIMARY KEY AUTOINCREMENT, tenantId INTEGER, address TEXT, terms TEXT, status TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY AUTOINCREMENT, tenantId INTEGER, amount REAL, date TEXT, status TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, tenantId INTEGER, message TEXT, date TEXT, is_read INTEGER DEFAULT 0)`);

    // Create default Admin if no users exist
    db.get(`SELECT count(*) as count FROM users`, (err, row) => {
        if (row.count === 0) {
            const hash = bcrypt.hashSync('admin123', 8);
            db.run(`INSERT INTO users (username, password, name, email, phone, role) VALUES ('admin1', ?, 'System Admin', 'admin@rental.com', '000', 'admin')`, [hash]);
            console.log('Default Admin Account Created: admin1 / admin123');
        }
    });
});

// --- SECURITY MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.sendStatus(403);
    next();
};

// --- API ROUTES ---

// Login (Option 3: Bcrypt & JWT)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, SECRET_KEY, { expiresIn: '24h' });
        delete user.password; // Don't send password hash to frontend
        res.json({ success: true, token, user });
    });
});

// Get Own Profile Data (Tenant)
app.get('/api/tenant/data', authenticateToken, (req, res) => {
    const tenantId = req.user.id;
    db.get(`SELECT * FROM agreements WHERE tenantId = ?`, [tenantId], (err, agreement) => {
        db.all(`SELECT * FROM payments WHERE tenantId = ? ORDER BY date DESC`, [tenantId], (err, payments) => {
            db.all(`SELECT * FROM notifications WHERE tenantId = ? ORDER BY date DESC`, [tenantId], (err, notifications) => {
                res.json({ agreement, payments, notifications });
            });
        });
    });
});

// Mark Notifications Read
app.post('/api/notifications/read', authenticateToken, (req, res) => {
    db.run(`UPDATE notifications SET is_read = 1 WHERE tenantId = ?`, [req.user.id], () => res.json({ success: true }));
});

// Admin: Get Dashboard Stats
app.get('/api/admin/stats', authenticateToken, isAdmin, (req, res) => {
    db.get(`SELECT COUNT(*) as users FROM users`, (e1, r1) => {
        db.get(`SELECT COUNT(*) as tenants FROM users WHERE role='tenant'`, (e2, r2) => {
            db.get(`SELECT COUNT(*) as agrs FROM agreements WHERE status='Active'`, (e3, r3) => {
                res.json({ totalUsers: r1.users, totalTenants: r2.tenants, activeAgreements: r3.agrs });
            });
        });
    });
});

// Admin: Manage Users
app.get('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    db.all(`SELECT id, username, name, email, phone, role FROM users`, (err, rows) => res.json(rows));
});
app.post('/api/admin/users', authenticateToken, isAdmin, (req, res) => {
    const hash = bcrypt.hashSync(req.body.password, 8);
    db.run(`INSERT INTO users (username, password, name, email, phone, role) VALUES (?, ?, ?, ?, ?, ?)`, 
    [req.body.username, hash, req.body.name, req.body.email, req.body.phone, req.body.role], () => res.json({ success: true }));
});

// Admin: Manage Agreements
app.get('/api/admin/agreements', authenticateToken, isAdmin, (req, res) => {
    db.all(`SELECT a.*, u.name as tenantName FROM agreements a JOIN users u ON a.tenantId = u.id`, (err, rows) => res.json(rows));
});
app.post('/api/admin/agreements', authenticateToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO agreements (tenantId, address, terms, status) VALUES (?, ?, ?, ?)`, 
    [req.body.tenantId, req.body.address, req.body.terms, req.body.status], () => res.json({ success: true }));
});

// Admin: Manage Payments (Option 2)
app.get('/api/admin/payments', authenticateToken, isAdmin, (req, res) => {
    db.all(`SELECT p.*, u.name as tenantName FROM payments p JOIN users u ON p.tenantId = u.id ORDER BY p.date DESC`, (err, rows) => res.json(rows));
});
app.post('/api/admin/payments', authenticateToken, isAdmin, (req, res) => {
    db.run(`INSERT INTO payments (tenantId, amount, date, status) VALUES (?, ?, ?, ?)`, 
    [req.body.tenantId, req.body.amount, req.body.date, req.body.status], function() {
        // Also send a notification to the tenant!
        db.run(`INSERT INTO notifications (tenantId, message, date) VALUES (?, ?, ?)`, 
        [req.body.tenantId, `A new rent bill of $${req.body.amount} has been added for ${req.body.date}.`, new Date().toISOString().split('T')[0]]);
        res.json({ success: true });
    });
});
app.put('/api/admin/payments/:id', authenticateToken, isAdmin, (req, res) => {
    db.run(`UPDATE payments SET status = ? WHERE id = ?`, [req.body.status, req.params.id], () => res.json({ success: true }));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Production-Ready V4 running at http://localhost:3000`));

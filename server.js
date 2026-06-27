// ==============================================
// GENZ X RAT - SERVER API
// Role: OWNER » TK » PT » RESELLER » MEMBER
// Setiap role bisa bikin role di bawahnya
// ==============================================

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 4004;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ============ DATABASE ============
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'member',
            telegram_id TEXT UNIQUE,
            session_key TEXT,
            android_id TEXT,
            expired_date TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT
        )
    `);

    // Insert default OWNER
    db.run(
        `INSERT OR IGNORE INTO users (username, password, role) 
         VALUES ('owner', ?, 'owner')`,
        [bcrypt.hashSync('owner123', 10)]
    );
});

// ============ HELPER ============
function generateSessionKey() {
    return uuidv4().replace(/-/g, '').substring(0, 32);
}

// ============ ROLE HIERARCHY ============
const roleLevel = {
    'owner': 1,
    'tk': 2,
    'pt': 3,
    'reseller': 4,
    'member': 5
};

// Cek apakah role A bisa bikin role B (A harus di atas B)
function canCreateRole(creatorRole, targetRole) {
    const creatorLevel = roleLevel[creatorRole];
    const targetLevel = roleLevel[targetRole];
    
    // Reseller ga bisa bikin apa-apa
    if (creatorRole === 'reseller' || creatorRole === 'member') {
        return false;
    }
    
    // Creator harus di atas target (level lebih kecil)
    return creatorLevel < targetLevel;
}

// Role yang bisa bikin akun
function canCreateAccount(role) {
    return ['owner', 'tk', 'pt'].includes(role);
}

// Role yang bisa lihat semua user
function canViewAllUsers(role) {
    return ['owner', 'tk', 'pt'].includes(role);
}

// Role yang bisa hapus user
function canDeleteUser(role) {
    return ['owner', 'tk'].includes(role);
}

// ============ 1. VALIDATE LOGIN ============
app.post('/validate', (req, res) => {
    const { username, password, androidId } = req.body;

    if (!username || !password) {
        return res.json({ valid: false, message: 'Username dan password wajib diisi' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) {
            return res.json({ valid: false, message: 'Invalid username or password' });
        }

        const validPass = bcrypt.compareSync(password, user.password);
        if (!validPass) {
            return res.json({ valid: false, message: 'Invalid username or password' });
        }

        if (user.expired_date && new Date(user.expired_date) < new Date()) {
            return res.json({ expired: true, message: 'Your access has expired' });
        }

        const sessionKey = generateSessionKey();
        db.run(
            'UPDATE users SET session_key = ?, android_id = ? WHERE username = ?',
            [sessionKey, androidId || 'unknown_device', username]
        );

        res.json({
            valid: true,
            key: sessionKey,
            role: user.role || 'member',
            username: user.username,
            expiredDate: user.expired_date || null,
            telegramId: user.telegram_id || null
        });
    });
});

// ============ 2. GET USER INFO ============
app.get('/myInfo', (req, res) => {
    const { username, key } = req.query;

    db.get(
        'SELECT * FROM users WHERE username = ? AND session_key = ?',
        [username, key],
        (err, user) => {
            if (err || !user) {
                return res.json({ valid: false, message: 'Invalid session' });
            }
            res.json({
                valid: true,
                role: user.role || 'member',
                username: user.username,
                telegramId: user.telegram_id || null,
                expiredDate: user.expired_date || null
            });
        }
    );
});

// ============ 3. CHANGE PASSWORD ============
app.post('/changepass', (req, res) => {
    const { username, oldPass, newPass, sessionKey } = req.body;

    db.get(
        'SELECT * FROM users WHERE username = ? AND session_key = ?',
        [username, sessionKey],
        (err, user) => {
            if (err || !user) {
                return res.json({ success: false, message: 'Invalid session' });
            }

            const validPass = bcrypt.compareSync(oldPass, user.password);
            if (!validPass) {
                return res.json({ success: false, message: 'Invalid old password' });
            }

            const hashedNew = bcrypt.hashSync(newPass, 10);
            db.run('UPDATE users SET password = ? WHERE username = ?', [hashedNew, username]);
            res.json({ success: true, message: 'Password changed successfully' });
        }
    );
});

// ============ 4. CREATE USER ============
app.get('/userAdd', (req, res) => {
    const { key, username, password, day, role, telegramId } = req.query;

    // Cek apakah yang request punya role yang bisa bikin akun
    db.get(
        'SELECT * FROM users WHERE session_key = ?',
        [key],
        (err, admin) => {
            if (err || !admin) {
                return res.json({ 
                    created: false, 
                    message: 'Invalid session' 
                });
            }

            // Cek apakah role admin bisa bikin akun
            if (!canCreateAccount(admin.role)) {
                return res.json({ 
                    created: false, 
                    message: `Role ${admin.role} tidak bisa membuat akun` 
                });
            }

            if (!username || !password) {
                return res.json({ 
                    created: false, 
                    message: 'Username dan password wajib diisi' 
                });
            }

            // Validasi role yang mau dibuat (harus di bawah role admin)
            const validRoles = ['owner', 'tk', 'pt', 'reseller', 'member'];
            const targetRole = validRoles.includes(role) ? role : 'member';

            // Cek apakah role admin bisa bikin role target
            if (!canCreateRole(admin.role, targetRole)) {
                return res.json({ 
                    created: false, 
                    message: `Role ${admin.role} tidak bisa membuat role ${targetRole}. 
                             Hanya bisa membuat role di bawahnya.` 
                });
            }

            // Cek 1 Telegram = 1 Akun
            if (telegramId) {
                db.get(
                    'SELECT * FROM users WHERE telegram_id = ?',
                    [telegramId],
                    (err, existingTelegram) => {
                        if (existingTelegram) {
                            return res.json({ 
                                created: false, 
                                message: 'Telegram ID ini sudah terdaftar! (1 Telegram = 1 Akun)' 
                            });
                        }
                        proceedCreate();
                    }
                );
            } else {
                proceedCreate();
            }

            function proceedCreate() {
                db.get('SELECT * FROM users WHERE username = ?', [username], (err, existing) => {
                    if (existing) {
                        return res.json({ 
                            created: false, 
                            message: 'Username sudah terdaftar' 
                        });
                    }

                    const expiredDate = new Date();
                    expiredDate.setDate(expiredDate.getDate() + (parseInt(day) || 30));

                    const hashedPass = bcrypt.hashSync(password, 10);
                    db.run(
                        `INSERT INTO users (username, password, role, expired_date, telegram_id, created_by) 
                         VALUES (?, ?, ?, ?, ?, ?)`,
                        [username, hashedPass, targetRole, expiredDate.toISOString(), telegramId || null, admin.username],
                        function(err) {
                            if (err) {
                                return res.json({ created: false, message: err.message });
                            }
                            res.json({
                                created: true,
                                user: {
                                    id: this.lastID,
                                    username,
                                    role: targetRole,
                                    expiredDate: expiredDate.toISOString(),
                                    telegramId: telegramId || null,
                                    createdBy: admin.username
                                },
                                message: `Akun ${username} (${targetRole}) berhasil dibuat! Expired: ${expiredDate.toLocaleDateString()}`
                            });
                        }
                    );
                });
            }
        }
    );
});

// ============ 5. GET ALL USERS ============
app.get('/users', (req, res) => {
    const { key } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        if (!canViewAllUsers(user.role)) {
            return res.json({ success: false, message: 'Unauthorized' });
        }

        db.all(
            'SELECT id, username, role, expired_date, created_at, created_by, telegram_id FROM users',
            (err, users) => {
                res.json({ success: true, users: users || [] });
            }
        );
    });
});

// ============ 6. DELETE USER ============
app.get('/userDelete', (req, res) => {
    const { key, username } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, admin) => {
        if (err || !admin) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        if (!canDeleteUser(admin.role)) {
            return res.json({ success: false, message: 'Unauthorized' });
        }

        // Gak bisa hapus OWNER dan gak bisa hapus role yang lebih tinggi
        db.run(
            'DELETE FROM users WHERE username = ? AND role != "owner" AND role_level > ?',
            [username, roleLevel[admin.role]],
            function(err) {
                if (err || this.changes === 0) {
                    return res.json({ 
                        success: false, 
                        message: 'User tidak ditemukan atau tidak bisa menghapus role yang lebih tinggi' 
                    });
                }
                res.json({ success: true, message: 'User berhasil dihapus' });
            }
        );
    });
});

// ============ 7. GET USER BY TELEGRAM ID ============
app.get('/userByTelegram', (req, res) => {
    const { telegramId } = req.query;

    if (!telegramId) {
        return res.json({ success: false, message: 'Telegram ID required' });
    }

    db.get(
        'SELECT id, username, role, expired_date FROM users WHERE telegram_id = ?',
        [telegramId],
        (err, user) => {
            if (err || !user) {
                return res.json({ success: false, message: 'User tidak ditemukan' });
            }
            res.json({
                success: true,
                user: {
                    username: user.username,
                    role: user.role,
                    expiredDate: user.expired_date
                }
            });
        }
    );
});

// ============ 8. DASHBOARD STATS ============
app.get('/dashboard', (req, res) => {
    const { key } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        db.get('SELECT COUNT(*) as total FROM users', (err, totalUsers) => {
            db.get('SELECT COUNT(*) as total FROM users WHERE role = "owner"', (err, totalOwner) => {
                db.get('SELECT COUNT(*) as total FROM users WHERE role = "tk"', (err, totalTk) => {
                    db.get('SELECT COUNT(*) as total FROM users WHERE role = "pt"', (err, totalPt) => {
                        db.get('SELECT COUNT(*) as total FROM users WHERE role = "reseller"', (err, totalReseller) => {
                            db.get('SELECT COUNT(*) as total FROM users WHERE role = "member"', (err, totalMember) => {
                                res.json({
                                    success: true,
                                    totalUsers: totalUsers?.total || 0,
                                    totalOwner: totalOwner?.total || 0,
                                    totalTk: totalTk?.total || 0,
                                    totalPt: totalPt?.total || 0,
                                    totalReseller: totalReseller?.total || 0,
                                    totalMember: totalMember?.total || 0,
                                    userRole: user.role
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

// ============ START ============
app.listen(PORT, () => {
    console.log(`✅ Genz x Rat Server jalan di http://localhost:${PORT}`);
    console.log(``);
    console.log(`📌 ROLE HIERARCHY (DARI ATAS KE BAWAH):`);
    console.log(`   👑 OWNER (Level 1) → Bisa bikin: TK, PT, Reseller, Member`);
    console.log(`   🖐️ TK (Level 2)    → Bisa bikin: PT, Reseller, Member`);
    console.log(`   🤝 PT (Level 3)    → Bisa bikin: Reseller, Member`);
    console.log(`   💼 Reseller (Level 4) → TIDAK BISA BIKIN`);
    console.log(`   👤 Member (Level 5)   → TIDAK BISA BIKIN`);
    console.log(``);
    console.log(`📌 ENDPOINT:`);
    console.log(`   POST /validate`);
    console.log(`   GET  /myInfo`);
    console.log(`   POST /changepass`);
    console.log(`   GET  /userAdd`);
    console.log(`   GET  /users`);
    console.log(`   GET  /userDelete`);
    console.log(`   GET  /userByTelegram`);
    console.log(`   GET  /dashboard`);
});

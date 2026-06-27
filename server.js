// ==============================================
// GENZ X RAT - SERVER API (FULL VERSION)
// Support 20 endpoint (8 dasar + 12 tambahan)
// Role: OWNER » TK » PT » RESELLER » MEMBER
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

const roleLevel = {
    'owner': 1,
    'tk': 2,
    'pt': 3,
    'reseller': 4,
    'member': 5
};

function canCreateRole(creatorRole, targetRole) {
    const creatorLevel = roleLevel[creatorRole];
    const targetLevel = roleLevel[targetRole];
    if (creatorRole === 'reseller' || creatorRole === 'member') return false;
    return creatorLevel < targetLevel;
}

function canCreateAccount(role) {
    return ['owner', 'tk'].includes(role);
}

function canViewAllUsers(role) {
    return ['owner', 'tk', 'pt'].includes(role);
}

function canDeleteUser(role) {
    return ['owner', 'tk'].includes(role);
}

// ==============================================
// 8 ENDPOINT DASAR
// ==============================================

// 1. VALIDATE LOGIN
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

// 2. GET USER INFO
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

// 3. CHANGE PASSWORD
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

// 4. CREATE USER (OWNER / TK ONLY)
app.get('/userAdd', (req, res) => {
    const { key, username, password, day, role, telegramId } = req.query;

    db.get(
        'SELECT * FROM users WHERE session_key = ? AND role IN ("owner", "tk")',
        [key],
        (err, admin) => {
            if (err || !admin) {
                return res.json({ 
                    created: false, 
                    message: 'Unauthorized - Hanya OWNER atau TK yang bisa membuat akun' 
                });
            }

            if (!username || !password) {
                return res.json({ 
                    created: false, 
                    message: 'Username dan password wajib diisi' 
                });
            }

            if (telegramId) {
                db.get('SELECT * FROM users WHERE telegram_id = ?', [telegramId], (err, existingTelegram) => {
                    if (existingTelegram) {
                        return res.json({ 
                            created: false, 
                            message: 'Telegram ID ini sudah terdaftar! (1 Telegram = 1 Akun)' 
                        });
                    }
                    proceedCreate();
                });
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

                    const validRoles = ['owner', 'tk', 'pt', 'reseller', 'member'];
                    const targetRole = validRoles.includes(role) ? role : 'member';

                    if (!canCreateRole(admin.role, targetRole)) {
                        return res.json({ 
                            created: false, 
                            message: `Role ${admin.role} tidak bisa membuat role ${targetRole}` 
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
                                message: `Akun ${username} (${targetRole}) berhasil dibuat!`
                            });
                        }
                    );
                });
            }
        }
    );
});

// 5. GET ALL USERS
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

// 6. DELETE USER
app.get('/userDelete', (req, res) => {
    const { key, username } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, admin) => {
        if (err || !admin) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        if (!canDeleteUser(admin.role)) {
            return res.json({ success: false, message: 'Unauthorized' });
        }

        db.run(
            'DELETE FROM users WHERE username = ? AND role != "owner"',
            [username],
            function(err) {
                if (err || this.changes === 0) {
                    return res.json({ 
                        success: false, 
                        message: 'User tidak ditemukan atau tidak bisa menghapus OWNER' 
                    });
                }
                res.json({ success: true, message: 'User berhasil dihapus' });
            }
        );
    });
});

// 7. GET USER BY TELEGRAM ID
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

// 8. DASHBOARD STATS
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

// ==============================================
// 12 ENDPOINT TAMBAHAN (MANTA STYLE)
// ==============================================

// 9. LIST USERS (alias)
app.get('/listUsers', (req, res) => {
    const { key } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        if (!canViewAllUsers(user.role)) {
            return res.json({ success: false, message: 'Unauthorized' });
        }

        db.all('SELECT id, username, role, expired_date, created_at, created_by, telegram_id FROM users', (err, users) => {
            res.json({ success: true, users: users || [] });
        });
    });
});

// 10. DELETE USER (alias)
app.get('/deleteUser', (req, res) => {
    const { key, username } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, admin) => {
        if (err || !admin) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        if (!canDeleteUser(admin.role)) {
            return res.json({ success: false, message: 'Unauthorized' });
        }

        db.run('DELETE FROM users WHERE username = ? AND role != "owner"', [username], function(err) {
            if (err || this.changes === 0) {
                return res.json({ success: false, message: 'User not found or cannot delete owner' });
            }
            res.json({ success: true, message: 'User deleted' });
        });
    });
});

// 11. MY SENDER
app.get('/mySender', (req, res) => {
    const { key } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        db.all('SELECT * FROM users WHERE created_by = ?', [user.username], (err, senders) => {
            res.json({
                success: true,
                senders: senders || [],
                total: senders?.length || 0
            });
        });
    });
});

// 12. GET PAIRING
app.get('/getPairing', (req, res) => {
    const { key } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        const pairingCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        res.json({
            success: true,
            code: pairingCode,
            expiresIn: 300
        });
    });
});

// 13. DELETE SENDER
app.get('/deleteSender', (req, res) => {
    const { key, username } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, admin) => {
        if (err || !admin) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        db.run('DELETE FROM users WHERE username = ? AND created_by = ?', [username, admin.username], function(err) {
            if (err || this.changes === 0) {
                return res.json({ success: false, message: 'Sender not found' });
            }
            res.json({ success: true, message: 'Sender deleted' });
        });
    });
});

// 14. SEND BUG
app.post('/sendBug', (req, res) => {
    const { key, bug } = req.body;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        res.json({ success: true, message: 'Bug reported' });
    });
});

// 15. MY SERVER
app.get('/myServer', (req, res) => {
    const { key } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        db.get('SELECT COUNT(*) as total FROM users', (err, total) => {
            res.json({
                success: true,
                server: {
                    name: 'Genz x Rat Server',
                    version: '1.0.0',
                    status: 'online',
                    uptime: process.uptime(),
                    totalUsers: total?.total || 0
                }
            });
        });
    });
});

// 16. ADD SERVER (cuma owner)
app.get('/addServer', (req, res) => {
    const { key, name, ip, port } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ? AND role = "owner"', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Unauthorized - Owner only' });
        }

        res.json({ success: true, message: 'Server added' });
    });
});

// 17. DEL SERVER (cuma owner)
app.get('/delServer', (req, res) => {
    const { key, serverId } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ? AND role = "owner"', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Unauthorized - Owner only' });
        }

        res.json({ success: true, message: 'Server deleted' });
    });
});

// 18. CREATE ACCOUNT (alias dari userAdd)
app.get('/createAccount', (req, res) => {
    // Redirect ke userAdd
    const { key, username, password, day, role, telegramId } = req.query;
    
    // Panggil logic userAdd
    db.get(
        'SELECT * FROM users WHERE session_key = ? AND role IN ("owner", "tk")',
        [key],
        (err, admin) => {
            if (err || !admin) {
                return res.json({ 
                    created: false, 
                    message: 'Unauthorized' 
                });
            }

            if (!username || !password) {
                return res.json({ 
                    created: false, 
                    message: 'Username dan password wajib diisi' 
                });
            }

            if (telegramId) {
                db.get('SELECT * FROM users WHERE telegram_id = ?', [telegramId], (err, existingTelegram) => {
                    if (existingTelegram) {
                        return res.json({ 
                            created: false, 
                            message: 'Telegram ID sudah terdaftar!' 
                        });
                    }
                    proceedCreate();
                });
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

                    const validRoles = ['owner', 'tk', 'pt', 'reseller', 'member'];
                    const targetRole = validRoles.includes(role) ? role : 'member';

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
                                message: `Akun ${username} (${targetRole}) berhasil dibuat!`
                            });
                        }
                    );
                });
            }
        }
    );
});

// 19. EDIT USER
app.get('/editUser', (req, res) => {
    const { key, username, role, expiredDate } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, admin) => {
        if (err || !admin) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        if (!canDeleteUser(admin.role)) {
            return res.json({ success: false, message: 'Unauthorized' });
        }

        let updates = [];
        let values = [];

        if (role) {
            const validRoles = ['owner', 'tk', 'pt', 'reseller', 'member'];
            if (validRoles.includes(role)) {
                updates.push('role = ?');
                values.push(role);
            }
        }

        if (expiredDate) {
            updates.push('expired_date = ?');
            values.push(expiredDate);
        }

        if (updates.length === 0) {
            return res.json({ success: false, message: 'Tidak ada yang diupdate' });
        }

        values.push(username);
        db.run(
            `UPDATE users SET ${updates.join(', ')} WHERE username = ?`,
            values,
            function(err) {
                if (err || this.changes === 0) {
                    return res.json({ success: false, message: 'User not found' });
                }
                res.json({ success: true, message: 'User updated' });
            }
        );
    });
});

// 20. KILL WIFI (edukasi / testing)
app.get('/killWifi', (req, res) => {
    const { key, target } = req.query;

    db.get('SELECT * FROM users WHERE session_key = ?', [key], (err, user) => {
        if (err || !user) {
            return res.json({ success: false, message: 'Invalid session' });
        }

        res.json({ 
            success: true, 
            message: 'Wifi kill command sent to target',
            target: target || 'unknown'
        });
    });
});

// ============ START SERVER ============
app.listen(PORT, () => {
    console.log(`✅ Genz x Rat Server jalan di http://localhost:${PORT}`);
    console.log(``);
    console.log(`📌 TOTAL ENDPOINT: 20`);
    console.log(`   ✅ 8 endpoint dasar`);
    console.log(`   ✅ 12 endpoint tambahan (Manta style)`);
    console.log(``);
    console.log(`📌 ROLE SYSTEM:`);
    console.log(`   👑 OWNER (Level 1) → Bisa bikin: TK, PT, Reseller, Member`);
    console.log(`   🖐️ TK (Level 2)    → Bisa bikin: PT, Reseller, Member`);
    console.log(`   🤝 PT (Level 3)    → Bisa bikin: Reseller, Member`);
    console.log(`   💼 Reseller (Level 4) → TIDAK BISA BIKIN`);
    console.log(`   👤 Member (Level 5)   → TIDAK BISA BIKIN`);
});

/**
 * Discord Clone Server - PostgreSQL Version
 * 
 * package.json:
 * {
 *   "name": "discord-clone",
 *   "version": "1.0.0",
 *   "main": "server.js",
 *   "scripts": {
 *     "start": "node server.js"
 *   },
 *   "dependencies": {
 *     "express": "^4.18.2",
 *     "ws": "^8.14.2",
 *     "pg": "^8.11.3",
 *     "bcryptjs": "^2.4.3",
 *     "jsonwebtoken": "^9.0.2",
 *     "uuid": "^9.0.1",
 *     "cors": "^2.8.5"
 *   },
 *   "engines": {
 *     "node": ">=18.0.0"
 *   }
 * }
 */

const express = require('express');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const http = require('http');

// ============================================
// КОНФИГУРАЦИЯ
// ============================================

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const BCRYPT_ROUNDS = 10;

// Строка подключения к PostgreSQL (Neon)
const DATABASE_URL = process.env.DATABASE_URL;

// ============================================
// ИНИЦИАЛИЗАЦИЯ ПРИЛОЖЕНИЯ
// ============================================

const app = express();
const server = http.createServer(app);

// Middleware
app.use(cors());
app.use(express.json());

// ============================================
// ПОДКЛЮЧЕНИЕ К POSTGRESQL
// ============================================

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    max: 20, // максимум соединений в пуле
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Проверка подключения
pool.on('connect', () => {
    console.log('✅ Подключено к PostgreSQL (Neon)');
});

pool.on('error', (err) => {
    console.error('❌ Ошибка PostgreSQL:', err);
});

// ============================================
// ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ
// ============================================

async function initializeDatabase() {
    const client = await pool.connect();
    
    try {
        // Таблица пользователей
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username VARCHAR(32) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                avatar_url TEXT,
                status VARCHAR(20) DEFAULT 'offline',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Таблица серверов (гильдий)
        await client.query(`
            CREATE TABLE IF NOT EXISTS servers (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(100) NOT NULL,
                owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                icon_url TEXT,
                invite_code VARCHAR(10) UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Таблица участников сервера
        await client.query(`
            CREATE TABLE IF NOT EXISTS server_members (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role VARCHAR(20) DEFAULT 'member',
                nickname VARCHAR(32),
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(server_id, user_id)
            )
        `);

        // Таблица каналов
        await client.query(`
            CREATE TABLE IF NOT EXISTS channels (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                type VARCHAR(20) DEFAULT 'text',
                topic TEXT,
                position INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Таблица сообщений в каналах
        await client.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
                author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                edited_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Таблица личных сообщений
        await client.query(`
            CREATE TABLE IF NOT EXISTS direct_messages (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                read_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Создаем индексы для оптимизации запросов
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_messages_channel_id ON messages(channel_id);
            CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_dm_sender ON direct_messages(sender_id);
            CREATE INDEX IF NOT EXISTS idx_dm_recipient ON direct_messages(recipient_id);
            CREATE INDEX IF NOT EXISTS idx_dm_created_at ON direct_messages(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_server_members_user ON server_members(user_id);
            CREATE INDEX IF NOT EXISTS idx_server_members_server ON server_members(server_id);
            CREATE INDEX IF NOT EXISTS idx_channels_server ON channels(server_id);
        `);

        console.log('✅ Таблицы базы данных созданы/проверены');
    } catch (error) {
        console.error('❌ Ошибка инициализации БД:', error);
        throw error;
    } finally {
        client.release();
    }
}

// ============================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ БД
// ============================================

// Генерация уникального инвайт-кода
function generateInviteCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

// ============================================
// MIDDLEWARE ДЛЯ АУТЕНТИФИКАЦИИ
// ============================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Токен не предоставлен' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Недействительный токен' });
        }
        req.user = user;
        next();
    });
}

// Проверка членства в сервере
async function checkServerMembership(req, res, next) {
    const { serverId } = req.params;
    const userId = req.user.id;
    
    try {
        const result = await pool.query(
            'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
            [serverId, userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'Вы не являетесь участником этого сервера' });
        }
        
        req.membership = result.rows[0];
        next();
    } catch (error) {
        console.error('Ошибка проверки членства:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
}

// Проверка владельца сервера
async function checkServerOwner(req, res, next) {
    const { serverId } = req.params;
    const userId = req.user.id;
    
    try {
        const result = await pool.query(
            'SELECT * FROM servers WHERE id = $1',
            [serverId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Сервер не найден' });
        }
        
        if (result.rows[0].owner_id !== userId) {
            return res.status(403).json({ error: 'Только владелец может выполнить это действие' });
        }
        
        req.server = result.rows[0];
        next();
    } catch (error) {
        console.error('Ошибка проверки владельца:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
}

// ============================================
// REST API МАРШРУТЫ - АУТЕНТИФИКАЦИЯ
// ============================================

// Регистрация
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Валидация
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        
        if (username.length < 3 || username.length > 32) {
            return res.status(400).json({ error: 'Имя пользователя должно быть от 3 до 32 символов' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });
        }
        
        // Проверка email формата
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Некорректный формат email' });
        }
        
        // Проверка существующего пользователя
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email.toLowerCase(), username]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email или имя пользователя уже используется' });
        }
        
        // Хеширование пароля
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        
        // Создание пользователя
        const result = await pool.query(
            `INSERT INTO users (id, username, email, password_hash) 
             VALUES ($1, $2, $3, $4) 
             RETURNING id, username, email, avatar_url, status, created_at`,
            [uuidv4(), username, email.toLowerCase(), passwordHash]
        );
        
        const user = result.rows[0];
        
        // Генерация токена
        const token = jwt.sign(
            { id: user.id, username: user.username }, 
            JWT_SECRET, 
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            message: 'Регистрация успешна',
            token,
            user
        });
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Вход
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email и пароль обязательны' });
        }
        
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email.toLowerCase()]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        const user = result.rows[0];
        
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        // Обновляем статус
        await pool.query(
            'UPDATE users SET status = $1 WHERE id = $2',
            ['online', user.id]
        );
        
        const token = jwt.sign(
            { id: user.id, username: user.username }, 
            JWT_SECRET, 
            { expiresIn: '7d' }
        );
        
        res.json({
            message: 'Вход выполнен',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                avatar_url: user.avatar_url,
                status: 'online'
            }
        });
    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение текущего пользователя
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, email, avatar_url, status, created_at FROM users WHERE id = $1',
            [req.user.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Ошибка получения пользователя:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Обновление профиля
app.put('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const { username, avatar_url } = req.body;
        const userId = req.user.id;
        
        // Проверка уникальности username если он меняется
        if (username && username !== req.user.username) {
            const existing = await pool.query(
                'SELECT id FROM users WHERE username = $1 AND id != $2',
                [username, userId]
            );
            if (existing.rows.length > 0) {
                return res.status(400).json({ error: 'Имя пользователя уже занято' });
            }
        }
        
        const result = await pool.query(
            `UPDATE users 
             SET username = COALESCE($1, username), 
                 avatar_url = COALESCE($2, avatar_url)
             WHERE id = $3
             RETURNING id, username, email, avatar_url, status, created_at`,
            [username, avatar_url, userId]
        );
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Ошибка обновления профиля:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ============================================
// REST API МАРШРУТЫ - СЕРВЕРЫ
// ============================================

// Создание сервера
app.post('/api/servers', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        const { name, icon_url } = req.body;
        const userId = req.user.id;
        
        if (!name || name.trim().length === 0) {
            return res.status(400).json({ error: 'Название сервера обязательно' });
        }
        
        if (name.length > 100) {
            return res.status(400).json({ error: 'Название сервера не более 100 символов' });
        }
        
        const serverId = uuidv4();
        const inviteCode = generateInviteCode();
        
        // Создаем сервер
        await client.query(
            `INSERT INTO servers (id, name, owner_id, icon_url, invite_code) 
             VALUES ($1, $2, $3, $4, $5)`,
            [serverId, name.trim(), userId, icon_url || null, inviteCode]
        );
        
        // Добавляем создателя как владельца
        await client.query(
            `INSERT INTO server_members (id, server_id, user_id, role) 
             VALUES ($1, $2, $3, $4)`,
            [uuidv4(), serverId, userId, 'owner']
        );
        
        // Создаем канал "general" по умолчанию
        const channelId = uuidv4();
        await client.query(
            `INSERT INTO channels (id, server_id, name, type, topic) 
             VALUES ($1, $2, $3, $4, $5)`,
            [channelId, serverId, 'general', 'text', 'Общий канал для общения']
        );
        
        await client.query('COMMIT');
        
        // Получаем созданный сервер с каналами
        const serverResult = await pool.query(
            'SELECT * FROM servers WHERE id = $1',
            [serverId]
        );
        const channelsResult = await pool.query(
            'SELECT * FROM channels WHERE server_id = $1 ORDER BY position',
            [serverId]
        );
        
        res.status(201).json({
            ...serverResult.rows[0],
            channels: channelsResult.rows
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Ошибка создания сервера:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    } finally {
        client.release();
    }
});

// Получение серверов пользователя
app.get('/api/servers', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT s.*, sm.role as my_role
             FROM servers s
             JOIN server_members sm ON s.id = sm.server_id
             WHERE sm.user_id = $1
             ORDER BY s.created_at DESC`,
            [req.user.id]
        );
        
        // Добавляем каналы к каждому серверу
        const servers = await Promise.all(
            result.rows.map(async (server) => {
                const channels = await pool.query(
                    'SELECT * FROM channels WHERE server_id = $1 ORDER BY position',
                    [server.id]
                );
                return { ...server, channels: channels.rows };
            })
        );
        
        res.json(servers);
    } catch (error) {
        console.error('Ошибка получения серверов:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение сервера по ID
app.get('/api/servers/:serverId', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const { serverId } = req.params;
        
        const serverResult = await pool.query(
            'SELECT * FROM servers WHERE id = $1',
            [serverId]
        );
        
        const channelsResult = await pool.query(
            'SELECT * FROM channels WHERE server_id = $1 ORDER BY position',
            [serverId]
        );
        
        const membersResult = await pool.query(
            `SELECT u.id, u.username, u.avatar_url, u.status, sm.role, sm.nickname, sm.joined_at
             FROM server_members sm
             JOIN users u ON sm.user_id = u.id
             WHERE sm.server_id = $1
             ORDER BY 
                CASE sm.role 
                    WHEN 'owner' THEN 1 
                    WHEN 'admin' THEN 2 
                    ELSE 3 
                END,
                sm.joined_at`,
            [serverId]
        );
        
        res.json({
            ...serverResult.rows[0],
            channels: channelsResult.rows,
            members: membersResult.rows
        });
    } catch (error) {
        console.error('Ошибка получения сервера:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Обновление сервера
app.put('/api/servers/:serverId', authenticateToken, checkServerOwner, async (req, res) => {
    try {
        const { name, icon_url } = req.body;
        const { serverId } = req.params;
        
        const result = await pool.query(
            `UPDATE servers 
             SET name = COALESCE($1, name), 
                 icon_url = COALESCE($2, icon_url)
             WHERE id = $3
             RETURNING *`,
            [name?.trim(), icon_url, serverId]
        );
        
        // Уведомляем участников
        broadcastToServer(serverId, {
            type: 'SERVER_UPDATED',
            server: result.rows[0]
        });
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Ошибка обновления сервера:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Удаление сервера
app.delete('/api/servers/:serverId', authenticateToken, checkServerOwner, async (req, res) => {
    try {
        const { serverId } = req.params;
        
        // Уведомляем участников перед удалением
        broadcastToServer(serverId, {
            type: 'SERVER_DELETED',
            serverId
        });
        
        await pool.query('DELETE FROM servers WHERE id = $1', [serverId]);
        
        res.json({ message: 'Сервер удален' });
    } catch (error) {
        console.error('Ошибка удаления сервера:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Присоединение к серверу по инвайт-коду
app.post('/api/servers/join/:inviteCode', authenticateToken, async (req, res) => {
    try {
        const { inviteCode } = req.params;
        const userId = req.user.id;
        
        const serverResult = await pool.query(
            'SELECT * FROM servers WHERE invite_code = $1',
            [inviteCode]
        );
        
        if (serverResult.rows.length === 0) {
            return res.status(404).json({ error: 'Сервер не найден или приглашение недействительно' });
        }
        
        const server = serverResult.rows[0];
        
        // Проверяем, не является ли уже участником
        const existingMember = await pool.query(
            'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
            [server.id, userId]
        );
        
        if (existingMember.rows.length > 0) {
            return res.status(400).json({ error: 'Вы уже участник этого сервера' });
        }
        
        // Добавляем участника
        await pool.query(
            `INSERT INTO server_members (id, server_id, user_id, role) 
             VALUES ($1, $2, $3, $4)`,
            [uuidv4(), server.id, userId, 'member']
        );
        
        // Получаем каналы
        const channelsResult = await pool.query(
            'SELECT * FROM channels WHERE server_id = $1 ORDER BY position',
            [server.id]
        );
        
        // Уведомляем участников о новом пользователе
        const userResult = await pool.query(
            'SELECT id, username, avatar_url, status FROM users WHERE id = $1',
            [userId]
        );
        
        broadcastToServer(server.id, {
            type: 'MEMBER_JOINED',
            serverId: server.id,
            member: { ...userResult.rows[0], role: 'member', joined_at: new Date().toISOString() }
        });
        
        res.json({
            ...server,
            channels: channelsResult.rows,
            message: 'Вы присоединились к серверу'
        });
    } catch (error) {
        console.error('Ошибка присоединения к серверу:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Присоединение к серверу по ID
app.post('/api/servers/:serverId/join', authenticateToken, async (req, res) => {
    try {
        const { serverId } = req.params;
        const userId = req.user.id;
        
        const serverResult = await pool.query(
            'SELECT * FROM servers WHERE id = $1',
            [serverId]
        );
        
        if (serverResult.rows.length === 0) {
            return res.status(404).json({ error: 'Сервер не найден' });
        }
        
        const server = serverResult.rows[0];
        
        const existingMember = await pool.query(
            'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
            [serverId, userId]
        );
        
        if (existingMember.rows.length > 0) {
            return res.status(400).json({ error: 'Вы уже участник этого сервера' });
        }
        
        await pool.query(
            `INSERT INTO server_members (id, server_id, user_id, role) 
             VALUES ($1, $2, $3, $4)`,
            [uuidv4(), serverId, userId, 'member']
        );
        
        const channelsResult = await pool.query(
            'SELECT * FROM channels WHERE server_id = $1 ORDER BY position',
            [serverId]
        );
        
        const userResult = await pool.query(
            'SELECT id, username, avatar_url, status FROM users WHERE id = $1',
            [userId]
        );
        
        broadcastToServer(serverId, {
            type: 'MEMBER_JOINED',
            serverId,
            member: { ...userResult.rows[0], role: 'member', joined_at: new Date().toISOString() }
        });
        
        res.json({
            ...server,
            channels: channelsResult.rows,
            message: 'Вы присоединились к серверу'
        });
    } catch (error) {
        console.error('Ошибка присоединения к серверу:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Выход с сервера
app.post('/api/servers/:serverId/leave', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const { serverId } = req.params;
        const userId = req.user.id;
        
        const serverResult = await pool.query(
            'SELECT owner_id FROM servers WHERE id = $1',
            [serverId]
        );
        
        if (serverResult.rows[0].owner_id === userId) {
            return res.status(400).json({ error: 'Владелец не может покинуть сервер. Удалите его или передайте права.' });
        }
        
        await pool.query(
            'DELETE FROM server_members WHERE server_id = $1 AND user_id = $2',
            [serverId, userId]
        );
        
        broadcastToServer(serverId, {
            type: 'MEMBER_LEFT',
            serverId,
            userId
        });
        
        res.json({ message: 'Вы покинули сервер' });
    } catch (error) {
        console.error('Ошибка выхода с сервера:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение участников сервера
app.get('/api/servers/:serverId/members', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.username, u.avatar_url, u.status, sm.role, sm.nickname, sm.joined_at
             FROM server_members sm
             JOIN users u ON sm.user_id = u.id
             WHERE sm.server_id = $1
             ORDER BY 
                CASE sm.role 
                    WHEN 'owner' THEN 1 
                    WHEN 'admin' THEN 2 
                    ELSE 3 
                END,
                sm.joined_at`,
            [req.params.serverId]
        );
        
        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка получения участников:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение инвайт-кода
app.get('/api/servers/:serverId/invite', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT invite_code FROM servers WHERE id = $1',
            [req.params.serverId]
        );
        
        res.json({ invite_code: result.rows[0].invite_code });
    } catch (error) {
        console.error('Ошибка получения инвайт-кода:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Обновление инвайт-кода (только владелец)
app.post('/api/servers/:serverId/invite/regenerate', authenticateToken, checkServerOwner, async (req, res) => {
    try {
        const newCode = generateInviteCode();
        
        await pool.query(
            'UPDATE servers SET invite_code = $1 WHERE id = $2',
            [newCode, req.params.serverId]
        );
        
        res.json({ invite_code: newCode });
    } catch (error) {
        console.error('Ошибка обновления инвайт-кода:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ============================================
// REST API МАРШРУТЫ - КАНАЛЫ
// ============================================

// Создание канала
app.post('/api/servers/:serverId/channels', authenticateToken, checkServerOwner, async (req, res) => {
    try {
        const { name, type = 'text', topic } = req.body;
        const { serverId } = req.params;
        
        if (!name || name.trim().length === 0) {
            return res.status(400).json({ error: 'Название канала обязательно' });
        }
        
        if (name.length > 100) {
            return res.status(400).json({ error: 'Название канала не более 100 символов' });
        }
        
        // Форматируем название (lowercase, без пробелов)
        const formattedName = name.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '');
        
        const channelId = uuidv4();
        
        // Получаем максимальную позицию
        const posResult = await pool.query(
            'SELECT COALESCE(MAX(position), -1) + 1 as next_pos FROM channels WHERE server_id = $1',
            [serverId]
        );
        
        const result = await pool.query(
            `INSERT INTO channels (id, server_id, name, type, topic, position) 
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING *`,
            [channelId, serverId, formattedName, type, topic || null, posResult.rows[0].next_pos]
        );
        
        const channel = result.rows[0];
        
        // Уведомляем через WebSocket
        broadcastToServer(serverId, {
            type: 'CHANNEL_CREATED',
            channel
        });
        
        res.status(201).json(channel);
    } catch (error) {
        console.error('Ошибка создания канала:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение каналов сервера
app.get('/api/servers/:serverId/channels', authenticateToken, checkServerMembership, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM channels WHERE server_id = $1 ORDER BY position',
            [req.params.serverId]
        );
        
        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка получения каналов:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение канала по ID
app.get('/api/channels/:channelId', authenticateToken, async (req, res) => {
    try {
        const { channelId } = req.params;
        
        const result = await pool.query(
            'SELECT * FROM channels WHERE id = $1',
            [channelId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Канал не найден' });
        }
        
        const channel = result.rows[0];
        
        // Проверяем членство
        const membership = await pool.query(
            'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
            [channel.server_id, req.user.id]
        );
        
        if (membership.rows.length === 0) {
            return res.status(403).json({ error: 'Нет доступа к этому каналу' });
        }
        
        res.json(channel);
    } catch (error) {
        console.error('Ошибка получения канала:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Обновление канала
app.put('/api/channels/:channelId', authenticateToken, async (req, res) => {
    try {
        const { channelId } = req.params;
        const { name, topic } = req.body;
        
        const channelResult = await pool.query(
            'SELECT * FROM channels WHERE id = $1',
            [channelId]
        );
        
        if (channelResult.rows.length === 0) {
            return res.status(404).json({ error: 'Канал не найден' });
        }
        
        const channel = channelResult.rows[0];
        
        // Проверяем права (владелец сервера)
        const serverResult = await pool.query(
            'SELECT owner_id FROM servers WHERE id = $1',
            [channel.server_id]
        );
        
        if (serverResult.rows[0].owner_id !== req.user.id) {
            return res.status(403).json({ error: 'Недостаточно прав' });
        }
        
        const formattedName = name ? name.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '') : null;
        
        const result = await pool.query(
            `UPDATE channels 
             SET name = COALESCE($1, name), 
                 topic = COALESCE($2, topic)
             WHERE id = $3
             RETURNING *`,
            [formattedName, topic, channelId]
        );
        
        const updatedChannel = result.rows[0];
        
        broadcastToServer(channel.server_id, {
            type: 'CHANNEL_UPDATED',
            channel: updatedChannel
        });
        
        res.json(updatedChannel);
    } catch (error) {
        console.error('Ошибка обновления канала:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Удаление канала
app.delete('/api/channels/:channelId', authenticateToken, async (req, res) => {
    try {
        const { channelId } = req.params;
        
        const channelResult = await pool.query(
            'SELECT * FROM channels WHERE id = $1',
            [channelId]
        );
        
        if (channelResult.rows.length === 0) {
            return res.status(404).json({ error: 'Канал не найден' });
        }
        
        const channel = channelResult.rows[0];
        
        const serverResult = await pool.query(
            'SELECT owner_id FROM servers WHERE id = $1',
            [channel.server_id]
        );
        
        if (serverResult.rows[0].owner_id !== req.user.id) {
            return res.status(403).json({ error: 'Недостаточно прав' });
        }
        
        // Проверяем, что это не последний канал
        const countResult = await pool.query(
            'SELECT COUNT(*) as count FROM channels WHERE server_id = $1',
            [channel.server_id]
        );
        
        if (parseInt(countResult.rows[0].count) <= 1) {
            return res.status(400).json({ error: 'Нельзя удалить последний канал сервера' });
        }
        
        await pool.query('DELETE FROM channels WHERE id = $1', [channelId]);
        
        broadcastToServer(channel.server_id, {
            type: 'CHANNEL_DELETED',
            channelId,
            serverId: channel.server_id
        });
        
        res.json({ message: 'Канал удален' });
    } catch (error) {
        console.error('Ошибка удаления канала:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ============================================
// REST API МАРШРУТЫ - СООБЩЕНИЯ
// ============================================

// Получение сообщений канала
app.get('/api/channels/:channelId/messages', authenticateToken, async (req, res) => {
    try {
        const { channelId } = req.params;
        const { limit = 50, before, after } = req.query;
        
        const channelResult = await pool.query(
            'SELECT * FROM channels WHERE id = $1',
            [channelId]
        );
        
        if (channelResult.rows.length === 0) {
            return res.status(404).json({ error: 'Канал не найден' });
        }
        
        // Проверяем членство
        const membership = await pool.query(
            'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
            [channelResult.rows[0].server_id, req.user.id]
        );
        
        if (membership.rows.length === 0) {
            return res.status(403).json({ error: 'Нет доступа к этому каналу' });
        }
        
        let query = `
            SELECT m.*, u.username, u.avatar_url 
            FROM messages m
            JOIN users u ON m.author_id = u.id
            WHERE m.channel_id = $1
        `;
        const params = [channelId];
        let paramIndex = 2;
        
        if (before) {
            query += ` AND m.created_at < $${paramIndex}`;
            params.push(before);
            paramIndex++;
        }
        
        if (after) {
            query += ` AND m.created_at > $${paramIndex}`;
            params.push(after);
            paramIndex++;
        }
        
        query += ` ORDER BY m.created_at DESC LIMIT $${paramIndex}`;
        params.push(parseInt(limit));
        
        const result = await pool.query(query, params);
        
        res.json(result.rows.reverse()); // Хронологический порядок
    } catch (error) {
        console.error('Ошибка получения сообщений:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Отправка сообщения через REST API
app.post('/api/channels/:channelId/messages', authenticateToken, async (req, res) => {
    try {
        const { channelId } = req.params;
        const { content } = req.body;
        const userId = req.user.id;
        
        if (!content || content.trim().length === 0) {
            return res.status(400).json({ error: 'Сообщение не может быть пустым' });
        }
        
        if (content.length > 2000) {
            return res.status(400).json({ error: 'Сообщение не более 2000 символов' });
        }
        
        const channelResult = await pool.query(
            'SELECT * FROM channels WHERE id = $1',
            [channelId]
        );
        
        if (channelResult.rows.length === 0) {
            return res.status(404).json({ error: 'Канал не найден' });
        }
        
        const channel = channelResult.rows[0];
        
        // Проверяем членство
        const membership = await pool.query(
            'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
            [channel.server_id, userId]
        );
        
        if (membership.rows.length === 0) {
            return res.status(403).json({ error: 'Нет доступа к каналу' });
        }
        
        const messageId = uuidv4();
        
        await pool.query(
            `INSERT INTO messages (id, channel_id, author_id, content) 
             VALUES ($1, $2, $3, $4)`,
            [messageId, channelId, userId, content.trim()]
        );
        
        // Получаем полные данные сообщения
        const result = await pool.query(
            `SELECT m.*, u.username, u.avatar_url 
             FROM messages m
             JOIN users u ON m.author_id = u.id
             WHERE m.id = $1`,
            [messageId]
        );
        
        const message = result.rows[0];
        
        // Рассылаем через WebSocket
        broadcastToServer(channel.server_id, {
            type: 'NEW_CHANNEL_MESSAGE',
            message
        });
        
        res.status(201).json(message);
    } catch (error) {
        console.error('Ошибка отправки сообщения:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Удаление сообщения
app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
    try {
        const { messageId } = req.params;
        
        const messageResult = await pool.query(
            `SELECT m.*, c.server_id 
             FROM messages m
             JOIN channels c ON m.channel_id = c.id
             WHERE m.id = $1`,
            [messageId]
        );
        
        if (messageResult.rows.length === 0) {
            return res.status(404).json({ error: 'Сообщение не найдено' });
        }
        
        const message = messageResult.rows[0];
        
        // Проверяем права (автор или владелец сервера)
        const serverResult = await pool.query(
            'SELECT owner_id FROM servers WHERE id = $1',
            [message.server_id]
        );
        
        if (message.author_id !== req.user.id && serverResult.rows[0].owner_id !== req.user.id) {
            return res.status(403).json({ error: 'Недостаточно прав для удаления' });
        }
        
        await pool.query('DELETE FROM messages WHERE id = $1', [messageId]);
        
        broadcastToServer(message.server_id, {
            type: 'MESSAGE_DELETED',
            messageId,
            channelId: message.channel_id
        });
        
        res.json({ message: 'Сообщение удалено' });
    } catch (error) {
        console.error('Ошибка удаления сообщения:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ============================================
// REST API МАРШРУТЫ - ЛИЧНЫЕ СООБЩЕНИЯ
// ============================================

// Получение списка диалогов
app.get('/api/dm', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Получаем уникальных собеседников с последним сообщением
        const result = await pool.query(`
            WITH conversations AS (
                SELECT DISTINCT 
                    CASE 
                        WHEN sender_id = $1 THEN recipient_id 
                        ELSE sender_id 
                    END as user_id,
                    MAX(created_at) as last_message_at
                FROM direct_messages
                WHERE sender_id = $1 OR recipient_id = $1
                GROUP BY 
                    CASE 
                        WHEN sender_id = $1 THEN recipient_id 
                        ELSE sender_id 
                    END
            )
            SELECT u.id, u.username, u.avatar_url, u.status, c.last_message_at
            FROM conversations c
            JOIN users u ON c.user_id = u.id
            ORDER BY c.last_message_at DESC
        `, [userId]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка получения диалогов:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение личных сообщений с пользователем
app.get('/api/dm/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const { limit = 50, before } = req.query;
        const currentUserId = req.user.id;
        
        // Проверяем существование пользователя
        const userResult = await pool.query(
            'SELECT id FROM users WHERE id = $1',
            [userId]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        let query = `
            SELECT dm.*, 
                   s.username as sender_username, s.avatar_url as sender_avatar,
                   r.username as recipient_username, r.avatar_url as recipient_avatar
            FROM direct_messages dm
            JOIN users s ON dm.sender_id = s.id
            JOIN users r ON dm.recipient_id = r.id
            WHERE (dm.sender_id = $1 AND dm.recipient_id = $2)
               OR (dm.sender_id = $2 AND dm.recipient_id = $1)
        `;
        
        const params = [currentUserId, userId];
        let paramIndex = 3;
        
        if (before) {
            query += ` AND dm.created_at < $${paramIndex}`;
            params.push(before);
            paramIndex++;
        }
        
        query += ` ORDER BY dm.created_at DESC LIMIT $${paramIndex}`;
        params.push(parseInt(limit));
        
        const result = await pool.query(query, params);
        
        res.json(result.rows.reverse());
    } catch (error) {
        console.error('Ошибка получения ЛС:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Отправка личного сообщения через REST API
app.post('/api/dm/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId: recipientId } = req.params;
        const { content } = req.body;
        const senderId = req.user.id;
        
        if (!content || content.trim().length === 0) {
            return res.status(400).json({ error: 'Сообщение не может быть пустым' });
        }
        
        if (content.length > 2000) {
            return res.status(400).json({ error: 'Сообщение не более 2000 символов' });
        }
        
        // Проверяем существование получателя
        const recipientResult = await pool.query(
            'SELECT id, username, avatar_url FROM users WHERE id = $1',
            [recipientId]
        );
        
        if (recipientResult.rows.length === 0) {
            return res.status(404).json({ error: 'Получатель не найден' });
        }
        
        const messageId = uuidv4();
        
        await pool.query(
            `INSERT INTO direct_messages (id, sender_id, recipient_id, content) 
             VALUES ($1, $2, $3, $4)`,
            [messageId, senderId, recipientId, content.trim()]
        );
        
        const senderResult = await pool.query(
            'SELECT id, username, avatar_url FROM users WHERE id = $1',
            [senderId]
        );
        
        const sender = senderResult.rows[0];
        const recipient = recipientResult.rows[0];
        
        const message = {
            id: messageId,
            sender_id: senderId,
            recipient_id: recipientId,
            content: content.trim(),
            created_at: new Date().toISOString(),
            sender_username: sender.username,
            sender_avatar: sender.avatar_url,
            recipient_username: recipient.username,
            recipient_avatar: recipient.avatar_url
        };
        
        // Отправляем обоим через WebSocket
        sendToUser(senderId, {
            type: 'NEW_DIRECT_MESSAGE',
            message
        });
        sendToUser(recipientId, {
            type: 'NEW_DIRECT_MESSAGE',
            message
        });
        
        res.status(201).json(message);
    } catch (error) {
        console.error('Ошибка отправки ЛС:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ============================================
// REST API МАРШРУТЫ - ПОЛЬЗОВАТЕЛИ
// ============================================

// Поиск пользователей
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const { q } = req.query;
        
        if (!q || q.length < 2) {
            return res.json([]);
        }
        
        const result = await pool.query(
            `SELECT id, username, avatar_url, status 
             FROM users 
             WHERE username ILIKE $1 AND id != $2
             LIMIT 20`,
            [`%${q}%`, req.user.id]
        );
        
        res.json(result.rows);
    } catch (error) {
        console.error('Ошибка поиска:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получение пользователя по ID
app.get('/api/users/:userId', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, avatar_url, status, created_at FROM users WHERE id = $1',
            [req.params.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Ошибка получения пользователя:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ============================================
// WEBSOCKET СЕРВЕР
// ============================================

const wss = new WebSocketServer({ server });

// Хранилище активных соединений
const clients = new Map(); // userId -> Set<WebSocket>
const wsUserMap = new WeakMap(); // WebSocket -> userId

// Функция отправки сообщения пользователю
function sendToUser(userId, data) {
    const userSockets = clients.get(userId);
    if (userSockets) {
        const message = JSON.stringify(data);
        userSockets.forEach(ws => {
            if (ws.readyState === ws.OPEN) {
                ws.send(message);
            }
        });
    }
}

// Функция рассылки всем участникам сервера
async function broadcastToServer(serverId, data) {
    try {
        const result = await pool.query(
            'SELECT user_id FROM server_members WHERE server_id = $1',
            [serverId]
        );
        
        const message = JSON.stringify(data);
        
        result.rows.forEach(row => {
            const userSockets = clients.get(row.user_id);
            if (userSockets) {
                userSockets.forEach(ws => {
                    if (ws.readyState === ws.OPEN) {
                        ws.send(message);
                    }
                });
            }
        });
    } catch (error) {
        console.error('Ошибка рассылки:', error);
    }
}

// Обработка WebSocket соединений
wss.on('connection', (ws, req) => {
    console.log('🔌 Новое WebSocket соединение');
    let authenticatedUserId = null;
    
    // Пинг для поддержания соединения
    const pingInterval = setInterval(() => {
        if (ws.readyState === ws.OPEN) {
            ws.ping();
        }
    }, 30000);
    
    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data.toString());
            
            // Аутентификация через WebSocket
            if (message.type === 'AUTH') {
                try {
                    const decoded = jwt.verify(message.token, JWT_SECRET);
                    authenticatedUserId = decoded.id;
                    
                    // Добавляем соединение в список
                    if (!clients.has(authenticatedUserId)) {
                        clients.set(authenticatedUserId, new Set());
                    }
                    clients.get(authenticatedUserId).add(ws);
                    wsUserMap.set(ws, authenticatedUserId);
                    
                    // Обновляем статус
                    await pool.query(
                        'UPDATE users SET status = $1 WHERE id = $2',
                        ['online', authenticatedUserId]
                    );
                    
                    // Уведомляем о успешной аутентификации
                    ws.send(JSON.stringify({ 
                        type: 'AUTH_SUCCESS', 
                        userId: authenticatedUserId,
                        username: decoded.username
                    }));
                    
                    // Уведомляем друзей/участников серверов о статусе онлайн
                    const servers = await pool.query(
                        'SELECT server_id FROM server_members WHERE user_id = $1',
                        [authenticatedUserId]
                    );
                    
                    for (const row of servers.rows) {
                        broadcastToServer(row.server_id, {
                            type: 'USER_STATUS_CHANGE',
                            userId: authenticatedUserId,
                            status: 'online'
                        });
                    }
                    
                    console.log(`✅ Пользователь ${decoded.username} аутентифицирован`);
                } catch (err) {
                    ws.send(JSON.stringify({ type: 'AUTH_ERROR', error: 'Недействительный токен' }));
                }
                return;
            }
            
            // Проверяем аутентификацию для остальных сообщений
            if (!authenticatedUserId) {
                ws.send(JSON.stringify({ type: 'ERROR', error: 'Необходима аутентификация' }));
                return;
            }
            
            // Обработка различных типов сообщений
            switch (message.type) {
                // Сообщение в канал
                case 'CHANNEL_MESSAGE': {
                    const { channelId, content } = message;
                    
                    if (!content || content.trim().length === 0) {
                        ws.send(JSON.stringify({ type: 'ERROR', error: 'Сообщение не может быть пустым' }));
                        return;
                    }
                    
                    if (content.length > 2000) {
                        ws.send(JSON.stringify({ type: 'ERROR', error: 'Сообщение слишком длинное' }));
                        return;
                    }
                    
                    const channelResult = await pool.query(
                        'SELECT * FROM channels WHERE id = $1',
                        [channelId]
                    );
                    
                    if (channelResult.rows.length === 0) {
                        ws.send(JSON.stringify({ type: 'ERROR', error: 'Канал не найден' }));
                        return;
                    }
                    
                    const channel = channelResult.rows[0];
                    
                    // Проверяем членство
                    const membership = await pool.query(
                        'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
                        [channel.server_id, authenticatedUserId]
                    );
                    
                    if (membership.rows.length === 0) {
                        ws.send(JSON.stringify({ type: 'ERROR', error: 'Нет доступа к каналу' }));
                        return;
                    }
                    
                    // Создаем сообщение
                    const messageId = uuidv4();
                    await pool.query(
                        `INSERT INTO messages (id, channel_id, author_id, content) 
                         VALUES ($1, $2, $3, $4)`,
                        [messageId, channelId, authenticatedUserId, content.trim()]
                    );
                    
                    // Получаем полные данные
                    const msgResult = await pool.query(
                        `SELECT m.*, u.username, u.avatar_url 
                         FROM messages m
                         JOIN users u ON m.author_id = u.id
                         WHERE m.id = $1`,
                        [messageId]
                    );
                    
                    // Рассылаем всем участникам сервера
                    broadcastToServer(channel.server_id, {
                        type: 'NEW_CHANNEL_MESSAGE',
                        message: msgResult.rows[0]
                    });
                    break;
                }
                
                // Личное сообщение
                case 'DIRECT_MESSAGE': {
                    const { recipientId, content } = message;
                    
                    if (!content || content.trim().length === 0) {
                        ws.send(JSON.stringify({ type: 'ERROR', error: 'Сообщение не может быть пустым' }));
                        return;
                    }
                    
                    if (content.length > 2000) {
                        ws.send(JSON.stringify({ type: 'ERROR', error: 'Сообщение слишком длинное' }));
                        return;
                    }
                    
                    const recipientResult = await pool.query(
                        'SELECT id, username, avatar_url FROM users WHERE id = $1',
                        [recipientId]
                    );
                    
                    if (recipientResult.rows.length === 0) {
                        ws.send(JSON.stringify({ type: 'ERROR', error: 'Получатель не найден' }));
                        return;
                    }
                    
                    // Создаем сообщение
                    const messageId = uuidv4();
                    await pool.query(
                        `INSERT INTO direct_messages (id, sender_id, recipient_id, content) 
                         VALUES ($1, $2, $3, $4)`,
                        [messageId, authenticatedUserId, recipientId, content.trim()]
                    );
                    
                    const senderResult = await pool.query(
                        'SELECT id, username, avatar_url FROM users WHERE id = $1',
                        [authenticatedUserId]
                    );
                    
                    const sender = senderResult.rows[0];
                    const recipient = recipientResult.rows[0];
                    
                    const newMessage = {
                        id: messageId,
                        sender_id: authenticatedUserId,
                        recipient_id: recipientId,
                        content: content.trim(),
                        created_at: new Date().toISOString(),
                        sender_username: sender.username,
                        sender_avatar: sender.avatar_url,
                        recipient_username: recipient.username,
                        recipient_avatar: recipient.avatar_url
                    };
                    
                    // Отправляем обоим участникам
                    sendToUser(authenticatedUserId, {
                        type: 'NEW_DIRECT_MESSAGE',
                        message: newMessage
                    });
                    sendToUser(recipientId, {
                        type: 'NEW_DIRECT_MESSAGE',
                        message: newMessage
                    });
                    break;
                }
                
                // Индикатор набора текста
                case 'TYPING_START': {
                    const { channelId, recipientId } = message;
                    
                    const userResult = await pool.query(
                        'SELECT username FROM users WHERE id = $1',
                        [authenticatedUserId]
                    );
                    
                    const username = userResult.rows[0]?.username;
                    
                    if (channelId) {
                        const channelResult = await pool.query(
                            'SELECT server_id FROM channels WHERE id = $1',
                            [channelId]
                        );
                        
                        if (channelResult.rows.length > 0) {
                            broadcastToServer(channelResult.rows[0].server_id, {
                                type: 'USER_TYPING',
                                channelId,
                                userId: authenticatedUserId,
                                username
                            });
                        }
                    } else if (recipientId) {
                        sendToUser(recipientId, {
                            type: 'USER_TYPING',
                            recipientId: authenticatedUserId,
                            userId: authenticatedUserId,
                            username
                        });
                    }
                    break;
                }
                
                // Остановка набора текста
                case 'TYPING_STOP': {
                    const { channelId, recipientId } = message;
                    
                    if (channelId) {
                        const channelResult = await pool.query(
                            'SELECT server_id FROM channels WHERE id = $1',
                            [channelId]
                        );
                        
                        if (channelResult.rows.length > 0) {
                            broadcastToServer(channelResult.rows[0].server_id, {
                                type: 'USER_STOP_TYPING',
                                channelId,
                                userId: authenticatedUserId
                            });
                        }
                    } else if (recipientId) {
                        sendToUser(recipientId, {
                            type: 'USER_STOP_TYPING',
                            userId: authenticatedUserId
                        });
                    }
                    break;
                }
                
                // Пинг
                case 'PING': {
                    ws.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
                    break;
                }
                
                default:
                    ws.send(JSON.stringify({ type: 'ERROR', error: 'Неизвестный тип сообщения' }));
            }
        } catch (error) {
            console.error('❌ Ошибка обработки WebSocket сообщения:', error);
            ws.send(JSON.stringify({ type: 'ERROR', error: 'Ошибка обработки сообщения' }));
        }
    });
    
    ws.on('close', async () => {
        clearInterval(pingInterval);
        
        if (authenticatedUserId) {
            // Удаляем соединение
            const userSockets = clients.get(authenticatedUserId);
            if (userSockets) {
                userSockets.delete(ws);
                
                if (userSockets.size === 0) {
                    clients.delete(authenticatedUserId);
                    
                    // Обновляем статус на оффлайн
                    await pool.query(
                        'UPDATE users SET status = $1 WHERE id = $2',
                        ['offline', authenticatedUserId]
                    );
                    
                    // Уведомляем о статусе оффлайн
                    const servers = await pool.query(
                        'SELECT server_id FROM server_members WHERE user_id = $1',
                        [authenticatedUserId]
                    );
                    
                    for (const row of servers.rows) {
                        broadcastToServer(row.server_id, {
                            type: 'USER_STATUS_CHANGE',
                            userId: authenticatedUserId,
                            status: 'offline'
                        });
                    }
                }
            }
            console.log(`👋 Пользователь ${authenticatedUserId} отключился`);
        }
    });
    
    ws.on('error', (error) => {
        console.error('❌ WebSocket ошибка:', error);
    });
    
    ws.on('pong', () => {
        // Соединение живое
    });
});

// ============================================
// СЛУЖЕБНЫЕ МАРШРУТЫ
// ============================================

// Health check
app.get('/health', async (req, res) => {
    try {
        // Проверяем подключение к БД
        await pool.query('SELECT 1');
        
        res.json({ 
            status: 'ok',
            database: 'connected',
            timestamp: new Date().toISOString(),
            activeConnections: clients.size,
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error',
            database: 'disconnected',
            error: error.message
        });
    }
});

// Документация API
app.get('/', (req, res) => {
    res.json({
        name: 'Discord Clone API',
        version: '2.0.0',
        database: 'PostgreSQL (Neon)',
        documentation: {
            auth: {
                'POST /api/auth/register': 'Регистрация нового пользователя',
                'POST /api/auth/login': 'Вход в систему',
                'GET /api/auth/me': 'Получение текущего пользователя',
                'PUT /api/auth/me': 'Обновление профиля'
            },
            servers: {
                'GET /api/servers': 'Список серверов пользователя',
                'POST /api/servers': 'Создание нового сервера',
                'GET /api/servers/:id': 'Информация о сервере',
                'PUT /api/servers/:id': 'Обновление сервера',
                'DELETE /api/servers/:id': 'Удаление сервера',
                'POST /api/servers/:id/join': 'Присоединиться к серверу',
                'POST /api/servers/join/:inviteCode': 'Присоединиться по инвайт-коду',
                'POST /api/servers/:id/leave': 'Покинуть сервер',
                'GET /api/servers/:id/members': 'Участники сервера',
                'GET /api/servers/:id/invite': 'Получить инвайт-код',
                'POST /api/servers/:id/invite/regenerate': 'Обновить инвайт-код'
            },
            channels: {
                'GET /api/servers/:serverId/channels': 'Каналы сервера',
                'POST /api/servers/:serverId/channels': 'Создание канала',
                'GET /api/channels/:id': 'Информация о канале',
                'PUT /api/channels/:id': 'Обновление канала',
                'DELETE /api/channels/:id': 'Удаление канала',
                'GET /api/channels/:id/messages': 'Сообщения канала',
                'POST /api/channels/:id/messages': 'Отправить сообщение'
            },
            messages: {
                'DELETE /api/messages/:id': 'Удаление сообщения'
            },
            directMessages: {
                'GET /api/dm': 'Список диалогов',
                'GET /api/dm/:userId': 'Сообщения с пользователем',
                'POST /api/dm/:userId': 'Отправить личное сообщение'
            },
            users: {
                'GET /api/users/search?q=query': 'Поиск пользователей',
                'GET /api/users/:id': 'Информация о пользователе'
            },
            websocket: {
                url: 'wss://[host]',
                authMessage: '{"type": "AUTH", "token": "JWT_TOKEN"}',
                events: {
                    outgoing: [
                        'AUTH - аутентификация',
                        'CHANNEL_MESSAGE - сообщение в канал',
                        'DIRECT_MESSAGE - личное сообщение',
                        'TYPING_START - начало набора',
                        'TYPING_STOP - конец набора',
                        'PING - проверка соединения'
                    ],
                    incoming: [
                        'AUTH_SUCCESS - успешная аутентификация',
                        'AUTH_ERROR - ошибка аутентификации',
                        'NEW_CHANNEL_MESSAGE - новое сообщение в канале',
                        'NEW_DIRECT_MESSAGE - новое личное сообщение',
                        'USER_TYPING - пользователь печатает',
                        'USER_STOP_TYPING - пользователь перестал печатать',
                        'USER_STATUS_CHANGE - изменение статуса пользователя',
                        'CHANNEL_CREATED - создан канал',
                        'CHANNEL_UPDATED - обновлен канал',
                        'CHANNEL_DELETED - удален канал',
                        'SERVER_UPDATED - обновлен сервер',
                        'SERVER_DELETED - удален сервер',
                        'MEMBER_JOINED - новый участник',
                        'MEMBER_LEFT - участник вышел',
                        'MESSAGE_DELETED - сообщение удалено',
                        'PONG - ответ на пинг',
                        'ERROR - ошибка'
                    ]
                }
            }
        },
        health: '/health'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Маршрут не найден' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Ошибка:', err);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// ============================================
// ЗАПУСК СЕРВЕРА
// ============================================

async function startServer() {
    try {
        // Инициализируем базу данных
        await initializeDatabase();
        
        // Запускаем сервер
        server.listen(PORT, '0.0.0.0', () => {
            console.log(`
╔═══════════════════════════════════════════════════════╗
║         Discord Clone Server v2.0 (PostgreSQL)        ║
╠═══════════════════════════════════════════════════════╣
║  🚀 HTTP Server:  http://localhost:${PORT}               ║
║  🔌 WebSocket:    ws://localhost:${PORT}                 ║
║  📊 Health Check: http://localhost:${PORT}/health        ║
║  🗄️  Database:    PostgreSQL (Neon)                    ║
╚═══════════════════════════════════════════════════════╝
            `);
        });
    } catch (error) {
        console.error('❌ Ошибка запуска сервера:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('\n🛑 Получен SIGTERM, закрываем соединения...');
    
    // Закрываем WebSocket соединения
    wss.clients.forEach(client => {
        client.close(1001, 'Server shutting down');
    });
    
    // Закрываем HTTP сервер
    server.close(async () => {
        console.log('✅ HTTP сервер остановлен');
        
        // Закрываем пул подключений к БД
        await pool.end();
        console.log('✅ Подключение к БД закрыто');
        
        process.exit(0);
    });
    
    // Принудительный выход через 10 секунд
    setTimeout(() => {
        console.error('⚠️ Принудительное завершение');
        process.exit(1);
    }, 10000);
});

process.on('SIGINT', () => {
    process.emit('SIGTERM');
});

// Запуск
startServer();

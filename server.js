// server.js - ЕДИНСТВЕННЫЙ ФАЙЛ БЭКЕНДА
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// Раздаем статические файлы (наши html)
app.use(express.static('public'));
app.use(express.json());

// --- API: АУТЕНТИФИКАЦИЯ ---

app.post('/api/auth', async (req, res) => {
    const { email, password, type } = req.body;
    
    try {
        if (type === 'register') {
            const hashed = await bcrypt.hash(password, 10);
            const username = email.split('@')[0];
            const user = await prisma.user.create({
                data: { 
                    email, 
                    password: hashed, 
                    username,
                    avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${username}`
                }
            });
            // Создаем сервер для новичка сразу
            await prisma.server.create({
                data: {
                    name: "My First Server",
                    ownerId: user.id,
                    channels: { create: [{ name: "general", type: "TEXT" }, { name: "voice-room", type: "VOICE" }] },
                    members: { create: { userId: user.id } }
                }
            });
            const token = jwt.sign({ userId: user.id }, JWT_SECRET);
            return res.json({ token, user });
        } else {
            const user = await prisma.user.findUnique({ where: { email } });
            if (!user || !await bcrypt.compare(password, user.password)) {
                return res.status(401).json({ error: "Неверный логин или пароль" });
            }
            const token = jwt.sign({ userId: user.id }, JWT_SECRET);
            return res.json({ token, user });
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Ошибка сервера" });
    }
});

// Middleware проверки токена
const auth = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch { res.status(401).json({ error: "Unauthorized" }); }
};

// --- API: ДАННЫЕ ---

app.get('/api/data', auth, async (req, res) => {
    // Грузим всё сразу: сервера юзера, каналы, участников
    const servers = await prisma.server.findMany({
        where: { members: { some: { userId: req.user.userId } } },
        include: { 
            channels: true,
            members: { include: { user: true } }
        }
    });
    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    res.json({ servers, user });
});

app.get('/api/messages/:channelId', auth, async (req, res) => {
    const messages = await prisma.message.findMany({
        where: { channelId: req.params.channelId },
        include: { user: true },
        orderBy: { createdAt: 'asc' },
        take: 50
    });
    res.json(messages);
});

// --- SOCKET.IO: ЧАТ И ГОЛОС ---

// Кто в какой комнате (для голоса)
const voiceRooms = {}; // { channelId: [socketId, ...] }
const socketToUser = {}; // { socketId: userId }

io.on('connection', (socket) => {
    console.log('User connected', socket.id);

    // Вход в текстовый канал (комнату сокетов)
    socket.on('join-text', (channelId) => {
        socket.join(channelId);
    });

    // Отправка сообщения
    socket.on('send-message', async ({ content, channelId, token }) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const msg = await prisma.message.create({
                data: { content, channelId, userId: decoded.userId },
                include: { user: true }
            });
            io.to(channelId).emit('new-message', msg);
        } catch (e) { console.error(e); }
    });

    // --- ГОЛОС (WebRTC Signaling) ---
    // Мы просто пересылаем данные между клиентами
    
    socket.on('join-voice', ({ channelId, userId }) => {
        if (!voiceRooms[channelId]) voiceRooms[channelId] = [];
        const usersInRoom = voiceRooms[channelId]; // Список socketId тех, кто уже там
        
        // Говорим новому юзеру: "Вот список тех, кто уже тут, позвони им"
        socket.emit('all-users', usersInRoom);
        
        // Добавляем нового в список
        voiceRooms[channelId].push(socket.id);
        socketToUser[socket.id] = userId;
    });

    // Пересылка сигнала (Offer/Answer/Candidate) конкретному юзеру
    socket.on('sending-signal', payload => {
        io.to(payload.userToSignal).emit('user-joined', { signal: payload.signal, callerID: payload.callerID });
    });

    socket.on('returning-signal', payload => {
        io.to(payload.callerID).emit('receiving-returned-signal', { signal: payload.signal, id: socket.id });
    });

    // Выход
    socket.on('disconnect', () => {
        // Удаляем из голосовых комнат
        for (const [roomId, users] of Object.entries(voiceRooms)) {
            if (users.includes(socket.id)) {
                voiceRooms[roomId] = users.filter(id => id !== socket.id);
                // Говорим остальным убрать видео этого юзера
                users.forEach(remainingUser => {
                    io.to(remainingUser).emit('user-left', socket.id);
                });
            }
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server ready on port ${PORT}`));

import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import path from 'path';
import { CONFIG } from './config';
import { sfuService } from './sfu.service';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: "*" }
});
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

// --- API ROUTES (Simplified for brevity) ---

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, name }
    });
    res.json(user);
  } catch (e) { res.status(400).json({ error: 'User exists' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ userId: user.id }, CONFIG.JWT_SECRET);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// Protected Data Routes (Middleware omitted for brevity, assumed valid token passed)
// In production, add a verifyToken middleware here.

app.get('/api/servers', async (req, res) => {
  const servers = await prisma.server.findMany({ include: { channels: true } });
  res.json(servers);
});

app.post('/api/servers', async (req, res) => {
  const { name, ownerId } = req.body;
  const server = await prisma.server.create({
    data: { 
      name, 
      ownerId,
      channels: { create: [{ name: 'general', type: 'TEXT' }, { name: 'Voice Lounge', type: 'AUDIO' }] },
      members: { create: [{ userId: ownerId, role: 'ADMIN' }] }
    },
    include: { channels: true }
  });
  res.json(server);
});

app.post('/api/channels', async (req, res) => {
  const { name, type, serverId } = req.body;
  const channel = await prisma.channel.create({
    data: { name, type, serverId }
  });
  res.json(channel);
});

app.get('/api/messages/:channelId', async (req, res) => {
  const messages = await prisma.message.findMany({
    where: { channelId: req.params.channelId },
    include: { member: { include: { user: true } } },
    orderBy: { createdAt: 'asc' }
  });
  res.json(messages);
});

// --- SOCKET.IO & MEDIASOUP SIGNALING ---

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  // Text Chat
  socket.on('join-channel', (channelId) => {
    socket.join(channelId);
  });

  socket.on('send-message', async (data) => {
    // data: { content, userId, channelId, serverId }
    // Resolve Member ID needed
    const member = await prisma.member.findFirst({ 
      where: { userId: data.userId, serverId: data.serverId } 
    });
    
    if(member) {
      const msg = await prisma.message.create({
        data: { content: data.content, channelId: data.channelId, memberId: member.id },
        include: { member: { include: { user: true } } }
      });
      io.to(data.channelId).emit('new-message', msg);
    }
  });

  // VOICE / MEDIASOUP Events
  socket.on('join-voice', async ({ channelId }, callback) => {
    const router = await sfuService.getOrCreateRouter(channelId);
    sfuService.addPeer(channelId, socket.id);
    socket.join(`voice-${channelId}`);
    
    // Send Router RTP Capabilities to client
    callback({ rtpCapabilities: router.rtpCapabilities });
  });

  socket.on('create-transport', async ({ channelId }, callback) => {
    const params = await sfuService.createWebRtcTransport(channelId, socket.id);
    callback(params);
  });

  socket.on('connect-transport', async ({ channelId, transportId, dtlsParameters }, callback) => {
    await sfuService.connectTransport(channelId, socket.id, transportId, dtlsParameters);
    callback();
  });

  socket.on('produce', async ({ channelId, transportId, kind, rtpParameters }, callback) => {
    const { id } = await sfuService.produce(channelId, socket.id, transportId, kind, rtpParameters);
    // Notify others in room
    socket.to(`voice-${channelId}`).emit('new-producer', { producerId: id, producerSocketId: socket.id });
    callback({ id });
  });

  socket.on('consume', async ({ channelId, transportId, producerId, rtpCapabilities }, callback) => {
    const params = await sfuService.consume(channelId, socket.id, transportId, producerId, rtpCapabilities);
    callback(params);
  });

  socket.on('resume-consumer', async ({ consumerId }) => {
    // Logic to resume consumer would go in service
    // For now simplistic implementation assume auto-resume or client handling
  });

  socket.on('disconnect', () => {
    sfuService.removePeer(socket.id);
  });
});

// Serve Frontend Static (Production)
if (process.env.NODE_ENV === 'production') {
  const clientPath = path.join(__dirname, '../../client/.next/server/pages'); // Adjust based on Next build
  // Simpler strategy: Serve static export or handle nextjs standalone
  // For this demo, we assume the Dockerfile handles putting the static export in 'public' or similar
  // OR proxying. 
  // BETTER: Serve 'client/out' if using 'next export' (static site)
  app.use(express.static(path.join(__dirname, '../../client/out')));
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../../client/out/index.html'));
  });
}

// Start
const start = async () => {
  await sfuService.init();
  httpServer.listen(CONFIG.PORT, () => {
    console.log(`Server running on port ${CONFIG.PORT}`);
  });
};

start();

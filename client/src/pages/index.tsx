import React, { useState, useEffect } from 'react';
import axios from 'axios';
import io, { Socket } from 'socket.io-client';
import { useMediasoup } from '../hooks/useMediasoup';
import { Mic, Headphones, Hash, Volume2 } from 'lucide-react';

// Env helpers
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export default function Discordia() {
  const [token, setToken] = useState<string>('');
  const [user, setUser] = useState<any>(null);
  const [servers, setServers] = useState<any[]>([]);
  const [activeServer, setActiveServer] = useState<any>(null);
  const [activeChannel, setActiveChannel] = useState<any>(null);
  const [messages, setMessages] = useState<any[]>([]);
  const [input, setInput] = useState('');
  
  const [socket, setSocket] = useState<Socket | null>(null);

  // Auth Forms State
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  useEffect(() => {
    if (token) {
      const newSocket = io(API_URL);
      setSocket(newSocket);
      fetchServers();
      return () => { newSocket.close(); };
    }
  }, [token]);

  useEffect(() => {
    if (!socket || !activeChannel) return;
    if (activeChannel.type === 'TEXT') {
       socket.emit('join-channel', activeChannel.id);
       fetchMessages(activeChannel.id);
       
       socket.on('new-message', (msg) => {
         setMessages(prev => [...prev, msg]);
       });
       
       return () => { socket.off('new-message'); };
    }
  }, [socket, activeChannel]);

  // Voice Hook
  const voiceState = useMediasoup(
      socket, 
      activeChannel?.type === 'AUDIO' ? activeChannel.id : null
  );

  const login = async () => {
    try {
      const res = await axios.post(`${API_URL}/api/auth/login`, { email, password });
      setToken(res.data.token);
      setUser(res.data.user);
    } catch (e) { alert('Login failed'); }
  };

  const fetchServers = async () => {
    const res = await axios.get(`${API_URL}/api/servers`);
    setServers(res.data);
    if(res.data.length > 0) setActiveServer(res.data[0]);
  };

  const fetchMessages = async (channelId: string) => {
    const res = await axios.get(`${API_URL}/api/messages/${channelId}`);
    setMessages(res.data);
  };

  const sendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!socket || !activeChannel) return;
    socket.emit('send-message', {
      content: input,
      userId: user.id,
      channelId: activeChannel.id,
      serverId: activeServer.id
    });
    setInput('');
  };

  if (!user) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#313338] text-white">
        <div className="w-96 p-8 bg-[#2b2d31] rounded-lg shadow-xl">
          <h1 className="text-2xl font-bold mb-4 text-center">Discordia Login</h1>
          <input className="w-full mb-2 p-2 bg-[#1e1f22] rounded" placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)}/>
          <input className="w-full mb-4 p-2 bg-[#1e1f22] rounded" type="password" placeholder="Password" value={password} onChange={e=>setPassword(e.target.value)}/>
          <button onClick={login} className="w-full bg-[#5865F2] p-2 rounded hover:bg-[#4752C4]">Login</button>
          <div className="mt-2 text-xs text-gray-400 text-center">Register not in UI demo (use curl)</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-[#313338] text-gray-100 font-sans overflow-hidden">
      {/* Server List */}
      <div className="w-[72px] bg-[#1e1f22] flex flex-col items-center py-3 gap-2 overflow-y-auto">
        {servers.map(srv => (
          <div 
            key={srv.id} 
            onClick={() => { setActiveServer(srv); setActiveChannel(null); }}
            className={`w-12 h-12 rounded-[24px] hover:rounded-[16px] transition-all cursor-pointer flex items-center justify-center bg-[#313338] hover:bg-[#5865F2] ${activeServer?.id === srv.id ? 'bg-[#5865F2] rounded-[16px]' : ''}`}
          >
            {srv.name.substring(0,2).toUpperCase()}
          </div>
        ))}
        <div className="w-12 h-12 rounded-[24px] bg-[#313338] flex items-center justify-center text-green-500 hover:text-white hover:bg-green-500 cursor-pointer transition-all">+</div>
      </div>

      {/* Channel List */}
      <div className="w-60 bg-[#2b2d31] flex flex-col">
        <div className="h-12 shadow-sm flex items-center px-4 font-bold border-b border-[#1f2023] hover:bg-[#35373c] transition">
           {activeServer?.name}
        </div>
        <div className="flex-1 overflow-y-auto p-2">
           {activeServer?.channels.map((ch: any) => (
             <div 
                key={ch.id} 
                onClick={() => setActiveChannel(ch)}
                className={`flex items-center gap-2 px-2 py-1 rounded cursor-pointer mb-1 ${activeChannel?.id === ch.id ? 'bg-[#404249] text-white' : 'text-gray-400 hover:bg-[#35373c] hover:text-gray-200'}`}
             >
               {ch.type === 'TEXT' ? <Hash size={18} /> : <Volume2 size={18} />}
               <span>{ch.name}</span>
             </div>
           ))}
        </div>
        {/* User User Profile Area */}
        <div className="h-14 bg-[#232428] flex items-center px-2 gap-2">
            <div className="w-8 h-8 rounded-full bg-yellow-500"></div>
            <div className="flex-1 text-sm overflow-hidden">
                <div className="font-bold">{user.name}</div>
                <div className="text-xs text-gray-400">Online</div>
            </div>
            <Mic size={18} className="cursor-pointer hover:text-white" />
            <Headphones size={18} className="cursor-pointer hover:text-white" />
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col bg-[#313338]">
        {/* Header */}
        <div className="h-12 border-b border-[#26272d] flex items-center px-4 font-bold shadow-sm">
           {activeChannel ? (
             <>
               {activeChannel.type === 'TEXT' ? <Hash size={24} className="text-gray-400 mr-2"/> : <Volume2 size={24} className="text-gray-400 mr-2"/>}
               {activeChannel.name}
             </>
           ) : "Select a channel"}
        </div>

        {/* Text Chat Area */}
        {activeChannel?.type === 'TEXT' && (
          <>
            <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
              {messages.map(msg => (
                <div key={msg.id} className="flex gap-4 group">
                  <div className="w-10 h-10 rounded-full bg-blue-500 flex-shrink-0 mt-1"></div>
                  <div>
                    <div className="flex items-baseline gap-2">
                      <span className="font-medium text-white">{msg.member.user.name}</span>
                      <span className="text-xs text-gray-400">{new Date(msg.createdAt).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-gray-300 whitespace-pre-wrap">{msg.content}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="p-4 pt-0">
               <form onSubmit={sendMessage} className="bg-[#383a40] rounded-lg px-4 py-3">
                 <input 
                   className="w-full bg-transparent outline-none text-gray-200 placeholder-gray-400" 
                   placeholder={`Message #${activeChannel.name}`}
                   value={input}
                   onChange={e => setInput(e.target.value)}
                 />
               </form>
            </div>
          </>
        )}

        {/* Voice Chat Area */}
        {activeChannel?.type === 'AUDIO' && (
          <div className="flex-1 flex flex-col items-center justify-center p-10 bg-[#1e1f22]">
            <h2 className="text-2xl font-bold mb-8">Voice Connected</h2>
            <div className="flex flex-wrap gap-4 justify-center">
               {/* Self */}
               <div className="w-32 h-32 rounded-lg bg-[#313338] border-2 border-green-500 flex items-center justify-center relative">
                  <div className="w-16 h-16 rounded-full bg-yellow-500"></div>
                  <div className="absolute bottom-2 left-2 text-sm font-bold shadow-black drop-shadow-md">You</div>
               </div>
               
               {/* Others */}
               {voiceState.peers.map((peer: any, idx) => (
                 <div key={idx} className="w-32 h-32 rounded-lg bg-[#313338] flex items-center justify-center relative">
                    <div className="w-16 h-16 rounded-full bg-blue-500"></div>
                    <div className="absolute bottom-2 left-2 text-sm font-bold">User {peer.socketId.substr(0,4)}</div>
                 </div>
               ))}
            </div>
          </div>
        )}
      </div>
      
      {/* Member List (Right Sidebar) */}
      <div className="w-60 bg-[#2b2d31] hidden lg:block p-3">
         <h3 className="uppercase text-xs font-bold text-gray-500 mb-2">Members</h3>
         {/* Mock members */}
         <div className="flex items-center gap-2 mb-2 opacity-50">
           <div className="w-8 h-8 rounded-full bg-gray-600"></div>
           <span>Offline Member</span>
         </div>
      </div>
    </div>
  );
}

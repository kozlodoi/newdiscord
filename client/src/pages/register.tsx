import React, { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';

export default function Register() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [username, setUsername] = useState('');
    const router = useRouter();

    const handleRegister = async (e: React.FormEvent) => {
        e.preventDefault();
    
        // Если переменная не задана, пробуем стучаться по относительному пути 
        // или укажите ваш URL на Render напрямую для теста
        const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'https://newdiscord-wx7m.onrender.com';
    
        try {
            const response = await axios.post(`${API_BASE}/auth/register`, {
                email, 
                username, 
                password
            });
            console.log('Успех:', response.data);
            router.push('/login');
        } catch (err) {
            console.error('Детали ошибки:', err);
            alert('Ошибка регистрации: проверьте консоль');
        }
    };

    return (
        <div className="flex h-screen w-full items-center justify-center bg-[#313338] text-white">
            <form onSubmit={handleRegister} className="w-[480px] rounded-md bg-[#2b2d31] p-8 shadow-xl">
                <h2 className="mb-2 text-center text-2xl font-bold">Создать учетную запись</h2>
                <div className="mt-4">
                    <label className="text-xs font-bold uppercase text-[#b5bac1]">Email</label>
                    <input type="email" onChange={e => setEmail(e.target.value)} className="mt-2 w-full rounded bg-[#1e1f22] p-2 outline-none" required />
                </div>
                <div className="mt-4">
                    <label className="text-xs font-bold uppercase text-[#b5bac1]">Имя пользователя</label>
                    <input type="text" onChange={e => setUsername(e.target.value)} className="mt-2 w-full rounded bg-[#1e1f22] p-2 outline-none" required />
                </div>
                <div className="mt-4">
                    <label className="text-xs font-bold uppercase text-[#b5bac1]">Пароль</label>
                    <input type="password" onChange={e => setPassword(e.target.value)} className="mt-2 w-full rounded bg-[#1e1f22] p-2 outline-none" required />
                </div>
                <button type="submit" className="mt-6 w-full rounded bg-[#5865f2] py-2 font-medium transition hover:bg-[#4752c4]">
                    Продолжить
                </button>
                <p className="mt-2 text-sm text-[#00a8fc] cursor-pointer" onClick={() => router.push('/login')}>
                    Уже есть аккаунт?
                </p>
            </form>
        </div>
    );
}

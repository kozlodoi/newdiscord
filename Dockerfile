# --- Stage 1: Build Client ---
FROM node:18-alpine AS client-builder
WORKDIR /app/client
# Копируем конфиги
COPY client/package*.json ./
# Используем npm install (он создаст lock-файл, если его нет)
RUN npm install
# Копируем исходники и билдим
COPY client/ ./
# Переменная для билда (можно оставить пустой слэш для относительных путей)
ENV NEXT_PUBLIC_API_URL=/ 
RUN npm run build

# --- Stage 2: Build Server ---
FROM node:18-alpine AS server-builder
# !!! ИСПРАВЛЕНИЕ: Устанавливаем инструменты для сборки mediasoup (Python, Make, G++)
RUN apk add --no-cache python3 make g++ py3-pip

WORKDIR /app/server
COPY server/package*.json ./

# Устанавливаем зависимости (теперь компиляция mediasoup пройдет успешно)
RUN npm install

COPY server/ ./
# Генерируем Prisma Client
RUN npx prisma generate
# Компилируем TypeScript
RUN npm run build

# --- Stage 3: Final Production Image ---
FROM node:18-alpine
WORKDIR /app

# Mediasoup может требовать runtime библиотеки, оставляем python/make на всякий случай
# (хотя для запуска скомпилированного воркера часто достаточно libstd)
RUN apk add --no-cache python3 make g++

# Копируем package.json
COPY --from=server-builder /app/server/package*.json ./

# !!! ВАЖНОЕ ИЗМЕНЕНИЕ:
# Мы копируем папку node_modules целиком из server-builder.
# Это гарантирует, что скомпилированный там mediasoup перенесется сюда и будет работать.
# Повторный npm install здесь не нужен и может вызвать ошибки.
COPY --from=server-builder /app/server/node_modules ./node_modules

# Копируем сбилженный бекенд
COPY --from=server-builder /app/server/dist ./dist
# Копируем prisma схему
COPY --from=server-builder /app/server/prisma ./prisma
# Копируем статику фронтенда
COPY --from=client-builder /app/client/out ./client/out

# Генерируем prisma клиент для production среды
RUN npx prisma generate

EXPOSE 3001

# Запуск: Применяем миграции (db push) -> Запускаем сервер
CMD npx prisma db push && node dist/index.js

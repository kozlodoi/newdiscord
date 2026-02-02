# --- Stage 1: Build Client ---
FROM node:18-alpine AS client-builder
WORKDIR /app/client
COPY client/package*.json ./
RUN npm install
COPY client/ ./
# Билд теперь сам создаст папку /app/client/out благодаря конфигу
RUN npm run build

# --- Stage 2: Build Server ---
FROM node:18-alpine AS server-builder
RUN apk add --no-cache python3 make g++ py3-pip
WORKDIR /app/server
COPY server/package*.json ./
RUN npm install
COPY server/ ./
RUN npx prisma generate
RUN npm run build

# --- Stage 3: Final Production Image ---
FROM node:18-alpine
WORKDIR /app
RUN apk add --no-cache python3 make g++

# Копируем зависимости и сбилженный код
COPY --from=server-builder /app/server/node_modules ./node_modules
COPY --from=server-builder /app/server/dist ./dist
COPY --from=server-builder /app/server/prisma ./prisma
COPY --from=server-builder /app/server/package*.json ./

# Копируем статику фронтенда (папка out)
COPY --from=client-builder /app/client/out ./client/out

RUN npx prisma generate

EXPOSE 3001

# Запуск с форсированным db push для синхронизации схемы NeonDB
CMD npx prisma db push && node dist/index.js

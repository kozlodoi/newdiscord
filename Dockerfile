# --- Build Client ---
FROM node:18-alpine AS client-builder
WORKDIR /app/client

# Копируем package.json (и lock если есть)
COPY client/package*.json ./

# ИЗМЕНЕНИЕ: Используем install вместо ci, чтобы работать без lock-файла
RUN npm install

COPY client/ ./
# Use specific env for build time if needed
ENV NEXT_PUBLIC_API_URL=/ 
RUN npm run build

# --- Build Server ---
FROM node:18-alpine AS server-builder
WORKDIR /app/server
COPY server/package*.json ./

# ИЗМЕНЕНИЕ: Используем install вместо ci
RUN npm install

COPY server/ ./
RUN npx prisma generate
RUN npm run build

# --- Final Image ---
FROM node:18-alpine
WORKDIR /app

# System dependencies for Mediasoup
RUN apk add --no-cache python3 make g++

COPY --from=server-builder /app/server/package*.json ./

# ИЗМЕНЕНИЕ: Используем install вместо ci для production зависимостей
RUN npm install --production

COPY --from=server-builder /app/server/dist ./dist
COPY --from=server-builder /app/server/prisma ./prisma
COPY --from=client-builder /app/client/out ./client/out

# Install runtime prisma (needed for migrations in prod)
RUN npx prisma generate

EXPOSE 3001
# Start Command: Migrate DB -> Start Server
CMD npx prisma db push && node dist/index.js

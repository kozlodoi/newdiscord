# --- Stage 1: Build Client ---
FROM node:18-bullseye-slim AS client-builder
WORKDIR /app/client
COPY client/package*.json ./
RUN npm install
COPY client/ ./
RUN npm run build

# --- Stage 2: Build Server ---
FROM node:18-bullseye-slim AS server-builder

# Устанавливаем инструменты сборки для Debian
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/server
COPY server/package*.json ./

# Флаги для игнорирования предупреждений компилятора, которые валят билд
ENV CXXFLAGS="-Wno-maybe-uninitialized -Wno-uninitialized"

RUN npm install

COPY server/ ./
RUN npx prisma generate
RUN npm run build

# --- Stage 3: Final Production Image ---
FROM node:18-bullseye-slim
WORKDIR /app

# Библиотеки для работы скомпилированного воркера
RUN apt-get update && apt-get install -y \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=server-builder /app/server/node_modules ./node_modules
COPY --from=server-builder /app/server/dist ./dist
COPY --from=server-builder /app/server/prisma ./prisma
COPY --from=server-builder /app/server/package*.json ./
COPY --from=client-builder /app/client/out ./client/out

RUN npx prisma generate

EXPOSE 3001

CMD npx prisma db push && node dist/index.js

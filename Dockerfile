# --- Этап 1: Сборка ---
FROM node:20-alpine AS builder

RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# 1. Копируем всё содержимое проекта
COPY . .

# 2. Устанавливаем зависимости корневого проекта (для Prisma и сервера)
RUN npm install --ignore-scripts

# 3. ПЕРЕХОДИМ В КЛИЕНТ И УСТАНАВЛИВАЕМ ЗАВИСИМОСТИ ТАМ
# Это решит ошибки "Module not found" для axios, lucide-react и т.д.
RUN cd client && npm install --ignore-scripts

# 4. Генерируем Prisma клиент в корне
RUN npx prisma generate

# 5. Собираем Next.js из папки client
WORKDIR /app/client
RUN npx next build

# --- Этап 2: Запуск ---
FROM node:20-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Копируем результаты сборки клиента
COPY --from=builder /app/client/public ./client/public
COPY --from=builder /app/client/.next ./client/.next
# Копируем node_modules из клиента (там axios и прочее) и из корня (там prisma)
COPY --from=builder /app/client/node_modules ./client/node_modules
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma

USER nextjs

EXPOSE 3000

# Запуск. В зависимости от вашей архитектуры, вы можете запускать либо сервер, либо клиент.
# Если вам нужен Next.js:
CMD ["npm", "start", "--prefix", "client"]

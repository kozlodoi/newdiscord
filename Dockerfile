# Этап 1: Сборка
FROM node:20-alpine AS builder

# Устанавливаем системные зависимости
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# 1. Копируем файлы манифестов
COPY package*.json ./

# 2. Копируем ВЕСЬ проект сразу (включая папки app, pages, public и т.д.)
# Это гарантирует, что Next.js увидит структуру проекта
COPY . .

# 3. Устанавливаем зависимости
# Используем --ignore-scripts, чтобы не запускать prisma до генерации клиента
RUN npm install --ignore-scripts

# 4. Генерируем клиент Prisma
RUN npx prisma generate

# 5. Запускаем сборку Next.js
# Теперь папки app или pages точно на месте
RUN npx next build

# Этап 2: Запуск
FROM node:20-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Копируем только необходимые результаты сборки
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules

USER nextjs

EXPOSE 3000

CMD ["npm", "start"]

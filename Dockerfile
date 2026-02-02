# Этап 1: Сборка (Builder)
FROM node:20-alpine AS builder

# Установка системных библиотек (обязательно для Prisma + Alpine Linux)
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем файлы package.json
COPY package*.json ./
COPY prisma ./prisma/

# ИСПРАВЛЕНИЕ: Используем 'npm install' вместо 'npm ci'.
# Это предотвратит ошибку отсутствующего package-lock.json.
RUN npm install

# Генерация клиента Prisma
RUN npx prisma generate

# Копируем весь исходный код проекта
COPY . .

# Запуск сборки (Next.js build)
RUN npm run build

# Этап 2: Запуск (Runner) — для уменьшения размера итогового образа
FROM node:20-alpine AS runner

WORKDIR /app

# Установка openssl для работы Prisma в продакшене
RUN apk add --no-cache openssl

ENV NODE_ENV=production

# Создаем системного пользователя (безопасность)
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Копируем только нужные файлы из этапа сборки
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma

# Копируем папку сборки Next.js (.next)
# Автоматически устанавливаем права для пользователя nextjs
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules

# Переключаемся на пользователя
USER nextjs

# Запускаем проект
CMD ["npm", "start"]

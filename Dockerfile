# Этап 1: Сборка (Builder)
FROM node:20-alpine AS builder

# Устанавливаем системные зависимости для Prisma
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем файлы зависимостей
COPY package*.json ./
COPY prisma ./prisma/

# 1. Устанавливаем зависимости, ИГНОРИРУЯ скрипты (это лечит ошибку 127)
RUN npm install --ignore-scripts

# 2. Явно запускаем генерацию Prisma через npx
RUN npx prisma generate

# Копируем исходный код
COPY . .

# Собираем проект
RUN npm run build

# Этап 2: Запуск (Runner)
FROM node:20-alpine AS runner

WORKDIR /app

# Системные зависимости для продакшена
RUN apk add --no-cache openssl

ENV NODE_ENV=production

# Создаем пользователя
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Копируем необходимые файлы из билдера
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules

USER nextjs

CMD ["npm", "start"]

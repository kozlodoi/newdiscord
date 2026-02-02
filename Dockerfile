# Этап 1: Сборка (Builder)
FROM node:20-alpine AS builder

# Системные зависимости для Prisma и Next.js
RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# Копируем только файлы зависимостей
COPY package*.json ./

# Устанавливаем ВСЕ зависимости (включая devDependencies для сборки)
# Мы убираем --ignore-scripts здесь, чтобы бинарники (типа next) установились корректно
RUN npm install

# Копируем схему Prisma и генерируем клиент
COPY prisma ./prisma/
RUN npx prisma generate

# Копируем оставшийся исходный код
COPY . .

# Принудительно проверяем наличие next и запускаем сборку
# Если вдруг 'next' не виден, запускаем через npx
RUN npx next build

# Этап 2: Запуск (Runner)
FROM node:20-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Копируем только то, что нужно для работы
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules

USER nextjs

EXPOSE 3000

CMD ["npm", "start"]

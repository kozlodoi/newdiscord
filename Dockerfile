# Этап 1: Сборка
FROM node:20-alpine AS builder

RUN apk add --no-cache openssl libc6-compat

WORKDIR /app

# 1. Сначала копируем только файлы манифестов
COPY package*.json ./

# 2. СРАЗУ копируем папку prisma (это исправит ошибку "schema.prisma not found")
COPY prisma ./prisma/

# 3. Устанавливаем зависимости. 
# Мы используем --force, чтобы избежать конфликтов версий, и --ignore-scripts, 
# чтобы Prisma не запускалась раньше времени.
RUN npm install --ignore-scripts

# 4. Теперь, когда всё на месте, генерируем клиент Prisma
RUN npx prisma generate

# 5. Копируем остальной код
COPY . .

# 6. Собираем Next.js проект
RUN npx next build

# Этап 2: Запуск
FROM node:20-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl
ENV NODE_ENV=production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules

USER nextjs

EXPOSE 3000

CMD ["npm", "start"]

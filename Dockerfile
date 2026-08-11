FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache python3

COPY package*.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY scripts ./scripts
COPY public ./public

RUN mkdir -p /data

ENV NODE_ENV=production
ENV PORT=80
ENV DATA_DIR=/data
ENV APP_NAME=chempboard
ENV APP_LABEL=ChempBoard

EXPOSE 80

CMD ["node", "server.js"]

FROM node:18.20.4-alpine3.19

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1

USER node
CMD ["node", "server.js"]

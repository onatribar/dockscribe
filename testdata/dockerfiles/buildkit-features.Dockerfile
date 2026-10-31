FROM --platform=$BUILDPLATFORM node:22-alpine

COPY package.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY . .

RUN <<EOF
apt-get update
apt-get install -y curl
EOF

CMD [
  "node",
  "server.js"
]

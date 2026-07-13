FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY src/ src/
RUN npm run build

FROM gcr.io/distroless/nodejs22-debian12
COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/node_modules ./node_modules
USER 65532:65532
ENTRYPOINT ["node", "/app/dist/index.js"]

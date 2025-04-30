FROM node:22.6.0-alpine3.20

WORKDIR /app

COPY package*.json ./
RUN apk add --no-cache git
# Install dependencies in a deterministic and repeatable way

COPY src ./src
COPY tsconfig.json ./
COPY deploy/config/production.yaml ./deploy/config/production.yaml
COPY deploy/config/conformance.yaml ./deploy/config/conformance.yaml

RUN npm ci
RUN npm run compile
RUN npm prune --omit=dev

ENV NODE_ENV=production
ENV NODE_CONFIG_DIR=/app/deploy/config

EXPOSE 8080


CMD [ "npm", "run", "start:prod" ]
FROM node:16.20.2-alpine3.18

WORKDIR /app

COPY package*.json ./
# Install dependencies in a deterministic and repeatable way
RUN npm ci --only=production

COPY src ./src
COPY tsconfig.json ./
COPY deploy/config/production.yaml ./deploy/config/production.yaml

ENV NODE_ENV=production
ENV NODE_CONFIG_DIR=/app/deploy/config

EXPOSE 8080

CMD [ "npm", "run", "serve" ]
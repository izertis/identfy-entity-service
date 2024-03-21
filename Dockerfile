FROM node:16.20.0-alpine3.18

WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./

RUN npm install --production
RUN npm ci --only=production

COPY src ./src
COPY tsconfig.json ./
COPY deploy/config/production.yaml ./deploy/config/production.yaml

EXPOSE 8080

# #! Needed to generate standalone image
CMD [ "npm run serve" ]
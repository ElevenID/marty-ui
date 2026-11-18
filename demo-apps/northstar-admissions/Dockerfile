FROM node:24.15.0-alpine
WORKDIR /app
COPY package.json ./
COPY public ./public
COPY src ./src
USER node
EXPOSE 4175
CMD ["node", "src/server.mjs"]

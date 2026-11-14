FROM node:22.11.0-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-package-lock && npm cache clean --force
COPY index.js .
CMD ["node","index.js"]

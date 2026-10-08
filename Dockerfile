FROM node:20-slim AS base
WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .
ENV NEXT_PUBLIC_API_BASE=http://localhost:8000

RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]

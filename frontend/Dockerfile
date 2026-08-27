# syntax=docker/dockerfile:1
FROM node:22-alpine AS base
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
EXPOSE 5173
# Dev default (Vite HMR); prod build served by nginx (M5).
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

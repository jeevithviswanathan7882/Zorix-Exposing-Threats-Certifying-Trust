# STAGE 1 - Development
FROM node:22-alpine AS development

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ .

EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]


# STAGE 2 - Build
FROM node:22-alpine AS builder

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ .
RUN npm run build


# STAGE 3 - Production
FROM nginxinc/nginx-unprivileged:1.31.7-alpine@sha256:b5047b9b76845eac124358373c6852377c52e4b05834a47647e955dd91cb8f1e AS production

USER root
RUN apk upgrade --no-cache

COPY --from=builder /app/dist /usr/share/nginx/html
COPY docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080
USER 101
CMD ["nginx", "-g", "daemon off;"]

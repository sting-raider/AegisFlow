FROM node:22.17.1-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --ignore-scripts
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27.5-alpine
ENV NGINX_RESOLVER=127.0.0.11
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/templates/default.conf.template
EXPOSE 8080

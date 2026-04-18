FROM node:20-alpine AS build

WORKDIR /app

# Ensure case-sensitive paths work consistently via Alpine linux and pinned node 20
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Build the app. Environment variables like VITE_API_BASE_URL should be available at build time
RUN npm run build

# Setup NGINX to serve the static assets
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

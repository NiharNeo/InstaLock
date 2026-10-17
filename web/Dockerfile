FROM node:22-alpine AS build
WORKDIR /workspace/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
COPY tools/build-stitch.mjs /workspace/tools/build-stitch.mjs
COPY stitch_intentlock_operator_console/metrics_intentlock/ /workspace/stitch_intentlock_operator_console/metrics_intentlock/
RUN npm run build
FROM nginxinc/nginx-unprivileged:alpine
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/web/dist /usr/share/nginx/html

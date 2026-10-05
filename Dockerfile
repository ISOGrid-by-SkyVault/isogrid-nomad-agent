# syntax=docker/dockerfile:1

# 1. Operator frontend
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# 2. Agent binary with the frontend embedded
FROM golang:1.23-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/nomad-agent ./cmd/nomad-agent

# 3. Runtime
FROM alpine:3.20
# Fixed ids: the installer mounts the key secret readable by this user only.
RUN addgroup -S -g 10001 nomad && adduser -S -u 10001 -G nomad nomad && mkdir -p /var/lib/nomad-agent && chown nomad:nomad /var/lib/nomad-agent
COPY --from=build /out/nomad-agent /usr/local/bin/nomad-agent
USER nomad
VOLUME ["/var/lib/nomad-agent"]
EXPOSE 8460
ENTRYPOINT ["/usr/local/bin/nomad-agent"]
CMD ["run"]

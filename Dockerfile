# ─── Stage 1: Build Astro frontend ────────────────────────────────
FROM docker.1ms.run/node:22-alpine AS frontend-builder

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm config set registry https://registry.npmmirror.com && npm ci

COPY frontend/ .
RUN chmod +x node_modules/.bin/astro 2>/dev/null; true
# 构建时使用空 API_BASE（相对路径，nginx/Caddy 反代或 Go 直接 serve）
ARG PUBLIC_API_BASE=""
ENV PUBLIC_API_BASE=$PUBLIC_API_BASE
RUN npm run build

# ─── Stage 2: Test + Build Go backend ─────────────────────────────
FROM docker.1ms.run/golang:1.21-alpine AS backend-builder

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app
COPY backend/go.mod backend/go.sum* ./
ENV GOPROXY=https://goproxy.cn,direct
COPY backend/ .
RUN go mod tidy
# Gate the image build on the test suite (storage sources, streaming, presign, security)
RUN go test ./...
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags="-s -w" -o xanime-api .

# ─── Stage 3: Runtime (single image) ──────────────────────────────
FROM docker.1ms.run/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk add --no-cache sqlite-libs ca-certificates tzdata

WORKDIR /app

COPY --from=backend-builder /app/xanime-api .
COPY --from=frontend-builder /app/dist ./dist

RUN mkdir -p /app/data /app/videos /app/static && chown -R 1000:1000 /app/data /app/videos /app/static

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD wget -q -O - http://localhost:8080/health || exit 1

USER 1000:1000

ENTRYPOINT ["./xanime-api"]

#!/bin/bash
# run-docker.sh — 模式①: Docker Compose 单机单副本启动
# 用法: bash run-docker.sh (可选: PORT=9090 VIDEO_PATH=/data/videos bash run-docker.sh)
set -euo pipefail

cd "$(dirname "$0")/.."

# 加载 .env
if [ -f .env ]; then
  set -a; source .env; set +a
fi

# 允许命令行覆盖
API_PORT=${API_PORT:-8080}
FRONTEND_PORT=${FRONTEND_PORT:-80}
VIDEO_HOST_PATH=${VIDEO_PATH:-./videos}
STATIC_HOST_PATH=${STATIC_PATH:-./static}

echo "========== Xanime Platform (Docker Compose 单机模式) =========="
echo "  API 端口:       $API_PORT"
echo "  前端端口:       $FRONTEND_PORT"
echo "  视频路径:       $VIDEO_HOST_PATH"
echo "  数据库:         SQLite (本地文件)"
echo "  管理员:         ${ADMIN_USER:-admin} / ${ADMIN_PASS:-admin}"
echo ""

# 确保目录存在
mkdir -p "$VIDEO_HOST_PATH" "$STATIC_HOST_PATH"

# 生成 docker-compose override
cat > docker-compose.override.yml <<YAML
services:
  api:
    ports:
      - "${API_PORT}:8080"
    environment:
      - DB_DRIVER=sqlite3
      - DB_PATH=/app/data/anime.db
      - VIDEO_PATH=/app/videos
      - STATIC_PATH=/app/static
      - ADMIN_USER=${ADMIN_USER:-admin}
      - ADMIN_PASS=${ADMIN_PASS:-admin}
      - JWT_SECRET=${JWT_SECRET:-dev-secret}
      - PORT=8080
      - GIN_MODE=release
    volumes:
      - anime_data:/app/data
      - ${VIDEO_HOST_PATH}:/app/videos
      - ${STATIC_HOST_PATH}:/app/static
# frontend is served by the app container on 8080 (monolith); no separate frontend service
YAML

echo "Building images..."
docker compose build

echo "Starting services..."
docker compose up -d

echo ""
echo "✓ 启动完成!"
echo "  前端: http://localhost:${FRONTEND_PORT}"
echo "  API:  http://localhost:${API_PORT}/health"
echo ""
echo "  停止: docker compose down"
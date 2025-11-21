#!/bin/bash

# 停止并删除容器
echo "停止容器..."
docker compose down

# 删除本地镜像
echo "删除本地镜像..."
docker compose down --rmi local

# 启动服务
echo "启动服务..."
docker compose up -d

echo "重新部署完成！"


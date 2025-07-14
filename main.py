#!/bin/bash

# 有效期检查（30天）
EXPIRY_DAYS=30
BUILD_DATE=$(date -d @$BUILD_TIMESTAMP +%s)
CURRENT_DATE=$(date +%s)
DAYS_PASSED=$(( (CURRENT_DATE - BUILD_DATE) / 86400 ))

if [ $DAYS_PASSED -gt $EXPIRY_DAYS ]; then
    echo "错误：此Docker镜像已过期（构建于 $(date -d @$BUILD_TIMESTAMP)）"
    echo "请重新构建并拉取最新版本镜像"
    exit 1
fi

# 运行加密后的程序
exec python /app/123pan_bot.py
#!/bin/sh

# 获取当前时间戳
CURRENT_TIMESTAMP=$(date +%s)

# 计算时间差（秒）
TIME_DIFF=$((CURRENT_TIMESTAMP - BUILD_TIMESTAMP))

# 转换为天数
DAYS_DIFF=$((TIME_DIFF / 86400))

# 检查是否超过30天
if [ $DAYS_DIFF -gt 30 ]; then
    echo "镜像已过期！请重新构建或拉取新镜像。"
    exit 1
fi

# 启动应用
exec "$@"

# 构建阶段
FROM python:3.12-slim as builder

WORKDIR /app

# 复制源码
COPY 123pan_bot.py .

# 编译为pyc并base64编码
RUN python -c "import py_compile, base64; \
    py_compile.compile('123pan_bot.py'); \
    encoded = base64.b64encode(open('__pycache__/123pan_bot.cpython-312.pyc', 'rb').read()); \
    open('encoded_bot.txt', 'wb').write(encoded)"

# 运行时阶段
FROM python:3.12-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制编码后的程序
COPY --from=builder /app/encoded_bot.txt .
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 设置构建时间戳
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP=$BUILD_TIMESTAMP

# 设置环境变量默认值
ENV DB_PATH=/data/bot123.db
VOLUME /data

# 创建entrypoint.sh（包含有效期检查和执行逻辑）
RUN echo $'#!/bin/bash\n\
# 有效期检查（30天）\n\
EXPIRY_DAYS=30\n\
BUILD_DATE=$(date -d @$BUILD_TIMESTAMP +%s)\n\
CURRENT_DATE=$(date +%s)\n\
DAYS_PASSED=$(( (CURRENT_DATE - BUILD_DATE) / 86400 ))\n\
\n\
if [ $DAYS_PASSED -gt $EXPIRY_DAYS ]; then\n\
    echo "错误：此Docker镜像已过期（构建于 $(date -d @$BUILD_TIMESTAMP)）"\n\
    echo "请重新构建并拉取最新版本镜像"\n\
    exit 1\n\
fi\n\
\n\
# 解码并执行\n\
echo "正在解码并启动程序..."\n\
base64 -d /app/encoded_bot.txt > /app/bot.pyc\n\
exec python /app/bot.pyc\n' > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
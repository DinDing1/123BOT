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

# 创建 entrypoint.sh 使用可靠的方法
RUN echo '#!/bin/sh' > /app/entrypoint.sh && \
    echo '# 有效期检查（30天）' >> /app/entrypoint.sh && \
    echo 'EXPIRY_DAYS=30' >> /app/entrypoint.sh && \
    echo 'BUILD_DATE=$(date -d "@$BUILD_TIMESTAMP" +%s)' >> /app/entrypoint.sh && \
    echo 'CURRENT_DATE=$(date +%s)' >> /app/entrypoint.sh && \
    echo 'DAYS_PASSED=$(( (CURRENT_DATE - BUILD_DATE) / 86400 ))' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo 'if [ "$DAYS_PASSED" -gt "$EXPIRY_DAYS" ]; then' >> /app/entrypoint.sh && \
    echo '    echo "错误：此Docker镜像已过期（构建于 $(date -d "@$BUILD_TIMESTAMP")）"' >> /app/entrypoint.sh && \
    echo '    echo "请重新构建并拉取最新版本镜像"' >> /app/entrypoint.sh && \
    echo '    exit 1' >> /app/entrypoint.sh && \
    echo 'fi' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# 调试信息' >> /app/entrypoint.sh && \
    echo 'echo "===== 环境诊断 ====="' >> /app/entrypoint.sh && \
    echo 'echo "入口点脚本路径: /app/entrypoint.sh"' >> /app/entrypoint.sh && \
    echo 'echo "Python版本: $(python --version)"' >> /app/entrypoint.sh && \
    echo 'echo "当前时间: $(date)"' >> /app/entrypoint.sh && \
    echo 'echo "构建时间: $(date -d "@$BUILD_TIMESTAMP")"' >> /app/entrypoint.sh && \
    echo 'echo "已运行天数: $DAYS_PASSED"' >> /app/entrypoint.sh && \
    echo 'echo "===================="' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# 解码并执行' >> /app/entrypoint.sh && \
    echo 'echo "正在解码并启动程序..."' >> /app/entrypoint.sh && \
    echo 'base64 -d /app/encoded_bot.txt > /app/bot.pyc' >> /app/entrypoint.sh && \
    echo 'exec python /app/bot.pyc' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
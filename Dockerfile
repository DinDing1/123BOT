# 第一阶段：构建依赖和加密
FROM python:3.11-slim as builder

WORKDIR /app

# 安装构建依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libssl-dev \
    build-essential \
    python3-pip

# 安装加密工具和依赖
RUN pip install pyarmor==8.3.8 cryptography==42.0.5
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制源码并加密
COPY . .
RUN pyarmor gen --output dist --recursive --platform linux.x86_64 123pan_bot.py

# 第二阶段：最终镜像
FROM python:3.11-slim

WORKDIR /app

# 从构建阶段复制加密后的程序和依赖
COPY --from=builder /app/dist /app
COPY --from=builder /root/.local /root/.local
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# 设置环境变量和路径
ENV PATH="/root/.local/bin:${PATH}"
ENV PYTHONPATH=/app
ENV DB_PATH="/data/bot123.db"
VOLUME /data

# 设置默认环境变量
ENV TG_BOT_TOKEN=""
ENV PAN_CLIENT_ID=""
ENV PAN_CLIENT_SECRET=""
ENV TG_ADMIN_USER_IDS=""
ENV DEFAULT_SAVE_DIR=""
ENV EXPORT_BASE_DIR=""
ENV SEARCH_MAX_DEPTH=

# 设置入口点
CMD ["python", "123pan_bot.py"]

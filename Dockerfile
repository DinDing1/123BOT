# 构建阶段
FROM python:3.12-slim as builder

# 安装编译依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 安装加密工具
RUN pip install --no-cache-dir pyarmor==8.3.6

WORKDIR /app

# 复制源码和依赖
COPY requirements.txt .
COPY 123pan_bot.py .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 创建最小化的加密配置文件
RUN echo "pyarmor-options: --obfuscate --mix-str --enable-suffix" > .pyarmor_config

# 使用配置文件进行加密
RUN pyarmor gen -C .pyarmor_config -O dist 123pan_bot.py

# 运行时阶段
FROM python:3.12-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制加密后的代码
COPY --from=builder /app/dist /app
COPY requirements.txt .
COPY entrypoint.sh /app/entrypoint.sh

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt \
    && chmod +x /app/entrypoint.sh

# 设置构建时间戳
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP=$BUILD_TIMESTAMP

# 设置环境变量默认值
ENV DB_PATH=/data/bot123.db
VOLUME /data

ENTRYPOINT ["/app/entrypoint.sh"]
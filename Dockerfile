# 使用多阶段构建
FROM python:3.12-slim-bookworm as builder

WORKDIR /app

# 安装构建依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 修改Dockerfile的requirements.txt部分
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt \
    && pip install --user p115client


# 运行阶段
FROM python:3.12-slim-bookworm
WORKDIR /app

# 复制依赖
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH


ENV CONFIG115_PATH=/app/config/115_config.txt \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    LOG_PATH=/app/logs

# 安装运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    curl \
    sqlite3 \
    uuid-runtime \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

    # 创建目录结构
RUN mkdir -p \
    templates \
    EmbyLibrary \
    /app/cache/config \
    /var/log/supervisor \
    /app/config \
    && chmod 777 /app

# 复制代码
COPY . .

# 设置权限
RUN chmod +x /app/auth_check.sh

# 暴露端口
EXPOSE 8123 8124

# 初始化配置
VOLUME /app/cache/config
VOLUME /app/config
VOLUME /app/logs


# 启动命令
ENTRYPOINT ["/app/auth_check.sh"]
CMD ["sh", "-c", \
    "python app.py & \
    uvicorn main:app --host 0.0.0.0 --port 8123 --no-access-log & \
    tail -f /dev/null"]




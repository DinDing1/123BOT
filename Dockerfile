# 使用多阶段构建
# 第一阶段：构建环境
FROM python:3.12-slim-bookworm as builder

WORKDIR /app

# 安装构建依赖（后续会清理）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 先安装 requirements 以利用缓存
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# 第二阶段：运行环境
FROM python:3.12-slim-bookworm

WORKDIR /app

# 只复制必要的运行时依赖
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# 安装运行时系统依赖
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
    && chmod 777 /app

# 复制项目文件（使用 .dockerignore 过滤无关文件）
COPY . .

# 设置权限
RUN chmod +x /app/auth_check.sh

# 暴露端口
EXPOSE 8123 8124

# 环境变量
ENV FLASK_APP=app.py \
    FLASK_ENV=production \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# 入口点
ENTRYPOINT ["/app/auth_check.sh"]
CMD ["sh", "-c", \
    "flask run --host=0.0.0.0 --port=8124 & \
    uvicorn main:app --host 0.0.0.0 --port=8123 --no-access-log & \
    tail -f /dev/null"]

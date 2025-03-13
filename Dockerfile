FROM python:3.12-bookworm

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    openssl \        
    uuid-runtime \    
    gcc \
    python3-dev \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# 创建必要目录结构
RUN mkdir -p \
    /app/templates \
    /app/EmbyLibrary \
    /app/cache \
    /var/log/supervisor

# 复制所有项目文件
COPY requirements.txt .
COPY generate_strm.py .
COPY app.py .
COPY main.py .
COPY auth_check.sh .
COPY templates/index.html ./templates/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 安装Python依赖
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# 设置权限（关键！）
RUN chmod +x /app/auth_check.sh && \
    chmod 777 /app  

# 暴露端口
EXPOSE 8124 8123

# 设置环境变量
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# 强制使用 ENTRYPOINT
ENTRYPOINT ["/app/auth_check.sh"]
CMD ["sh", "-c", \
    "flask run --host=0.0.0.0 --port=8124 & \
    uvicorn main:app --host 0.0.0.0 --port=8123 --no-access-log & \
    tail -f /dev/null"]
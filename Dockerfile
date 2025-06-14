# 使用轻量级Python基础镜像
FROM python:3.10-slim

# 设置工作目录
WORKDIR /app

# 安装必要的系统工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制应用文件和依赖清单
COPY 123pan_bot.py /app/
COPY requirements.txt /app/

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 清理临时文件
RUN apt-get purge -y --auto-remove gcc && \
    rm -rf /var/lib/apt/lists/*

# 设置环境变量默认值
ENV TG_BOT_TOKEN=""
ENV PAN_CLIENT_ID=""
ENV PAN_CLIENT_SECRET=""
ENV TG_ADMIN_USER_IDS=""

# 启动应用
CMD ["python", "123pan_bot.py"]

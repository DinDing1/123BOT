# 使用 Python 3.12 的 slim 版本作为基础镜像，slim 版本更轻量
FROM python:3.12-slim
# 将工作目录设置为 /app
WORKDIR /app

# 安装必要的系统包，确保 Python 和 pip 的正常运行
RUN apt-get update && apt-get install -y --no-install-recommends \
    && apt-get install -y libffi-dev libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 复制 requirements.txt 文件并安装依赖
COPY requirements.txt .
# 安装依赖，--no-cache-dir 用于避免缓存，减少镜像体积
RUN pip install --no-cache-dir -r requirements.txt

# 将 VERSION 文件复制到镜像中
COPY VERSION .

# 复制 Python 脚本并编译为字节码文件
COPY 123pan_bot.py .
RUN python -m py_compile 123pan_bot.py

# 删除源码文件，仅保留字节码文件
RUN rm -f 123pan_bot.py

# 设置环境变量，用于存储构建时间戳
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP=${BUILD_TIMESTAMP}

# 复制 entrypoint 脚本并设置为可执行
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# 设置入口点和命令
ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "-c", "import sys; exec(compile(open('123pan_bot.pyc').read(), '123pan_bot.py', 'exec'))"]

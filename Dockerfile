# 使用 Python 3.12 的 slim 版本作为基础镜像，slim 版本更轻量
FROM python:3.12-slim
# 设置工作目录
WORKDIR /app

# 更新包列表并安装必要的系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    && apt-get install -y libffi-dev libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 复制 requirements.txt 文件并安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 将 VERSION 文件复制到镜像中
COPY VERSION .

# 复制 Python 脚本并编译为字节码文件
COPY 123pan_bot.py .
RUN python -m py_compile 123pan_bot.py

# 删除源码文件，仅保留字节码文件
RUN rm -f 123pan_bot.py

# 将编译后的字节码文件重命名为 123pan_bot.pyc
RUN mv __pycache__/123pan_bot.cpython-312.pyc 123pan_bot.pyc

# 设置环境变量，用于存储构建时间戳
ARG BUILD_TIMESTAMP
ENV BUILD_TIMESTAMP=${BUILD_TIMESTAMP}

# 复制 entrypoint 脚本并设置为可执行
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# 设置入口点和命令
ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "-c", "import marshal; exec(marshal.loads(open('123pan_bot.pyc', 'rb').read()[8:]))"]

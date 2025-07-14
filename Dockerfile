# 使用 Python 3.12 的 slim 版本作为基础镜像，slim 版本更轻量
FROM python:3.12-slim

# 设置工作目录
WORKDIR /app

# 复制 requirements.txt 文件并安装依赖
# 将依赖安装与应用代码分离，利用 Docker 构建缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 将 VERSION 文件复制到镜像中
COPY VERSION .

# 将 Python 脚本编译为字节码文件并复制到镜像中
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

# 设置数据卷
VOLUME /data

# 设置入口点和命令
ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "-c", "import marshal; exec(marshal.loads(open('123pan_bot.pyc', 'rb').read()[8:]))"]

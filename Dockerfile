# 使用官方 Python 基础镜像
FROM python:3.12-slim

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libreadline-dev \
    libffi-dev \
    libsqlite3-dev \
    wget \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=on
ENV PIP_DISABLE_PIP_VERSION_CHECK=on

# 复制项目文件
COPY requirements.txt .
COPY VERSION .
COPY 123pan_bot.py .

# 安装 Python 依赖
RUN pip install --upgrade pip && \
    pip install -r requirements.txt 

# 添加安全检测代码
RUN echo "import sys, os, hashlib" > security.py && \
    echo "def security_check():" >> security.py && \
    echo "    # 检测调试器" >> security.py && \
    echo "    if sys.gettrace() is not None:" >> security.py && \
    echo "        sys.exit('Debugger detected! Exiting for security.')" >> security.py && \
    echo "    # 检测调试环境变量" >> security.py && \
    echo "    if os.environ.get('PYTHON_DEBUG'):" >> security.py && \
    echo "        sys.exit('Debug environment detected! Exiting for security.')" >> security.py && \
    echo "    def verify_license(license_key):" >> security.py && \
    echo "        valid_hashes = [" >> security.py && \
    echo "            'f871cab818025f1f4781483ea21ccf5d',  # BY123_666ZTJ" >> security.py && \
    echo "            '6d30a34ca9ec1bd5308618a24e40d5bf',  # BY123_269VBR" >> security.py && \
    echo "            'ef3b6917603fb32bbb0bffbb9f9336e7',  # BY123_135HDC" >> security.py && \
    echo "            '13546b91d0543ea599969ce501e6278d'   # BY123_690CDF" >> security.py && \   
    echo "            '8d27b87d1e7f3f99fd6f00cbe65fe610',  # BY123_7J3F9K2L" >> security.py && \
    echo "            'dd3dea2a4f89d3b7db9df6b5a38dc44f',  # BY123_R4T6Y8U1" >> security.py && \
    echo "            '9f4b1a191ca427d5109b5690d47b1b69',  # BY123_Q9W2E4R6" >> security.py && \
    echo "            'fc5378de7343df1580a84eb59ef739f3',  # BY123_Z3X5C7V9" >> security.py && \
    echo "        ]" >> security.py && \
    echo "        hash_md5 = hashlib.md5(license_key.encode('utf-8')).hexdigest()" >> security.py && \
    echo "        return hash_md5 in valid_hashes" >> security.py && \
    echo "    license_key = os.getenv('PAN_BOT_LICENSE', '')" >> security.py && \
    echo "    if not license_key:" >> security.py && \
    echo "        sys.exit('❌ 未提供许可证密钥，请设置PAN_BOT_LICENSE环境变量')" >> security.py && \
    echo "    if not verify_license(license_key):" >> security.py && \
    echo "        sys.exit('❌ 许可证密钥无效或已过期')" >> security.py && \
    echo "security_check()" >> security.py

# 将安全检测代码和主脚本合并
RUN cat security.py 123pan_bot.py > protected_bot.py

# 设置容器健康检查（可选）
HEALTHCHECK --interval=5m --timeout=30s \
  CMD curl -f http://localhost:8080/ || exit 1

# 设置数据卷
VOLUME /data

# 设置入口点
ENTRYPOINT ["python", "protected_bot.py"]

#!/bin/bash

# 执行授权检查
./auth_check.sh

# 如果授权失败，auth_check.sh 会退出并返回非零状态码，容器启动终止
# 授权成功后，执行 CMD 中的命令
exec "$@"

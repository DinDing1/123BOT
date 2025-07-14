# main.py
import marshal, sys, os, time, datetime

# 镜像有效期：30 天
BUILD_TIMESTAMP = int(os.getenv("BUILD_TIMESTAMP", "0"))
if BUILD_TIMESTAMP == 0:
    print("BUILD_TIMESTAMP 未设置，跳过有效期检查")
else:
    now = int(time.time())
    if (now - BUILD_TIMESTAMP) > 30 * 86400:
        print("❌ 镜像已过期，请重新拉取")
        sys.exit(1)

# 加载字节码并执行
import importlib.util
spec = importlib.util.spec_from_file_location("bot", "123pan_bot.cpython-312.pyc")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)

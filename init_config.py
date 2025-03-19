import os
import json

def init_files():
    config_path = "/app/cache/config/115_config.json"
    if not os.path.exists(config_path):
        with open(config_path, 'w') as f:
            json.dump({"main": {}, "subs": [], "schedule_time": "08:00"}, f)
        os.chmod(config_path, 0o666)

if __name__ == "__main__":
    init_files()

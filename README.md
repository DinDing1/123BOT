# Media Sync（123bot）

<p align="center">
  <img src="static/img/logo_256.png" width="128" alt="Media Sync Logo" />
</p>

Media Sync 是一个围绕「123 云盘」构建的媒体工作流工具：支持从多网盘/分享链接接收资源、同步元数据、生成 STRM、提供 WebDAV/直链播放，并提供 Web 可视化管理。

## 亮点

- 多来源接入：123/夸克/天翼/115 分享链接与 JSON 秒传统一接入
- 媒体工作流闭环：接收 → 整理 → 同步 → 直链/STRM → Emby 302 播放
- Web 可视化：文件管理、洗版（去重/清理）、迁移中心、订阅追更、配置面板
- 115 生态支持：扫码登录、签到、资源搬运至 123（离线）
- 部署友好：Docker 一键启动，默认端口清晰

## 一图看懂

```mermaid
flowchart LR
  A[分享链接 / JSON 秒传] --> B[保存至 123 目录]
  B --> C[媒体整理（外部工具）]
  C --> D[-sync 同步数据库]
  D --> E[WebDAV / 直链 / STRM]
  E --> F[Emby 302 播放]
```

## 快速开始（Docker）

需要准备：

- Docker Engine 与 Docker Compose（推荐 Compose v2）
- 端口：8122（Web/UI & WebDAV & 直链）、8124（Emby 反代）
- 挂载目录：/app/media、/app/data、/app/logs

### Docker Compose（推荐）

```yaml
version: '3.9'
services:
  123bot:
    privileged: true
    container_name: 123bot
    image: dinding1/123bot:latest
    restart: always
    network_mode: bridge
    ports:
      - "8122:8122"
      - "8124:8124"
    environment:
      - TZ=Asia/Shanghai
      - PYTHONUNBUFFERED=1
      - PYTHONDONTWRITEBYTECODE=1
    volumes:
      - /path/to/media:/app/media
      - /path/to/data:/app/data
      - /path/to/logs:/app/logs
      - /var/run/docker.sock:/var/run/docker.sock
```

`/var/run/docker.sock` 用于支持 `-restart` 指令，仅建议在受控环境启用，不需要可移除。

### Docker Run（快速体验）

```bash
docker run -d \
  --name 123bot \
  --privileged \
  -p 8122:8122 -p 8124:8124 \
  -e TZ=Asia/Shanghai \
  -e PYTHONUNBUFFERED=1 \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v /path/to/media:/app/media \
  -v /path/to/data:/app/data \
  -v /path/to/logs:/app/logs \
  -v /var/run/docker.sock:/var/run/docker.sock \
  dinding1/123bot:latest
```

## 初次配置（2 分钟）

1. 打开 Web：`http://服务器IP:8122/`
2. 进入“系统设置”，填写 Telegram 管理员 ID，并配置云盘/代理/Emby
3. 如需 115 功能，在页面进行“115 扫码登录”
4. 保存配置并刷新页面

TG API 申请地址：https://my.telegram.org（获取 api_id / api_hash）

## 常用能力

### 接收资源

- 发送 123/夸克/天翼/115 分享链接或 JSON 秒传文件，资源会保存到 123 云盘配置的保存目录

### 媒体同步与播放

- `-sync`：同步 123 云盘资源信息到数据库
- `-strm` / `-strm115`：生成 STRM 到本地媒体目录
- WebDAV：`http://服务器IP:8122/dav`
- 直链：
  - 123：`http://服务器IP:8122/d123`
  - 115：`http://服务器IP:8122/d115`
- Emby 反代：监听 `8124`，支持 302 播放（需在 Web 配置）

## 指令速查

| 指令 | 说明 |
|---|---|
| `-start` | 系统信息 |
| `-sync` | 云盘同步（将 123 视频信息同步至数据库） |
| `-strm` | 生成 123 云盘 STRM 到本地 |
| `-strm115` | 生成 115 云盘 STRM 到本地 |
| `-sub` | 下载字幕文件到本地 |
| `-by115` | 115 资源搬运至 123（离线下载） |
| `-115签到` | 115 网盘签到与查询 |
| `-export` | 导出秒传 JSON 文件 |
| `-export2` | 导出秒传 JSON 链接 |
| `-db迁移` | PostgreSQL 迁移到 DB（仅媒体信息） |
| `-sql迁移` | DB 迁移到 PostgreSQL（仅媒体信息） |
| `-id` | 查询群组/频道 ID |
| `-de` | 删除历史消息 |
| `-restart` | 重启机器人（需挂载 Docker Socket） |

## 端口与路径

| 项目 | 默认值 |
|---|---|
| Web/UI | `8122` |
| WebDAV | `/dav` |
| 123 直链 | `/d123` |
| 115 直链 | `/d115` |
| Emby 反代 | `8124` |

## 部署自检

- 访问 `http://服务器IP:8122/` 可打开页面
- Web“系统设置”保存配置有成功提示
- 发送 `-start` 能返回系统信息
- WebDAV 可被客户端挂载（如 rclone / Finder）

## 日志与排障

```bash
docker logs -f 123bot
```

- 115 登录异常：检查 Cookie 是否有效，必要时重新扫码登录
- 端口冲突：调整映射端口，确保未被占用
- 权限问题：宿主目录需读写权限，NAS 请确认共享权限

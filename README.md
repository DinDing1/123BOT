# Media Sync 部署与使用说明

## 目录
1. [环境准备](#1-环境准备)
2. [安装步骤](#2-安装步骤)
3. [配置说明](#3-配置说明)
4. [运行指南](#4-运行指南)
5. [正确使用方法](#5-正确使用方法)
6. [使用流程](#6-使用流程)
7. [指令介绍](#7-指令介绍)
8. [端口说明](#8-端口说明)
9. [部署验证](#9-部署验证)
10. [其他功能](#10-其他功能)
11. [调试与日志](#11-调试与日志)
12. [常见问题](#12-常见问题)

---

## 1. 环境准备

*   Docker Engine 与 Docker Compose（推荐 Compose v2，支持 `version: "3.9"`）
*   支持的系统：Linux（x86_64/arm64），Windows（WSL2），NAS（Synology/Unraid）
*   开放端口：`8122`（Web/UI & WebDAV & 直链）、`8124`（Emby反代）
*   准备宿主目录：`/app/media`、`/app/data`、`/app/logs` 对应的挂载路径
*   容器需访问 `/var/run/docker.sock` 以支持 `-restart` 指令（仅在受控环境中使用）

> ⚠️ **注意**：在生产环境中启用 Docker Socket 挂载需评估安全风险；如不需要远程重启功能，可移除该挂载。

## 2. 安装步骤

### 方式 A：Docker Compose（推荐）

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

### 方式 B：Docker Run（快速体验）

```bash
$ docker run -d \
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

> ✅ **完成**：容器启动后，服务默认监听 `8122`/`8124` 端口。

## 3. 配置说明

*   **管理员账号（Admin User IDs）**：在 Web“系统设置”中填写 Telegram 用户 ID
*   **云盘设置**：配置 123 云盘、夸克以及需要的 Emby 反代
*   **115 网盘**：在页面中使用“115扫码登录”完成授权
*   **代理设置**：如需通过代理访问 Telethon，可在“代理配置”中填写
*   **WebDAV**：默认路径 `/dav`（示例：`http://服务器IP:8122/dav`）

> TG API 申请地址：[https://my.telegram.org](https://my.telegram.org)（获取 `api_id` / `api_hash`）。

## 4. 运行指南

1.  访问 Web：`http://服务器IP:8122/`
2.  进入“系统设置”，配置管理员与云盘/代理参数
3.  如需使用 115 功能，打开“115扫码登录”完成授权
4.  保存全部配置并刷新页面

## 5. 正确使用方法

1.  发送 123 云盘链接、天翼云盘链接、夸克云盘链接或 JSON 秒传文件，资源将保存 123 云盘配置中的保存目录。
2.  使用 MP、Filmix 等整理工具对保存目录的视频进行分类，如：`电视剧/国产剧/琅琊榜(2025)[tmdb=12345]`，建议加上 `tmdb` 便于 Emby 识别。
3.  分类整理好的视频会进入设定好的媒体库目录，随后发送 `-sync` 执行媒体库同步，将 123 云盘的资源信息同步到数据库。
4.  同步完成后，可以删除 123 云盘中的视频文件，不影响播放（播放依赖数据库中记录与直链/STRM）。
5.  Web 页面“文件管理”会显示与 123 云盘一致的目录结构；也可通过 WebDAV 直接挂载观看：`http://IP:8122/dav`。
6.  如使用 Emby 播放，在“Emby 反代”表单中配置好 Emby 参数以启用 302 播放，然后通过 `-strm` 生成 STRM 文件供 Emby 使用。

## 6. 使用流程

> 秒传接收视频 → 借助工具整理视频 → 同步视频 → 删除视频 → 生成 STRM（或 WebDAV 挂载） → Emby 302 播放

## 7. 指令介绍

*   `-start` 系统信息
*   `-sync` 云盘同步（将 123 视频信息同步至数据库）
*   `-strm` 生成 123云盘STRM 到本地
*   `-strm115` 生成 115云盘STRM 到本地
*   `-sub` 下载字幕文件到本地
*   `-by115` 115 资源搬运至 123（离线下载）
*   `-115签到` 115 网盘每日签到
*   `-export` 导出秒传 JSON 文件
*   `-export2` 导出秒传JSON链接
*   `-db迁移` PostgreSQL迁移到SQLite（仅媒体信息）
*   `-sql迁移` SQLite迁移到PostgreSQL（仅媒体信息）
*   `-id` 查询群组 频道ID
*   `-de` 删除历史消息
*   `-restart` 重启机器人（需挂载 Docker Socket）

> **支持**：JSON 秒传文件、123 云盘链接、夸克、天翼链接秒传至 123（需资源已存在于 123）。

## 8. 端口说明

*   Web/UI：`8122`
*   WebDAV：`http://localhost:8122/dav`
*   123云盘直链服务：`http://localhost:8122/d123`
*   115云盘直链服务：`http://localhost:8122/d115`
*   Emby 反代：`8124`

## 9. 部署验证

*   访问 `http://服务器IP:8122/` 能正常打开页面 ✅
*   在“系统设置”保存配置后出现成功提示 ✅
*   发送 `-start` 指令能返回系统信息 ✅
*   WebDAV 能被客户端（如 `rclone` 或 Finder）挂载 ✅

## 10. 其他功能

*   115 云盘每日自动签到
*   115 云盘指定目录视频离线下载到 123 云盘
*   订阅追更：设置监控频道/群组自动保存视频，或订阅指定 123 云盘分享链接，定时自动追更
*   洗版管理：视频均存储于数据库，支持通过文件名规则进行重复项筛选与清理

## 11. 调试与日志

**容器日志**：
```bash
$ docker logs -f 123bot
```

**持久化日志目录（宿主机挂载）**：`/app/logs`

*   **115 登录异常**：检查 Cookie 是否有效；必要时重新扫码登录
*   **端口冲突**：调整映射端口，确保未被占用
*   **权限问题**：宿主目录需读写权限；NAS 请确认共享权限

## 12. 常见问题

*   **未收到“重启完成”提示**：检查 `ADMIN_USER_IDS`、Telethon 登录状态，以及是否挂载 `/var/run/docker.sock`
*   **无法重启**：确认容器进程具备访问 Docker Socket 的权限
*   **更新镜像**：在 Web“版本信息”中可跳转至镜像标签页面进行更新
*   **版本兼容性**：镜像适配 Docker Compose v2；旧版 Compose 可能行为差异

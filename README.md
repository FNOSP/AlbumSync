# AlbumSync · 相册同步

[![Version](https://img.shields.io/badge/version-0.2.5-blue)](https://github.com/fried-avocado/AlbumSync/releases/latest)
[![Platform](https://img.shields.io/badge/platform-fnOS%20x86-green)](#系统要求)
[![Python](https://img.shields.io/badge/python-3.11+-yellow)](#系统要求)
[![Upstream](https://img.shields.io/badge/engine-hwcloudpd-orange)](https://github.com/tuber0613/hwcloudpd)

飞牛 fnOS 原生应用：把华为云空间相册自动备份到 NAS。支持多账号、多 NAS 用户隔离、Web 管理界面，同步引擎为上游开源项目 [hwcloudpd](https://github.com/tuber0613/hwcloudpd)，纯 Python 标准库实现、零第三方依赖。

## 功能特性

### 多账号
- 同一平台可添加多个华为账号，各自独立管理相册选择、存储目录、调度计划与登录态，账号间完全隔离、互不干扰
- 分步向导式创建账号：凭据 → 相册选择 → 存储与计划
- 配置保存按账号热生效，无需重启服务

### 两种登录方式（华为云空间）
- **cURL 会话导入**（免密码）：从已登录浏览器复制 cURL 命令导入会话
- **账号密码登录**：短信/邮箱二次验证码在网页提交；信任设备后静默重登，无需每次 2FA

### 同步能力
- 按相册 / 文件类型 / 时间范围过滤，增量下载（跳过已存在文件）
- 目录结构模板：按相册名、拍摄日期等自定义落盘目录
- 删除镜像策略：云端删除后本地同步删除（可关闭）
- 并发与限速控制，避免占满带宽
- cron 定时同步 + 手动立即同步
- dry-run 预览：只扫描不下载，确认后再执行
- Webhook 通知：同步完成/失败推送

### 多 NAS 用户隔离（0.2.5+）
- 普通用户可从 fnOS 桌面访问应用，复用 fnOS 网关登录身份，零登录页
- 账号归属隔离：普通用户仅可见并仅能操作**自己创建的账号**，越权访问一律 404（不泄露存在性）
- 管理员（或直连服务端口）可见全部账号，并可改派账号归属
- 身份头由 fnOS 网关注入并防伪造（外部伪造头在网关层被剥离覆盖）

### Web 管理界面
- 账号管理 / 状态总览 / 全局设置 / 单账号工作区（日志、试运行、单账号同步）
- cron 可视化构造器：标签页 + 预设 + 实时预览
- 存储目录：授权目录探测下拉 + 手输路径实时探测徽章 + 保存预检
- 界面右上角显示当前身份徽章（管理员·用户名 / 普通用户 / 直连本机管理）

## 系统要求

| 项目 | 要求 |
|---|---|
| 系统 | 飞牛 fnOS ≥ 1.1.8（x86） |
| Python | fnOS 应用中心「python 3.11」依赖包（应用自动探测 3.11/3.12/3.13） |
| 网络 | 可访问华为云空间（`*.huawei.com`） |

## 安装

### 方式一：应用中心（推荐社区用户）
1. 从 [Releases](https://github.com/fried-avocado/AlbumSync/releases/latest) 下载 `AlbumSync.fpk`
2. fnOS 桌面 → 应用中心 → 右上角「手动安装」→ 选择 fpk 文件
3. 安装完成，从桌面打开「相册同步」

### 方式二：命令行
```bash
sudo appcenter-cli install-fpk /tmp/AlbumSync.fpk -v 1
```

### 升级
应用中心手动安装新版 fpk 即可；命令行升级需**先卸载再安装**（`install-fpk` 对已安装应用会静默跳过）：
```bash
sudo appcenter-cli uninstall AlbumSync      # 卸载保留数据
sudo appcenter-cli install-fpk /tmp/AlbumSync.fpk -v 1
sudo appcenter-cli start AlbumSync
```

## 快速上手

1. 打开应用 → 「新建账号」进入向导
2. 选择凭据方式：
   - **cURL 导入**：浏览器登录云空间 → 任意请求「以 cURL 复制」→ 粘贴导入（免密码，推荐）
   - **账号密码**：输入华为账号密码，触发二次验证时在页面提交短信/邮箱验证码
3. 选择要备份的相册（可全选）
4. 选择存储目录（推荐存到 fnOS 共享目录，便于其他应用读取；应用默认目录为数据目录下 `photos/`）
5. 设置同步计划（cron）→ 完成，等待计划触发或点击「立即同步」
6. 建议在 系统设置 → 应用 → 相册同步 → 应用设置 → 访问权限 中授予照片存储目录读写权限

## 访问方式

| 路径 | 地址 | 身份 |
|---|---|---|
| fnOS 网关 | `http://<NAS>:5666/app/AlbumSync/` | 当前登录的 fnOS 用户（推荐） |
| 直连端口 | `http://<NAS>:9801/` | 视为本机管理（全部权限） |

经网关访问时，普通用户只能看到自己的账号；直连端口视为本机管理信任域（与 fnOS 官方「端口直连不受桌面权限限制」的生态行为一致）。

## 目录与数据

| 路径 | 内容 |
|---|---|
| `/vol1/@appdata/AlbumSync/` | 应用数据：config.json、登录凭据、同步状态库、日志、默认照片目录 |
| 照片目录 | 可在界面中改为任意包用户可写的绝对路径（如共享目录） |

- 共享目录授权经 系统设置 → 应用 → 相册同步 → 访问权限 管理，运行中授权即时生效
- 卸载应用默认**保留**全部数据（凭据/配置/照片/日志）；卸载向导勾选「删除数据」才清空应用数据目录；共享目录中的照片任何方式都不会被删除

## 架构

```
AlbumSync/
├── manifest                # 应用清单
├── cmd/                    # 生命周期脚本（main/install/uninstall/upgrade…）
├── config/
│   ├── privilege           # 权限声明
│   └── resource            # 端口 9801 + Unix socket app.sock + 共享目录声明
├── app/
│   ├── server/             # Web 服务壳 + 调度 + 身份层 + Provider 抽象
│   │   ├── server.py       #   双监听 HTTP 服务（TCP + 网关 Unix socket）
│   │   ├── app_runtime.py  #   运行时：账号/配置/调度/引擎托管
│   │   ├── identity.py     #   网关身份头解析（X-Trim-Userid/Username/Isadmin）
│   │   ├── scheduler.py    #   可见性核心与账号级调度
│   │   ├── providers/      #   平台抽象层（AuthStrategy + Provider capabilities）
│   │   └── hwcloudpd/      #   vendored 同步引擎（由 tools/sync_engine.py 生成）
│   └── ui/                 # Web 管理界面（纯静态，无构建依赖）
├── patches/                # 上游引擎修复补丁（vendor 时自动应用）
├── tests/                  # 单元测试（unittest，91 项）
└── tools/                  # fnpack 打包工具 + 引擎 vendor 脚本
```

- 服务同时监听 TCP 端口（健康检查/直连）与 Unix socket（fnOS 网关经 nginx 代理）
- 引擎以「vendored 副本 + patches」方式管理：上游仓库保持只读，`tools/sync_engine.py` 复制源码并按序应用补丁，保证可复现构建

## 开发与构建

```powershell
# 打包（cwd = 应用根目录）
.\tools\fnpack.exe build -d .          # 产出 AlbumSync.fpk

# 单元测试（WSL）
wsl sh -c "cd /mnt/e/workspace/fn/hwcloudpd/hwcloudpd-fnos && PYTHONPATH=app/server python3 -m unittest discover -s tests"
```

部署验证（Windows → NAS，经 WSL sshpass 上传 fpk + 两段式部署脚本）：

```bash
wsl sh -c "sshpass -p <密码> scp /mnt/e/.../AlbumSync.fpk <用户>@<NAS_IP>:/tmp/ && sshpass -p <密码> ssh <用户>@<NAS_IP> 'sudo appcenter-cli uninstall AlbumSync && sudo appcenter-cli install-fpk /tmp/AlbumSync.fpk -v 1 && sudo appcenter-cli start AlbumSync'"
```

部署后验证：
```bash
curl -s http://127.0.0.1:9801/api/status      # 直连健康检查
curl -s http://<NAS>:5666/app/AlbumSync/      # 网关访问
```

更多平台机制（网关身份注入、目录授权模型、桌面入口可见性落地）：fnOS 网关经内部 CGI 鉴权后向应用注入 `X-Trim-Userid` / `X-Trim-Username` / `X-Trim-Isadmin` 请求头（外部伪造的同名头会被剥离覆盖）；应用目录授权落地为内核 trim_acl xattr，运行中授权即时生效。

## 常见问题

- **升级后版本没变？** `install-fpk` 对已装应用静默跳过，必须先 uninstall（保留数据）再 install。
- **`appcenter-cli start` 报 error 10500？** install 后应用已自动启动导致 start 冲突，用 `appcenter-cli list` + `curl` 确认实际状态即可。
- **普通用户打开应用提示 Forbidden？** 入口可见性由 `app/ui/config` 的 `allUsers` 控制，修改后需重新安装才能生效。
- **直连端口安全吗？** 直连即管理权限，请勿将 9801 端口暴露到公网；日常使用建议走网关路径以获得按用户隔离。

## 版本历史

见 [Releases](https://github.com/fried-avocado/AlbumSync/releases)。

- **v0.2.5** 多 NAS 用户隔离（allUsers + 网关身份头直信 + owner 归属过滤）
- **v0.2.4** Provider 抽象重构（平台抽象层，华为实现迁移，行为不变）
- **v0.2.0–0.2.3** 多账号支持（多华为账号并存 + 向导创建 + 缺陷修复批次）
- **v0.1.x** 首版：单账号同步全流程、Web 界面、cron 构造器、存储目录探测、真机验证

## 致谢

- 同步引擎：[hwcloudpd](https://github.com/tuber0613/hwcloudpd)（纯 Python 标准库实现华为云空间相册下载）
- 平台参照：飞牛 fnOS 官方应用（trim.photos 的入口与隔离模式）

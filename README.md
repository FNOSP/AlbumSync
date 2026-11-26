# AlbumSync · 相册同步

[![Version](https://img.shields.io/badge/version-0.3.30-blue)](https://github.com/fried-avocado/AlbumSync/releases/latest)
[![Platform](https://img.shields.io/badge/platform-fnOS%20x86-green)](#系统要求)
[![Python](https://img.shields.io/badge/python-3.11+-yellow)](#系统要求)
[![Upstream](https://img.shields.io/badge/engine-hwcloudpd-orange)](https://github.com/tuber0613/hwcloudpd)

飞牛 fnOS 原生应用：把 **华为云空间 / 小米云相册 / iCloud 相册** 自动备份到 NAS。支持多平台多账号、多 NAS 用户隔离、Web 管理界面。同步引擎基于上游开源项目 [hwcloudpd](https://github.com/tuber0613/hwcloudpd)（vendored 管理），全部依赖随包内置（纯 Python，无需 pip 安装）。

## 功能特性

### 多平台多账号
- 支持三个平台：**华为云空间 / 小米云相册 / iCloud 相册**，同一平台可添加多个账号，跨平台账号并存
- 每个账号独立管理登录态、相册选择、存储目录与调度计划，账号间完全隔离、互不干扰
- 分步向导式创建账号：凭据 → 相册选择 → 存储与计划；配置保存按账号热生效，无需重启服务

### 登录方式（按平台）

**华为云空间**
- **cURL 会话导入**（免密码）：从已登录浏览器复制 cURL 命令导入会话
- **账号密码登录**：短信/邮箱二次验证码在网页提交；信任设备后静默重登，无需每次 2FA

**小米云相册（i.mi.com）**
- **扫码登录**：小米手机「扫一扫」授权，无需手动复制 cookie（受风控限制会话约 15–35 分钟，适合临时批次同步）
- **账号密码登录**：输入账号密码直登；自动处理图形验证码与短信/邮箱二次验证，`trust=true` 信任设备后签发**长效 passToken**——与浏览器信任设备登录等价
- **长效票据导入**：从浏览器 DevTools 复制 account 域 passToken 导入（双次换发校验拒绝一次性扫码票）
- **免扫码模式**：登录/导入后 daemon 每 15 分钟自动静默续期，401 自动恢复，长期不掉线；失败 30 分钟冷却防风控升级；固定 deviceId（仿真机格式）降低风控概率
- cURL/cookie 导入兜底

**iCloud 相册**
- **Apple ID 密码登录**：支持双重认证（2FA，自动推送验证码/短信回退）与两步验证（2SA）
- **可信会话恢复**：会话与 cookie 持久化，掉线自动重登；支持国际区（com）与中国区（cn）

### 同步能力
- 按相册 / 文件类型 / 时间范围过滤，增量下载（跳过已存在文件）
- 目录结构模板：按相册名、拍摄日期等自定义落盘目录
- 删除镜像策略：云端删除后本地同步删除（可关闭）
- 并发与限速控制，避免占满带宽
- 断点续传：下载中断以 `.aspart` 分片续传，应用重启不丢进度
- 认证自愈：长效票据自动续期 + 请求级 401 兜底（续签后同轮重试），长扫描不掉线
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
- 凭据备份：整包口令加密导出/导入（`.asbak`），支持先预览再合并/替换
- 界面右上角显示当前身份徽章（管理员·用户名 / 普通用户 / 直连本机管理）

## 系统要求

| 项目 | 要求 |
|---|---|
| 系统 | 飞牛 fnOS ≥ 1.1.8（x86） |
| Python | fnOS 应用中心「python 3.11」依赖包（应用自动探测 3.11/3.12/3.13） |
| 网络 | 可访问对应平台：华为云空间（`*.huawei.com`）、小米云相册（`i.mi.com` / `account.xiaomi.com`）、iCloud（`icloud.com`） |

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
| fnOS 网关 | `http://<NAS>:5666/app/AlbumSync/` | 当前登录的 fnOS 用户 |

应用不监听任何 TCP 端口，全部流量经 fnOS 网关（nginx → Unix socket）代理并注入登录身份；经网关访问时，普通用户只能看到自己的账号。

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
│   └── resource            # Unix socket app.sock + 共享目录声明（无端口）
├── app/
│   ├── server/             # Web 服务壳 + 调度 + 身份层 + Provider 抽象
│   │   ├── server.py       #   HTTP 服务（部署：仅网关 Unix socket；本地开发：仅 TCP）
│   │   ├── app_runtime.py  #   运行时：账号/配置/调度/引擎托管
│   │   ├── identity.py     #   网关身份头解析（X-Trim-Userid/Username/Isadmin）
│   │   ├── scheduler.py    #   可见性核心与账号级调度
│   │   ├── providers/      #   平台抽象层（华为/小米/iCloud：AuthStrategy + Provider capabilities）
│   │   │   └── xiaomi/     #   小米登录链路（扫码 / cURL / 长效票据 / 账号密码登录）
│   │   └── hwcloudpd/      #   vendored 同步引擎（由 tools/sync_engine.py 生成）
│   └── ui/                 # Web 管理界面（纯静态，无构建依赖）
├── patches/                # 上游引擎修复补丁（vendor 时自动应用）
├── tests/                  # 单元测试（unittest/pytest，272 项）
└── tools/                  # fnpack 打包工具 + 引擎 vendor 脚本 + fpk 构建脚本
```

- 服务不监听 TCP 端口，仅监听 Unix socket（fnOS 网关经 nginx 代理；本地开发模式除外）
- 引擎以「vendored 副本 + patches」方式管理：上游仓库保持只读，`tools/sync_engine.py` 复制源码并按序应用补丁，保证可复现构建

## 开发与构建

### 从源码打包

**前置要求**：Windows 环境 + Python ≥ 3.11（构建脚本会做 iCloud vendor 导入检查）；
打包工具 `tools/fnpack.exe` 为 Windows 程序，**不要在 WSL 内执行构建**（路径映射失败会产出陈旧包）。

```powershell
# cwd = 应用根目录（hwcloudpd-fnos/）
python tools\build_fpk.py               # 推荐：行尾清理 → fnpack 打包 → fpk 布局校验，产出 AlbumSync.fpk
.\tools\fnpack.exe build -d .           # 仅打包（跳过构建前检查，不推荐）
```

构建产物为应用根目录下的 `AlbumSync.fpk`。构建后建议核对包内 manifest 版本与源码一致（脚本校验布局，不校验版本号）。

### 单元测试

```bash
# WSL（272 项，含小米登录链路/长效续期/iCloud 心跳 mock 测试）
cd hwcloudpd-fnos && PYTHONPATH=app/server python3 -m pytest tests -q
```

### 部署到 NAS（Windows → fnOS，经 WSL sshpass）

```bash
wsl sh -c "sshpass -p <密码> scp /mnt/e/.../AlbumSync.fpk <用户>@<NAS_IP>:/tmp/ && sshpass -p <密码> ssh <用户>@<NAS_IP> 'sudo appcenter-cli uninstall AlbumSync && sudo appcenter-cli install-fpk /tmp/AlbumSync.fpk -v 1 && sudo appcenter-cli start AlbumSync'"
```

部署后验证：
```bash
# NAS 本机经网关健康检查（应用无端口，socket 仅本机可达）
curl -s http://127.0.0.1:5666/app/AlbumSync/api/status
curl -s http://<NAS>:5666/app/AlbumSync/      # 网关访问
```

更多平台机制（网关身份注入、目录授权模型、桌面入口可见性落地）：fnOS 网关经内部 CGI 鉴权后向应用注入 `X-Trim-Userid` / `X-Trim-Username` / `X-Trim-Isadmin` 请求头（外部伪造的同名头会被剥离覆盖）；应用目录授权落地为内核 trim_acl xattr，运行中授权即时生效。

## 常见问题

- **升级后版本没变？** `install-fpk` 对已装应用静默跳过，必须先 uninstall（保留数据）再 install。
- **`appcenter-cli start` 报 error 10500？** install 后应用已自动启动导致 start 冲突，用 `appcenter-cli list` + `curl` 确认实际状态即可。
- **普通用户打开应用提示 Forbidden？** 入口可见性由 `app/ui/config` 的 `allUsers` 控制，修改后需重新安装才能生效。
- **为什么没有端口直连？** 0.3.36 起应用去端口化（测试环境安全策略），仅经 fnOS 网关代理，登录身份由网关注入并按用户隔离；NAS 本机可用 `curl --unix-socket /var/apps/AlbumSync/app.sock http://localhost/api/status` 直连诊断。

## 版本历史

见 [Releases](https://github.com/fried-avocado/AlbumSync/releases)。

- **v0.2.5** 多 NAS 用户隔离（allUsers + 网关身份头直信 + owner 归属过滤）
- **v0.2.4** Provider 抽象重构（平台抽象层，华为实现迁移，行为不变）
- **v0.2.0–0.2.3** 多账号支持（多华为账号并存 + 向导创建 + 缺陷修复批次）
- **v0.1.x** 首版：单账号同步全流程、Web 界面、cron 构造器、存储目录探测、真机验证

## 开源引用与致谢

本项目在以下部分直接引用或参考了开源项目（各项目许可以其上游仓库为准）：

| 开源项目 | 引用 / 参考方式 |
|---|---|
| [hwcloudpd](https://github.com/tuber0613/hwcloudpd) | **同步引擎（直接引用）**：`app/server/hwcloudpd/` 整目录 vendored，由 `tools/sync_engine.py` 从上游复制并应用 `patches/0001-0008` 修复补丁 |
| [icloud_photos_downloader (icloudpd)](https://github.com/icloud-photos-downloader/icloud_photos_downloader) | **iCloud 协议（直接引用）**：`providers/icloud/vendor/` 随包内置 `pyicloud_ipd` 及其纯 Python 依赖（foundation 等），登录/2FA/下载均走该库 |
| [AlexxIT/XiaomiGateway3](https://github.com/AlexxIT/XiaomiGateway3) | **小米账号密码登录（协议参考）**：`providers/xiaomi/password_login.py` 按其 `core/xiaomi_cloud.py` 实现移植 serviceLoginAuth2 + 图形验证码 + identity 2FA 流程（`sid=i.mi.com`），详见 `docs/xiaomi-cloud-api-research.md` §8.5 |
| [Coooolfan/XiaomiAlbumSyncer](https://github.com/Coooolfan/XiaomiAlbumSyncer) | **小米登录方案调研对照**：其登录调研文档提供了 trust=true（信任设备）与固定 deviceId 等关键技巧 |
| [sucjs/mi-note-for-pi](https://github.com/sucjs/mi-note-for-pi) | **续期端点辨析参考**：serviceLogin 交互式端点与浏览器主路径（`api/user/login` 重定向链）的区别、反风控三原则（只重试一次/并发去重/网络故障不判失效） |
| [lyj0309/xiaomi-cloud](https://github.com/lyj0309/xiaomi-cloud)、[al-one/hass-xiaomi-miot](https://github.com/al-one/hass-xiaomi-miot) | **identity 2FA 端点适配参考**（fe/service/identity/authStart 新版 URL 等） |
| [LastDisciple/FreePower](https://github.com/LastDisciple/FreePower) | **fnOS 应用包模型参照**：manifest/cmd/config 目录结构与 fpk 打包流程 |
| 飞牛 fnOS 官方应用（trim.photos） | 平台行为参照：网关身份注入、桌面入口与多用户隔离模式 |

小米登录链路的完整协议调研（含上述项目的对照分析）见仓库内 `docs/xiaomi-cloud-api-research.md`。

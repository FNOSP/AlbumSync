# 小米云相册 Web API 调研报告（T26）

> 调研日期：2026-11-18 · 方式：真实浏览器登录 + WSL Python 纯标准库（urllib）独立复现验证
> 结论先行：**import_session（cookie 导入）路线完全成立**；全部核心接口零第三方依赖可复现，T27 可按原计划实施。
> 本文不含任何账号凭据、密码或 token 值。

## 1. 登录入口与登录态模型

- 登录入口：`https://i.mi.com/gallery/h5#/` 未登录时 302 → `https://account.xiaomi.com/fe/service/login/password?sid=i.mi.com&...`（统一密码登录页，另有扫码登录 / 手机号验证码登录）。
- 登录流程：账号密码 + 勾选协议 →（可选「同意并继续」二次确认弹窗）→ 跳转 i.mi.com sts 回调 → 种下会话 cookie → 进入图库。
- 风控实测（两次登录对比）：
  - **首次登录（新上下文）**：静默通过，无任何验证。
  - **登出后重登**：触发**短信验证码**（安全手机），页面提供「这是我的私人设备，以后登录无需输入口令」信任设备选项，勾选后下次登录可静默（`i.mi.com_istrudev=true`）。
  - **结论**：密码直登在冷启动/登出场景大概率触发短信验证，无法全自动；**import_session（cookie 导入）是唯一稳妥的自动化路线**。若用户在常用设备上勾选过信任设备，密码直登可静默，但依赖账号侧风控状态，不可依赖。

### 会话 cookie（i.mi.com 域，document.cookie 全部可读——均非 httpOnly）

| Cookie | 作用 |
|---|---|
| `userId` | 数字用户 ID（如 `196519672` 形态） |
| `serviceToken` | 核心会话凭证（长 base64 串），全部 API 鉴权仅靠它 |
| `i.mi.com_isvalid_servicetoken` | serviceToken 有效性标志 |
| `i.mi.com_istrudev` | 信任设备标志 |
| `i.mi.com_slh` / `i.mi.com_ph` | 辅助校验值 |
| `mstuid` / `xmuuid` / `xm_user_bucket` / `uLocale` / `iplocale` | 统计/环境字段，非必需 |

- **有效期**：serviceToken 长效（web 端静默续期），具体 TTL 未从 Set-Cookie 捕获；工程上建议以「接口探活失败 → 重新导入/重登」处理，不做本地续期。
- localStorage/sessionStorage 仅统计用（onetrack），无业务 token。
- account.xiaomi.com 域另有登录中间 cookie，调 i.mi.com API 用不到。

## 2. 接口清单（全部 GET 鉴权仅凭 Cookie；`ts` 为当前毫秒时间戳，非签名）

### 2.1 相册列表

```
GET https://i.mi.com/gallery/user/album/list?ts={ms}&pageNum=0&pageSize=20&isShared=false&numOfThumbnails=1
```

响应骨架（实测）：

```json
{"result":"ok","retriable":false,"code":0,"description":"成功","ts":...,
 "data":{"albums":[{"albumId":"1","mediaCount":1610,"userId":196519672,
   "lastUpdateTime":1601089129000,
   "thumbnails":[{"orientation":3,"url":"https://.../get_thumbnail?data=..."}]},
   ...],
  "isLastPage":true,"indexHash":-358378455}}
```

- **相册名称不在响应中**：web 前端按 albumId 本地映射显示（系统相册：1=相机、截屏、所有视频、私密、屏幕录制等 + 用户自定义相册）。T27 需要在前端/引擎内置一份 albumId→名称映射，或进一步核对前端 bundle。

### 2.2 时间线（日期→数量）

```
GET https://i.mi.com/gallery/user/timeline?ts={ms}[&albumId={id}]
```

响应：`data.dayCount` = `{"20200926": 3, ...}`（YYYYMMDD → 当日照片数），用于确定需要拉取的日期集合。

### 2.3 照片列表（按日期分页）

```
GET https://i.mi.com/gallery/user/galleries?ts={ms}&startDate=YYYYMMDD&endDate=YYYYMMDD&pageNum=0&pageSize=30[&albumId={id}]
```

- 分页语义：`pageNum/pageSize` + `data.isLastPage`；单张照片对象实测字段：
  - `id`（字符串照片 ID，如 `"14400041706979777"`）
  - `fileName` / `title` / `mimeType` / `type`（"image"）/ `size`（字节）
  - `sha1`（内容哈希，可用于增量去重）
  - `dateTaken` / `sortTime` / `dateModified` / `createTime`（毫秒时间戳）
  - `thumbnailInfo` / `bigThumbnailInfo`：`{"data":"<完整预签名 CDN URL>","isUrl":true}` —— 缩略图 URL 直接可用，无需二次请求
  - `exifInfo`：宽高、方向、机型、GPS 等
  - `description`：JSON 字符串 `{"isFavorite":false,"specialTypeFlags":0}`
- 全量遍历策略：timeline 拿 dayCount → 按天调 galleries（pageSize=30 翻页），或直接用宽日期区间分页。

### 2.4 下载原图（三跳链路，已全链路复现）

```
① GET https://i.mi.com/gallery/storage?ts={ms}&id={photoId}&callBack=dl_img_cb_{ts}_{n}
   → {"result":"ok","data":{"url":"https://c3.xmssmc.mws.xiaomi.net/kss_web/rd?i=...&cb=...&fn=<base64 文件名>&..."}}

② GET ①返回的 url（JSONP 脚本，浏览器用 <script> 加载）
   → 回调体：dl_img_cb_{ts}_{n}({"meta":"<一次性 meta 串>","url":"https://ali.xmssdn.micloud.mi.com/2/{uid}/download_file?ts=<过期毫秒>&sig=<预签名>&_cachekey=..."})

③ POST ②返回的 url，表单字段 meta=<②中 meta>（application/x-www-form-urlencoded）
   → 200 application/octet-stream，Content-Disposition: attachment; filename="IMG_....jpg"，正文即原图字节
```

- 前端实现（main bundle 逆向确认）：第③步用隐藏 iframe + POST form 完成，`meta` 为必填表单字段——**GET 直接访问 download_file 会报 `{"msg":"require meta","stat":"ERR_BAD_PARAMS"}`，GET+query 或 GET+header 均无效（400）**。
- `download_file?ts=` 为过期时刻（实测约签发后 +24h），`sig` 为服务端预签名——客户端无需计算任何签名。
- 预览图（缩略图）与原图差异：缩略图在 galleries 响应中直接给 `get_thumbnail` 预签名 URL；原图必须走上述三跳。

## 3. 签名与风控结论（T26.7）

1. **请求无签名校验**：所有 i.mi.com API 仅凭 `Cookie`（核心为 `serviceToken` + `userId`）；`ts` 只是时间戳参数。实测在 WSL 用 urllib 裸调全部成功。
2. **风控观察**：本次密码登录未触发任何验证码；短时间几十次 API 调用无限流迹象。建议引擎侧仍做保守限速（如 ≥1s/请求）以降低封禁风险。
3. **下载凭证**：`sig`/`meta` 均为服务端签发的一次性/时效凭证，客户端零密码学。
4. **可复现性总评：满分**。相册列表、时间线、照片列表、下载 URL 获取、原图字节流下载共 5 项全部在 WSL python3 纯标准库复现成功（含 9.8MB 原图逐字节校验：字节数与 API `size` 字段一致、JPEG magic 正确）。

## 4. T27 路线建议

- **import_session 可行性：确认成立**。cookie 可从浏览器/用户导入手动获取（`userId` + `serviceToken` 为最小集，建议整串导入），导入后以 `/gallery/user/album/list` 或 `/common/check` 探活。
- **密码直登：本次未逆向**（account.xiaomi.com 提交含密码加密参数）。按 T27.1 原计划仅做 cookie 导入通道；密码直登可作为后续实验性增强，不建议阻塞主线。
- **能力矩阵**：`list_albums` / `iter_simple_files` / `get_download_url` / `download_to_part` 均可实现；`delete`（未调研删除接口，声明 false）；连拍/实况（burst/live，未调研，声明 false）。
- 遍历建议：timeline(dayCount) → galleries 按天分页；sha1 可用作增量同步指纹。

## 5. 实验性支持风险声明

- 以上均为**非公开私有 API**（未含在小米开放平台），无稳定性承诺，随时可能变更或加强风控。
- 仅用于读取/下载自有相册内容做个人备份同步；不做删除、分享等写操作。
- 引擎实现应：导入会话失败给明确提示、请求失败区分 401（会话失效）与网络错误、全局限速、单账号并发 ≤2。

## 6. 扫码登录协议（T31.1 spike，2026-11-19 实测全链路打通 ✅）

> 结论：i.mi.com 可通过「二维码扫码」在**纯标准库（urllib）无浏览器**条件下建立会话，
> 全程无验证码/无风控拦截（WSL 匿名环境实测）。扫码建立的是**独立新会话**（不与已登录浏览器共用 token）。

### 6.1 端点与流程（6 步）

1. **匿名探活拿回调签名**：`GET https://i.mi.com/gallery/user/album/list?ts=<ms>&pageNum=0&pageSize=10&isShared=false&numOfThumbnails=1`（无 cookie）
   → HTTP 200，body `{"R":401,"S":"Err","D":"https://account.xiaomi.com/pass/serviceLogin?callback=https%3A%2F%2Fi.mi.com%2Fsts%3Fsign%3D<sign>%26followup%3D%252F&sid=i.mi.com&_group=DEFAULT&checkSafePhone=true&_bal=true"}`
   → 解码 `D` 提取 `callback`（带 i.mi.com 服务器签发的 `sign`，**必须用它**，否则 loginUrl 报 10025「Callback连接不合法」）
2. **创建扫码票据**：`GET https://account.xiaomi.com/longPolling/loginUrl?sid=i.mi.com&callback=<quote(callback)>&serviceParam=&qs=%253Fsid%253Di.mi.com&_hasLogo=false&_qrsize=240&_locale=zh_CN&_dc=<ms>`
   → `&&&START&&&` 前缀 JSON：`{code:0, qr:<官方二维码图片URL>, lp:<长轮询URL>, loginUrl:<可扫内容>, sl:"", timeout:300, timeInterval:0, result:"ok"}`
   - **需编码成二维码的字符串是 `loginUrl`**（形如 `https://<dc>.account.xiaomi.com/longPolling/login?ticket=lp_XXXX&dc=<dc>&sid=i.mi.com&ts=<ms>`，与 `lp` 同 ticket），用户用小米手机「设置→小米账号→扫一扫」扫描后手机直接弹确认
   - ⚠️ 实测纠错（2026-11-20，0.3.8）：`qr` 字段（形如 `https://account.xiaomi.com/pass/qr/login?ticket=lp_XXXX&...`）**不是**可扫内容——GET 它返回的是一张 PNG 二维码图片（官方登录页当 `<img src>` 用），图片内嵌的二维码内容即 `loginUrl`（zxing 解码实测）。误把 `qr` 编码进二维码会导致手机扫开后只展示图片里的「真二维码」（0.3.7 真机反馈）
   - 三字段同 ticket 实测：`lp.k == loginUrl.ticket == qr.ticket`，扫码确认驱动同一 `lp` 轮询
   - `lp` 形如 `https://<dc>.lp.account.xiaomi.com/lp/s?k=<ticket>`
3. **长轮询扫码状态**：循环 `GET <lp>`（服务端单次挂起约 60s 无事件即断开，客户端捕获超时后重挂即可；全程 `timeout:300` 秒总时限）
   → 确认后返回 `&&&START&&&` JSON：`{psecurity, nonce, ssecurity, passToken, userId, cUserId, securityStatus:0, location, code:0, result:"ok", desc:"成功", ...}`
   - **`passToken` 存在 = 已确认**；无 passToken 的等待期轮询表现为连接超时（无中间载荷）
   - `location` 为 passport **预签好的**最终 STS 跳转 URL（含 `auth`/`_ssign`，无需本地签名计算）
4. **换发（passToken → serviceToken）**：`GET https://account.xiaomi.com/pass/serviceLogin?sid=i.mi.com&callback=<quote(callback)>&_group=DEFAULT&_json=true`
   - 请求需带 cookie：`passToken` + `userId`（域 `.account.xiaomi.com`）
   - → JSON `{code:0, location:<新签的 https://i.mi.com/sts?sign=...&auth=...&_ssign=...>, ssecurity, passToken(刷新), ...}`
   - 注：步骤 3 的 `location` 也可直接用（一次性），经 serviceLogin 重签更稳
5. **STS 种 cookie**：`GET <location>` → 302（响应即种 `serviceToken` / `userId` / `i.mi.com_slh` / `i.mi.com_ph`）→ 302 http→https → 200 `https://i.mi.com/`
6. **验证**：用种好的完整 cookie（`userId`+`serviceToken` 最小集）调 `album/list` → 200 ✅（实测 5428 字节相册数据）

### 6.2 实现要点

- 所有响应（loginUrl/lp/serviceLogin）带 `&&&START&&&` 前缀，解析前须去掉
- `userId` cookie 在 STS 302 链中可能因 secure/domain 属性被 http.cookiejar 丢弃——**从 Set-Cookie 原始头手工解析**全部 cookie（v3 实验 jar 只有 3/6 个）
- 会话独占：扫码建立的新会话与浏览器会话互不影响（本 spike 后 NAS 旧导入会话仍有效）
- 与 T28.1 观察器衔接：confirmed 后走 `store.save()` + `_new_client()`（+`probe_session`），后续轮替自动落盘
- `timeout:300` 过期后票据作废，需重新 `loginUrl`；`/longPolling/cancle`（原拼写）可主动取消（未实测，非必需）

### 6.3 spike 记录

- 环境：WSL python3 纯标准库 + `qrcode` 库仅用于渲染二维码图（实现时由前端 JS 渲染）
- 时间线：00:30 生成票据 → 00:32 用户扫码（lp 挂起 2×60s 超时后第 3 次返回确认）→ serviceLogin 重签 → STS → album/list 200
- 产物：`mi_qr_confirm.json`（完整确认载荷）、`mi_qr_cookies.json`（最终 cookie 集）——已含敏感凭证，不入库

## 7. 长效会话机制（T36，2026-11-21 实测解密 ✅）

> 起因：扫码会话 ~17 分钟作废（绝对过期，高频探活无法保活），但用户浏览器 i.mi.com 可长期使用——差异未明。

### 7.1 实测证据（TRAE 浏览器 + WSL 对照）

| 实验 | 结果 |
|---|---|
| 浏览器 serviceToken 提取后 WSL 直连 | ✅ 200（document.cookie 全集即可，**无隐藏 httpOnly 必需项**） |
| 浏览器页面 F5 后 token 值 | 364→407 字节变化（**服务端静默重签**，公共前缀保留） |
| 重签后旧 serviceToken | ~15 分钟并存窗口后被作废 |
| WSL 连续两轮「探活→serviceLogin→STS」 | ✅ 全部成功，新 serviceToken 实测 200 |

### 7.2 机制结论

- **serviceToken 本身短命（~15-30 分钟）**；长效钥匙是 account.xiaomi.com 域的 **passToken**（浏览器「信任设备」密码登录签发，`i.mi.com_istrudev=true` + `deviceId` 配套）
- **passToken 可无限次换发 serviceToken 且不轮替**（两次重签后值不变）——与扫码 passToken（一次性特权，换发即作废 70016）本质不同
- 静默重签链（WSL 纯标准库已复现）：
  1. 匿名 GET `album/list` → 401 响应 `D` URL（内含新鲜 `sign` 的 callback）
  2. ⚠️ **callback 编码层次**：D 里的 callback 是双层编码（sign 的 `=` 为 `%253D`），serviceLogin 白名单要求**单层**（`%3D`）——解码一层后将 sign 尾部字面 `%3D` 还原为 `=`，再单层 quote
  3. ⚠️ **必须带 `sid=i.mi.com`**（缺了报 10025「Callback 连接不合法」，与编码无关）
  4. `GET /pass/serviceLogin?sid=i.mi.com&callback=<单层编码>&_group=DEFAULT&_json=true`，Cookie 带 account 域集（passToken+userId+cUserId+deviceId+pass_ua+passInfo+serviceToken(account 域 2.0&V1_passport 形态)+passport_slh/ph）
  5. 响应 JSON `location` = 预签 STS URL → GET 之 → Set-Cookie 新 `serviceToken`
  6. 新 serviceToken 实测 album/list 200 ✅
- account 域 cookie 集（用户 DevTools Application 面板可复制，含 httpOnly）：passToken、userId、cUserId、deviceId（`wb_` 前缀）、pass_ua、passInfo、serviceToken（account 域形态 `2.0&V1_passport&1:...`）、passport_slh、passport_ph

### 7.3 产品化方向（T36.5 待实现）

- 导入通道扩展：引导用户复制 account 域 passToken（DevTools → Application → Cookies → account.xiaomi.com）
- daemon 401 时自动走重签链（持有长效 passToken 时）；主动续期阈值建议 30 分钟
- 扫码通道保留为短时应急批次模式

## 8. 开源实现对照与备选续期路径（2026-11-23 GitHub 调研）

> 起因：为「最少依赖 + 最少代码 + 最低风控暴露」的登录方案选型做公开项目对照。

### 8.1 ⚠️ 续期端点辨析：serviceLogin?_json=true 是「网页交互式」端点

小米笔记插件 [sucjs/mi-note-for-pi](https://github.com/sucjs/mi-note-for-pi) 的踩坑记录
（与本项 2026-11-22 浏览器实测互相印证）：

- `GET /pass/serviceLogin?...&_json=true` 无人交互时只返回**验证挑战**
  （`notificationUrl`/`captchaUrl`/`pwd`/`securityStatus`，只给 `psecurity` 不给
  `ssecurity`）——本项目浏览器实测看到的「code=0 但 passToken/ssecurity 为空」即此形态；
- **浏览器主路径**是纯重定向链：`GET https://i.mi.com/api/user/login → 302
  serviceLogin?… →（带 .xiaomi.com 域 passToken/cUserId）→ 302 回 i.mi.com，
  Set-Cookie 种新 serviceToken`——不产出可读 JSON，票据经 Set-Cookie 交付；
- 本项目 NAS 侧续期链（探活 D-callback → serviceLogin?_json=true → STS）已真机
  验证可用（两轮 renew + album/list 200），保持现状；若未来遇风控升级，备选切换
  `api/user/login` 重定向链（更贴近浏览器主路径）。

### 8.2 密码登录（备选方案，社区已完整实现）

> **2026-11-23 更新：本项目已实现**（0.3.29，`app/server/providers/xiaomi/password_login.py`，
> 按 §8.5 移植决策），三分支状态机 + 双次换发校验接入长效管线；真机验收待下次发版。

`POST /pass/serviceLoginAuth2`（application/x-www-form-urlencoded）：
`user=<手机号/邮箱/小米ID>`、`hash=<MD5(password).upper()>`、`qs`/`_sign`/`callback`/
`sid=i.mi.com`/`_json=true` → `userId`/`cUserId`/`passToken`/`ssecurity`/`location`/`nonce`。

失败模式（各家 issue 共同教训）：

| 场景 | 特征 | 处理 |
|---|---|---|
| 图形验证码 | `captchaUrl` 非空 | 取图（`ick` cookie）→ 用户输 `captCode` 重提 |
| 短信/邮箱 2FA | `notificationUrl` + `securityStatus:16` | identity 流程（flag 4=手机 8=邮箱）→ send/verify Ticket → 重定向链 |
| 异地/机房 IP | 2FA 触发率高 | 服务器部署场景普遍踩坑 |

关键技巧：identity 验证 `trust:"true"` 等价网页「信任此设备」，配合**固定 deviceId**
有望让密码登录直接产出长效 passToken（免浏览器）。但需存储密码、且机房 IP 验证
率高——本项目维持「登录面交给用户浏览器」的形态不变。

### 8.3 反风控要点（社区共识，本项目对齐情况）

- deviceId 固定持久化（`wb_`+UUID 仿真机格式），跨导入/重装不变——**已实现**：
  导入缺省时生成并写入 longterm 块（同赛道 XiaomiAlbumSyncer 同款做法）；
- 续期只重试一次 + 并发去重（防 401 风暴触发风控）——已有；
- 网络故障绝不判凭据失效（掉线时重登必失败，误判逼用户白白重扫）——已有；
- 主动续期阈值参考：XiaomiAlbumSyncer ~10 分钟（本项 25 分钟更温和）；
- 不做 ssecurity+nonce 签名交换（mi-note-for-pi 同款结论：证据不足、易被风控、
  非浏览器主路径；i.mi.com 相册链路不涉及）。

### 8.5 Gateway3 实现细节提取（T40.1 移植备忘，源码：AlexxIT/XiaomiGateway3 `custom_components/xiaomi_gateway3/core/xiaomi_cloud.py` @ master 65f7249）

**登录状态机**（四条入口，对应我们四个 API）：

```
login(user, pw)                        # 主入口
 ├─ _service_login → res1
 ├─ res1.captchaUrl        → _get_captcha_url → {captcha PNG bytes, ick}   # 存 auth={user,pw,ick}
 ├─ res1.notificationUrl   → _get_notification_url → identity/list{code:2,flag:4|8}
 │                           + identity_session cookie → _send_ticket(flag, session)
 └─ code=0                 → _get_credentials
login_captcha(code)                     # 统一验证码入口
 ├─ auth 有 flag+identity_session → _send_ticket(flag, session, code)   # sendTicket 嵌套验证码
 └─ 否则                          → login(user, pw, captcha_code=code)  # Auth2 阶段验证码
login_verify(ticket)                    # 2FA 验证码提交
 └─ POST identity/auth/verify{Phone|Email}?_flag&_json=true + trust 参数
```

**端点与参数精确表**：

| 步骤 | 请求 | Cookie | 关键参数/响应 |
|---|---|---|---|
| 取签 | GET `account.xiaomi.com/pass/serviceLogin?_json=true&sid=<sid>` | `sdkVersion=<SDK 版本>` + `deviceId` | 未登录 code=70016 是正常应答，`_sign`/`qs`/`callback`/`sid` 照常返回——**无需 i.mi.com 探活取签**（与续期链不同） |
| Auth2 | POST `account.xiaomi.com/pass/serviceLoginAuth2` | 同上（验证码重提时加 `ick`） | form：`_json=true, sid, callback, _sign, qs, user, hash=MD5(pw).upper()`（+`captCode`）；成功响应 JSON 含 `passToken/ssecurity/userId/location` |
| 验证码图 | GET `account.xiaomi.com` + captchaUrl 路径 | — | PNG 字节 + Set-Cookie `ick` |
| identity 列表 | GET notificationUrl 把 `/fe/service/identity/authStart` 替换为 `/identity/list` | （session jar） | `{code:2, flag:4|8}` + Set-Cookie `identity_session` |
| 发码 | GET `identity/auth/verify{Phone\|Email}?_flag&_json=true` → POST `identity/auth/send{key}Ticket` | `identity_session`（+`ick` 嵌套验证码时） | GET 返回 `maskedPhone/maskedEmail`；POST data `{retry:0, icode:<图码或空>, _json:true}`；POST 也可能回 captchaUrl（嵌套验证码） |
| 2FA 校验 | POST `identity/auth/verify{Phone\|Email}?_flag&ticket&_json=true&trust=?` | `identity_session` | code=0 → _get_credentials；**passToken/userId 在 302 历史 Set-Cookie 中，ssecurity 在 `extension-pragma` 响应头（JSON）** |
| 取凭据 | GET res.location | （jar） | body=`ok`；Set-Cookie：`userId/cUserId/serviceToken`；redirect 历史逐跳收 Set-Cookie + extension-pragma |

响应统一 `&&&START&&&` 前缀（11 字节）。

**与本项目差异清单（移植决策）**：

| Gateway3 | 本项目移植决策 |
|---|---|
| `sid=xiaomiio`（米家） | `sid=i.mi.com`（云相册，lyj0309 同款已验证可行） |
| aiohttp session jar | 沿用 `longterm._http`（urllib 手动 Cookie 头 + _NoRedirect），pending 状态机内维护 cookie dict，每跳 harvest Set-Cookie |
| deviceId=16 位随机大写字母数字；sdkVersion=4.2.29 | 用 `wb_+UUID` 仿真机格式（浏览器同款，与续期链一致）+ 固定 sdkVersion cookie |
| login_verify `trust="false"` | **`trust="true"`**（XiaomiAlbumSyncer 调研：等价网页「信任此设备」→ 长效票）；真机验收验证，若被拒回退 false |
| 取签无需 callback（Auth2 只回传 serviceLogin 给的值） | 同左——比续期链简化（无需 D-field 探活） |
| 成功分支产 token=`userId:passToken` | 改接 `import_longterm` 落盘（双次换发校验+身份回填+长 ticket 块） |
| cryptography 库做 RC4（仅米家 api.io.mi.com 需要） | 不移植——i.mi.com 相册链路无签名交换需求 |

### 8.4 参考实现清单

| 项目 | 语言 | 覆盖 |
|---|---|---|
| [AlexxIT/XiaomiGateway3](https://github.com/AlexxIT/XiaomiGateway3) `core/xiaomi_cloud.py` | Python | 密码+验证码+identity 2FA 全流程（公认最完整） |
| [al-one/hass-xiaomi-miot](https://github.com/al-one/hass-xiaomi-miot) | Python | 新版 fe/service/identity/authStart 适配 |
| [lyj0309/xiaomi-cloud](https://github.com/lyj0309/xiaomi-cloud)、fineemb/xiaomi-cloud | Python/HA | **sid=i.mi.com 云相册**密码登录+验证码 |
| [sucjs/mi-note-for-pi](https://github.com/sucjs/mi-note-for-pi) `lib/auth.js` | Node（零依赖） | 扫码 + 浏览器主路径续期链 + 反风控三铁律 |
| [Coooolfan/XiaomiAlbumSyncer](https://github.com/Coooolfan/XiaomiAlbumSyncer) | Python | 同赛道（云相册）：扫码主路径 + PassToken 手动兜底 + 密码方案调研 |
| [wangbjun/go-micloud](https://github.com/wangbjun/go-micloud) | Go | i.mi.com 云盘 + serviceLoginAuth2 + 短信码 |
| [Mi-Bee-Studio/MiBeeNvr](https://github.com/Mi-Bee-Studio/MiBeeNvr) | Go | 登录+验证码+2FA |
| [Guyuepp/xiaomi-drive-go](https://github.com/Guyuepp/xiaomi-drive-go) `docs/api-notes.md` | Go | identity/result/check → serviceLoginAuth2/end → i.mi.com/sts 全链文档 |
| [PiotrMachowski/Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor) | Python | 密码+验证码取 token |
| [offici5l/MiUnlockTool](https://github.com/offici5l/MiUnlockTool) | Python | identity 端点文档化 |

## 附：调研环境与复现验证记录

- 浏览器：Trae 外接 Chrome（真实窗口），密码登录一次通过，无验证码。
- 复现环境：WSL python3（仅 urllib/json/time，无第三方包），同一 cookie 导出文件（已删除）。
- 验证矩阵：album/list 200 ✅ · timeline 200 ✅ · galleries 200 ✅ · gallery/storage 200 ✅ · kss_web/rd JSONP 解析 ✅ · download_file POST 原图 9,817,448 字节 ✅（与 API size 一致）
- 前端逆向定位：`main.f7a44e87.chunk.js`（下载三跳逻辑）、`album-pc-detail` chunk（详情页）。

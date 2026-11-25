"use strict";
/* 小米云相册平台模块：账号密码登录（凭据存于「同步设置」）+ 扫码登录 +
 * cookie/cURL 导入。
 *
 * 本文件自治小米平台的全部 UI 内容（认证页登录方式卡、设置页凭据卡、
 * 向导凭据字段），通用页面不含任何小米字样。
 */
let _qrPolling = false;
let _qrStartId = null;
let _riskTimer = null;

PlatformUI.register("xiaomi", {
  label: "小米云相册",
  userIdLabel: "小米用户 ID",
  wizardDesc: "账号密码 / 扫码 / cURL 导入，产出长效会话",

  albumTip() { return "小米端相册计数为云端实时值"; },

  /* -- 认证状态平台差异行（状态页 / 认证页共用） -- */
  authSummaryRows(a) {
    const rows = [["已保存账号密码", a.pwd_configured ? "是" : "否（可在「同步设置」填写）"]];
    rows.push(["会话导入/更新时间", a.session_updated_at ? fmtTs(a.session_updated_at) : "—"]);
    if (a.risk && a.risk.kind === "rate_limited" && a.risk.retry_after_ts) {
      rows.push(["风控限流", "限流中，恢复时间见下方倒计时"]);
    }
    if (a.longterm) {
      rows.push(["免扫码模式", a.longterm.dead
        ? "长效票已失效，请重新登录"
        : `已启用（已自动续期 ${a.longterm.rounds || 1} 次，上次 ${a.longterm.last_renew_at ? fmtTs(a.longterm.last_renew_at) : "—"}）`]);
    }
    return rows;
  },

  /* -- 认证页登录方式卡：密码登录（凭据来自同步设置） + 扫码登录 -- */
  renderAuthMethods(accountId) {
    const mount = $("auth-methods-mount");
    if (!mount || this._mountedFor === accountId) return;
    this._mountedFor = accountId;
    mount.innerHTML = `
      <div id="risk-banner" style="display:none"></div>
      <div class="card" id="pwd-login-card">
        <h2>账号密码登录 <span class="hint">使用「同步设置」中保存的小米账号密码</span></h2>
        <div class="tip" style="display:block;line-height:1.7">
          密码登录签发的 passToken 与浏览器「信任设备」等价：导入后每 15 分钟自动静默续期，<b>不再掉线</b>。
          ⚠️ 服务器/异地 IP 登录触发图形验证码或短信/邮箱二次验证的概率较高，属正常现象，按提示完成即可；失败后有 30 分钟冷却。
        </div>
        <div class="btn-row" style="margin-top:10px">
          <button class="btn primary" id="btn-pwd-start" onclick="pwdLoginStart()">使用已保存账号登录</button>
        </div>
        <div id="pwd-captcha-area" style="display:none;margin-top:10px">
          <img id="pwd-captcha-img" class="pwd-captcha-img" alt="图形验证码">
          <div class="lt-grid-btn">
            <label>图形验证码 <input id="pwd-captcha-code" placeholder="输入图中字符" autocomplete="off"></label>
            <button class="btn" id="btn-pwd-captcha" style="align-self:end" onclick="pwdLoginCaptcha()">提交验证码</button>
          </div>
        </div>
        <div id="pwd-2fa-area" style="display:none;margin-top:10px">
          <div class="tip" id="pwd-2fa-tip" style="display:block"></div>
          <div class="lt-grid-btn">
            <label>验证码 <input id="pwd-2fa-code" placeholder="短信/邮箱验证码" autocomplete="off"></label>
            <button class="btn" id="btn-pwd-verify" style="align-self:end" onclick="pwdLoginVerify()">提交验证码</button>
          </div>
        </div>
        <div id="pwd-msg" style="margin-top:10px"></div>
      </div>
      <div class="card" id="qr-login-card">
        <h2>扫码登录 <span class="hint">小米手机「设置 → 小米账号 → 扫一扫」；无需手动复制 cookie</span></h2>
        <div id="qr-status-tip" class="tip" style="display:block;line-height:1.7">点击「生成二维码」，用小米手机扫一扫并在手机上确认登录（二维码 5 分钟内有效）。扫码建立的是本应用独占的新会话，不影响浏览器登录态。<br><b>注意：受小米风控限制，扫码会话约 15–35 分钟后失效，无法自动续期</b>——建议在需要同步前扫码，确认后在「同步状态」页点「立即同步」；失效后重新扫码即可。</div>
        <div class="btn-row" style="margin-top:10px">
          <button class="btn primary" id="btn-qr-start" onclick="qrLoginStart()">生成二维码</button>
          <button class="btn" id="btn-qr-stop" style="display:none" onclick="qrLoginStop()">取消等待</button>
        </div>
        <div id="qr-qr-area" style="display:none;text-align:center;margin-top:14px"></div>
        <div id="qr-msg" style="margin-top:10px"></div>
      </div>
      <div class="card" id="longterm-card">
        <h2>长效会话导入（免扫码） <span class="hint">导入一次，自动静默续期，不再掉线</span></h2>
        <div id="longterm-tip" class="tip" style="display:block;line-height:1.7">
          从<strong>用密码登录（信任设备）i.mi.com</strong> 的浏览器复制账号域长效票据（passToken）。
          ⚠️ 扫码登录签发的票据是一次性的（换发一次即作废），导入时会做双次换发校验并拒绝。
          导入后每 15 分钟自动静默续期，<b>不再需要扫码</b>（passToken 有效期通常数天~数周）。
          <br>获取步骤：F12 → <b>Application（应用）</b> → 左侧 <b>Cookies → https://account.xiaomi.com</b>（注意是 account 域，不是 i.mi.com）→ 复制
          <b>passToken</b>、<b>userId</b>、<b>cUserId</b>、<b>deviceId</b>、<b>serviceToken</b>（2.0&amp;V1_passport 开头那份）的值分别填入下方。
          <br>若导入报「passToken 已失效」：说明浏览器会话的票已过期，退出后重新用密码登录再复制。
        </div>
        <div class="lt-grid">
          <label>userId（数字 ID）<input id="lt-user-id" placeholder="如 196519672"></label>
          <label>cUserId<input id="lt-c-user-id" placeholder="可从同表格复制"></label>
          <label>deviceId<input id="lt-device-id" placeholder="wb_ 开头"></label>
          <label>serviceToken（account 域，可选）<input id="lt-account-st" placeholder="2.0&V1_passport& 开头"></label>
        </div>
        <label style="display:block;margin-top:10px">passToken（必填）<textarea id="lt-pass-token" rows="3" placeholder="V1: 开头的长串" style="width:100%;word-break:break-all"></textarea></label>
        <div class="btn-row" style="margin-top:10px">
          <button class="btn primary" id="btn-lt-import" onclick="longtermImport()">导入并验证换发</button>
        </div>
        <div id="lt-msg" style="margin-top:10px"></div>
      </div>`;
  },

  /* -- 认证状态到达：风控限流倒计时横幅（T31.10）+ 密码登录按钮可用性 -- */
  onAuthRefresh(a) {
    renderRiskBanner(a && a.risk);
    const btn = $("btn-pwd-start");
    if (btn) {
      const ok = !!(a && a.pwd_configured);
      btn.disabled = !ok;
      btn.title = ok ? "" : "请先在「同步设置」填写小米账号密码并保存";
    }
  },

  /* -- cURL 导入卡文案 -- */
  applyCurlCopy() {
    $("curl-card-hint").textContent = "从已登录小米云相册的浏览器复制 cookie 或 cURL";
    $("curl-card-tip").innerHTML = "两种方式任选：① F12 → Network → 任意 i.mi.com 请求 → 右键「Copy as cURL」→ 整段粘贴；② F12 → 应用(Application) → Cookies → https://i.mi.com → 全选复制为「名=值; 名=值」格式粘贴。导入后 daemon 约 15 秒内热重载。";
  },

  /* -- 设置页凭据卡（与华为/iCloud 同模式：保存配置时随 payload 加密落盘） -- */
  renderSettingsCred(mount, accountId) {
    if (!mount || this._credFor === accountId) return;
    this._credFor = accountId;
    mount.innerHTML = `
      <div class="card" id="cred-card">
        <h2>账号与认证 <span class="hint">密码以密文保存在 NAS 本地（密钥文件 secret.key，均 chmod 600），提交后不再回显</span></h2>
        <div class="form-grid">
          <div class="field"><label>小米账号</label><input type="text" id="f-username" placeholder="手机号 / 邮箱 / 小米ID" autocomplete="username">
            <span class="tip">用于「认证与安全」页的密码登录；也可不填，改用扫码登录或 cURL 导入（免密码）</span></div>
          <div class="field"><label>密码</label><input type="password" id="f-password" placeholder="留空保持不变" autocomplete="current-password">
            <span class="tip"><label style="font-weight:400"><input type="checkbox" id="f-password-clear" style="vertical-align:-2px"> 清除已保存的密码</label></span></div>
        </div>
      </div>`;
  },

  onConfigLoaded(c) {
    const u = $("f-username");
    if (!u) return;
    u.value = c.username || "";
    $("f-password").value = "";
    $("f-password-clear").checked = false;
  },

  /* 密码仅在新输入 / 显式清除时携带，空值走服务端掩码保留语义 */
  credentialPayload() {
    const u = $("f-username");
    if (!u) return null;
    const payload = { username: u.value.trim() };
    const pw = $("f-password") ? $("f-password").value : "";
    if ($("f-password-clear") && $("f-password-clear").checked) payload.password = "__clear__";
    else if (pw) payload.password = pw;
    return payload;
  },

  /* -- 新建向导：凭据字段（可选填写，也可创建后在认证页扫码/导入） -- */
  wizardCredHtml() {
    return `
      <div class="field" id="w-cred-fields"><label>账号（手机号/邮箱/小米ID）</label><input type="text" id="w-username" placeholder="用于密码登录，可留空" value="${esc(wiz.input.username)}" oninput="wiz.input.username=this.value"></div>
      <div class="field" id="w-pass-fields"><label>密码</label><input type="password" id="w-password" placeholder="用于密码登录，可留空" value="${esc(wiz.input.password)}" oninput="wiz.input.password=this.value">
        <span class="tip">加密保存于应用私有数据目录（chmod 600），不发往任何第三方；也可创建后在「认证与安全」页扫码登录或 cURL 导入</span></div>`;
  },

  collectWizardCred() {
    return {
      username: ($("w-username") ? $("w-username").value : wiz.input.username || "").trim(),
      password: $("w-password") ? $("w-password").value : (wiz.input.password || ""),
    };
  },

  wizardFinishHint() {
    return `· 到「认证与安全」页点「使用已保存账号登录」完成密码登录（可能需图形验证码/短信验证）<br>
      · 也可在该页使用「扫码登录」或「cURL / cookie 导入」直接导入登录态`;
  },
});

/* ---------- 长效会话导入（T36.5，免扫码模式） ---------- */

async function longtermImport() {
  const id = curId();
  const payload = {
    userId: ($("lt-user-id").value || "").trim(),
    cUserId: ($("lt-c-user-id").value || "").trim(),
    deviceId: ($("lt-device-id").value || "").trim(),
    accountServiceToken: ($("lt-account-st").value || "").trim(),
    passToken: ($("lt-pass-token").value || "").trim(),
  };
  if (!payload.passToken || !payload.userId) {
    $("lt-msg").innerHTML = `<div class="banner err">passToken 与 userId 为必填项</div>`;
    return;
  }
  const btn = $("btn-lt-import"); btn.disabled = true;
  $("lt-msg").innerHTML = `<span class="spin"></span> 正在验证换发（约 5-10 秒）…`;
  try {
    const r = await api(`accounts/${id}/auth/import-longterm`, { method: "POST", body: payload });
    if (r.status === "ok") {
      $("lt-msg").innerHTML = `<div class="banner ok">${esc(r.message)}（userId=${esc(r.user_id || "")}）</div>`;
    } else {
      $("lt-msg").innerHTML = `<div class="banner err">${esc(r.message || "导入失败")}</div>`;
    }
  } catch (e) {
    $("lt-msg").innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  } finally {
    btn.disabled = false;
  }
}

/* ---------- 账号密码登录（T38：Auth2 + 图形验证码 + identity 2FA；
 * 凭据读自「同步设置」保存的账号配置，前端不再收集账号/密码） ---------- */

function pwdApplyResult(r) {
  if (r.status === "ok") {
    $("pwd-captcha-area").style.display = "none";
    $("pwd-2fa-area").style.display = "none";
    $("pwd-msg").innerHTML = `<div class="banner ok">${esc(r.message || "密码登录成功，长效会话已导入")}</div>`;
    toast("密码登录成功", "ok");
    refreshAuth();
    return true;
  }
  if (r.status === "captcha") {
    $("pwd-2fa-area").style.display = "none";
    $("pwd-captcha-img").src = r.image;
    $("pwd-captcha-area").style.display = "";
    $("pwd-msg").innerHTML = `<div class="banner">需要图形验证码，请输入图中字符后提交。</div>`;
    return false;
  }
  if (r.status === "2fa") {
    $("pwd-captcha-area").style.display = "none";
    $("pwd-2fa-area").style.display = "";
    $("pwd-2fa-tip").innerHTML =
      `已向 <b>${esc(r.target || ("绑定" + (r.channel === "email" ? "邮箱" : "手机号")))}</b> 发送验证码，请查收并输入（验证码 10 分钟内有效）。`;
    $("pwd-msg").innerHTML = "";
    return false;
  }
  return false;
}

async function pwdLoginStart() {
  const id = curId(); if (!id) return;
  const btn = $("btn-pwd-start"); btn.disabled = true;
  $("pwd-msg").innerHTML = `<span class="spin"></span> 正在登录…`;
  try {
    const r = await api(`accounts/${id}/auth/password-login/start`, { method: "POST", body: {} });
    if (!pwdApplyResult(r) && r.status === "error") {
      $("pwd-msg").innerHTML = `<div class="banner err">${esc(r.message || "登录失败")}</div>`;
    }
  } catch (e) {
    $("pwd-msg").innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  } finally { btn.disabled = false; }
}

async function pwdLoginCaptcha() {
  const id = curId(); if (!id) return;
  const code = ($("pwd-captcha-code").value || "").trim();
  if (!code) { $("pwd-msg").innerHTML = `<div class="banner err">请输入图中验证码</div>`; return; }
  const btn = $("btn-pwd-captcha"); btn.disabled = true;
  $("pwd-msg").innerHTML = `<span class="spin"></span> 正在提交验证码…`;
  try {
    const r = await api(`accounts/${id}/auth/password-login/captcha`, { method: "POST", body: { code } });
    if (!pwdApplyResult(r) && r.status === "error") {
      $("pwd-msg").innerHTML = `<div class="banner err">${esc(r.message || "验证码校验失败")}</div>`;
    }
  } catch (e) {
    $("pwd-msg").innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  } finally { btn.disabled = false; }
}

async function pwdLoginVerify() {
  const id = curId(); if (!id) return;
  const code = ($("pwd-2fa-code").value || "").trim();
  if (!code) { $("pwd-msg").innerHTML = `<div class="banner err">请输入收到的验证码</div>`; return; }
  const btn = $("btn-pwd-verify"); btn.disabled = true;
  $("pwd-msg").innerHTML = `<span class="spin"></span> 正在校验…`;
  try {
    const r = await api(`accounts/${id}/auth/password-login/verify`, { method: "POST", body: { code } });
    if (!pwdApplyResult(r) && r.status === "error") {
      $("pwd-msg").innerHTML = `<div class="banner err">${esc(r.message || "校验失败")}</div>`;
    }
  } catch (e) {
    $("pwd-msg").innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  } finally { btn.disabled = false; }
}

/* ---------- 扫码登录（模块自治，模板内联 onclick 调用） ---------- */

/* 风控限流倒计时横幅（T31.10）：服务端检测到 album/list 10001 限流后，
 * 提示用户勿扫码/勿同步，倒计时结束提示「可以重新扫码」。 */
function renderRiskBanner(risk) {
  const el = $("risk-banner");
  if (!el) return;
  if (_riskTimer) { clearInterval(_riskTimer); _riskTimer = null; }
  if (!risk || risk.kind !== "rate_limited" || !risk.retry_after_ts) {
    el.style.display = "none"; el.innerHTML = ""; return;
  }
  const targetMs = risk.retry_after_ts * 1000; // 服务端 epoch 秒 → JS 毫秒
  const render = () => {
    const leftSec = Math.floor(targetMs / 1000 - Date.now() / 1000);
    if (leftSec <= 0) {
      el.style.display = "";
      el.innerHTML = `<div class="banner ok">✅ 风控限流时间已过，现在可以重新扫码登录了（扫码确认后建议立即同步）。</div>`;
      if (_riskTimer) { clearInterval(_riskTimer); _riskTimer = null; }
      return;
    }
    const hh = Math.floor(leftSec / 3600);
    const mm = String(Math.floor((leftSec % 3600) / 60)).padStart(2, "0");
    const ss = String(leftSec % 60).padStart(2, "0");
    const clock = new Date(targetMs).toTimeString().slice(0, 8);
    el.style.display = "";
    el.innerHTML = `<div class="banner err" style="line-height:1.8">⚠ 小米风控限流中（近期扫码/重签过于频繁，接口返回 10001 系统错误）。请勿扫码或触发同步，<b>${hh > 0 ? hh + " 小时 " : ""}${mm} 分 ${ss} 秒</b>后（约 ${clock}）恢复——届时再扫码登录并立即同步。</div>`;
  };
  render();
  _riskTimer = setInterval(render, 1000);
}

function renderQrImage(text) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  return qr.createDataURL(6, 8);
}

async function qrLoginStart() {
  const id = curId(); if (!id) return;
  const btn = $("btn-qr-start"); btn.disabled = true;
  $("qr-msg").innerHTML = `<span class="spin"></span> 正在生成二维码…`;
  try {
    const r = await api(`accounts/${id}/auth/qr/start`, { method: "POST", body: {} });
    $("qr-qr-area").innerHTML =
      `<img src="${renderQrImage(r.qr_content)}" alt="小米扫码登录二维码" style="width:248px;height:248px;image-rendering:pixelated;background:#fff;padding:10px;border:1px solid var(--border);border-radius:8px">
       <div class="tip" style="margin-top:8px">小米手机：设置 → 小米账号 → 扫一扫</div>`;
    $("qr-qr-area").style.display = "";
    $("qr-msg").innerHTML = `<div class="banner">等待扫码确认中…（二维码 5 分钟内有效）</div>`;
    $("btn-qr-stop").style.display = "";
    _qrStartId = id;
    qrPollLoop();
  } catch (e) {
    $("qr-msg").innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  } finally { btn.disabled = false; }
}

async function qrPollLoop() {
  _qrPolling = true;
  while (_qrPolling && curId() === _qrStartId) {
    let r;
    try {
      r = (await api(`accounts/${curId()}/auth/qr/poll`)).qr;
    } catch (e) {
      $("qr-msg").innerHTML = `<div class="banner err">扫码轮询失败：${esc(e.message)}</div>`;
      break;
    }
    if (r.status === "confirmed") {
      $("qr-msg").innerHTML = `<div class="banner ok">扫码登录成功（userId=${esc(r.user_id || "")}），daemon 将在 15 秒内热重载。<br>会话约 15–35 分钟有效（小米风控限制）——建议立即到「同步状态」点「立即同步」。</div>`;
      toast("扫码登录成功", "ok");
      refreshAuth();
      break;
    }
    if (r.status === "failed") {
      $("qr-msg").innerHTML = `<div class="banner err">${esc(r.error || "扫码登录失败，请重试")}</div>`;
      break;
    }
    if (r.status === "expired") {
      $("qr-msg").innerHTML = `<div class="banner warn">二维码已过期或已取消，请重新生成。</div>`;
      break;
    }
    // waiting：继续长轮询
  }
  _qrPolling = false;
  const stopBtn = $("btn-qr-stop");
  if (stopBtn) stopBtn.style.display = "none";
}

function qrLoginStop() {
  _qrPolling = false;
  $("btn-qr-stop").style.display = "none";
  $("qr-msg").innerHTML = `<div class="banner warn">已取消等待。</div>`;
}

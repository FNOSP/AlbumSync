"use strict";
/* 华为云空间平台模块：账密登录 + 两段式 2FA + cURL 导入。
 *
 * 本文件自治华为平台的全部 UI 内容（认证页登录方式卡、2FA 面板、
 * 设置页凭据卡、向导凭据字段），通用页面不含任何华为字样。
 */
PlatformUI.register("huawei", {
  label: "华为云空间",
  userIdLabel: "华为用户 ID",
  wizardDesc: "相册同步 / 2FA / cURL 导入",

  albumTip() { return "华为云端不返回空相册，其「相机 / 截屏录屏」等空系统相册为占位显示"; },

  /* -- 认证状态平台差异行（状态页 / 认证页共用） -- */
  authSummaryRows(a) {
    const lvl = a.login_sec_level == 2 ? "2（完整，可同步）"
      : a.login_sec_level == 1 ? "1（受限，需二次验证解锁）" : "—";
    const rows = [
      ["图库解锁级别", lvl],
      ["CAS 会话", a.has_cas_tgt ? "有效" : "无"],
      ["已保存账号密码", a.credentials_configured ? "是" : "否（可用 cURL 导入）"],
    ];
    if (a.pending_2fa) {
      rows.push(["待二次验证",
        `<span class="badge warn">${esc(a.pending_2fa.flow || "")}</span> ${fmtTs(a.pending_2fa.created_at)}`]);
    }
    return rows;
  },

  /* -- 认证页登录方式卡：密码登录按钮 + 输出区 + 2FA 面板 -- */
  renderAuthMethods(accountId) {
    const mount = $("auth-methods-mount");
    if (!mount || this._mountedFor === accountId) return;
    this._mountedFor = accountId;
    mount.innerHTML = `
      <div class="card">
        <h2>账号密码登录 <span class="hint">使用「同步设置」中保存的华为账号密码</span></h2>
        <div class="btn-row">
          <button class="btn primary" id="btn-login" onclick="webLogin()">使用已保存账号登录</button>
        </div>
        <div id="login-output" style="margin-top:12px"></div>
        <div id="twofa-panel" style="display:none">
          <div class="section-title">二次验证</div>
          <div id="twofa-channels"></div>
          <div class="btn-row" style="margin-top:8px">
            <input type="text" class="code-input" id="twofa-code" maxlength="6" placeholder="______" inputmode="numeric">
            <button class="btn primary" id="btn-2fa" onclick="submit2fa()">提交验证码</button>
          </div>
          <div class="tip" style="margin-top:6px;color:var(--muted);font-size:12px">验证码 10 分钟内有效；验证通过后设备将被信任，后续会话过期可静默自动重登。</div>
        </div>
      </div>`;
  },

  /* auth 刷新钩子：有待完成的 2FA 时直接弹出验证码面板 */
  onAuthRefresh(a) {
    if (a.pending_2fa && a.pending_2fa.channels && a.pending_2fa.channels.length) {
      showTwoFa(a.pending_2fa.channels, "检测到未完成的二次验证（验证码可能已发送），可直接提交：");
    }
  },

  /* -- cURL 导入卡文案 -- */
  applyCurlCopy() {
    $("curl-card-hint").textContent = "从已登录华为云空间的浏览器复制登录请求 cURL";
    $("curl-card-tip").textContent = "Chrome/Edge 开发者工具 → Network → 任意 cloud.dual.huawei.com 请求 → 右键「Copy as cURL」→ 粘贴到下面 → 导入。导入后 daemon 约 15 秒内热重载。";
  },

  /* -- 设置页凭据卡 -- */
  renderSettingsCred(mount, accountId) {
    if (!mount || this._credFor === accountId) return;
    this._credFor = accountId;
    mount.innerHTML = `
      <div class="card" id="cred-card">
        <h2>账号与认证 <span class="hint">密码以密文保存在 NAS 本地（密钥文件 secret.key，均 chmod 600），提交后不再回显</span></h2>
        <div class="form-grid">
          <div class="field"><label>华为账号</label><input type="text" id="f-username" placeholder="手机号 / 邮箱">
            <span class="tip">也可不填账号，改用「认证与安全」页的 cURL 导入（免密码）</span></div>
          <div class="field"><label>密码</label><input type="password" id="f-password" placeholder="留空保持不变">
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

  credentialPayload() {
    const u = $("f-username");
    if (!u) return null;
    const payload = { username: u.value.trim() };
    const pw = $("f-password") ? $("f-password").value : "";
    if ($("f-password-clear") && $("f-password-clear").checked) payload.password = "__clear__";
    else if (pw) payload.password = pw;
    return payload;
  },

  /* -- 新建向导：凭据字段（切换到其他平台时返回内容被整体替换） -- */
  wizardCredHtml() {
    return `
      <div class="field" id="w-cred-fields"><label>账号（手机号/邮箱）</label><input type="text" id="w-username" placeholder="用于登录态过期后自动重登，可留空" value="${esc(wiz.input.username)}" oninput="wiz.input.username=this.value">
      </div>
      <div class="field" id="w-pass-fields"><label>密码</label><input type="password" id="w-password" placeholder="用于自动重登，可留空" value="${esc(wiz.input.password)}" oninput="wiz.input.password=this.value">
        <span class="tip">保存于应用私有数据目录（chmod 600），不发往任何第三方；也可创建后仅用 cURL 导入会话</span></div>`;
  },

  collectWizardCred() {
    return {
      username: ($("w-username") ? $("w-username").value : wiz.input.username || "").trim(),
      password: $("w-password") ? $("w-password").value : (wiz.input.password || ""),
    };
  },

  wizardFinishHint() {
    return `· 华为账号登录通常需要输入短信验证码（二次验证），在该页按提示操作即可<br>
      · 若未填写账号密码，可在该页使用「cURL 导入」直接导入登录态`;
  },
});

/* ---------- 华为账密登录 + 2FA（模块自治，模板内联 onclick 调用） ---------- */

function showTwoFa(channels, note) {
  $("twofa-panel").style.display = "";
  $("twofa-code").value = "";
  const list = (channels && channels.length ? channels : []).map((c, i) => `
    <div class="chan-row"><input type="radio" name="chan" ${i === 0 ? "checked" : ""} data-chan='${esc(JSON.stringify(c))}'>
      <span>${c.accountType === 1 ? "手机" : "邮箱"}：${esc(c.name || "-")}${c.sent ? "（验证码已发送）" : ""}</span></div>`).join("");
  $("twofa-channels").innerHTML = `${note ? `<div class="tip" style="margin-bottom:6px">${esc(note)}</div>` : ""}
    ${list || `<div class="tip">验证码已发送，直接输入即可。</div>`}`;
}

async function webLogin() {
  const id = curId(); if (!id) return;
  const btn = $("btn-login"); btn.disabled = true;
  $("login-output").innerHTML = `<span class="spin"></span> 登录中，最长约 30 秒…`;
  $("twofa-panel").style.display = "none";
  try {
    const r = await api(`accounts/${id}/auth/login`, { method: "POST", body: {} });
    if (r.status === "2fa_required") {
      $("login-output").innerHTML = `<div class="banner warn">${esc(r.message)}</div>`;
      showTwoFa(r.channels, "请选择接收通道并输入验证码：");
    } else {
      $("login-output").innerHTML = `<div class="banner" style="background:#e7f6ee;color:#147a45;border:1px solid #bfe8d1">${esc(r.message)}</div>`;
      toast("登录成功", "ok");
    }
  } catch (e) {
    $("login-output").innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    refreshAuth();
  }
}

async function submit2fa() {
  const code = $("twofa-code").value.trim();
  if (!/^\d{6}$/.test(code)) { toast("请输入 6 位数字验证码", "err"); return; }
  const btn = $("btn-2fa"); btn.disabled = true;
  try {
    const r = await api(`accounts/${curId()}/auth/2fa`, { method: "POST", body: { code } });
    if (r.status === "2fa_required") {
      showTwoFa(r.channels, "验证码校验未通过，请重新输入：");
      toast("验证码校验未通过", "err");
    } else {
      $("twofa-panel").style.display = "none";
      $("login-output").innerHTML = `<div class="banner" style="background:#e7f6ee;color:#147a45;border:1px solid #bfe8d1">${esc(r.message)}</div>`;
      toast("二次验证通过", "ok");
    }
  } catch (e) { toast(e.message, "err"); }
  finally { btn.disabled = false; refreshAuth(); }
}

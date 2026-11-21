"use strict";
/* iCloud 云相册平台模块：Apple ID/密码登录 + 双重认证/两步验证。
 *
 * 会话由服务端受信任会话机制恢复；本平台不支持 cURL 导入、扫码或云删除。
 */
PlatformUI.register("icloud", {
  label: "iCloud 云相册",
  userIdLabel: "Apple ID",
  wizardDesc: "Apple ID / 密码登录，支持双重认证与两步验证",

  albumTip() { return "iCloud 包含用户相册与智能相册；图库和单相册计数不作全库遍历统计"; },

  authSummaryRows(a) {
    const rows = [
      ["已保存 Apple ID 密码", a.credentials_configured ? "是" : "否"],
      ["会话更新时间", a.session_updated_at ? fmtTs(a.session_updated_at) : "—"],
    ];
    if (a.pending_2fa) {
      const flow = a.pending_2fa.flow === "2sa" ? "两步验证（2SA）" : "双重认证（2FA）";
      rows.push(["待二次验证", `<span class="badge warn">${flow}</span> ${fmtTs(a.pending_2fa.created_at)}`]);
    }
    return rows;
  },

  renderAuthMethods(accountId) {
    const mount = $("auth-methods-mount");
    if (!mount || this._mountedFor === accountId) return;
    this._mountedFor = accountId;
    mount.innerHTML = `
      <div class="card">
        <h2>Apple ID 登录 <span class="hint">使用「同步设置」中保存的 Apple ID、密码和账号区域</span></h2>
        <div class="btn-row">
          <button class="btn primary" id="icloud-btn-login" onclick="iCloudWebLogin()">使用已保存账号登录</button>
        </div>
        <div id="icloud-login-output" style="margin-top:12px"></div>
        <div id="icloud-twofa-panel" style="display:none">
          <div class="section-title">Apple 二次验证</div>
          <div id="icloud-twofa-channels"></div>
          <div class="btn-row" style="margin-top:8px">
            <input type="text" class="code-input" id="icloud-twofa-code" maxlength="6" placeholder="______" inputmode="numeric" autocomplete="one-time-code">
            <button class="btn primary" id="icloud-btn-2fa" onclick="iCloudSubmit2fa()">提交验证码</button>
          </div>
          <div class="tip" style="margin-top:6px;color:var(--muted);font-size:12px">验证码为 6 位数字。验证通过后会保存受信任会话，后续过期可自动尝试恢复。</div>
        </div>
      </div>`;
  },

  onAuthRefresh(a) {
    if (a.pending_2fa) iCloudShowChallenge(a.pending_2fa, "检测到未完成的二次验证，可直接提交验证码：");
  },

  renderSettingsCred(mount, accountId) {
    if (!mount || this._credFor === accountId) return;
    this._credFor = accountId;
    mount.innerHTML = `
      <div class="card" id="cred-card">
        <h2>账号与认证 <span class="hint">密码以密文保存在 NAS 本地（密钥文件 secret.key，均 chmod 600），提交后不再回显</span></h2>
        <div class="form-grid">
          <div class="field"><label>Apple ID</label><input type="text" id="f-username" placeholder="Apple ID 邮箱或手机号" autocomplete="username"></div>
          <div class="field"><label>密码</label><input type="password" id="f-password" placeholder="留空保持不变" autocomplete="current-password">
            <span class="tip"><label style="font-weight:400"><input type="checkbox" id="f-password-clear" style="vertical-align:-2px"> 清除已保存的密码</label></span></div>
          <div class="field"><label>账号区域</label><select id="f-domain">
            <option value="com">国际区（icloud.com）</option>
            <option value="cn">中国区（icloud.com.cn）</option>
          </select><span class="tip">需与 Apple ID 实际区域一致</span></div>
        </div>
      </div>`;
  },

  onConfigLoaded(c) {
    const u = $("f-username");
    if (!u) return;
    u.value = c.username || "";
    $("f-password").value = "";
    $("f-password-clear").checked = false;
    $("f-domain").value = c.domain === "cn" ? "cn" : "com";
  },

  credentialPayload() {
    const u = $("f-username");
    if (!u) return null;
    const payload = {
      username: u.value.trim(),
      domain: $("f-domain").value === "cn" ? "cn" : "com",
    };
    const pw = $("f-password") ? $("f-password").value : "";
    if ($("f-password-clear") && $("f-password-clear").checked) payload.password = "__clear__";
    else if (pw) payload.password = pw;
    return payload;
  },

  wizardCredHtml() {
    const domain = wiz.input.domain === "cn" ? "cn" : "com";
    return `
      <div class="field"><label>Apple ID</label><input type="text" id="w-username" placeholder="Apple ID 邮箱或手机号" value="${esc(wiz.input.username)}" oninput="wiz.input.username=this.value" autocomplete="username"></div>
      <div class="field"><label>密码</label><input type="password" id="w-password" placeholder="用于登录和受信任会话失效后的自动重登" value="${esc(wiz.input.password)}" oninput="wiz.input.password=this.value" autocomplete="current-password">
        <span class="tip">密码加密保存于应用私有数据目录，不会回显</span></div>
      <div class="field"><label>账号区域</label><select id="w-domain" onchange="wiz.input.domain=this.value">
        <option value="com" ${domain === "com" ? "selected" : ""}>国际区（icloud.com）</option>
        <option value="cn" ${domain === "cn" ? "selected" : ""}>中国区（icloud.com.cn）</option>
      </select></div>`;
  },

  collectWizardCred() {
    return {
      username: ($("w-username") ? $("w-username").value : wiz.input.username || "").trim(),
      password: $("w-password") ? $("w-password").value : (wiz.input.password || ""),
      domain: ($("w-domain") ? $("w-domain").value : wiz.input.domain) === "cn" ? "cn" : "com",
    };
  },

  wizardFinishHint() {
    return `· 使用已保存的 Apple ID 和密码登录，按页面提示完成双重认证或两步验证<br>
      · 若账号区域选择错误，请先在「同步设置」中修正后重新登录`;
  },
});

function iCloudShowChallenge(pending, note, resetCode = false) {
  const panel = $("icloud-twofa-panel");
  if (!panel) return;
  panel.style.display = "";
  const code = $("icloud-twofa-code");
  if (resetCode) code.value = "";
  const flow = pending && pending.flow === "2sa" ? "两步验证（2SA）" : "双重认证（2FA）";
  const channels = (pending && pending.channels) || [];
  const list = channels.map((c, i) => `<div class="tip">· ${esc(c.name || "受信任设备")}${pending.flow === "2sa" && i === 0 ? "（验证码已发送至此设备）" : ""}</div>`).join("");
  $("icloud-twofa-channels").innerHTML = `
    <div class="tip" style="margin-bottom:6px">${esc(note || "")}</div>
    <div class="tip" style="margin-bottom:6px">验证方式：${flow}</div>
    ${list || '<div class="tip">请在受信任 Apple 设备上查看验证码。</div>'}`;
}

async function iCloudWebLogin() {
  const id = curId(); if (!id) return;
  const btn = $("icloud-btn-login"); btn.disabled = true;
  $("icloud-login-output").innerHTML = `<span class="spin"></span> 正在登录 Apple 服务…`;
  $("icloud-twofa-panel").style.display = "none";
  try {
    const r = await api(`accounts/${id}/auth/login`, { method: "POST", body: {} });
    if (r.status === "2fa_required") {
      $("icloud-login-output").innerHTML = `<div class="banner warn">${esc(r.message)}</div>`;
      iCloudShowChallenge({ channels: r.channels || [] }, "请输入收到的 6 位验证码：", true);
    } else {
      $("icloud-login-output").innerHTML = `<div class="banner" style="background:#e7f6ee;color:#147a45;border:1px solid #bfe8d1">${esc(r.message)}</div>`;
      toast("iCloud 登录成功", "ok");
    }
  } catch (e) {
    $("icloud-login-output").innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    refreshAuth();
  }
}

async function iCloudSubmit2fa() {
  const code = $("icloud-twofa-code").value.trim();
  if (!/^\d{6}$/.test(code)) { toast("请输入 6 位数字验证码", "err"); return; }
  const btn = $("icloud-btn-2fa"); btn.disabled = true;
  try {
    const r = await api(`accounts/${curId()}/auth/2fa`, { method: "POST", body: { code } });
    if (r.status === "2fa_required") {
      $("icloud-login-output").innerHTML = `<div class="banner warn">${esc(r.message)}</div>`;
      iCloudShowChallenge({ channels: r.channels || [] }, "验证码校验未通过，请重新输入：", true);
      toast("验证码校验未通过", "err");
    } else {
      $("icloud-twofa-panel").style.display = "none";
      $("icloud-login-output").innerHTML = `<div class="banner" style="background:#e7f6ee;color:#147a45;border:1px solid #bfe8d1">${esc(r.message)}</div>`;
      toast("Apple 二次验证通过", "ok");
    }
  } catch (e) {
    $("icloud-login-output").innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    refreshAuth();
  }
}

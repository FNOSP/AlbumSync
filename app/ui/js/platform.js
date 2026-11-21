"use strict";
/* 平台 UI 注册表：每个云相册平台一个独立模块，杜绝平台内容互相渗透。
 *
 * 新增平台 = 新建 js/platform-<id>.js 并 PlatformUI.register(<id>, {...})，
 * 通用页面（index.html）只调用本注册表，不出现任何平台名/平台分支。
 *
 * 模块对象接口约定（全部可选，按平台能力实现）：
 *   label              平台显示名（账号列表徽章 / 总览列 / 备份面板 / 向导）
 *   userIdLabel        认证状态里用户 ID 的显示标签（如「华为用户 ID」）
 *   wizardDesc         新建向导平台选项的副标题
 *   wizardCredHtml()   向导第一步凭据字段 HTML（不支持密码登录的平台返回 ""）
 *   collectWizardCred() 向导提交时收集凭据 {username, password}
 *   wizardFinishHint() 向导完成页的平台指引 HTML
 *   authSummaryRows(a) 认证状态平台差异行 [[label, valueHtml], ...]
 *   renderAuthMethods(accountId)  登录方式卡渲染到 #auth-methods-mount（按账号幂等）
 *   onAuthRefresh(a)   auth/status 刷新后的钩子（如华为 pending_2fa 弹 2FA 面板）
 *   applyCurlCopy()    cURL 导入卡的平台文案（#curl-card-hint / #curl-card-tip）
 *   renderSettingsCred(mount, accountId) 设置页凭据区渲染（按账号幂等）
 *   onConfigLoaded(c)  loadConfig 时回填本平台凭据字段
 *   credentialPayload() saveConfig 时收集凭据字段（无则返回 null）
 *   albumTip()         相册页平台行为差异提示（可空）
 *
 * 约定：模块渲染的 DOM 由模块自治（含事件绑定），通用层只提供挂载点并在
 * openAccount 时调用 resetMounts() 复位幂等缓存。工具函数（$/esc/api/toast/
 * fmtTs）由 index.html 主脚本提供，模块仅在运行时调用。
 */
const PlatformUI = {
  _mods: new Map(),

  register(id, mod) { this._mods.set(id, mod); },

  get(id) { return this._mods.get(id) || null; },

  ids() { return Array.from(this._mods.keys()); },

  /* 注册顺序第一个平台 = 新建向导默认平台（与后端 DEFAULT_PLATFORM 一致） */
  defaultId() { return this._mods.keys().next().value || ""; },

  /* 当前账号的平台模块（无账号 / 未知平台返回 null） */
  current() { return this.get(typeof curPlatform === "function" ? curPlatform() : ""); },

  label(id) { const m = this._mods.get(id); return m ? m.label : (id || "-"); },

  labelsText() { return Array.from(this._mods.values()).map(m => m.label).join(" / "); },

  /* 账号切换时复位各模块的按账号幂等缓存（强制重建挂载内容） */
  resetMounts() {
    for (const m of this._mods.values()) {
      m._mountedFor = null;
      m._credFor = null;
    }
  },

  /* 生成新建向导的平台单选卡片组 HTML */
  wizardPlatformCards(selectedId) {
    return Array.from(this._mods.entries()).map(([pid, m], i) => `
      <label style="display:flex;gap:8px;align-items:flex-start;border:1px solid var(--border);border-radius:8px;padding:10px 14px;cursor:pointer">
        <input type="radio" name="w-platform" value="${esc(pid)}" ${((selectedId || this.defaultId()) === pid) ? "checked" : ""} style="margin-top:3px;cursor:pointer" onchange="wizInputPlatform('${esc(pid)}')">
        <span><b>${esc(m.label)}</b><br><span class="tip">${esc(m.wizardDesc || "")}</span></span></label>`).join("");
  },

  /* 相册页平台提示拼接 */
  albumTipsText() {
    const tips = Array.from(this._mods.values()).map(m => m.albumTip ? m.albumTip() : "").filter(Boolean);
    return tips.length ? "注：" + tips.join("；") + "。" : "";
  },
};

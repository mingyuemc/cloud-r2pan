import adminHTML from "../public/admin.html";
import shareHTML from "../public/share.html";
import marketHTML from "../public/market.html";
import myHTML from "../public/my.html";
import { pickLang, type L10n } from "./i18n";

/**
 * 统一安全响应头 —— 加在所有 HTML / JSON / 下载响应上。
 * 零成本，浏览器级防护：
 *   - CSP：允许 self + Turnstile CDN（所有页面都可能用到），允许 inline（单文件 SPA 权衡）
 *   - X-Frame-Options：防点击劫持
 *   - X-Content-Type-Options：防 MIME 嗅探
 *   - Referrer-Policy：最小泄露
 *   - Permissions-Policy：禁用不需要的浏览器能力
 *
 * 注意：download 响应是流式的，这里的 headers 同样适用。
 */
export function addSecurityHeaders(headers: Headers, opts: { isDownload?: boolean } = {}): void {
  // CSP —— Turnstile 需要 challenges.cloudflare.com 的 script/frame/connect
  // 'unsafe-inline' 是必要的：三个 HTML 页面都是单文件 inline JS SPA
  const csp = opts.isDownload
    ? "default-src 'none'; style-src 'none'; script-src 'none'; frame-src 'none'; connect-src 'none'"
    : [
        "default-src 'self'",
        // ECharts + echarts-gl 从 jsdelivr CDN 加载（用于全球分布地球仪）
        "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "frame-src 'self' https://challenges.cloudflare.com",
        "connect-src 'self' https://challenges.cloudflare.com https://api.github.com https://api.google.com https://graph.microsoft.com https://discord.com",
        // ECharts 需要加载世界地图 GeoJSON
        "img-src 'self' data: https: https://cdn.jsdelivr.net",
        "form-action 'self'",
        "base-uri 'self'",
      ].join("; ");

  headers.set("Content-Security-Policy", csp);
  headers.set("X-Frame-Options", "DENY"); // 禁止被 iframe 嵌入（防点击劫持）
  headers.set("X-Content-Type-Options", "nosniff"); // 防 MIME 嗅探
  headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()");
}

/** 带安全头的 JSON 响应（API 统一用这个） */
export function json(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers ?? {});
  if (!headers.has("content-type")) headers.set("content-type", "application/json;charset=utf-8");
  addSecurityHeaders(headers);
  return new Response(JSON.stringify(body), { ...init, headers });
}

export function serveAdminPage(): Response {
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(adminHTML, { headers });
}

/**
 * 带 ETag 协商缓存的静态 HTML 服务。
 * market.html / share.html 是 bundle 里的固定字符串，不会在运行时变。
 * 用内容 hash 做 ETag，Cache-Control: max-age=0 让浏览器每次都校验。
 * 如果 If-None-Match 命中 → 返回 304（空 body），节省 15-45KB 带宽。
 * Worker 重新部署后 HTML 变了 → ETag 自然变 → 浏览器自动拿新版本。
 *
 * 安全考虑：内容是 bundle 里固定的，没有安全风险。admin.html 不走这个（必须 no-store）。
 */
async function serveStaticHTML(html: string, req: Request): Promise<Response> {
  // 用 SHA-256 前 16 字符当 ETag —— 轻量且足够唯一
  const encoder = new TextEncoder();
  const hashBytes = await crypto.subtle.digest("SHA-256", encoder.encode(html));
  let etag = '"';
  const bytes = new Uint8Array(hashBytes);
  for (let i = 0; i < 8; i++) etag += bytes[i].toString(16).padStart(2, "0");
  etag += '"';

  // 协商缓存命中 → 304 Not Modified
  const ifNoneMatch = req.headers.get("if-none-match");
  if (ifNoneMatch && ifNoneMatch.includes(etag)) {
    const headers = new Headers({
      "etag": etag,
      "cache-control": "public, max-age=0, must-revalidate",
    });
    addSecurityHeaders(headers);
    return new Response(null, { status: 304, headers });
  }

  const headers = new Headers({
    "content-type": "text/html;charset=utf-8",
    "cache-control": "public, max-age=0, must-revalidate",
    "etag": etag,
  });
  addSecurityHeaders(headers);
  return new Response(html, { headers });
}

export async function serveSharePage(req?: Request): Promise<Response> {
  if (req) return serveStaticHTML(shareHTML, req);
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(shareHTML, { headers });
}

export async function serveMarketPage(req?: Request): Promise<Response> {
  if (req) return serveStaticHTML(marketHTML, req);
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(marketHTML, { headers });
}

/** 成员前台 /my —— 会话态页面，no-store（与 admin 一致） */
export function serveMyPage(): Response {
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(myHTML, { headers });
}

/**
 * 根路径落地页 —— 成员与管理员统一登录入口（Edgechat 浅色玻璃风）。
 * 成员登录调用 /api/my/login，成功后进入 /my；管理员登录调用 /api/admin/login，成功后进入 /admin。
 */
export function serveLandingPage(): Response {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>cloud-r2pan</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{min-height:100%}
body{
  font-family:"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  color:#1f2521;min-height:100vh;position:relative;overflow-x:hidden;padding:24px 20px 70px;
  background:radial-gradient(circle at 12% 8%,rgba(45,156,151,.20),transparent 32%),radial-gradient(circle at 88% 16%,rgba(90,143,203,.18),transparent 34%),radial-gradient(circle at 76% 88%,rgba(90,143,203,.13),transparent 30%),radial-gradient(circle at 28% 72%,rgba(45,156,151,.11),transparent 26%),linear-gradient(180deg,#eef5f9 0%,#e6eef4 100%);
}
.orb{position:fixed;border-radius:50%;filter:blur(90px);opacity:.16;pointer-events:none;animation:drift 18s ease-in-out infinite alternate}
.o1{width:46vmax;height:46vmax;background:#2d9c97;top:-18%;left:-14%}
.o2{width:40vmax;height:40vmax;background:#5a8fcb;bottom:-20%;right:-10%;animation-delay:-6s}
.o3{width:30vmax;height:30vmax;background:#7fb0d6;top:55%;left:8%;animation-delay:-12s;opacity:.14}
@keyframes drift{from{transform:translate(0,0) scale(1)}to{transform:translate(6vw,-5vh) scale(1.12)}}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
.wrap{min-height:calc(100vh - 94px);display:flex;align-items:center;justify-content:center}
.card{
  width:100%;max-width:420px;padding:32px 30px 26px;border-radius:20px;position:relative;z-index:1;
  background:rgba(252,252,252,.55);
  backdrop-filter:blur(30px) saturate(125%);-webkit-backdrop-filter:blur(30px) saturate(125%);
  border:1px solid rgba(255,255,255,.55);
  box-shadow:0 8px 24px rgba(0,0,0,.12),inset 0 0 0 1px rgba(255,255,255,.18);
  animation:rise .48s cubic-bezier(.22,1,.36,1) both;
}
.head{display:flex;align-items:center;gap:12px;margin-bottom:22px}
.logo{width:46px;height:46px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:24px;background:rgba(252,252,252,.55);border:1px solid rgba(255,255,255,.55);box-shadow:inset 0 0 0 1px rgba(255,255,255,.18)}
.head h1{font-size:17px;font-weight:700;letter-spacing:-.02em}
.head .sub{font-size:12px;color:rgba(31,37,33,.55);margin-top:2px}
.tabs{display:flex;gap:6px;padding:4px;border-radius:12px;background:rgba(255,255,255,.42);border:1px solid rgba(88,107,124,.18);margin-bottom:20px}
.tabs button{flex:1;padding:10px;border:none;border-radius:9px;background:transparent;color:rgba(31,37,33,.55);font-size:14px;font-weight:600;cursor:pointer;transition:all .18s}
.tabs button.active{background:#ffffff;color:#1f2521;box-shadow:0 1px 2px rgba(13,23,49,.08)}
.field{margin-bottom:14px;text-align:left}
.field label{display:block;font-size:12px;color:rgba(31,37,33,.55);margin-bottom:6px;padding-left:4px}
input{width:100%;padding:12px 14px;border-radius:14px;font-size:15px;color:#1f2521;outline:none;background:linear-gradient(180deg,rgba(255,255,255,.56),rgba(236,243,249,.4)),rgba(228,236,243,.26);border:1px solid rgba(88,107,124,.22);box-shadow:inset 0 1px 0 rgba(255,255,255,.52),0 1px 2px rgba(88,107,124,.06);transition:border-color .2s,box-shadow .2s}
input::placeholder{color:rgba(31,37,33,.52)}
input:focus{border-color:rgba(45,156,151,.42);box-shadow:0 0 0 3px rgba(45,156,151,.12)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:12px 20px;border-radius:14px;border:none;cursor:pointer;font-size:14px;font-weight:600;color:#fffaf2;background:linear-gradient(180deg,rgba(90,143,203,.92),rgba(69,121,186,.88));box-shadow:0 4px 16px rgba(90,143,203,.22);transition:transform .28s cubic-bezier(.37,0,.63,1),box-shadow .28s cubic-bezier(.37,0,.63,1)}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(90,143,203,.3)}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none}
.msg{margin-top:14px;font-size:13px;min-height:18px;text-align:center}
.msg.err{color:#b42318}.msg.ok{color:#17857c}
.ts-box{display:flex;justify-content:center;margin:4px 0 14px}
.ts-box:empty{display:none}
.links{margin-top:18px;display:flex;gap:14px;justify-content:center;flex-wrap:wrap;font-size:13px}
.links a{color:#17857c;text-decoration:none;cursor:pointer}
.links a.muted{color:rgba(31,37,33,.5)}
.hidden{display:none!important}
.lang-btn{position:fixed;top:18px;right:18px;padding:6px 14px;border-radius:12px;border:1px solid rgba(255,255,255,.5);background:rgba(252,252,252,.55);color:#1f2521;font-size:12px;cursor:pointer}
footer{position:fixed;bottom:20px;left:0;right:0;text-align:center;font-size:12px;color:rgba(31,37,33,.42)}
</style>
</head>
<body>
<div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
<button class="lang-btn" id="lang"></button>
<div class="wrap">
  <div class="card">
    <div class="head">
      <div class="logo">🗂️</div>
      <div><h1>cloud-r2pan</h1><div class="sub" id="sub"></div></div>
    </div>
    <div class="tabs">
      <button id="tab-member" class="active"></button>
      <button id="tab-admin"></button>
    </div>
    <div id="pane-member">
      <div class="field"><label id="l-user"></label><input id="m-user" autocomplete="username"></div>
      <div class="field"><label id="l-pass"></label><input id="m-pass" type="password" autocomplete="current-password"></div>
      <button class="btn" id="m-btn"></button>
      <div class="links"><a id="to-register"></a><a class="muted" href="/market" id="to-market"></a></div>
    </div>
    <div id="pane-admin" class="hidden">
      <div class="field"><label id="l-auser"></label><input id="a-user" autocomplete="username"></div>
      <div class="field"><label id="l-apass"></label><input id="a-pass" type="password" autocomplete="current-password"></div>
      <div class="field hidden" id="f-code"><label id="l-code"></label><input id="a-code" inputmode="numeric"></div>
      <button class="btn" id="a-btn"></button>
    </div>
    <div class="ts-box" id="ts"></div>
    <div class="msg" id="msg"></div>
  </div>
</div>
<footer>Powered by cloud-r2pan</footer>
<script>
(function(){
  var I18N={
    zh:{sub:'成员与管理员统一登录入口',member:'成员登录',admin:'管理员登录',
      user:'用户名',pass:'密码',login:'登录',adminUser:'管理员账号或密钥',adminPass:'密码（用密钥登录时留空）',
      code:'2FA 验证码',register:'注册新账号',market:'文件市场',
      need2fa:'请输入 2FA 验证码',bad:'用户名或密码错误',net:'网络错误，请稍后再试',tsreq:'请先完成人机验证',lang:'EN'},
    en:{sub:'Unified sign-in for members and admins',member:'Member',admin:'Admin',
      user:'Username',pass:'Password',login:'Sign in',adminUser:'Admin account or key',adminPass:'Password (leave empty when using the key)',
      code:'2FA code',register:'Register',market:'Marketplace',
      need2fa:'Enter your 2FA code',bad:'Invalid username or password',net:'Network error, please try later',tsreq:'Please complete the human verification first',lang:'中文'}
  };
  var lang='';
  try{ var s=localStorage.getItem('cd_lang'); if(s==='zh'||s==='en') lang=s; }catch(e){}
  if(!lang){ var f=String((navigator.languages&&navigator.languages[0])||navigator.language||'').toLowerCase(); lang=f.indexOf('zh')===0?'zh':'en'; }
  function $(id){ return document.getElementById(id); }
  function t(k){ return (I18N[lang]&&I18N[lang][k])||I18N.en[k]||k; }
  function render(){
    document.documentElement.lang = lang==='zh'?'zh-CN':'en';
    $('sub').textContent=t('sub');
    $('tab-member').textContent=t('member');
    $('tab-admin').textContent=t('admin');
    $('l-user').textContent=t('user'); $('l-pass').textContent=t('pass'); $('m-btn').textContent=t('login');
    $('l-auser').textContent=t('adminUser'); $('l-apass').textContent=t('adminPass'); $('a-btn').textContent=t('login');
    $('l-code').textContent=t('code');
    $('to-register').textContent=t('register');
    $('to-market').textContent=t('market');
    $('lang').textContent=t('lang');
  }
  function show(text,kind){ var el=$('msg'); el.textContent=text; el.className='msg '+(kind||''); }
  function setMode(m){
    var isM = m==='member';
    $('tab-member').className = isM?'active':'';
    $('tab-admin').className = isM?'':'active';
    $('pane-member').className = isM?'':'hidden';
    $('pane-admin').className = isM?'hidden':'';
    show('','');
  }
  function post(url,body){
    return fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}).then(function(r){
      return r.json().then(function(d){ return {ok:r.ok,d:d}; }).catch(function(){ return {ok:r.ok,d:{}}; });
    });
  }
  /* ── Turnstile 人机验证 ── */
  var TS={required:false,sitekey:null,widgetId:null,token:''};
  var tsApiLoading=null;
  function loadTurnstileApi(cb){
    if(window.turnstile) return cb();
    if(!tsApiLoading){
      tsApiLoading=new Promise(function(res){
        var s=document.createElement('script');
        s.src='https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
        s.async=true; s.defer=true;
        s.onload=function(){res();}; s.onerror=function(){res();};
        document.head.appendChild(s);
      });
    }
    tsApiLoading.then(cb);
  }
  function renderTurnstile(){
    TS.token=''; TS.widgetId=null;
    var el=$('ts'); if(!el) return;
    el.innerHTML='';
    if(!TS.required||!TS.sitekey) return;
    loadTurnstileApi(function(){
      if(!el||!window.turnstile) return;
      try{
        TS.widgetId=window.turnstile.render(el,{
          sitekey:TS.sitekey,
          callback:function(tok){TS.token=tok;},
          'expired-callback':function(){TS.token='';},
          'error-callback':function(){TS.token='';}
        });
      }catch(e){}
    });
  }
  function resetTurnstile(){
    TS.token='';
    try{ if(TS.widgetId!=null&&window.turnstile) window.turnstile.reset(TS.widgetId); }catch(e){}
  }
  function initTurnstile(){
    fetch('/api/turnstile').then(function(r){return r.json();}).then(function(d){
      TS.required=!!d.login; TS.sitekey=d.sitekey||null;
    }).catch(function(){}).then(function(){ renderTurnstile(); });
  }
  $('lang').onclick=function(){ lang = lang==='zh'?'en':'zh'; try{localStorage.setItem('cd_lang',lang);}catch(e){} render(); };
  $('tab-member').onclick=function(){ setMode('member'); };
  $('tab-admin').onclick=function(){ setMode('admin'); };
  $('to-register').onclick=function(){ location.href='/my'; };
  $('m-btn').onclick=function(){
    var u=$('m-user').value.trim(), p=$('m-pass').value, btn=this;
    if(!u||!p){ show(t('bad'),'err'); return; }
    if(TS.required&&!TS.token){ show(t('tsreq'),'err'); return; }
    btn.disabled=true;
    post('/api/my/login',{username:u,password:p,turnstile:TS.token}).then(function(res){
      btn.disabled=false;
      if(res.ok&&res.d.ok){ location.href='/my'; return; }
      show((res.d&&res.d.error)||t('bad'),'err'); resetTurnstile();
    }).catch(function(){ btn.disabled=false; show(t('net'),'err'); resetTurnstile(); });
  };
  $('a-btn').onclick=function(){
    var user=$('a-user').value.trim(), pass=$('a-pass').value, code=$('a-code').value.trim(), btn=this;
    if(!user){ show(t('bad'),'err'); return; }
    if(TS.required&&!TS.token){ show(t('tsreq'),'err'); return; }
    var body = pass ? {username:user,password:pass} : {key:user};
    if(code) body.code=code;
    body.turnstile = TS.token;
    btn.disabled=true;
    post('/api/admin/login',body).then(function(res){
      btn.disabled=false;
      if(res.d&&res.d.need_2fa){ $('f-code').className='field'; show(t('need2fa'),''); resetTurnstile(); return; }
      if(res.ok&&res.d.ok){ location.href='/admin'; return; }
      show((res.d&&res.d.error)||t('bad'),'err'); resetTurnstile();
    }).catch(function(){ btn.disabled=false; show(t('net'),'err'); resetTurnstile(); });
  };
  render();
  initTurnstile();
})();
</script>
</body>
</html>`;
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(html, { headers });
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)
  );
}

/** iOS 26 液态玻璃风格的错误/状态页（封禁、过期、限额等），文案跟随访客语言 */
export function errorPage(
  req: Request,
  status: number,
  title: L10n,
  message: L10n,
  opts: { siteTitle?: string; oauth_login_url?: string } = {}
): Response {
  const lang = pickLang(req);
  const site = esc(opts.siteTitle ?? "cloud-r2pan");
  const icons: Record<number, string> = {
    401: "🔐",
    403: "🚫",
    404: "🔍",
    410: "⏳",
    416: "📏",
    503: "🛑",
  };
  const loginBtn = opts.oauth_login_url
    ? `<div style="margin-top:28px"><a href="${esc(opts.oauth_login_url)}" style="display:inline-block;padding:12px 34px;border-radius:14px;background:linear-gradient(180deg,rgba(90,143,203,.92),rgba(69,121,186,.88));color:#fffaf2;text-decoration:none;font-weight:600;font-size:15px;box-shadow:0 4px 16px rgba(90,143,203,.22);transition:transform .28s cubic-bezier(.37,0,.63,1),box-shadow .28s cubic-bezier(.37,0,.63,1)" onmouseover="this.style.transform='translateY(-1px)';this.style.boxShadow='0 8px 24px rgba(90,143,203,.3)'" onmouseout="this.style.transform='none';this.style.boxShadow='0 4px 16px rgba(90,143,203,.22)'">${lang === "zh" ? "登录下载" : "Login to Download"}</a></div>`
    : "";
  const html = `<!DOCTYPE html>
<html lang="${lang === "zh" ? "zh-CN" : "en"}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${esc(title[lang])} · ${site}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
html, body { height: 100%; }
body {
  font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  padding: 24px; color: #1f2521; overflow: hidden; position: relative;
  background: radial-gradient(circle at 12% 8%, rgba(45,156,151,.20), transparent 32%), radial-gradient(circle at 88% 16%, rgba(90,143,203,.18), transparent 34%), radial-gradient(circle at 76% 88%, rgba(90,143,203,.13), transparent 30%), radial-gradient(circle at 28% 72%, rgba(45,156,151,.11), transparent 26%), linear-gradient(180deg, #eef5f9 0%, #e6eef4 100%);
}
.orb { position: fixed; border-radius: 50%; filter: blur(90px); opacity: .18; pointer-events: none; animation: drift 18s ease-in-out infinite alternate; }
.o1 { width: 46vmax; height: 46vmax; background: #2d9c97; top: -18%; left: -14%; }
.o2 { width: 40vmax; height: 40vmax; background: #5a8fcb; bottom: -20%; right: -10%; animation-delay: -6s; }
.o3 { width: 30vmax; height: 30vmax; background: #7fb0d6; top: 55%; left: 8%; animation-delay: -12s; opacity: .16; }
@keyframes drift { from { transform: translate(0, 0) scale(1); } to { transform: translate(6vw, -5vh) scale(1.12); } }
.card {
  position: relative; width: 100%; max-width: 420px; text-align: center;
  padding: 56px 36px 44px; border-radius: 20px;
  background: rgba(252,252,252,.55);
  backdrop-filter: blur(30px) saturate(125%); -webkit-backdrop-filter: blur(30px) saturate(125%);
  border: 1px solid rgba(255,255,255,.55);
  box-shadow: 0 8px 24px rgba(0,0,0,.12), inset 0 0 0 1px rgba(255,255,255,.18);
  animation: rise .48s cubic-bezier(.22,1,.36,1) both;
}
@keyframes rise { from { opacity: 0; transform: translateY(24px) scale(.96); } to { opacity: 1; transform: none; } }
.icon {
  width: 84px; height: 84px; margin: 0 auto 22px; border-radius: 20px;
  display: flex; align-items: center; justify-content: center; font-size: 42px;
  background: rgba(252,252,252,.55);
  border: 1px solid rgba(255,255,255,.55);
  box-shadow: inset 0 0 0 1px rgba(255,255,255,.18), 0 8px 24px rgba(0,0,0,.1);
}
h1 { font-size: 24px; font-weight: 700; letter-spacing: -.02em; margin-bottom: 12px; }
p { font-size: 15px; line-height: 1.65; color: rgba(31,37,33,.6); }
.code { margin-top: 22px; font-size: 13px; color: rgba(31,37,33,.42); font-family: ui-monospace, "SF Mono", monospace; }
.brand { position: fixed; bottom: 22px; left: 0; right: 0; text-align: center; font-size: 13px; color: rgba(31,37,33,.42); letter-spacing: .08em; }
</style>
</head>
<body>
<div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
<div class="card">
  <div class="icon">${icons[status] ?? "⚠️"}</div>
  <h1>${esc(title[lang])}</h1>
  <p>${esc(message[lang])}</p>
  ${loginBtn}
  <div class="code">HTTP ${status}</div>
</div>
<div class="brand">Powered by ${site}</div>
</body>
</html>`;
  const headers = new Headers({ "content-type": "text/html;charset=utf-8", "cache-control": "no-store" });
  addSecurityHeaders(headers);
  return new Response(html, { status, headers });
}

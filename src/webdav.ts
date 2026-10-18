/**
 * WebDAV 协议实现 —— 挂载点 /webdav/*
 *
 * 支持的方法：
 *   OPTIONS   —— 探测 DAV 能力
 *   PROPFIND  —— 列出目录 / 文件属性（Depth: 0/1/infinity）
 *   GET       —— 下载文件
 *   HEAD      —— 仅返回文件元数据
 *   PUT       —— 上传/覆盖文件
 *   DELETE    —— 删除文件或空目录（非空目录递归删除）
 *   MKCOL     —— 创建目录
 *   MOVE      —— 移动 / 重命名 文件或目录
 *   COPY      —— 复制文件或目录
 *
 * 认证：HTTP Basic Auth，两套账号映射到两个互相隔离的空间：
 *   - 管理员/全局空间：设置里的 webdav_username / webdav_password_hash
 *     → 作用域 owner_id IS NULL（历史与后台上传的文件）
 *   - 成员空间：成员自己的用户名 / 密码（users 表，PBKDF2 校验）
 *     → 作用域 owner_id = 该成员 id，只能看到/操作自己的文件
 * 存储：复用 StorageProvider（R2 / S3），文件元数据存 D1 files 表，目录存 directories 表
 */

import type { Env } from "./types";
import { getSettings, getStorageUsedBytes, STORAGE_LIMIT_BYTES } from "./settings";
import { sha256Hex, safeEqual } from "./crypto";
import { createStorageProvider, type StorageProvider } from "./storage";
import { randomId } from "./db";
import { getUserByUsername, isUserUsable, verifyUserPassword } from "./authz";

/* ═══════════ 懒加载 StorageProvider ═══════════ */
let _storagePromise: Promise<StorageProvider> | null = null;
async function storage(env: Env): Promise<StorageProvider> {
  if (!_storagePromise) {
    _storagePromise = (async () => {
      const s = await getSettings(env);
      return createStorageProvider(env, s);
    })();
  }
  return _storagePromise;
}

/* ═══════════ 工具函数 ═══════════ */

/** 路径标准化：确保以 / 开头，不以 / 结尾（根目录除外） */
function normPath(p: string): string {
  p = decodeURIComponent(p);
  p = p.replace(/\\/g, "/").replace(/\/+/g, "/");
  if (!p.startsWith("/")) p = "/" + p;
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

/** 从 WebDAV URL 提取内部路径（去掉 /webdav 前缀） */
function extractInternalPath(urlPath: string): string {
  // /webdav         → /
  // /webdav/        → /
  // /webdav/foo.txt → /foo.txt
  // /webdav/dir/a.txt → /dir/a.txt
  const stripped = urlPath.replace(/^\/webdav/, "");
  return normPath(stripped || "/");
}

/** 从完整 URL 构建 WebDAV href（用于 PROPFIND 响应） */
function buildHref(baseUrl: string, internalPath: string): string {
  const u = new URL(baseUrl);
  const clean = internalPath === "/" ? "" : internalPath;
  return `${u.origin}/webdav${clean}/`;
}

/** RFC 1123 日期格式 */
function rfc1123(date: Date): string {
  return date.toUTCString().replace(/GMT$/, "GMT");
}

/** 将毫秒时间戳转 RFC 1123 */
function tsToRfc1123(ts: number): string {
  return rfc1123(new Date(ts));
}

/* ═══════════ Basic Auth 认证 ═══════════ */

/** 已解析的 WebDAV 身份上下文 */
interface WebDavAuth {
  /** null = 管理员/全局空间（owner_id IS NULL）；否则为成员 id */
  scopeOwnerId: string | null;
  isAdmin: boolean;
  username: string;
  /** 成员个人配额（null = 不限，仅受全局上限约束） */
  quotaBytes: number | null;
}

/** 解析 Basic Auth 头 → {username, password} 或 null */
function parseBasicAuth(authHeader: string | null): { username: string; password: string } | null {
  if (!authHeader || !authHeader.startsWith("Basic ")) return null;
  try {
    const decoded = atob(authHeader.slice(6));
    const i = decoded.indexOf(":");
    if (i < 0) return null;
    return { username: decoded.slice(0, i), password: decoded.slice(i + 1) };
  } catch {
    return null;
  }
}

/**
 * 验证 WebDAV Basic Auth，返回身份上下文（含空间作用域）。
 *   - 设置里的固定管理员账号 → 全局空间（owner_id IS NULL）
 *   - users 表里的账号（任意可用用户）→ 自己的空间（owner_id = 该用户 id）
 */
async function checkWebDAVAuth(req: Request, env: Env): Promise<WebDavAuth | null> {
  const settings = await getSettings(env);
  if (!settings.webdavEnabled) return null;

  const auth = parseBasicAuth(req.headers.get("authorization"));
  if (!auth) return null;

  // ① 管理员空间：设置里的固定账号（密码校验：salt:sha256(salt:password)）
  if (settings.webdavPasswordHash && auth.username === settings.webdavUsername) {
    const stored = settings.webdavPasswordHash;
    const i = stored.indexOf(":");
    if (i > 0) {
      const salt = stored.slice(0, i);
      const want = stored.slice(i + 1);
      const got = await sha256Hex(salt + ":" + auth.password);
      if (safeEqual(want, got)) {
        return { scopeOwnerId: null, isAdmin: true, username: auth.username, quotaBytes: null };
      }
    }
    // 用户名命中管理员账号但密码错误：直接拒绝，不再回退成员表（避免账号歧义）
    return null;
  }

  // ② 成员空间：users 表里的账号
  const u = await getUserByUsername(env, auth.username);
  if (!u || !isUserUsable(u)) return null;
  if (!(await verifyUserPassword(auth.password, u.password_hash, u.password_salt))) return null;
  return { scopeOwnerId: u.id, isAdmin: false, username: u.username, quotaBytes: u.quota_bytes };
}

/* ═══════════ 数据库辅助查询（全部按 owner 作用域隔离）═══════════ */

interface DBFile {
  id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  path: string;
  uploaded_at: number;
}

/** 查找一个文件（精确 path + name，限定在 owner 空间内） */
async function findFile(env: Env, owner: string | null, dir: string, name: string): Promise<DBFile | null> {
  const path = dir === "/" ? `/${name}` : `${dir}/${name}`;
  const base = "SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path = ? AND name = ?";
  if (owner === null) {
    return await env.db.prepare(base + " AND owner_id IS NULL").bind(path, name).first<DBFile>();
  }
  return await env.db.prepare(base + " AND owner_id = ?").bind(path, name, owner).first<DBFile>();
}

/** 查找目录是否存在（directories 表 或 有文件直接在其中），限定 owner 空间 */
async function directoryExists(env: Env, owner: string | null, path: string): Promise<boolean> {
  path = path === "/" ? "/" : path.replace(/\/$/, "");
  if (path === "/") return true; // 根目录永远存在
  const ownerKey = owner ?? ""; // admin 空间用空串（directories 复合主键不接受 NULL）
  // directories 表
  const dir: any = await env.db
    .prepare("SELECT 1 FROM directories WHERE path = ? AND owner_key = ?")
    .bind(path, ownerKey)
    .first();
  if (dir) return true;
  // 有文件直接在这个目录下（不是子目录）
  const child: any =
    owner === null
      ? await env.db.prepare("SELECT 1 FROM files WHERE path = ? AND owner_id IS NULL LIMIT 1").bind(path).first()
      : await env.db.prepare("SELECT 1 FROM files WHERE path = ? AND owner_id = ? LIMIT 1").bind(path, owner).first();
  if (child) return true;
  // 有文件以这个目录开头（更深层）—— 也算存在
  const deeper: any =
    owner === null
      ? await env.db.prepare("SELECT 1 FROM files WHERE path LIKE ? AND owner_id IS NULL LIMIT 1").bind(path + "/%").first()
      : await env.db.prepare("SELECT 1 FROM files WHERE path LIKE ? AND owner_id = ? LIMIT 1").bind(path + "/%", owner).first();
  return !!deeper;
}

/** 列出目录的直接子项（文件 + 子目录），限定 owner 空间 */
async function listDirChildren(
  env: Env,
  owner: string | null,
  path: string
): Promise<{ files: DBFile[]; dirs: string[] }> {
  path = path === "/" ? "" : path; // 查询时根目录用 "" 前缀
  const nextSlash = path ? path + "/" : "/";

  // 1. 直接子文件：path = 父路径 + "/" + name（精确）
  const filesLike = path === "" ? "/%" : path + "/%";
  const { results: files } =
    owner === null
      ? await env.db
          .prepare("SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path LIKE ? AND owner_id IS NULL")
          .bind(filesLike)
          .all<DBFile>()
      : await env.db
          .prepare("SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path LIKE ? AND owner_id = ?")
          .bind(filesLike, owner)
          .all<DBFile>();

  // 过滤出直接子文件（不是子目录里的）
  const directFiles: DBFile[] = [];
  const subDirSet = new Set<string>();

  for (const f of files) {
    // f.path 类似 "/foo" 或 "/dir/file.txt"
    const relPath = f.path;
    if (path === "") {
      // 根目录下："/foo" → 直接子项；"/sub/foo" → 子目录项
      const parts = relPath.split("/").filter(Boolean);
      if (parts.length === 1) {
        directFiles.push(f);
      } else if (parts.length >= 2) {
        subDirSet.add("/" + parts[0]);
      }
    } else {
      // 子目录下：path="/dir"，f.path="/dir/sub" 或 "/dir/file.txt"
      const rest = relPath.slice(nextSlash.length); // 去掉 "/dir/" 前缀
      if (!rest) continue;
      const slashIdx = rest.indexOf("/");
      if (slashIdx < 0) {
        // 直接子文件
        directFiles.push(f);
      } else {
        // 属于某个子目录
        subDirSet.add(nextSlash + rest.slice(0, slashIdx));
      }
    }
  }

  // 2. directories 表里显式创建的子目录
  const dirPrefix = path === "" ? "/" : nextSlash;
  const excludeSelf = path === "" ? "/" : path;
  const ownerKey = owner ?? "";
  const { results: explicitDirs } = await env.db
    .prepare("SELECT path FROM directories WHERE path LIKE ? AND path != ? AND owner_key = ?")
    .bind(dirPrefix + "%", excludeSelf, ownerKey)
    .all<{ path: string }>();

  for (const d of explicitDirs) {
    if (path === "") {
      // 只取第一段
      const parts = d.path.split("/").filter(Boolean);
      if (parts.length >= 1) subDirSet.add("/" + parts[0]);
    } else {
      const rest = d.path.slice(nextSlash.length); // 去掉 "/dir/" 前缀
      if (!rest) continue;
      const slashIdx = rest.indexOf("/");
      if (slashIdx < 0) {
        subDirSet.add(d.path);
      } else {
        subDirSet.add(nextSlash + rest.slice(0, slashIdx));
      }
    }
  }

  return { files: directFiles, dirs: Array.from(subDirSet).sort() };
}

/** 某成员已占用的存储字节数（仅统计自己名下的文件） */
async function ownerUsedBytes(env: Env, ownerId: string): Promise<number> {
  const row = await env.db
    .prepare("SELECT COALESCE(SUM(size), 0) AS total FROM files WHERE owner_id = ?")
    .bind(ownerId)
    .first<{ total: number }>();
  return Number(row?.total ?? 0) || 0;
}

/* ═══════════ PROPFIND XML 生成 ═══════════ */

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function filePropstatAsFile(file: DBFile, href: string): string {
  const displayName = escapeXml(file.name);
  const mime = escapeXml(file.mime || "application/octet-stream");
  const lastModified = tsToRfc1123(file.uploaded_at);
  const creationDate = new Date(file.uploaded_at).toISOString();
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype/>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontentlength>${file.size}</getcontentlength>
        <getcontenttype>${mime}</getcontenttype>
        <getetag>"${file.id}"</getetag>
        <getlastmodified>${lastModified}</getlastmodified>
        <creationdate>${creationDate}</creationdate>
        <displayname>${displayName}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

/** 目录自身的 propstat */
function dirPropstat(path: string, baseUrl: string): string {
  const href = buildHref(baseUrl, path);
  const displayName = path === "/" ? "/" : path.split("/").filter(Boolean).pop() || "";
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype><collection/></resourcetype>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontenttype>httpd/unix-directory</getcontenttype>
        <getlastmodified>${tsToRfc1123(Date.now())}</getlastmodified>
        <creationdate>${new Date().toISOString()}</creationdate>
        <displayname>${escapeXml(displayName)}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

/** 生成 multistatus XML 响应 */
function multistatusXML(responses: string[]): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">${responses.join("")}
</D:multistatus>`;
}

/* ═══════════ WebDAV 主入口 ═══════════ */

export async function handleWebDAV(
  req: Request,
  env: Env,
  _ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(req.url);
  const method = req.method.toUpperCase();
  const internalPath = extractInternalPath(url.pathname);

  // 1. OPTIONS —— 不强制认证（让客户端先探测能力）
  if (method === "OPTIONS") {
    return new Response("", {
      status: 200,
      headers: {
        "Allow": "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY",
        "DAV": "1, 2, 3",
        "Accept-Ranges": "bytes",
        "Cache-Control": "no-store",
      },
    });
  }

  // 2. 认证 —— 同时解析出所属空间作用域
  const auth = await checkWebDAVAuth(req, env);
  if (!auth) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": `Basic realm="cloud-r2pan WebDAV"`,
        "Content-Type": "text/plain",
      },
    });
  }

  // 3. 根路径限制（仅管理员空间的设置生效）
  if (auth.isAdmin) {
    const settings = await getSettings(env);
    if (settings.webdavRootPath && settings.webdavRootPath !== "/") {
      const root = settings.webdavRootPath.replace(/\/+$/, "") || "/";
      if (!internalPath.startsWith(root)) {
        return new Response("Forbidden", { status: 403 });
      }
    }
  }

  const owner = auth.scopeOwnerId;

  // 4. 分发到各方法处理
  switch (method) {
    case "PROPFIND":
      return handlePropfind(req, env, url, internalPath, owner);
    case "GET":
      return handleWebDavGet(req, env, internalPath, owner, false);
    case "HEAD":
      return handleWebDavGet(req, env, internalPath, owner, true);
    case "PUT":
      return handleWebDavPut(req, env, internalPath, auth);
    case "DELETE":
      return handleWebDavDelete(env, internalPath, owner);
    case "MKCOL":
      return handleWebDavMkcol(env, internalPath, owner);
    case "MOVE":
      return handleWebDavMove(req, env, internalPath, owner);
    case "COPY":
      return handleWebDavCopy(req, env, internalPath, auth);
    default:
      return new Response("Method Not Allowed", { status: 405 });
  }
}

/* ═══════════ PROPFIND ═══════════ */

/** 从内部路径拆分目录与文件名 */
function splitPath(internalPath: string): { dir: string; name: string } {
  const lastSlash = internalPath.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const name = internalPath.slice(lastSlash + 1);
  return { dir, name };
}

async function handlePropfind(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string,
  owner: string | null
): Promise<Response> {
  const depth = req.headers.get("depth") || "1"; // 0 / 1 / infinity
  const baseUrl = url.origin;

  const pathExists = await directoryExists(env, owner, internalPath);
  const file = pathExists && internalPath !== "/"
    ? await findFile(env, owner, splitPath(internalPath).dir, splitPath(internalPath).name)
    : null;

  // 检查这到底是个文件还是目录
  if (file && file.path === internalPath) {
    // 这是个文件
    const href = buildHref(baseUrl, internalPath);
    const body = multistatusXML([filePropstatAsFile(file, href)]);
    return new Response(body, {
      status: 207,
      headers: { "Content-Type": "application/xml; charset=utf-8" },
    });
  }

  // 应该是目录
  if (!pathExists) {
    return new Response("Not Found", { status: 404 });
  }

  // Depth: 0 —— 只返回目录自身
  if (depth === "0") {
    const body = multistatusXML([dirPropstat(internalPath, baseUrl)]);
    return new Response(body, {
      status: 207,
      headers: { "Content-Type": "application/xml; charset=utf-8" },
    });
  }

  // Depth: 1 或 infinity —— 返回目录自身 + 子项
  const responses: string[] = [dirPropstat(internalPath, baseUrl)];

  if (depth === "1") {
    const { files, dirs } = await listDirChildren(env, owner, internalPath);
    for (const d of dirs) {
      responses.push(dirPropstat(d, baseUrl));
    }
    for (const f of files) {
      const href = buildHref(baseUrl, f.path);
      responses.push(filePropstatAsFile(f, href));
    }
  } else {
    // infinity —— 递归列出所有
    await collectAll(env, owner, internalPath, baseUrl, responses);
  }

  const body = multistatusXML(responses);
  return new Response(body, {
    status: 207,
    headers: { "Content-Type": "application/xml; charset=utf-8" },
  });
}

/** 递归收集目录下所有子项（Depth: infinity） */
async function collectAll(
  env: Env,
  owner: string | null,
  path: string,
  baseUrl: string,
  responses: string[]
): Promise<void> {
  const { files, dirs } = await listDirChildren(env, owner, path);
  for (const d of dirs) {
    responses.push(dirPropstat(d, baseUrl));
    await collectAll(env, owner, d, baseUrl, responses);
  }
  for (const f of files) {
    const href = buildHref(baseUrl, f.path);
    responses.push(filePropstatAsFile(f, href));
  }
}

/* ═══════════ GET / HEAD ═══════════ */

async function handleWebDavGet(
  req: Request,
  env: Env,
  internalPath: string,
  owner: string | null,
  headOnly: boolean
): Promise<Response> {
  const { dir, name } = splitPath(internalPath);

  if (!name) {
    // 目录 —— 返回目录列表或错误
    return new Response("Not a file", { status: 409 });
  }

  const file = await findFile(env, owner, dir, name);
  if (!file) {
    return new Response("Not Found", { status: 404 });
  }

  const st = await storage(env);
  const obj = await st.head(file.key);
  if (!obj) {
    return new Response("Not Found", { status: 404 });
  }

  const headers = new Headers();
  headers.set("Content-Type", obj.contentType);
  headers.set("Content-Length", String(obj.size));
  headers.set("ETag", `"${file.id}"`);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Last-Modified", tsToRfc1123(file.uploaded_at));
  headers.set("Cache-Control", "no-store");

  if (headOnly) {
    return new Response("", { status: 200, headers });
  }

  // 支持 Range 请求
  const rangeHeader = req.headers.get("range");
  if (rangeHeader) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
    if (m) {
      let offset = m[1] === "" ? null : Number(m[1]);
      let end = m[2] === "" ? null : Number(m[2]);
      if (offset === null && end !== null) {
        // 后缀范围 bytes=-N
        offset = obj.size - end;
        end = obj.size - 1;
      } else if (offset !== null) {
        if (end === null) end = obj.size - 1;
        if (end >= obj.size) end = obj.size - 1;
        if (offset > end) {
          return new Response("Range Not Satisfiable", { status: 416, headers: { "Content-Range": `bytes */${obj.size}` } });
        }
      }
      if (offset !== null && end !== null) {
        const len = end - offset + 1;
        headers.set("Content-Range", `bytes ${offset}-${end}/${obj.size}`);
        headers.set("Content-Length", String(len));
        const ranged = await st.get(file.key, { offset, length: len });
        if (!ranged) return new Response("Not Found", { status: 404 });
        return new Response(ranged.body, { status: 206, headers });
      }
    }
  }

  const fullObj = await st.get(file.key);
  if (!fullObj) return new Response("Not Found", { status: 404 });
  return new Response(fullObj.body, { status: 200, headers });
}

/* ═══════════ PUT ═══════════ */

async function handleWebDavPut(
  req: Request,
  env: Env,
  internalPath: string,
  auth: WebDavAuth
): Promise<Response> {
  const owner = auth.scopeOwnerId;
  const { dir, name } = splitPath(internalPath);

  if (!name) {
    return new Response("No file name", { status: 400 });
  }

  // 父目录必须存在
  if (!(await directoryExists(env, owner, dir))) {
    return new Response("Conflict: parent directory does not exist", { status: 409 });
  }

  const mime = req.headers.get("content-type") || "application/octet-stream";
  const st = await storage(env);

  // 同名文件（覆盖写）—— 提前查出，用于容量增量核算
  const existing = await findFile(env, owner, dir, name);

  // ── 全局存储容量硬上限核验（覆盖写按增量计）──
  const usedBefore = await getStorageUsedBytes(env);
  const baseline = usedBefore - (existing?.size ?? 0);
  if (baseline >= STORAGE_LIMIT_BYTES) {
    return new Response("Insufficient Storage: 9.9 GB limit reached", { status: 507 });
  }
  const declaredLen = parseInt(req.headers.get("content-length") || "", 10);
  if (Number.isFinite(declaredLen) && baseline + declaredLen > STORAGE_LIMIT_BYTES) {
    return new Response("Insufficient Storage: upload would exceed the 9.9 GB limit", { status: 507 });
  }

  // ── 成员个人配额核验（仅成员空间）──
  let ownerBase = 0;
  const quota = auth.quotaBytes;
  if (owner && quota != null) {
    const ownerUsed = await ownerUsedBytes(env, owner);
    ownerBase = ownerUsed - (existing?.size ?? 0);
    if (ownerBase >= quota) {
      return new Response("Insufficient Storage: personal quota reached", { status: 507 });
    }
    if (Number.isFinite(declaredLen) && ownerBase + declaredLen > quota) {
      return new Response("Insufficient Storage: upload would exceed your personal quota", { status: 507 });
    }
  }

  // 生成文件记录
  const id = randomId(14);
  const key = `files/${id}`;
  const now = Date.now();

  let size = 0;
  try {
    const res = await st.put(key, req.body as any, {
      contentType: mime,
      contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
    });
    size = res.size;
  } catch (err: any) {
    return new Response(`Storage error: ${err?.message || err}`, { status: 502 });
  }
  // 大小兜底：流式 body 在部分后端拿不到大小，用 head 补一次
  if (!size) {
    const head = await st.head(key).catch(() => null);
    if (head) size = head.size;
  }

  // ── 强制撤回：本次写入把全局总量顶过 9.9 GB 时，删除刚写入的对象 ──
  if (baseline + size > STORAGE_LIMIT_BYTES) {
    await st.delete(key).catch(() => {});
    return new Response("Insufficient Storage: upload rolled back (9.9 GB limit)", { status: 507 });
  }
  // ── 强制撤回：超出成员个人配额时，删除刚写入的对象 ──
  if (owner && quota != null && ownerBase + size > quota) {
    await st.delete(key).catch(() => {});
    return new Response("Insufficient Storage: upload rolled back (personal quota)", { status: 507 });
  }

  // 覆盖同名文件：删除旧文件 + 关联的 shares
  if (existing) {
    try {
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(existing.id),
      ]);
      await st.delete(existing.key).catch(() => {});
    } catch { /* 忽略清理失败 */ }
  }

  // 插入新文件记录（带 owner 归属）
  const fullPath = dir === "/" ? `/${name}` : `${dir}/${name}`;
  try {
    await env.db.prepare(
      "INSERT INTO files(id, key, name, size, mime, path, uploaded_at, owner_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
    ).bind(id, key, name, size, mime, fullPath, now, owner).run();
  } catch (err: any) {
    // D1 失败 —— 清理 storage
    await st.delete(key).catch(() => {});
    return new Response(`DB error: ${err?.message || err}`, { status: 502 });
  }

  return new Response("", {
    status: existing ? 204 : 201,
    headers: { "ETag": `"${id}"` },
  });
}

/* ═══════════ DELETE ═══════════ */

async function handleWebDavDelete(env: Env, internalPath: string, owner: string | null): Promise<Response> {
  if (internalPath === "/") {
    return new Response("Cannot delete root", { status: 403 });
  }

  const { dir, name } = splitPath(internalPath);

  // 1. 先看是不是文件
  if (name) {
    const file = await findFile(env, owner, dir, name);
    if (file) {
      const st = await storage(env);
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(file.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(file.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(file.id),
      ]);
      await st.delete(file.key).catch(() => {});
      return new Response("", { status: 204 });
    }
  }

  // 2. 看看是不是目录
  if (await directoryExists(env, owner, internalPath)) {
    // 递归删除目录下所有文件
    const st = await storage(env);
    const likePattern = internalPath + "/%";
    const { results: files } =
      owner === null
        ? await env.db
            .prepare("SELECT id, key FROM files WHERE path LIKE ? AND owner_id IS NULL")
            .bind(likePattern)
            .all<{ id: string; key: string }>()
        : await env.db
            .prepare("SELECT id, key FROM files WHERE path LIKE ? AND owner_id = ?")
            .bind(likePattern, owner)
            .all<{ id: string; key: string }>();

    for (const f of files) {
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(f.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(f.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(f.id),
      ]);
      await st.delete(f.key).catch(() => {});
    }

    // 删除目录本身（directories 表）
    await env.db
      .prepare("DELETE FROM directories WHERE path = ? AND owner_key = ?")
      .bind(internalPath, owner ?? "")
      .run();

    return new Response("", { status: 204 });
  }

  return new Response("Not Found", { status: 404 });
}

/* ═══════════ MKCOL ═══════════ */

async function handleWebDavMkcol(env: Env, internalPath: string, owner: string | null): Promise<Response> {
  if (internalPath === "/") {
    return new Response("Root exists", { status: 200 });
  }

  // 父目录必须存在
  const parent = internalPath.slice(0, internalPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, owner, parent))) {
    return new Response("Conflict: parent does not exist", { status: 409 });
  }

  // 目标不能是已存在的文件
  const { dir: pdir, name: pname } = splitPath(internalPath);
  if (pname) {
    const existingFile = await findFile(env, owner, pdir, pname);
    if (existingFile) {
      return new Response("Method Not Allowed: file exists here", { status: 405 });
    }
  }

  // 已经存在也返回 201（WebDAV 规范）
  try {
    await env.db.prepare(
      "INSERT INTO directories(path, owner_key, created_at) VALUES(?1, ?2, ?3) ON CONFLICT(path, owner_key) DO NOTHING"
    ).bind(internalPath, owner ?? "", Date.now()).run();
  } catch (err: any) {
    return new Response(`DB error: ${err?.message || err}`, { status: 502 });
  }

  return new Response("", { status: 201 });
}

/* ═══════════ MOVE ═══════════ */

async function handleWebDavMove(
  req: Request,
  env: Env,
  internalPath: string,
  owner: string | null
): Promise<Response> {
  const destHeader = req.headers.get("destination");
  if (!destHeader) {
    return new Response("Missing Destination header", { status: 400 });
  }

  // 从 Destination URL 提取目标路径
  let destPath: string;
  try {
    const destUrl = new URL(destHeader);
    destPath = extractInternalPath(destUrl.pathname);
  } catch {
    return new Response("Invalid Destination", { status: 400 });
  }

  const overwrite = (req.headers.get("overwrite") || "T").toUpperCase() === "T";

  // 检查源是否存在
  const srcExists = await directoryExists(env, owner, internalPath);
  const srcFile = await pathIsFile(env, owner, internalPath);
  if (!srcExists && !srcFile) {
    return new Response("Not Found", { status: 404 });
  }

  // 目标父目录必须存在
  const destParent = destPath.slice(0, destPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, owner, destParent))) {
    return new Response("Conflict", { status: 409 });
  }

  // 检查目标是否存在
  const destExists = await directoryExists(env, owner, destPath);
  const destFile = await pathIsFile(env, owner, destPath);
  if ((destExists || destFile) && !overwrite) {
    return new Response("Precondition Failed: destination exists", { status: 412 });
  }

  // 如果目标已存在，先删除
  if (destExists || destFile) {
    await handleWebDavDelete(env, destPath, owner);
  }

  if (srcFile) {
    // 移动文件
    await moveFile(env, owner, internalPath, destPath);
  } else {
    // 移动目录（递归更新 path）
    await moveDirectory(env, owner, internalPath, destPath);
  }

  return new Response("", { status: destExists || destFile ? 204 : 201 });
}

/* ═══════════ COPY ═══════════ */

async function handleWebDavCopy(
  req: Request,
  env: Env,
  internalPath: string,
  auth: WebDavAuth
): Promise<Response> {
  const owner = auth.scopeOwnerId;
  const destHeader = req.headers.get("destination");
  if (!destHeader) {
    return new Response("Missing Destination header", { status: 400 });
  }

  let destPath: string;
  try {
    const destUrl = new URL(destHeader);
    destPath = extractInternalPath(destUrl.pathname);
  } catch {
    return new Response("Invalid Destination", { status: 400 });
  }

  const overwrite = (req.headers.get("overwrite") || "T").toUpperCase() === "T";

  const srcFile = await pathIsFile(env, owner, internalPath);
  if (!srcFile) {
    return new Response("Only file copy supported", { status: 501 });
  }

  const destParent = destPath.slice(0, destPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, owner, destParent))) {
    return new Response("Conflict", { status: 409 });
  }

  const destFile = await pathIsFile(env, owner, destPath);
  if (destFile && !overwrite) {
    return new Response("Precondition Failed", { status: 412 });
  }
  if (destFile) {
    await handleWebDavDelete(env, destPath, owner);
  }

  const st = await storage(env);
  const srcObj = await st.get(srcFile.key);
  if (!srcObj) return new Response("Source not found", { status: 404 });

  // ── 存储容量硬上限：复制会新增一份，超限直接拒绝 ──
  const usedBefore = await getStorageUsedBytes(env);
  if (usedBefore + srcFile.size > STORAGE_LIMIT_BYTES) {
    return new Response("Insufficient Storage: copy would exceed the 9.9 GB limit", { status: 507 });
  }
  // ── 成员个人配额：复制同样计入 ──
  if (owner && auth.quotaBytes != null) {
    const ownerUsed = await ownerUsedBytes(env, owner);
    if (ownerUsed + srcFile.size > auth.quotaBytes) {
      return new Response("Insufficient Storage: copy would exceed your personal quota", { status: 507 });
    }
  }

  const newId = randomId(14);
  const newKey = `files/${newId}`;
  const newName = destPath.split("/").filter(Boolean).pop() || srcFile.name;

  await st.put(newKey, srcObj.body, { contentType: srcFile.mime });

  await env.db.prepare(
    "INSERT INTO files(id, key, name, size, mime, path, uploaded_at, owner_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
  ).bind(newId, newKey, newName, srcFile.size, srcFile.mime, destPath, Date.now(), owner).run();

  return new Response("", { status: 201 });
}

/* ═══════════ 辅助：判断路径是否是文件 ═══════════ */

async function pathIsFile(env: Env, owner: string | null, p: string): Promise<DBFile | null> {
  const { dir, name } = splitPath(p);
  if (!name) return null;
  return await findFile(env, owner, dir, name);
}

/* ═══════════ 辅助：移动文件 ═══════════ */

async function moveFile(env: Env, owner: string | null, srcPath: string, destPath: string): Promise<void> {
  const { dir: srcDir, name: srcName } = splitPath(srcPath);
  const file = await findFile(env, owner, srcDir, srcName);
  if (!file) return;

  const { dir: destDir, name: destName } = splitPath(destPath);
  const fullDestPath = destDir === "/" ? `/${destName}` : `${destDir}/${destName}`;

  await env.db.prepare(
    "UPDATE files SET path = ?1, name = ?2 WHERE id = ?3"
  ).bind(fullDestPath, destName, file.id).run();
}

/* ═══════════ 辅助：移动目录（递归更新 path 前缀） ═══════════ */

async function moveDirectory(env: Env, owner: string | null, srcDir: string, destDir: string): Promise<void> {
  const likePattern = srcDir === "/" ? "/%" : srcDir + "/%";
  const { results: files } =
    owner === null
      ? await env.db
          .prepare("SELECT id, path FROM files WHERE path LIKE ? AND owner_id IS NULL")
          .bind(likePattern)
          .all<{ id: string; path: string }>()
      : await env.db
          .prepare("SELECT id, path FROM files WHERE path LIKE ? AND owner_id = ?")
          .bind(likePattern, owner)
          .all<{ id: string; path: string }>();

  for (const f of files) {
    let newPath: string;
    if (srcDir === "/") {
      newPath = destDir + f.path;
      if (!newPath.startsWith("/")) newPath = "/" + newPath;
    } else {
      newPath = destDir + f.path.slice(srcDir.length);
    }
    await env.db.prepare("UPDATE files SET path = ?1 WHERE id = ?2").bind(newPath, f.id).run();
  }

  // 也更新 directories 表中的子目录记录
  const ownerKey = owner ?? "";
  const { results: dirs } = await env.db
    .prepare("SELECT path FROM directories WHERE path LIKE ? AND owner_key = ?")
    .bind(likePattern, ownerKey)
    .all<{ path: string }>();

  for (const d of dirs) {
    let newPath: string;
    if (srcDir === "/") {
      newPath = destDir + d.path;
    } else {
      newPath = destDir + d.path.slice(srcDir.length);
    }
    await env.db
      .prepare("DELETE FROM directories WHERE path = ? AND owner_key = ?")
      .bind(d.path, ownerKey)
      .run();
    await env.db.prepare("INSERT INTO directories(path, owner_key, created_at) VALUES(?1, ?2, ?3) ON CONFLICT(path, owner_key) DO NOTHING")
      .bind(newPath, ownerKey, Date.now()).run();
  }

  // 更新目录本身
  await env.db
    .prepare("DELETE FROM directories WHERE path = ? AND owner_key = ?")
    .bind(srcDir, ownerKey)
    .run();
  await env.db.prepare("INSERT INTO directories(path, owner_key, created_at) VALUES(?1, ?2, ?3) ON CONFLICT(path, owner_key) DO NOTHING")
    .bind(destDir, ownerKey, Date.now()).run();
}

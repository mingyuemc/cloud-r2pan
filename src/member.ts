/**
 * 成员（member）域 —— 前台 /my 的 API。
 *
 * 定位：给普通成员一个「独立空间」：
 *   - 只看到 / 操作自己的文件（files.owner_id = 自己）
 *   - 可为自己的文件创建分享链接
 *   - 可提交「发布到下载市场」的申请，等待管理员审批
 *   - 两级配额：自身配额（users.quota_bytes）+ 全局 9.9 GiB 硬上限兜底
 *
 * 与管理端（admin.ts）完全隔离：member 不能访问 /api/admin/*，
 * 管理员访问 /api/my/* 会被引导使用后台。
 */
import type { Env } from "./types";
import { ensureSchema, randomId } from "./db";
import { readSession, createSession, clientIp, rateLimitLogin, type SessionPayload } from "./auth";
import { getSettings, getStorageUsedBytes, STORAGE_LIMIT_BYTES } from "./settings";
import {
  USERNAME_RE,
  getUserById,
  getUserByUsername,
  isUserUsable,
  hashUserPassword,
  verifyUserPassword,
  recordUserLogin,
  writeAudit,
  type Role,
  type UserRecord,
} from "./authz";
import { pickLang } from "./i18n";
import { hashPassword } from "./public";
import { encryptSecret } from "./crypto";
import { createStorageProvider, type StorageProvider } from "./storage";
import { parseUA } from "./ua";

const msg = (req: Request, zh: string, en: string) => (pickLang(req) === "zh" ? zh : en);

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json;charset=utf-8", "cache-control": "no-store" },
  });

/** 懒加载 StorageProvider —— 与管理端一致 */
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

async function readJson<T>(req: Request): Promise<Partial<T>> {
  try {
    return (await req.json()) as Partial<T>;
  } catch {
    return {};
  }
}

function sanitizeName(name: string): string {
  const cleaned = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_").replace(/^\.+/, "").trim();
  return (cleaned || "unnamed").slice(0, 200);
}

/* ═══════════════ 成员鉴权 ═══════════════ */

export interface MemberCtx {
  session: SessionPayload;
  user: UserRecord;
}

/**
 * 成员守卫：必须是带身份的用户会话；隐式超管（uid 为空）与 member 之外的
 * 管理员都需要走各自入口。这里允许 member / admin 使用 /my（给自己留空间亦无妨），
 * 但不允许隐式超管。
 */
async function memberAuth(
  req: Request,
  env: Env
): Promise<{ ok: true; ctx: MemberCtx } | { ok: false; res: Response }> {
  const session = await readSession(req, env);
  if (!session || !session.uid) return { ok: false, res: json({ error: "unauthorized" }, 401) };
  const user = await getUserById(env, session.uid);
  if (!isUserUsable(user)) return { ok: false, res: json({ error: "unauthorized" }, 401) };
  if (user.session_version !== session.ver) return { ok: false, res: json({ error: "unauthorized" }, 401) };
  return { ok: true, ctx: { session, user } };
}

/** 该成员已占用的存储字节数（仅统计自己名下的文件） */
async function memberUsedBytes(env: Env, uid: string): Promise<number> {
  const row = await env.db
    .prepare("SELECT COALESCE(SUM(size), 0) AS total FROM files WHERE owner_id = ?1")
    .bind(uid)
    .first<{ total: number }>();
  return Number(row?.total ?? 0) || 0;
}

/** 成员登录日志（与管理端 login_logs 同表，便于统一查看） */
async function writeLoginLog(
  env: Env,
  req: Request,
  action: string,
  result: string,
  reason: string | null = null
): Promise<void> {
  try {
    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    const country = req.headers.get("cf-ipcountry") ?? null;
    await env.db
      .prepare(
        "INSERT INTO login_logs(action, ip, ua, browser, os, country, result, reason, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
      )
      .bind(action, clientIp(req), ua || null, browser, os, country, result, reason, Date.now())
      .run();
  } catch {
    /* 日志失败不影响主流程 */
  }
}

/* ═══════════════ 路由入口 ═══════════════ */

export async function handleMemberApi(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  path: string
): Promise<Response> {
  try {
    await ensureSchema(env);
    const method = req.method;
    const url = new URL(req.url);

    // ══════════ 注册（邀请码） ══════════
    if (path === "/api/my/register" && method === "POST") {
      const ip = clientIp(req);
      if (!rateLimitLogin(ip, 6, 60_000)) {
        return json({ error: msg(req, "操作过于频繁，请稍后再试", "Too many attempts. Try again later.") }, 429);
      }
      const s = await getSettings(env);
      if (!s.memberRegistrationEnabled)
        return json({ error: msg(req, "当前未开放注册", "Registration is currently closed") }, 403);
      const body = await readJson<{ username?: string; password?: string; invite?: string }>(req);
      const username = (body.username ?? "").trim().toLowerCase();
      const inviteToken = (body.invite ?? "").trim();
      if (!USERNAME_RE.test(username))
        return json({ error: msg(req, "用户名需 3-32 位字母/数字/_ . -", "Username must be 3-32 of a-z0-9_.-") }, 400);
      if (!body.password || body.password.length < 6)
        return json({ error: msg(req, "密码至少 6 位", "Password must be at least 6 characters") }, 400);
      if (!inviteToken) return json({ error: msg(req, "需要邀请码", "An invite code is required") }, 400);
      if (await getUserByUsername(env, username))
        return json({ error: msg(req, "用户名已存在", "Username already exists") }, 409);

      const invite: any = await env.db
        .prepare("SELECT * FROM registration_invites WHERE token = ?1")
        .bind(inviteToken)
        .first();
      if (
        !invite ||
        invite.deleted_at ||
        invite.used_count >= invite.max_uses ||
        (invite.expires_at && invite.expires_at <= Date.now())
      ) {
        return json({ error: msg(req, "邀请码无效或已用尽", "Invite code invalid or exhausted") }, 400);
      }

      const role: Role = invite.default_role === "admin" ? "admin" : "member";
      const { hash, salt } = await hashUserPassword(body.password);
      const id = randomId(14);
      const now = Date.now();
      // 用户写入 + 邀请码消费放在同一 batch（事务）：触发器校验并自增 used_count，
      // 并发抢同一个码时后到者会因触发器 RAISE 而整体回滚。
      try {
        await env.db.batch([
          env.db
            .prepare(
              `INSERT INTO users(id, username, display_name, password_hash, password_salt, role, created_by, created_at, updated_at)
               VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)`
            )
            .bind(id, username, username, hash, salt, role, invite.created_by ?? null, now),
          env.db
            .prepare("INSERT INTO registration_invite_uses(invite_id, user_id, used_at) VALUES(?1, ?2, ?3)")
            .bind(invite.id, id, now),
        ]);
      } catch (e: any) {
        const m = String(e?.message ?? e);
        if (m.includes("invite_unavailable"))
          return json({ error: msg(req, "邀请码已被使用完", "Invite code already exhausted") }, 409);
        if (m.includes("UNIQUE"))
          return json({ error: msg(req, "用户名已存在", "Username already exists") }, 409);
        return json({ error: m }, 400);
      }
      ctx.waitUntil(
        writeAudit(env, {
          actorId: id,
          actorName: username,
          action: "member.register",
          target: username,
          summary: `invite=${inviteToken}`,
          ip,
        })
      );
      // 注册成功直接登录
      const token = await createSession(env, url.protocol === "https:", { uid: id, role, ver: 0 });
      return new Response(JSON.stringify({ ok: true, role, username }), {
        status: 201,
        headers: {
          "content-type": "application/json;charset=utf-8",
          "set-cookie": token,
          "cache-control": "no-store",
        },
      });
    }

    // ══════════ 登录 / 登出 / 会话 ══════════
    if (path === "/api/my/login" && method === "POST") {
      const ip = clientIp(req);
      if (!rateLimitLogin(ip, 8, 60_000)) {
        ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "rate_limited"));
        return json({ error: msg(req, "尝试过于频繁，请稍后再试", "Too many attempts. Try again later.") }, 429);
      }
      const body = await readJson<{ username?: string; password?: string }>(req);
      const u = body.username ? await getUserByUsername(env, body.username) : null;
      if (!u || !body.password || !(await verifyUserPassword(body.password, u.password_hash, u.password_salt))) {
        ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "invalid_credentials"));
        return json({ error: msg(req, "用户名或密码错误", "Invalid username or password") }, 401);
      }
      if (!isUserUsable(u)) {
        ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "account_disabled"));
        return json({ error: msg(req, "账号已被禁用或删除", "Account disabled or removed") }, 403);
      }
      ctx.waitUntil(writeLoginLog(env, req, "login", "success"));
      ctx.waitUntil(recordUserLogin(env, u.id, ip, req.headers.get("user-agent") ?? ""));
      const token = await createSession(env, url.protocol === "https:", {
        uid: u.id,
        role: u.role,
        ver: u.session_version,
      });
      return new Response(
        JSON.stringify({ ok: true, role: u.role, username: u.username, display_name: u.display_name || u.username }),
        {
          headers: {
            "content-type": "application/json;charset=utf-8",
            "set-cookie": token,
            "cache-control": "no-store",
          },
        }
      );
    }

    if (path === "/api/my/logout" && method === "POST") {
      const secure = url.protocol === "https:";
      return new Response(JSON.stringify({ ok: true }), {
        headers: {
          "content-type": "application/json;charset=utf-8",
          "set-cookie": `cd_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`,
        },
      });
    }

    // 会话状态（未登录返回 ok:false，而不是 401 —— 便于前端渲染登录页）
    if (path === "/api/my/session" && method === "GET") {
      const s = await getSettings(env);
      const session = await readSession(req, env);
      if (!session || !session.uid) return json({ ok: false, registration_enabled: s.memberRegistrationEnabled });
      const u = await getUserById(env, session.uid);
      if (!isUserUsable(u) || u.session_version !== session.ver)
        return json({ ok: false, registration_enabled: s.memberRegistrationEnabled });
      const [used, globalUsed] = await Promise.all([memberUsedBytes(env, u.id), getStorageUsedBytes(env)]);
      return json({
        ok: true,
        registration_enabled: s.memberRegistrationEnabled,
        username: u.username,
        display_name: u.display_name || u.username,
        role: u.role,
        quota: {
          used,
          quota: u.quota_bytes, // null = 不限（仅受全局上限约束）
          global_limit: STORAGE_LIMIT_BYTES,
          global_used: globalUsed,
        },
      });
    }

    // ══════════ 以下全部需要成员身份 ══════════
    const auth = await memberAuth(req, env);
    if (!auth.ok) return auth.res;
    const { user } = auth.ctx;
    const uid = user.id;

    // ── 我的文件列表 ──
    if (path === "/api/my/files" && method === "GET") {
      const { results } = await env.db
        .prepare(
          `SELECT f.id, f.name, f.size, f.mime, f.uploaded_at,
                  (SELECT COUNT(*) FROM shares s WHERE s.file_id = f.id AND s.revoked = 0) AS share_count
           FROM files f WHERE f.owner_id = ?1 ORDER BY f.uploaded_at DESC`
        )
        .bind(uid)
        .all();
      return json({ files: results ?? [] });
    }

    // ── 上传（成员配额 + 全局 9.9 GiB 兜底，超限强制撤回） ──
    if (path === "/api/my/upload" && method === "POST") {
      const rawName = req.headers.get("x-file-name");
      if (!rawName) return json({ error: msg(req, "缺少 X-File-Name 头", "Missing X-File-Name header") }, 400);
      let name: string;
      try {
        name = sanitizeName(decodeURIComponent(rawName));
      } catch {
        name = sanitizeName(rawName);
      }
      if (!req.body) return json({ error: msg(req, "请求体为空", "Empty request body") }, 400);

      const declaredLen = parseInt(req.headers.get("content-length") || "", 10);
      const memberUsed = await memberUsedBytes(env, uid);
      const globalUsed = await getStorageUsedBytes(env);

      // ① 全局硬上限预检
      if (globalUsed >= STORAGE_LIMIT_BYTES)
        return json({ error: msg(req, "全站存储已满（9.9 GB 上限），上传被拒绝", "Site storage is full (9.9 GB limit). Upload rejected.") }, 413);
      if (Number.isFinite(declaredLen) && globalUsed + declaredLen > STORAGE_LIMIT_BYTES)
        return json({ error: msg(req, "上传将超出全站 9.9 GB 上限，已拒绝", "Upload would exceed the site 9.9 GB limit. Rejected.") }, 413);
      // ② 成员个人配额预检
      if (user.quota_bytes && memberUsed >= user.quota_bytes)
        return json({ error: msg(req, "你的配额已用满，无法上传", "Your quota is full. Upload rejected.") }, 413);
      if (user.quota_bytes && Number.isFinite(declaredLen) && memberUsed + declaredLen > user.quota_bytes)
        return json({ error: msg(req, "上传将超出你的个人配额，已拒绝", "Upload would exceed your personal quota. Rejected.") }, 413);

      const id = randomId(14);
      const key = `files/${id}`;
      const mime = req.headers.get("content-type") || "application/octet-stream";
      const st = await storage(env);
      let resultSize = 0;
      try {
        const res = await st.put(key, req.body, {
          contentType: mime,
          contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
        });
        resultSize = res.size;
      } catch (err: any) {
        return json({ error: msg(req, "存储写入失败", "Storage write failed"), detail: String(err?.message || err) }, 500);
      }
      if (!resultSize) {
        const head = await st.head(key).catch(() => null);
        if (head) resultSize = head.size;
      }
      // ③ 写后兜底：超全局上限 → 强制撤回
      if (globalUsed + resultSize > STORAGE_LIMIT_BYTES) {
        await st.delete(key).catch(() => {});
        return json({ error: msg(req, "上传将超出全站 9.9 GB 上限，已强制撤回", "Upload exceeded the site 9.9 GB limit and was rolled back.") }, 413);
      }
      // ④ 写后兜底：超个人配额 → 强制撤回
      if (user.quota_bytes && memberUsed + resultSize > user.quota_bytes) {
        await st.delete(key).catch(() => {});
        return json({ error: msg(req, "上传将超出你的个人配额，已强制撤回", "Upload exceeded your personal quota and was rolled back.") }, 413);
      }
      try {
        await env.db
          .prepare(
            "INSERT INTO files(id, key, name, size, mime, uploaded_at, owner_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
          )
          .bind(id, key, name, resultSize, mime, Date.now(), uid)
          .run();
      } catch (dbErr) {
        ctx.waitUntil(st.delete(key).catch(() => {}));
        console.error("member upload: D1 insert failed, cleaned up:", dbErr);
        return json({ error: msg(req, "数据库写入失败，请重试", "Database write failed. Please retry.") }, 500);
      }
      return json({ ok: true, id, name, size: resultSize }, 201);
    }

    // ── 删除自己的文件 ──
    const myFileMatch = /^\/api\/my\/files\/([^/]+)$/.exec(path);
    if (myFileMatch && method === "DELETE") {
      const fileId = myFileMatch[1];
      const file = await env.db
        .prepare("SELECT key, owner_id FROM files WHERE id = ?1")
        .bind(fileId)
        .first<{ key: string; owner_id: string | null }>();
      if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
      if (file.owner_id !== uid) return json({ error: msg(req, "无权删除他人文件", "Not your file") }, 403);
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(fileId),
        env.db.prepare("DELETE FROM share_requests WHERE file_id = ?1").bind(fileId),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(fileId),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(fileId),
      ]);
      const st = await storage(env);
      ctx.waitUntil(st.delete(file.key).catch(() => {}));
      return json({ ok: true });
    }

    // ── 我的分享列表 ──
    if (path === "/api/my/shares" && method === "GET") {
      const { results } = await env.db
        .prepare(
          `SELECT s.id, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_count, s.revoked,
                  s.password_hash, s.download_name, f.name AS file_name, f.size AS file_size, f.mime AS file_mime
           FROM shares s JOIN files f ON f.id = s.file_id
           WHERE f.owner_id = ?1
           ORDER BY s.created_at DESC`
        )
        .bind(uid)
        .all();
      const now = Date.now();
      const shares = (results ?? []).map((s: any) => ({
        ...s,
        has_password: !!s.password_hash,
        password_hash: undefined,
        url: `/s/${s.id}`,
        status: s.revoked
          ? "revoked"
          : s.expires_at && s.expires_at < now
            ? "expired"
            : s.max_downloads && s.download_count >= s.max_downloads
              ? "maxed"
              : "active",
      }));
      return json({ shares });
    }

    // ── 创建分享（限自己的文件） ──
    if (path === "/api/my/shares" && method === "POST") {
      const body = await readJson<{
        file_id?: string;
        expires_hours?: number | null;
        max_downloads?: number | null;
        password?: string | null;
        download_name?: string | null;
      }>(req);
      if (!body.file_id) return json({ error: msg(req, "缺少 file_id", "Missing file_id") }, 400);
      const file = await env.db
        .prepare("SELECT id, owner_id FROM files WHERE id = ?1")
        .bind(body.file_id)
        .first<{ id: string; owner_id: string | null }>();
      if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
      if (file.owner_id !== uid) return json({ error: msg(req, "只能分享自己的文件", "You can only share your own files") }, 403);
      const expiresAt =
        body.expires_hours && body.expires_hours > 0 ? Date.now() + body.expires_hours * 3600_000 : null;
      const maxDownloads =
        body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
      const password =
        typeof body.password === "string" && body.password.trim() ? body.password.trim() : null;
      const passwordHash = password ? await hashPassword(password) : null;
      const passwordCipher = password ? await encryptSecret(password, env.admin) : null;
      const downloadName =
        typeof body.download_name === "string" && body.download_name.trim() ? body.download_name.trim() : null;
      const id = randomId(10);
      await env.db
        .prepare(
          `INSERT INTO shares(id, file_id, created_at, expires_at, max_downloads, password_hash, password_cipher, download_name, created_by)
           VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
        )
        .bind(id, body.file_id, Date.now(), expiresAt, maxDownloads, passwordHash, passwordCipher, downloadName, uid)
        .run();
      return json({ ok: true, id, url: `/s/${id}` }, 201);
    }

    // ── 撤销/删除自己的分享 ──
    const myShareMatch = /^\/api\/my\/shares\/([^/]+)$/.exec(path);
    if (myShareMatch && method === "DELETE") {
      const sid = myShareMatch[1];
      const s = await env.db
        .prepare("SELECT s.id, f.owner_id AS owner_id FROM shares s JOIN files f ON f.id = s.file_id WHERE s.id = ?1")
        .bind(sid)
        .first<{ id: string; owner_id: string | null }>();
      if (!s) return json({ error: msg(req, "分享不存在", "Share not found") }, 404);
      if (s.owner_id !== uid) return json({ error: msg(req, "无权操作他人分享", "Not your share") }, 403);
      await env.db.prepare("DELETE FROM shares WHERE id = ?1").bind(sid).run();
      return json({ ok: true });
    }

    // ── 我的发布申请 ──
    if (path === "/api/my/requests" && method === "GET") {
      const { results } = await env.db
        .prepare(
          `SELECT r.id, r.file_id, r.title, r.description, r.status, r.review_reason, r.share_id,
                  r.created_at, r.reviewed_at, f.name AS file_name, f.size AS file_size
           FROM share_requests r LEFT JOIN files f ON f.id = r.file_id
           WHERE r.requester_id = ?1
           ORDER BY r.created_at DESC LIMIT 200`
        )
        .bind(uid)
        .all();
      return json({ requests: results ?? [] });
    }

    // ── 提交发布到市场的申请 ──
    if (path === "/api/my/requests" && method === "POST") {
      const body = await readJson<{ file_id?: string; title?: string; description?: string }>(req);
      if (!body.file_id) return json({ error: msg(req, "缺少 file_id", "Missing file_id") }, 400);
      const file = await env.db
        .prepare("SELECT id, owner_id FROM files WHERE id = ?1")
        .bind(body.file_id)
        .first<{ id: string; owner_id: string | null }>();
      if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
      if (file.owner_id !== uid) return json({ error: msg(req, "只能申请发布自己的文件", "You can only request publishing your own files") }, 403);
      const pending: any = await env.db
        .prepare("SELECT id FROM share_requests WHERE requester_id = ?1 AND file_id = ?2 AND status = 'pending'")
        .bind(uid, body.file_id)
        .first();
      if (pending) return json({ error: msg(req, "该文件已有待审批的申请", "A pending request already exists for this file") }, 409);
      const id = randomId(14);
      await env.db
        .prepare(
          `INSERT INTO share_requests(id, requester_id, file_id, title, description, status, created_at)
           VALUES(?1, ?2, ?3, ?4, ?5, 'pending', ?6)`
        )
        .bind(id, uid, body.file_id, (body.title ?? "").trim().slice(0, 100), (body.description ?? "").trim().slice(0, 500), Date.now())
        .run();
      ctx.waitUntil(
        writeAudit(env, {
          actorId: uid,
          actorName: user.username,
          action: "request.submit",
          target: id,
          summary: `file=${body.file_id}`,
          ip: clientIp(req),
        })
      );
      return json({ ok: true, id }, 201);
    }

    // ── 修改自己的密码 ──
    if (path === "/api/my/password" && method === "POST") {
      const body = await readJson<{ old_password?: string; new_password?: string }>(req);
      if (!body.old_password || !(await verifyUserPassword(body.old_password, user.password_hash, user.password_salt)))
        return json({ error: msg(req, "原密码错误", "Current password is incorrect") }, 400);
      if (!body.new_password || body.new_password.length < 6)
        return json({ error: msg(req, "新密码至少 6 位", "New password must be at least 6 characters") }, 400);
      const { hash, salt } = await hashUserPassword(body.new_password);
      await env.db
        .prepare("UPDATE users SET password_hash = ?1, password_salt = ?2, must_change_password = 0, updated_at = ?3 WHERE id = ?4")
        .bind(hash, salt, Date.now(), uid)
        .run();
      ctx.waitUntil(
        writeAudit(env, {
          actorId: uid,
          actorName: user.username,
          action: "member.password_change",
          ip: clientIp(req),
        })
      );
      return json({ ok: true });
    }

    return json({ error: "not_found" }, 404);
  } catch (e: any) {
    console.error("[handleMemberApi]", e?.stack || e);
    return json({ error: "server_error", message: String(e?.message ?? e) }, 500);
  }
}

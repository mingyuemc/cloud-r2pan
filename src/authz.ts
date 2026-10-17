/**
 * 成员与授权域 —— 用户、固定三级角色、管理员权限位、审计。
 *
 * 角色：super（不可剥夺）/ admin（权限位可配）/ member（固定能力）。
 * 会话身份见 auth.ts；此处只负责「谁是谁、能做什么」。
 */
import type { Env } from "./types";
import { randomId } from "./db";
import { randomHex, safeEqual } from "./crypto";

export type Role = "super" | "admin" | "member";

/** 管理员可配的权限位（super 隐式拥有全部） */
export const PERMISSIONS = [
  "file.read",
  "file.write",
  "share.manage",
  "market.moderate",
  "request.review",
  "member.manage",
  "settings.manage",
  "log.read",
  "log.manage",
  "code.manage",
] as const;
export type Permission = (typeof PERMISSIONS)[number];

/** 权限位中文标签（前端展示用） */
export const PERMISSION_LABELS: Record<Permission, string> = {
  "file.read": "浏览文件",
  "file.write": "上传 / 删除文件",
  "share.manage": "分享与直链",
  "market.moderate": "市场内容管理",
  "request.review": "审批成员申请",
  "member.manage": "成员与邀请码",
  "settings.manage": "系统设置",
  "log.read": "查看日志与统计",
  "log.manage": "清除日志 / 封禁",
  "code.manage": "激活码管理",
};

/** 新建 admin 时的默认权限位 */
export const DEFAULT_ADMIN_PERMISSIONS: Permission[] = [
  "file.read",
  "file.write",
  "share.manage",
  "log.read",
];

export const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

export interface UserRecord {
  id: string;
  username: string;
  display_name: string;
  password_hash: string;
  password_salt: string;
  role: Role;
  is_disabled: number;
  disabled_until: number | null;
  quota_bytes: number | null;
  session_version: number;
  must_change_password: number;
  created_by: string | null;
  created_at: number;
  updated_at: number;
  last_login_at: number | null;
  deleted_at: number | null;
}

/* ═══════════════ 口令哈希（PBKDF2-SHA256） ═══════════════ */

const PBKDF2_ITERATIONS = 100_000;

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations = PBKDF2_ITERATIONS): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

export async function hashUserPassword(password: string): Promise<{ hash: string; salt: string }> {
  const salt = randomHex(16);
  const hash = await pbkdf2(password, hexToBytes(salt));
  return { hash, salt };
}

export async function verifyUserPassword(password: string, hash: string, salt: string): Promise<boolean> {
  if (!hash || !salt) return false;
  try {
    const computed = await pbkdf2(password, hexToBytes(salt));
    return safeEqual(computed, hash);
  } catch {
    return false;
  }
}

/* ═══════════════ 用户查询 ═══════════════ */

const USER_COLUMNS =
  "id, username, display_name, password_hash, password_salt, role, is_disabled, disabled_until, quota_bytes, session_version, must_change_password, created_by, created_at, updated_at, last_login_at, deleted_at";

export async function getUserById(env: Env, id: string): Promise<UserRecord | null> {
  if (!id) return null;
  return await env.db
    .prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?1`)
    .bind(id)
    .first<UserRecord>();
}

export async function getUserByUsername(env: Env, username: string): Promise<UserRecord | null> {
  const uname = username.trim().toLowerCase();
  if (!uname) return null;
  return await env.db
    .prepare(`SELECT ${USER_COLUMNS} FROM users WHERE username = ?1`)
    .bind(uname)
    .first<UserRecord>();
}

/**
 * 判定用户当前是否可用（未删除、未禁用、禁用期已过）。
 * 用完即弃，不做缓存。
 */
export function isUserUsable(u: UserRecord | null): u is UserRecord {
  if (!u || u.deleted_at) return false;
  if (u.is_disabled) return false;
  if (u.disabled_until && u.disabled_until > Date.now()) return false;
  return true;
}

/* ═══════════════ 权限位 ═══════════════ */

export async function ensureDefaultRolePermissions(env: Env): Promise<void> {
  const row: any = await env.db
    .prepare("SELECT COUNT(*) AS c FROM role_permissions WHERE role_key = 'admin'")
    .first();
  if ((row?.c ?? 0) > 0) return;
  await env.db.batch(
    DEFAULT_ADMIN_PERMISSIONS.map((p) =>
      env.db
        .prepare("INSERT OR IGNORE INTO role_permissions(role_key, permission_key) VALUES('admin', ?1)")
        .bind(p)
    )
  );
}

export async function getAdminPermissions(env: Env): Promise<Set<string>> {
  const { results }: any = await env.db
    .prepare("SELECT permission_key FROM role_permissions WHERE role_key = 'admin'")
    .all();
  const set = new Set<string>((results ?? []).map((r: any) => r.permission_key));
  if (set.size === 0) {
    await ensureDefaultRolePermissions(env);
    for (const p of DEFAULT_ADMIN_PERMISSIONS) set.add(p);
  }
  return set;
}

export async function setAdminPermissions(env: Env, perms: string[]): Promise<void> {
  const valid = perms.filter((p) => (PERMISSIONS as readonly string[]).includes(p));
  await env.db.batch([
    env.db.prepare("DELETE FROM role_permissions WHERE role_key = 'admin'"),
    ...valid.map((p) =>
      env.db
        .prepare("INSERT OR IGNORE INTO role_permissions(role_key, permission_key) VALUES('admin', ?1)")
        .bind(p)
    ),
  ]);
}

/** 计算某用户的有效权限集合 */
export async function effectivePermissions(env: Env, u: UserRecord): Promise<Set<string>> {
  if (u.role === "super") return new Set(PERMISSIONS);
  if (u.role === "admin") return await getAdminPermissions(env);
  return new Set();
}

export function hasPermission(perms: Set<string>, key: string): boolean {
  return perms.has(key);
}

/* ═══════════════ 路由 → 权限位映射 ═══════════════ */

/** 未知 admin 路由的安全兜底：仅 super 可访问 */
export const SUPER_ONLY = "__super__";

/**
 * 根据 (method, path) 推导访问该 admin 路由所需的权限位。
 * 返回 null = 只需已登录（super/admin）；返回 SUPER_ONLY = 仅 super。
 */
export function permissionForRoute(method: string, path: string): string | null {
  // 认证类：登录/登出/会话 自身不需要额外权限
  if (path === "/api/admin/login" || path === "/api/admin/logout" || path === "/api/admin/session")
    return null;

  // 仪表盘
  if (method === "GET" && path === "/api/admin/stats") return "log.read";

  // 文件 / 存储对象
  if (method === "GET" && (path === "/api/admin/files" || path === "/api/admin/storage/objects"))
    return "file.read";
  if (method === "POST" && path === "/api/admin/upload") return "file.write";
  if (method === "DELETE" && /^\/api\/admin\/files\/[^/]+$/.test(path)) return "file.write";
  if (method === "DELETE" && path === "/api/admin/storage/objects") return "file.write";

  // 分享
  if (path === "/api/admin/shares" && (method === "POST" || method === "GET")) return "share.manage";
  if (method === "POST" && path === "/api/admin/shares/cleanup") return "share.manage";
  if (/^\/api\/admin\/shares\/[^/]+\/market$/.test(path)) return "market.moderate";
  if (method === "DELETE" && /^\/api\/admin\/shares\/[^/]+$/.test(path)) return "share.manage";

  // 市场管理
  if (method === "GET" && path === "/api/admin/market") return "market.moderate";

  // 日志类（查看 vs 清理/封禁）
  if (path === "/api/admin/logs" || path === "/api/admin/login-logs") {
    if (method === "GET") return "log.read";
    if (method === "DELETE") return "log.manage";
  }
  if (path === "/api/admin/bans") return method === "GET" ? "log.read" : "log.manage";
  if (method === "DELETE" && /^\/api\/admin\/bans\/[^/]+$/.test(path)) return "log.manage";

  // 2FA（super 级功能，但归入设置权限）
  if (path.startsWith("/api/admin/2fa/")) return "settings.manage";

  // 直链
  if (path === "/api/admin/direct-links" && (method === "POST" || method === "GET")) return "share.manage";
  if (method === "POST" && path === "/api/admin/direct-links/cleanup") return "share.manage";
  if (/^\/api\/admin\/direct-links\/[^/]+$/.test(path)) return "share.manage";

  // 系统设置 / 存储 / OAuth / Turnstile / 流量
  if (path === "/api/admin/settings") return "settings.manage";
  if (method === "DELETE" && path === "/api/admin/turnstile/visits") return "settings.manage";
  if (method === "POST" && path === "/api/admin/traffic/reset") return "settings.manage";
  if (path.startsWith("/api/admin/oauth/providers")) return "settings.manage";
  if (method === "POST" && path === "/api/admin/storage/test") return "settings.manage";

  // 激活码
  if (path.startsWith("/api/admin/codes")) return "code.manage";

  // 全球分布 / 数据库工具
  if (method === "GET" && path === "/api/admin/global/stats") return "log.read";
  if (path === "/api/admin/db/status" || path === "/api/admin/db/repair") return "settings.manage";

  // 成员 / 邀请码
  if (path.startsWith("/api/admin/users") || path.startsWith("/api/admin/invites"))
    return "member.manage";

  // 申请审批
  if (path.startsWith("/api/admin/requests")) return "request.review";

  // 审计日志
  if (method === "GET" && path === "/api/admin/audit") return "log.read";

  // 未登记的路由 → 仅 super（安全默认）
  return SUPER_ONLY;
}

/* ═══════════════ 审计 ═══════════════ */

export interface AuditInput {
  actorId: string | null;
  actorName: string;
  action: string;
  target?: string | null;
  summary?: string | null;
  result?: string;
  ip?: string | null;
}

/** 写审计日志（失败静默，不影响主流程） */
export async function writeAudit(env: Env, a: AuditInput): Promise<void> {
  try {
    await env.db
      .prepare(
        "INSERT INTO admin_audit_log(actor_id, actor_name, action, target, summary, result, ip, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
      )
      .bind(
        a.actorId ?? null,
        a.actorName || "?",
        a.action,
        a.target ?? "",
        a.summary ?? "",
        a.result ?? "success",
        a.ip ?? null,
        Date.now()
      )
      .run();
  } catch {
    /* 审计失败不阻断 */
  }
}

/* ═══════════════ 用户写入 ═══════════════ */

export interface CreateUserInput {
  username: string;
  password: string;
  role: Role;
  displayName?: string;
  quotaBytes?: number | null;
  createdBy?: string | null;
  mustChangePassword?: boolean;
}

export async function createUser(env: Env, input: CreateUserInput): Promise<UserRecord> {
  const username = input.username.trim().toLowerCase();
  if (!USERNAME_RE.test(username)) throw new Error("invalid_username");
  if (!input.password || input.password.length < 6) throw new Error("weak_password");

  const { hash, salt } = await hashUserPassword(input.password);
  const now = Date.now();
  const id = randomId(14);
  await env.db
    .prepare(
      `INSERT INTO users(id, username, display_name, password_hash, password_salt, role,
         quota_bytes, must_change_password, created_by, created_at, updated_at)
       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
    )
    .bind(
      id,
      username,
      (input.displayName ?? "").trim().slice(0, 40),
      hash,
      salt,
      input.role,
      input.quotaBytes ?? null,
      input.mustChangePassword ? 1 : 0,
      input.createdBy ?? null,
      now,
      now
    )
    .run();
  const created = await getUserById(env, id);
  if (!created) throw new Error("user_create_failed");
  return created;
}

/** 记录一次成功登录（最近登录时间 + 登录记录表） */
export async function recordUserLogin(env: Env, userId: string, ip: string | null, ua: string): Promise<void> {
  const now = Date.now();
  try {
    await env.db.batch([
      env.db.prepare("UPDATE users SET last_login_at = ?1 WHERE id = ?2").bind(now, userId),
      env.db
        .prepare("INSERT INTO user_login_info(user_id, ip, user_agent, created_at) VALUES(?1, ?2, ?3, ?4)")
        .bind(userId, ip, ua.slice(0, 200), now),
    ]);
  } catch {
    /* 记录失败不影响登录 */
  }
}

/** 使某用户的现有会话全部失效 */
export async function bumpSessionVersion(env: Env, userId: string): Promise<void> {
  await env.db
    .prepare("UPDATE users SET session_version = session_version + 1, updated_at = ?1 WHERE id = ?2")
    .bind(Date.now(), userId)
    .run();
}

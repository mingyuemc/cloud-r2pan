import type { Env } from "./types";

/**
 * 数据库初始化 —— 首次请求时自动建表, 无需手动迁移。
 * 表结构:
 *   files              上传到 R2 的文件元数据
 *   shares             分享链接 (token 即主键)
 *   download_logs      下载记录 (IP / 浏览器 / 系统 / 流量)
 *   login_logs         管理员登录记录 (成功/失败/登出, 防盗号审计)
 *   turnstile_visits   IP 每日访问计数 (超过阈值触发 Turnstile)
 *   banned_ips         封禁名单 (支持到期自动解封)
 *   settings           可调参数 + 流量用量统计
 *   traffic_stats      每日流量/下载汇总 (用于图表)
 */
const SCHEMA_STATEMENTS: string[] = [
  `CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime TEXT NOT NULL DEFAULT 'application/octet-stream',
    uploaded_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    password_hash TEXT,
    password_cipher TEXT,
    download_name TEXT,
    is_market INTEGER NOT NULL DEFAULT 0,
    market_views INTEGER NOT NULL DEFAULT 0,
    market_title TEXT,
    market_desc TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id)`,
  `CREATE INDEX IF NOT EXISTS idx_shares_market ON shares(is_market, revoked)`,
  `CREATE TABLE IF NOT EXISTS direct_links (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    download_name TEXT,
    notes TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_direct_links_file ON direct_links(file_id)`,
  `CREATE TABLE IF NOT EXISTS download_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    ip TEXT NOT NULL,
    ua TEXT,
    browser TEXT,
    os TEXT,
    country TEXT,
    bytes INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_logs_share_ip ON download_logs(share_id, ip, created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_logs_created ON download_logs(created_at)`,
  `CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    ip TEXT NOT NULL,
    ua TEXT,
    browser TEXT,
    os TEXT,
    country TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_login_logs_created ON login_logs(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_login_logs_ip ON login_logs(ip)`,
  `CREATE TABLE IF NOT EXISTS turnstile_visits (
    ip TEXT NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(ip, day)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_turnstile_day ON turnstile_visits(day)`,
  `CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_at INTEGER NOT NULL,
    expires_at INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS traffic_stats (
    day TEXT PRIMARY KEY,
    bytes INTEGER NOT NULL DEFAULT 0,
    downloads INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at)`,
  `CREATE TABLE IF NOT EXISTS oauth_providers (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    client_secret_cipher TEXT,
    scope TEXT NOT NULL DEFAULT 'openid email profile',
    custom_authorize_url TEXT NOT NULL DEFAULT '',
    custom_token_url TEXT NOT NULL DEFAULT '',
    custom_userinfo_url TEXT NOT NULL DEFAULT '',
    custom_token_field TEXT NOT NULL DEFAULT 'access_token',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_providers_enabled ON oauth_providers(enabled)`,
  // ═══════════ 激活码 ═══════════
  // 每个激活码独立额度，和全局 traffic_limit_bytes 互不影响
  `CREATE TABLE IF NOT EXISTS activation_plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    traffic_bytes INTEGER NOT NULL DEFAULT 0,
    days_valid INTEGER NOT NULL DEFAULT 0,
    quota_message TEXT,
    batch_id TEXT,
    notes TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS activation_codes (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    plan_id TEXT,
    traffic_bytes INTEGER NOT NULL DEFAULT 0,
    used_bytes INTEGER NOT NULL DEFAULT 0,
    days_valid INTEGER NOT NULL DEFAULT 0,
    quota_message TEXT,
    status TEXT NOT NULL DEFAULT 'unused',
    batch_id TEXT,
    notes TEXT,
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    expires_at INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_codes_status ON activation_codes(status)`,
  `CREATE INDEX IF NOT EXISTS idx_codes_batch ON activation_codes(batch_id)`,
  `CREATE INDEX IF NOT EXISTS idx_codes_code ON activation_codes(code)`,
  // ═══════════ WebDAV 虚拟目录 ═══════════
  `CREATE TABLE IF NOT EXISTS directories (
    path TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
  )`,

  // ══════════════════════════════════════════════════════════════
  // 成员与管理员（多用户）
  // ══════════════════════════════════════════════════════════════
  // 固定三级角色：super（不可剥夺）/ admin（权限位可配）/ member（固定能力）
  // 时间戳统一用毫秒（与全库一致），DB 触发器用 unixepoch()*1000 取当前时间。
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('super', 'admin', 'member')),
    is_disabled INTEGER NOT NULL DEFAULT 0 CHECK(is_disabled IN (0, 1)),
    disabled_until INTEGER,
    quota_bytes INTEGER,
    session_version INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK(must_change_password IN (0, 1)),
    created_by TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_login_at INTEGER,
    deleted_at INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_users_role ON users(role, is_disabled)`,
  // 管理员权限位（仅 role_key = 'admin' 使用）
  `CREATE TABLE IF NOT EXISTS role_permissions (
    role_key TEXT NOT NULL,
    permission_key TEXT NOT NULL,
    PRIMARY KEY(role_key, permission_key)
  )`,
  // 邀请码（手动新建之外的另一路注册入口）
  `CREATE TABLE IF NOT EXISTS registration_invites (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    note TEXT NOT NULL DEFAULT '',
    max_uses INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0,
    default_role TEXT NOT NULL DEFAULT 'member' CHECK(default_role IN ('admin', 'member')),
    created_by TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    deleted_at INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_registration_invites_token ON registration_invites(token)`,
  `CREATE TABLE IF NOT EXISTS registration_invite_uses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invite_id TEXT NOT NULL,
    user_id TEXT,
    used_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_registration_invite_uses_invite ON registration_invite_uses(invite_id)`,
  // 管理操作审计
  `CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT,
    actor_name TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT 'success',
    ip TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_admin_audit_time ON admin_audit_log(created_at, id)`,
  // 成员登录记录（每人最多留 3 条）
  `CREATE TABLE IF NOT EXISTS user_login_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_user_login_info_recent ON user_login_info(user_id, id DESC)`,
  // 成员提交的市场发布申请（管理员审批）
  `CREATE TABLE IF NOT EXISTS share_requests (
    id TEXT PRIMARY KEY,
    requester_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
    reviewer_id TEXT,
    review_reason TEXT NOT NULL DEFAULT '',
    share_id TEXT,
    created_at INTEGER NOT NULL,
    reviewed_at INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_share_requests_status ON share_requests(status, created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_share_requests_requester ON share_requests(requester_id, created_at)`,

  // ── 邀请码使用的事务内校验与计数（防并发超额） ──
  `CREATE TRIGGER IF NOT EXISTS validate_registration_invite_use
   BEFORE INSERT ON registration_invite_uses
   BEGIN
     SELECT CASE WHEN NOT EXISTS (
       SELECT 1 FROM registration_invites
       WHERE id = NEW.invite_id AND deleted_at IS NULL AND used_count < max_uses
         AND (expires_at IS NULL OR expires_at > (unixepoch() * 1000))
     ) THEN RAISE(ABORT, 'invite_unavailable') END;
   END`,
  `CREATE TRIGGER IF NOT EXISTS consume_registration_invite_use
   AFTER INSERT ON registration_invite_uses
   BEGIN
     UPDATE registration_invites SET used_count = used_count + 1 WHERE id = NEW.invite_id;
   END`,

  // ── 最后超级管理员保护：不可被降级 / 禁用 / 删除 ──
  `CREATE TRIGGER IF NOT EXISTS protect_last_super_update
   BEFORE UPDATE ON users
   WHEN OLD.role = 'super' AND OLD.deleted_at IS NULL AND OLD.is_disabled = 0
     AND (OLD.disabled_until IS NULL OR OLD.disabled_until <= (unixepoch() * 1000))
     AND (NEW.role != 'super' OR NEW.deleted_at IS NOT NULL OR NEW.is_disabled = 1
       OR (NEW.disabled_until IS NOT NULL AND NEW.disabled_until > (unixepoch() * 1000)))
     AND NOT EXISTS (
       SELECT 1 FROM users WHERE id != OLD.id AND role = 'super' AND deleted_at IS NULL
         AND is_disabled = 0 AND (disabled_until IS NULL OR disabled_until <= (unixepoch() * 1000))
     )
   BEGIN SELECT RAISE(ABORT, 'last_super'); END`,
  `CREATE TRIGGER IF NOT EXISTS protect_last_super_delete
   BEFORE DELETE ON users
   WHEN OLD.role = 'super' AND OLD.deleted_at IS NULL AND OLD.is_disabled = 0
     AND (OLD.disabled_until IS NULL OR OLD.disabled_until <= (unixepoch() * 1000))
     AND NOT EXISTS (
       SELECT 1 FROM users WHERE id != OLD.id AND role = 'super' AND deleted_at IS NULL
         AND is_disabled = 0 AND (disabled_until IS NULL OR disabled_until <= (unixepoch() * 1000))
     )
   BEGIN SELECT RAISE(ABORT, 'last_super'); END`,

  // ── 登录记录 / 审计日志自动裁剪（避免无限增长） ──
  `CREATE TRIGGER IF NOT EXISTS limit_user_login_info
   AFTER INSERT ON user_login_info
   BEGIN
     DELETE FROM user_login_info WHERE user_id = NEW.user_id AND id NOT IN (
       SELECT id FROM user_login_info WHERE user_id = NEW.user_id ORDER BY id DESC LIMIT 3
     );
   END`,
  `CREATE TRIGGER IF NOT EXISTS limit_admin_audit
   AFTER INSERT ON admin_audit_log
   BEGIN
     DELETE FROM admin_audit_log WHERE id IN (
       SELECT id FROM admin_audit_log
       WHERE created_at < (unixepoch() - 7776000) * 1000 OR id <= NEW.id - 20000
       ORDER BY id LIMIT 200
     );
   END`,
];

/** 所有预期的业务表 —— 自动建表 & 升级时都要检查 */
export const EXPECTED_TABLES = [
  "files", "shares", "direct_links", "download_logs", "login_logs",
  "turnstile_visits", "banned_ips", "settings", "traffic_stats",
  "oauth_states", "oauth_providers", "activation_plans", "activation_codes",
  "directories",
  // 成员与管理员
  "users", "role_permissions", "registration_invites", "registration_invite_uses",
  "admin_audit_log", "user_login_info", "share_requests",
];

let schemaReady = false;

/**
 * 确保数据库表结构存在 —— 首次请求时自动建表，无需手动迁移。
 *
 * ── Bug #5 修复：并发 DDL 风险 ──────────────────────────────────
 * 原实现每个 Isolate 都有独立的 schemaReady 布尔，冷启动时多 Isolate 会并发跑 DDL batch，
 * 虽然 CREATE TABLE IF NOT EXISTS 本身幂等，但每次都跑完整 DDL 很重。
 *
 * 新实现分层短路：
 *   1. schemaReady（内存）—— 本 Isolate 内的快速短路，零成本
 *   2. 轻量 SELECT settings —— 跨 Isolate 安全检测，schema 已就绪时极快（D1 命中索引）
 *   3. 只有表真的不存在时才执行 DDL batch —— 且用 try/catch 兜底竞态
 *
 * 绝大多数请求命中 ① 或 ②，不会触发 DDL。
 *
 * ⚠️ 注意：ALTER TABLE 迁移语句不参与 schemaReady 短路，每次 ensureSchema 都执行一遍
 * （用 try/catch 保护，列已存在时静默忽略），保证老用户库升级后列补齐。
 */

/** 所有增量迁移语句 —— 用 migration_version 追踪已执行版本，只跑未执行的 */
const MIGRATION_STATEMENTS: string[] = [
  "ALTER TABLE shares ADD COLUMN password_hash TEXT",
  "ALTER TABLE shares ADD COLUMN password_cipher TEXT",
  "ALTER TABLE shares ADD COLUMN download_name TEXT",
  "ALTER TABLE download_logs ADD COLUMN activation_code TEXT",
  "ALTER TABLE shares ADD COLUMN is_market INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE shares ADD COLUMN market_views INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE shares ADD COLUMN market_title TEXT",
  "ALTER TABLE shares ADD COLUMN market_desc TEXT",
  "CREATE INDEX IF NOT EXISTS idx_shares_market ON shares(is_market, revoked)",
  // ═══════════ WebDAV 虚拟目录 ═══════════
  "ALTER TABLE files ADD COLUMN path TEXT NOT NULL DEFAULT '/'",
  "CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)",
  // ═══════════ 成员空间归属（owner / created_by）═══════════
  "ALTER TABLE files ADD COLUMN owner_id TEXT",
  "CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id)",
  "ALTER TABLE directories ADD COLUMN owner_id TEXT",
  "CREATE INDEX IF NOT EXISTS idx_directories_owner ON directories(owner_id)",
  "ALTER TABLE shares ADD COLUMN created_by TEXT",
  "ALTER TABLE direct_links ADD COLUMN created_by TEXT",
];

/**
 * 幂等迁移：读 settings.migration_version，只跑 index >= version 的迁移语句。
 * 这样每个迁移只执行一次，避免每次请求都白跑 9 条 ALTER。
 * migration_version 存的是"已执行到的最高下标"，默认 -1（一个都没跑过）。
 */
async function runMigrations(env: Env): Promise<void> {
  let version = -1;
  try {
    const row: any = await env.db.prepare(
      "SELECT value FROM settings WHERE key = 'migration_version'"
    ).first();
    if (row?.value) version = Number(row.value) - 1; // 存的是 len（已执行数量），转成下标
  } catch {
    // settings 表可能还不存在（首次部署），这时候全跑一遍
  }

  if (version >= MIGRATION_STATEMENTS.length - 1) return; // 最新

  // 只跑 version+1 之后的迁移
  for (let i = version + 1; i < MIGRATION_STATEMENTS.length; i++) {
    try {
      await env.db.prepare(MIGRATION_STATEMENTS[i]).run();
    } catch {
      /* 列/索引已存在，忽略（保持幂等兜底） */
    }
  }

  // 写入新版本（存数量，不是下标）
  try {
    await env.db.prepare(
      "INSERT INTO settings(key, value) VALUES('migration_version', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(String(MIGRATION_STATEMENTS.length)).run();
  } catch {
    /* settings 表不存在时忽略 */
  }
}

/**
 * directories 表结构升级 —— 旧的 PRIMARY KEY(path) 无法区分不同 owner 的同名目录，
 * 重建为 (path, owner_key) 复合主键：
 *   - admin / 全局空间：owner_key = ''（避免 NULL 在唯一约束里被当作互不相同）
 *   - 成员空间：owner_key = 成员 id
 * 幂等：表已含 owner_key 列时直接返回。
 */
async function migrateDirectories(env: Env): Promise<void> {
  try {
    const exists: any = await env.db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='directories'")
      .first();
    if (!exists) return;

    const info: any = await env.db.prepare("PRAGMA table_info(directories)").all();
    const cols = new Set<string>((info.results ?? []).map((c: any) => c.name));
    if (cols.has("owner_key")) return; // 已是新结构

    // 清理可能残留的中间表（上次迁移中断）
    await env.db.prepare("DROP TABLE IF EXISTS directories_legacy").run();
    await env.db.prepare("ALTER TABLE directories RENAME TO directories_legacy").run();
    await env.db.prepare(
      "CREATE TABLE directories (path TEXT NOT NULL, owner_key TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, PRIMARY KEY(path, owner_key))"
    ).run();

    const legacyInfo: any = await env.db.prepare("PRAGMA table_info(directories_legacy)").all();
    const legacyCols = new Set<string>((legacyInfo.results ?? []).map((c: any) => c.name));
    const srcOwner = legacyCols.has("owner_id") ? "COALESCE(owner_id, '')" : "''";
    await env.db
      .prepare(
        `INSERT OR IGNORE INTO directories(path, owner_key, created_at) SELECT path, ${srcOwner}, created_at FROM directories_legacy`
      )
      .run();

    await env.db.prepare("DROP TABLE directories_legacy").run();
  } catch (e) {
    // 迁移失败不应阻塞建表流程（下次冷启动会重试）
    console.error("[migrateDirectories]", e);
  }
}

export async function ensureSchema(env: Env): Promise<void> {
  // ① 防御性检查：如果数据库绑定不存在，直接报错
  if (!env.db) {
    throw new Error("Database binding 'db' is not configured. " +
      "在 Cloudflare 控制台 → Worker Settings → Bindings 添加 D1 绑定，" +
      "或在 wrangler.jsonc 的 d1_databases 中声明。");
  }

  // ② 内存短路 —— 本 isolate 已确认过 schema + 迁移都就绪，直接返回，零成本
  //    Worker 冷启动 / isolate 重启时 schemaReady=false，会重新跑一遍
  if (schemaReady) return;

  // ③ 跨 Isolate 安全检测：用 sqlite_master 检查所有预期的表是否都存在
  let needCreate = false;
  try {
    const { results }: any = await env.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table'"
    ).all();
    const existing = new Set((results ?? []).map((r: any) => r.name));
    needCreate = !EXPECTED_TABLES.every((t) => existing.has(t));
  } catch {
    // 查询失败（如数据库完全损坏），继续尝试建表
    needCreate = true;
  }

  if (needCreate) {
    // ④ 真正的建表路径（首次部署 / 升级后新增表 / 库被清空时触发）
    // 用 try/catch 处理极端竞态：另一个 Isolate 刚好也在执行 DDL
    try {
      await env.db.batch(SCHEMA_STATEMENTS.map((sql) => env.db.prepare(sql)));
    } catch {
      // 竞态兜底：可能另一个 Isolate 刚建完表。
      // 再检测一次，确认表都存在就算成功
      try {
        const { results }: any = await env.db.prepare(
          "SELECT name FROM sqlite_master WHERE type='table'"
        ).all();
        const existing = new Set((results ?? []).map((r: any) => r.name));
        const stillMissing = EXPECTED_TABLES.filter((t) => !existing.has(t));
        if (stillMissing.length > 0)
          throw new Error("schema still missing tables after DDL: " + stillMissing.join(", "));
      } catch (e) {
        // 表确实没建起来，重新抛出让上层决定
        throw e;
      }
    }
  }

  // ⑤ 跑增量迁移（幂等，只跑未执行过的）
  await runMigrations(env);

  // ⑥ directories 表结构升级（幂等）
  await migrateDirectories(env);

  schemaReady = true;
}

/** 生成 URL 安全的随机 ID */
export function randomId(len = 12): string {
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

/**
 * 预期的列（旧版升级数据库可能缺失）—— 用于 getSchemaStatus 检测。
 * 只列出通过 MIGRATION_STATEMENTS 增量添加的列，CREATE TABLE IF NOT EXISTS 里本来就有的不算。
 */
const EXPECTED_COLUMNS: { table: string; column: string }[] = [
  { table: "shares", column: "password_hash" },
  { table: "shares", column: "password_cipher" },
  { table: "shares", column: "download_name" },
  { table: "shares", column: "is_market" },
  { table: "shares", column: "market_views" },
  { table: "shares", column: "market_title" },
  { table: "shares", column: "market_desc" },
  { table: "download_logs", column: "activation_code" },
  { table: "files", column: "path" },
  { table: "files", column: "owner_id" },
  // directories 表已迁移为 (path, owner_key) 复合主键，admin 空间 owner_key = ''
  { table: "directories", column: "owner_key" },
  { table: "shares", column: "created_by" },
  { table: "direct_links", column: "created_by" },
];

/** 预期的索引（同样是可能缺失的） */
const EXPECTED_INDEXES: string[] = [
  "idx_shares_market",
  "idx_files_path",
  "idx_files_owner",
];

export interface SchemaStatus {
  healthy: boolean;
  tables: { expected: string[]; existing: string[]; missing: string[] };
  columns: { table: string; column: string }[]; // 缺失的列
  indexes: string[]; // 缺失的索引名
  migration: { current: number; total: number; latest: boolean }; // current 是已执行数量
  tableCounts: Record<string, number>; // 各表行数（用于诊断）
}

/**
 * 查询数据库当前 schema 状态，用于设置页面展示健康状况。
 */
export async function getSchemaStatus(env: Env): Promise<SchemaStatus> {
  if (!env.db) {
    throw new Error("Database binding 'db' is not configured");
  }

  // 1. 所有现有表
  const tablesRes: any = await env.db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table'"
  ).all();
  const existingTables = new Set((tablesRes.results ?? []).map((r: any) => r.name));
  const missingTables = EXPECTED_TABLES.filter((t) => !existingTables.has(t));

  // 2. 所有现有索引名（只取我们关心的，避免系统索引干扰）
  const idxRes: any = await env.db.prepare(
    "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
  ).all();
  const existingIndexes = new Set((idxRes.results ?? []).map((r: any) => r.name));
  const missingIndexes = EXPECTED_INDEXES.filter((i) => !existingIndexes.has(i));

  // 3. 逐表检查缺失的列
  const missingColumns: { table: string; column: string }[] = [];
  for (const { table, column } of EXPECTED_COLUMNS) {
    if (!existingTables.has(table)) continue; // 表都没有了就不用查列了
    try {
      const colRes: any = await env.db.prepare(`PRAGMA table_info(${table})`).all();
      const has = (colRes.results ?? []).some((c: any) => c.name === column);
      if (!has) missingColumns.push({ table, column });
    } catch {
      /* 表不存在等情况，忽略 */
    }
  }

  // 4. 迁移版本
  let migrationCurrent = 0;
  try {
    const row: any = await env.db.prepare(
      "SELECT value FROM settings WHERE key = 'migration_version'"
    ).first();
    if (row?.value) migrationCurrent = Number(row.value);
  } catch { /* settings 表可能不存在 */ }
  const migrationTotal = MIGRATION_STATEMENTS.length;

  // 5. 各表行数（限制 6 个主要表）
  const tableCounts: Record<string, number> = {};
  for (const t of EXPECTED_TABLES) {
    if (!existingTables.has(t)) continue;
    try {
      const r: any = await env.db.prepare(`SELECT COUNT(*) AS c FROM ${t}`).first();
      tableCounts[t] = r?.c ?? 0;
    } catch {
      tableCounts[t] = -1; // 查询失败
    }
  }

  const healthy =
    missingTables.length === 0 &&
    missingColumns.length === 0 &&
    missingIndexes.length === 0 &&
    migrationCurrent >= migrationTotal;

  return {
    healthy,
    tables: {
      expected: EXPECTED_TABLES.slice(),
      existing: EXPECTED_TABLES.filter((t) => existingTables.has(t)),
      missing: missingTables,
    },
    columns: missingColumns,
    indexes: missingIndexes,
    migration: {
      current: migrationCurrent,
      total: migrationTotal,
      latest: migrationCurrent >= migrationTotal,
    },
    tableCounts,
  };
}

export interface RepairResult {
  ok: boolean;
  tablesCreated: string[];
  columnsAdded: string[];
  indexesCreated: string[];
  migrationsRun: number;
  durationMs: number;
  finalStatus: SchemaStatus;
  error?: string;
}

/**
 * 强制修复数据库 —— 重置 schemaReady 短路，重新跑完整 ensureSchema。
 * 即使之前已经 "schemaReady"，也会重新执行建表 + 增量迁移。
 *
 * 返回详细的修复摘要，便于前端展示。
 */
export async function repairDatabase(env: Env): Promise<RepairResult> {
  const start = Date.now();
  const tablesCreated: string[] = [];
  const columnsAdded: string[] = [];
  const indexesCreated: string[] = [];

  try {
    if (!env.db) throw new Error("Database binding 'db' is not configured");

    // 强制让 ensureSchema 重新跑一遍 —— 先把内存短路清掉
    schemaReady = false;

    // ── Step 1: 先记录修复前缺什么 —— 修复后对比就能知道 "新增了什么" ──
    const before = await getSchemaStatus(env);

    // ── Step 2: 跑完整 ensureSchema ──
    await ensureSchema(env);

    // ── Step 3: 再跑一次迁移，确保 migration_version 对齐 ──
    // （ensureSchema 内部已经跑过 runMigrations，但这里再次调用也幂等）
    await runMigrations(env);

    // ── Step 4: 记录修复后状态 ──
    const after = await getSchemaStatus(env);

    // 对比 before / after，算出修复动作
    tablesCreated.push(...before.tables.missing);
    for (const c of before.columns) {
      if (!after.columns.some((x) => x.table === c.table && x.column === c.column)) {
        columnsAdded.push(`${c.table}.${c.column}`);
      }
    }
    for (const idx of before.indexes) {
      if (!after.indexes.includes(idx)) indexesCreated.push(idx);
    }

    const migrationsRun =
      after.migration.current > before.migration.current
        ? after.migration.current - before.migration.current
        : 0;

    return {
      ok: true,
      tablesCreated,
      columnsAdded,
      indexesCreated,
      migrationsRun,
      durationMs: Date.now() - start,
      finalStatus: after,
    };
  } catch (e: any) {
    // 就算失败也尽量返回最终状态，方便用户排查
    let finalStatus: SchemaStatus | null = null;
    try {
      finalStatus = await getSchemaStatus(env);
    } catch { /* 数据库可能已经完全挂了 */ }
    return {
      ok: false,
      tablesCreated,
      columnsAdded,
      indexesCreated,
      migrationsRun: 0,
      durationMs: Date.now() - start,
      finalStatus: finalStatus ?? ({
        healthy: false,
        tables: { expected: EXPECTED_TABLES.slice(), existing: [], missing: EXPECTED_TABLES.slice() },
        columns: [],
        indexes: [],
        migration: { current: 0, total: 0, latest: false },
        tableCounts: {},
      }),
      error: String(e?.message ?? e),
    };
  }
}

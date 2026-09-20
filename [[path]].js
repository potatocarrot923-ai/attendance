const DEFAULT_SCHEDULE = [
  { id: "mon-math", day: "Monday", start: "08:00", end: "09:00", subject: "Mathematics", room: "Room 201", teacher: "Instructor" },
  { id: "mon-science", day: "Monday", start: "09:15", end: "10:15", subject: "Science", room: "Lab 1", teacher: "Instructor" },
  { id: "tue-english", day: "Tuesday", start: "08:00", end: "09:00", subject: "English", room: "Room 201", teacher: "Instructor" },
  { id: "tue-computing", day: "Tuesday", start: "09:15", end: "10:15", subject: "Computer Studies", room: "Computer Lab", teacher: "Instructor" },
  { id: "wed-history", day: "Wednesday", start: "08:00", end: "09:00", subject: "History", room: "Room 201", teacher: "Instructor" },
  { id: "wed-filipino", day: "Wednesday", start: "09:15", end: "10:15", subject: "Filipino", room: "Room 201", teacher: "Instructor" },
  { id: "thu-pe", day: "Thursday", start: "08:00", end: "09:00", subject: "Physical Education", room: "Gymnasium", teacher: "Instructor" },
  { id: "thu-arts", day: "Thursday", start: "09:15", end: "10:15", subject: "Arts", room: "Studio", teacher: "Instructor" },
  { id: "fri-review", day: "Friday", start: "08:00", end: "09:00", subject: "Computer Studies", room: "Computer Lab", teacher: "Instructor" },
  { id: "fri-advisory", day: "Friday", start: "09:15", end: "10:15", subject: "Other", room: "Room 201", teacher: "Instructor" },
];

const enc = new TextEncoder();
const now = () => new Date().toISOString();
const dateKey = () => new Date().toISOString().slice(0, 10);

function headers(extra = {}) {
  return {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(self), microphone=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; connect-src 'self'; camera 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    ...extra,
  };
}

function json(status, body) {
  return new Response(JSON.stringify(body), { status, headers: headers() });
}

async function setup(db) {
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS attendance (id TEXT PRIMARY KEY, student_id TEXT NOT NULL, student_name TEXT NOT NULL, subject TEXT NOT NULL, schedule_id TEXT NOT NULL, schedule_label TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL, reporter_role TEXT NOT NULL, teacher_status TEXT NOT NULL, flags TEXT NOT NULL, date_key TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(student_id, subject, date_key))"),
    db.prepare("CREATE INDEX IF NOT EXISTS attendance_today ON attendance(date_key)"),
  ]);
}

async function setting(db, key, fallback) {
  const row = await db.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
  if (row) return JSON.parse(row.value);
  await db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").bind(key, JSON.stringify(fallback)).run();
  return fallback;
}

async function setSetting(db, key, value) {
  await db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(key, JSON.stringify(value)).run();
}

async function getSession(db) {
  const today = dateKey();
  const saved = await setting(db, "current_session", null);
  if (saved && saved.date === today && /^\d{6}$/.test(saved.code || "")) return saved;
  const session = { date: today, code: String(Math.floor(Math.random() * 1000000)).padStart(6, "0"), startedAt: now() };
  await setSetting(db, "current_session", session);
  return session;
}

async function validToken(request, db) {
  const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return false;
  const row = await db.prepare("SELECT token FROM sessions WHERE token = ? AND expires_at > ?").bind(token, Date.now()).first();
  return Boolean(row);
}

function validSchedule(schedule) {
  if (!Array.isArray(schedule) || schedule.length > 100) return false;
  const ids = new Set();
  return schedule.every((slot) => {
    const fields = ["id", "day", "start", "end", "subject", "room", "teacher"];
    if (!slot || fields.some((key) => typeof slot[key] !== "string" || slot[key].length > 100) || !slot.id || ids.has(slot.id)) return false;
    ids.add(slot.id);
    return /^\d\d:\d\d$/.test(slot.start) && /^\d\d:\d\d$/.test(slot.end) && slot.start < slot.end;
  });
}

async function body(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 65536) throw new Error("Request too large");
  return request.json();
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export async function onRequest(context) {
  const { request, env } = context;
  if (!env.CARROT_DB) return json(503, { error: "Database binding is not configured" });
  if (!env.CARROT_ADMIN_PASSWORD) return json(503, { error: "Administrator password is not configured" });
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers({ "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS" }) });

  try {
    await setup(env.CARROT_DB);
    const path = new URL(request.url).pathname;
    const isAdmin = await validToken(request, env.CARROT_DB);

    if (request.method === "GET" && path === "/api/health") return json(200, { ok: true, mode: "cloudflare-d1" });
    if (request.method === "GET" && path === "/api/schedule") return json(200, await setting(env.CARROT_DB, "schedule", DEFAULT_SCHEDULE));
    if (request.method === "GET" && path === "/api/session") return json(200, await getSession(env.CARROT_DB));
    if (request.method === "GET" && path === "/api/attendance/today") {
      if (!isAdmin) return json(401, { error: "Authentication required" });
      const rows = await env.CARROT_DB.prepare("SELECT * FROM attendance WHERE date_key = ? ORDER BY created_at DESC").bind(dateKey()).all();
      return json(200, rows.results.map((row) => ({ studentId: row.student_id, studentName: row.student_name, subject: row.subject, scheduleId: row.schedule_id, scheduleLabel: row.schedule_label, status: row.status, reason: row.reason, reporterRole: row.reporter_role, teacherStatus: row.teacher_status, flags: JSON.parse(row.flags), dateKey: row.date_key, timestamp: row.created_at })));
    }

    if (request.method === "POST" && path === "/api/auth/login") {
      const data = await body(request);
      if (data.username !== "admin" || data.password !== env.CARROT_ADMIN_PASSWORD) return json(401, { error: "Invalid credentials" });
      const token = randomToken();
      await env.CARROT_DB.prepare("INSERT INTO sessions (token, expires_at) VALUES (?, ?)").bind(token, Date.now() + 8 * 60 * 60 * 1000).run();
      return json(200, { token, role: "instructor" });
    }

    if (request.method === "POST" && path === "/api/attendance") {
      const data = await body(request);
      const schedule = await setting(env.CARROT_DB, "schedule", DEFAULT_SCHEDULE);
      const slot = schedule.find((item) => item.id === data.scheduleId);
      const session = await getSession(env.CARROT_DB);
      if (!isAdmin && data.sessionCode !== session.code) return json(401, { error: "A valid classroom session code is required" });
      if (!slot || typeof data.studentId !== "string" || !data.studentId || data.studentId.length > 32 || typeof data.studentName !== "string" || !data.studentName || data.studentName.length > 80 || data.subject !== slot.subject || !["present", "late", "absent"].includes(data.status)) return json(400, { error: "Invalid attendance record" });
      try {
        await env.CARROT_DB.prepare("INSERT INTO attendance (id, student_id, student_name, subject, schedule_id, schedule_label, status, reason, reporter_role, teacher_status, flags, date_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), data.studentId, data.studentName, data.subject, data.scheduleId, String(data.scheduleLabel || ""), data.status, String(data.reason || ""), String(data.reporterRole || "Student"), String(data.teacherStatus || "Teacher present"), JSON.stringify(Array.isArray(data.flags) ? data.flags : []), dateKey(), now()).run();
      } catch (error) {
        if (String(error).includes("UNIQUE")) return json(409, { error: "Attendance already exists" });
        throw error;
      }
      return json(201, { ok: true });
    }

    if (request.method === "POST" && path === "/api/session") {
      if (!isAdmin) return json(401, { error: "Authentication required" });
      const session = { date: dateKey(), code: String(Math.floor(Math.random() * 1000000)).padStart(6, "0"), startedAt: now() };
      await setSetting(env.CARROT_DB, "current_session", session);
      return json(200, session);
    }

    if (request.method === "PUT" && path === "/api/schedule") {
      if (!isAdmin) return json(401, { error: "Authentication required" });
      const schedule = (await body(request)).schedule;
      if (!validSchedule(schedule)) return json(400, { error: "Invalid schedule" });
      await setSetting(env.CARROT_DB, "schedule", schedule);
      return json(200, schedule);
    }

    if (request.method === "POST" && ["/api/auth/forgot-password", "/api/auth/reset-password"].includes(path)) return json(503, { error: "Password recovery is not configured" });
    return json(404, { error: "Not found" });
  } catch (error) {
    console.error(error);
    return json(500, { error: "Server error" });
  }
}

"""Carrot Attendance shared API. Dependency-free local server for classroom.html."""
from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import ssl
import time
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

LAN_MODE = os.environ.get("CARROT_LAN_MODE") == "1"
PUBLIC_MODE = os.environ.get("CARROT_PUBLIC_MODE") == "1"
HOST = "0.0.0.0" if LAN_MODE or PUBLIC_MODE else "127.0.0.1"
PORT = int(os.environ.get("PORT", "3000"))
HTTPS_PORT = 3443
DATA_FILE = Path(__file__).with_name("carrot_data.json")
CERT_FILE = Path(__file__).with_name("certs") / "carrot-cert.pem"
KEY_FILE = Path(__file__).with_name("certs") / "carrot-key.pem"
PASSWORD_FILE = Path(__file__).with_name("carrot_admin_password.txt")
MAX_BODY_BYTES = 64 * 1024
TOKEN_TTL_SECONDS = 8 * 60 * 60
PASSWORD_ITERATIONS = 310_000
DEFAULT_SCHEDULE = [
    {"id": "mon-math", "day": "Monday", "start": "08:00", "end": "09:00", "subject": "Mathematics", "room": "Room 201", "teacher": "Instructor"},
    {"id": "mon-science", "day": "Monday", "start": "09:15", "end": "10:15", "subject": "Science", "room": "Lab 1", "teacher": "Instructor"},
    {"id": "tue-english", "day": "Tuesday", "start": "08:00", "end": "09:00", "subject": "English", "room": "Room 201", "teacher": "Instructor"},
    {"id": "tue-computing", "day": "Tuesday", "start": "09:15", "end": "10:15", "subject": "Computer Studies", "room": "Computer Lab", "teacher": "Instructor"},
    {"id": "wed-history", "day": "Wednesday", "start": "08:00", "end": "09:00", "subject": "History", "room": "Room 201", "teacher": "Instructor"},
    {"id": "wed-filipino", "day": "Wednesday", "start": "09:15", "end": "10:15", "subject": "Filipino", "room": "Room 201", "teacher": "Instructor"},
    {"id": "thu-pe", "day": "Thursday", "start": "08:00", "end": "09:00", "subject": "Physical Education", "room": "Gymnasium", "teacher": "Instructor"},
    {"id": "thu-arts", "day": "Thursday", "start": "09:15", "end": "10:15", "subject": "Arts", "room": "Studio", "teacher": "Instructor"},
    {"id": "fri-review", "day": "Friday", "start": "08:00", "end": "09:00", "subject": "Computer Studies", "room": "Computer Lab", "teacher": "Instructor"},
    {"id": "fri-advisory", "day": "Friday", "start": "09:15", "end": "10:15", "subject": "Other", "room": "Room 201", "teacher": "Instructor"},
]
TOKENS: dict[str, float] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
ATTENDANCE_ATTEMPTS: dict[str, list[float]] = {}
RESET_CHALLENGES: dict[str, dict] = {}
RESET_ATTEMPTS: dict[str, list[float]] = {}
RESET_TTL_SECONDS = 10 * 60
SMS_ACCOUNT_SID = os.environ.get("CARROT_TWILIO_ACCOUNT_SID", "")
SMS_AUTH_TOKEN = os.environ.get("CARROT_TWILIO_AUTH_TOKEN", "")
SMS_FROM_NUMBER = os.environ.get("CARROT_TWILIO_FROM_NUMBER", "")
RECOVERY_PHONE = os.environ.get("CARROT_ADMIN_PHONE", "")


def password_hash(value: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return digest.hex()


def password_matches(value: str, data: dict) -> bool:
    try:
        salt = bytes.fromhex(data["password_salt"])
        expected_hash = data["password_hash"]
    except (KeyError, ValueError, TypeError):
        return False
    return hmac.compare_digest(password_hash(value, salt), expected_hash)


def password_record(value: str) -> dict:
    salt = secrets.token_bytes(16)
    return {"password_salt": salt.hex(), "password_hash": password_hash(value, salt)}


def load_data() -> dict:
    generated_password = os.environ.get("CARROT_ADMIN_PASSWORD")
    if PUBLIC_MODE and not generated_password:
        raise RuntimeError("CARROT_ADMIN_PASSWORD must be set in public mode")
    if not PUBLIC_MODE and not generated_password and PASSWORD_FILE.exists():
        generated_password = PASSWORD_FILE.read_text(encoding="utf-8").strip()
    if DATA_FILE.exists():
        try:
            data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            if "password_salt" not in data:
                generated_password = generated_password or secrets.token_urlsafe(18)
                data.update(password_record(generated_password))
                if not PUBLIC_MODE:
                    PASSWORD_FILE.write_text(generated_password, encoding="utf-8")
            elif generated_password:
                data.update(password_record(generated_password))
                if not PUBLIC_MODE:
                    PASSWORD_FILE.write_text(generated_password, encoding="utf-8")
            return data
        except (OSError, json.JSONDecodeError):
            pass
    generated_password = generated_password or secrets.token_urlsafe(18)
    if not PUBLIC_MODE and not os.environ.get("CARROT_ADMIN_PASSWORD"):
        PASSWORD_FILE.write_text(generated_password, encoding="utf-8")
    return {"attendance": [], "reports": [], "schedule": DEFAULT_SCHEDULE, **password_record(generated_password)}


def save_data(data: dict) -> None:
    temporary_file = DATA_FILE.with_suffix(".tmp")
    temporary_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temporary_file.replace(DATA_FILE)


def current_session(data: dict) -> dict:
    today = date.today().isoformat()
    session = data.get("current_session")
    if not isinstance(session, dict) or session.get("date") != today or not str(session.get("code", "")).isdigit():
        session = {"date": today, "code": f"{secrets.randbelow(1_000_000):06d}", "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        data["current_session"] = session
        save_data(data)
    return session


def valid_token(handler: BaseHTTPRequestHandler) -> bool:
    token = handler.headers.get("Authorization", "").removeprefix("Bearer ")
    expires_at = TOKENS.get(token)
    if not expires_at:
        return False
    if expires_at <= time.time():
        TOKENS.pop(token, None)
        return False
    return True


def client_is_rate_limited(handler: BaseHTTPRequestHandler) -> bool:
    now = time.time()
    address = handler.client_address[0]
    attempts = [stamp for stamp in LOGIN_ATTEMPTS.get(address, []) if now - stamp < 60]
    LOGIN_ATTEMPTS[address] = attempts
    return len(attempts) >= 5


def record_attempt(handler: BaseHTTPRequestHandler) -> None:
    LOGIN_ATTEMPTS.setdefault(handler.client_address[0], []).append(time.time())


def attendance_is_rate_limited(handler: BaseHTTPRequestHandler) -> bool:
    now = time.time()
    address = handler.client_address[0]
    attempts = [stamp for stamp in ATTENDANCE_ATTEMPTS.get(address, []) if now - stamp < 60]
    ATTENDANCE_ATTEMPTS[address] = attempts
    return len(attempts) >= 30


def record_attendance_attempt(handler: BaseHTTPRequestHandler) -> None:
    ATTENDANCE_ATTEMPTS.setdefault(handler.client_address[0], []).append(time.time())


def reset_is_rate_limited(handler: BaseHTTPRequestHandler) -> bool:
    now = time.time()
    address = handler.client_address[0]
    attempts = [stamp for stamp in RESET_ATTEMPTS.get(address, []) if now - stamp < 60]
    RESET_ATTEMPTS[address] = attempts
    return len(attempts) >= 5


def record_reset_attempt(handler: BaseHTTPRequestHandler) -> None:
    RESET_ATTEMPTS.setdefault(handler.client_address[0], []).append(time.time())


def normalize_phone(value: object) -> str:
    digits = "".join(char for char in str(value) if char.isdigit())
    if digits.startswith("09") and len(digits) == 11:
        return "63" + digits[1:]
    if digits.startswith("639") and len(digits) == 12:
        return digits
    if digits.startswith("9") and len(digits) == 10:
        return "63" + digits
    return ""


def send_recovery_sms(phone: str, code: str) -> None:
    if not all((SMS_ACCOUNT_SID, SMS_AUTH_TOKEN, SMS_FROM_NUMBER, RECOVERY_PHONE)):
        raise RuntimeError("Password recovery SMS is not configured on the server")
    if phone != normalize_phone(RECOVERY_PHONE):
        raise RuntimeError("No recovery account is registered for that number")
    endpoint = f"https://api.twilio.com/2010-04-01/Accounts/{quote(SMS_ACCOUNT_SID)}/Messages.json"
    body = urlencode({
        "To": f"+{phone}",
        "From": SMS_FROM_NUMBER,
        "Body": f"Carrot Attendance password reset code: {code}. It expires in 10 minutes.",
    }).encode("utf-8")
    request = Request(endpoint, data=body, method="POST")
    credentials = f"{SMS_ACCOUNT_SID}:{SMS_AUTH_TOKEN}".encode("utf-8")
    import base64
    request.add_header("Authorization", f"Basic {base64.b64encode(credentials).decode('ascii')}")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urlopen(request, timeout=10) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError("SMS provider rejected the recovery message")


def valid_schedule(schedule: object) -> bool:
    if not isinstance(schedule, list) or len(schedule) > 100:
        return False
    required = {"id", "day", "start", "end", "subject", "room", "teacher"}
    ids: set[str] = set()
    for slot in schedule:
        if not isinstance(slot, dict) or not required.issubset(slot):
            return False
        if any(not isinstance(slot[key], str) or len(slot[key]) > 100 for key in required):
            return False
        if slot["id"] in ids or len(slot["id"]) < 1:
            return False
        ids.add(slot["id"])
        if len(slot["start"]) != 5 or len(slot["end"]) != 5 or slot["start"] >= slot["end"]:
            return False
    return True


class Handler(BaseHTTPRequestHandler):
    data = load_data()
    server_version = "Carrot"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        return

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin")
        if origin in {None, "http://127.0.0.1:3000", "http://localhost:3000", "https://127.0.0.1:3443", "https://localhost:3443"}:
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; connect-src 'self'; camera 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(self), microphone=()")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY_BYTES:
            raise ValueError("Request too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_OPTIONS(self) -> None:
        self.send_json(204, {})

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in {"/", "/classroom", "/classroom/", "/classroom.html", "/Attendance.html", "/at/Attendance.html"}:
            page = Path(__file__).with_name("classroom.html") if "classroom" in path or path == "/" else Path(__file__).parent / "at" / "Attendance.html"
            body = page.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(str(page))[0] or "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; connect-src 'self'; camera 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(self), microphone=()")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/health":
            self.send_json(200, {"ok": True, "mode": "shared-local-api"})
        elif path == "/api/schedule":
            self.send_json(200, self.data["schedule"])
        elif path == "/api/session":
            self.send_json(200, current_session(self.data))
        elif path == "/api/attendance/today":
            if not valid_token(self):
                self.send_json(401, {"error": "Authentication required"})
                return
            today = date.today().isoformat()
            self.send_json(200, [record for record in self.data["attendance"] if str(record.get("date_key", "")).startswith(today)])
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            payload = self.read_json()
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON"})
            return

        if path == "/api/auth/login":
            if client_is_rate_limited(self):
                self.send_json(429, {"error": "Too many login attempts. Try again in one minute."})
                return
            if payload.get("username") != "admin" or not password_matches(str(payload.get("password", "")), self.data):
                record_attempt(self)
                self.send_json(401, {"error": "Invalid credentials"})
                return
            token = secrets.token_urlsafe(32)
            TOKENS[token] = time.time() + TOKEN_TTL_SECONDS
            self.send_json(200, {"token": token, "role": "instructor"})
        elif path == "/api/attendance":
            if attendance_is_rate_limited(self):
                self.send_json(429, {"error": "Too many attendance attempts. Try again later."})
                return
            record_attendance_attempt(self)
            session = current_session(self.data)
            if not valid_token(self) and payload.get("sessionCode") != session["code"]:
                self.send_json(401, {"error": "A valid classroom session code is required"})
                return
            student_id = str(payload.get("studentId", ""))
            student_name = str(payload.get("studentName", ""))
            subject = str(payload.get("subject", ""))
            schedule_id = str(payload.get("scheduleId", ""))
            schedule_slot = next((slot for slot in self.data["schedule"] if slot.get("id") == schedule_id), None)
            if len(student_id) > 32 or not student_id or len(student_name) > 80 or not student_name or len(subject) > 80 or not schedule_slot or subject != schedule_slot.get("subject") or payload.get("status") not in {"present", "late", "absent"}:
                self.send_json(400, {"error": "Invalid attendance record"})
                return
            if not student_id or not subject or any(record.get("student_id") == student_id and record.get("subject") == subject and record.get("date_key") == date.today().isoformat() for record in self.data["attendance"]):
                self.send_json(409, {"error": "Attendance already exists or is incomplete"})
                return
            record = {str(key): value for key, value in payload.items() if key in {"studentId", "studentName", "subject", "scheduleId", "scheduleLabel", "status", "reason", "reporterRole", "teacherStatus", "flags"}}
            record["student_id"] = record.pop("studentId", "")
            record["student_name"] = record.pop("studentName", "")
            record["date_key"] = date.today().isoformat()
            self.data["attendance"].append(record)
            save_data(self.data)
            self.send_json(201, {"ok": True})
        elif path == "/api/auth/forgot-password":
            if reset_is_rate_limited(self):
                self.send_json(429, {"error": "Too many recovery requests. Try again in one minute."})
                return
            record_reset_attempt(self)
            phone = normalize_phone(payload.get("phone", ""))
            if not phone:
                self.send_json(400, {"error": "A valid phone number is required"})
                return
            challenge_id = secrets.token_urlsafe(24)
            code = f"{secrets.randbelow(1_000_000):06d}"
            RESET_CHALLENGES[challenge_id] = {
                "code_hash": hashlib.sha256(code.encode("ascii")).hexdigest(),
                "phone": phone,
                "expires_at": time.time() + RESET_TTL_SECONDS,
                "attempts": 0,
            }
            try:
                send_recovery_sms(phone, code)
            except (OSError, RuntimeError) as error:
                RESET_CHALLENGES.pop(challenge_id, None)
                self.send_json(503, {"error": str(error) if not PUBLIC_MODE else "Password recovery is temporarily unavailable"})
                return
            self.send_json(200, {"ok": True, "challengeId": challenge_id, "message": "If the number is eligible, a recovery code was sent."})
        elif path == "/api/auth/reset-password":
            challenge_id = str(payload.get("challengeId", ""))
            challenge = RESET_CHALLENGES.get(challenge_id)
            code = str(payload.get("code", ""))
            phone = normalize_phone(payload.get("phone", ""))
            new_password = str(payload.get("newPassword", ""))
            if not challenge or challenge["expires_at"] <= time.time():
                RESET_CHALLENGES.pop(challenge_id, None)
                self.send_json(400, {"error": "Recovery code expired. Request a new code."})
                return
            if challenge["attempts"] >= 5:
                RESET_CHALLENGES.pop(challenge_id, None)
                self.send_json(429, {"error": "Too many invalid recovery attempts. Request a new code."})
                return
            challenge["attempts"] += 1
            if phone != challenge["phone"] or not hmac.compare_digest(hashlib.sha256(code.encode("ascii")).hexdigest(), challenge["code_hash"]):
                self.send_json(400, {"error": "Invalid recovery code"})
                return
            if len(new_password) < 10 or len(new_password) > 128 or not any(char.isupper() for char in new_password) or not any(char.islower() for char in new_password) or not any(char.isdigit() for char in new_password):
                self.send_json(400, {"error": "Password must be 10–128 characters with uppercase, lowercase, and a number"})
                return
            self.data.update(password_record(new_password))
            if not PUBLIC_MODE:
                PASSWORD_FILE.write_text(new_password, encoding="utf-8")
            save_data(self.data)
            RESET_CHALLENGES.pop(challenge_id, None)
            TOKENS.clear()
            self.send_json(200, {"ok": True})
        elif path == "/api/session":
            if not valid_token(self):
                self.send_json(401, {"error": "Authentication required"})
                return
            session = {"date": date.today().isoformat(), "code": f"{secrets.randbelow(1_000_000):06d}", "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            self.data["current_session"] = session
            save_data(self.data)
            self.send_json(200, session)
        else:
            self.send_json(404, {"error": "Not found"})

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/schedule" or not valid_token(self):
            self.send_json(401 if path == "/api/schedule" else 404, {"error": "Authentication required"})
            return
        try:
            schedule = self.read_json().get("schedule")
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON"})
            return
        if not valid_schedule(schedule):
            self.send_json(400, {"error": "Invalid schedule"})
            return
        self.data["schedule"] = schedule
        save_data(self.data)
        self.send_json(200, schedule)


class RedirectHandler(BaseHTTPRequestHandler):
    server_version = "Carrot"
    sys_version = ""

    def do_GET(self) -> None:
        host = self.headers.get("Host", "localhost:3000").split(":", 1)[0]
        destination = f"https://{host}:{HTTPS_PORT}{self.path}"
        self.send_response(308)
        self.send_header("Location", destination)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_GET
    do_PUT = do_GET
    do_OPTIONS = do_GET

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    if PUBLIC_MODE:
        save_data(Handler.data)
        print(f"Carrot public service listening on {HOST}:{PORT}; use the hosting provider HTTPS URL.")
        ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

    if not CERT_FILE.exists() or not KEY_FILE.exists():
        raise SystemExit("Missing HTTPS certificate. Generate certs/carrot-cert.pem and certs/carrot-key.pem first.")
    save_data(Handler.data)
    https_server = ThreadingHTTPServer((HOST, HTTPS_PORT), Handler)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    https_server.socket = tls_context.wrap_socket(https_server.socket, server_side=True)

    http_server = ThreadingHTTPServer((HOST, PORT), RedirectHandler)
    import threading
    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    print(f"Carrot secure site: https://localhost:{HTTPS_PORT}/classroom.html")
    if LAN_MODE:
        print(f"LAN sharing enabled. Open https://192.168.254.123:{HTTPS_PORT}/classroom.html on the same Wi-Fi.")
    https_server.serve_forever()

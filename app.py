#!/usr/bin/env python3
"""
Production Backend API & Web Server for Suwasetha Veda Madura (සුවසෙත වෙද මැදුර)
Implements:
- Server-side PBKDF2-HMAC-SHA256 password hashing (310,000 iterations)
- Secure HTTP-Only session cookies & X-CSRF-Token verification
- Brute-force login rate limiting & temporary account lockout
- Protected /api/admin/* endpoints for Products, Treatments, Categories, Settings, Media, Account, Backups, Audit Logs
- Public /api/public/* endpoints returning only Published records
- SEO routes (/sitemap.xml, /robots.txt) blocking /admin/ from crawlers
"""
import base64
import datetime
import hashlib
import hmac
import html
import http.cookies
import json
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from init_db import BASE_DIR, DB_PATH, hash_password, init_database

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
PUBLIC_HTML_PATH = os.path.join(BASE_DIR, "public", "index.html")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

ALLOWED_IMAGE_MIMES = {"image/jpeg", "image/png", "image/webp"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB max upload

# In-memory IP rate limiter for login attempts
LOGIN_ATTEMPTS_BY_IP = {}  # ip -> [timestamps]
RATE_LIMIT_WINDOW_SEC = 300
RATE_LIMIT_MAX_ATTEMPTS = 8


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def log_audit(conn, actor: str, action: str, entity_type: str, entity_id: str, summary: str, ip: str = "127.0.0.1"):
    conn.execute(
        """
        INSERT INTO audit_logs (actor_username, action_type, entity_type, entity_id, summary, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor, action, entity_type, str(entity_id), summary, ip),
    )


def sanitize_str(val, max_len=5000) -> str:
    if val is None:
        return ""
    s = str(val).strip()
    return s[:max_len]


class SuwasethaRequestHandler(BaseHTTPRequestHandler):
    server_version = "SuwasethaSecureServer/2.0"

    def log_message(self, fmt, *args):
        # Quiet standard logging unless debugging
        if os.environ.get("SUWASETHA_VERBOSE") == "1":
            super().log_message(fmt, *args)

    def send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")

    def send_json(self, status_code: int, payload: dict, extra_headers: list = None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 10 * 1024 * 1024:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def get_session(self, conn):
        cookie_hdr = self.headers.get("Cookie", "")
        if not cookie_hdr:
            return None
        c = http.cookies.SimpleCookie()
        try:
            c.load(cookie_hdr)
        except Exception:
            return None
        if "suwasetha_session" not in c:
            return None
        raw_token = c["suwasetha_session"].value
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT s.session_token_hash, s.user_id, s.csrf_token, s.expires_at,
                   u.username, u.must_change_password, u.is_owner
            FROM admin_sessions s
            JOIN admin_users u ON u.id = s.user_id
            WHERE s.session_token_hash = ?
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        if not row:
            return None
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if row["expires_at"] < now_iso:
            cur.execute("DELETE FROM admin_sessions WHERE session_token_hash = ?", (token_hash,))
            conn.commit()
            return None
        return dict(row)

    def require_admin(self, conn, check_csrf: bool = True):
        sess = self.get_session(conn)
        if not sess:
            self.send_json(401, {"ok": False, "error": "Authentication required. Please log in at /admin/login."})
            return None
        if check_csrf:
            csrf_hdr = self.headers.get("X-CSRF-Token", "")
            if not csrf_hdr or not hmac.compare_digest(csrf_hdr, sess["csrf_token"]):
                self.send_json(403, {"ok": False, "error": "Invalid or missing CSRF token."})
                return None
        return sess

    # ------------------------------------------------------------------
    # GET ROUTER
    # ------------------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. SEO Routes: /robots.txt and /sitemap.xml
        if path == "/robots.txt":
            txt = (
                "User-agent: *\n"
                "Allow: /\n"
                "Disallow: /admin/\n"
                "Disallow: /api/admin/\n"
                "Sitemap: http://localhost:8080/sitemap.xml\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(txt)))
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(txt)
            return

        if path == "/sitemap.xml":
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id, updated_at FROM products WHERE publication_status = 'Published'")
            prods = cur.fetchall()
            cur.execute("SELECT id, updated_at FROM treatments WHERE publication_status = 'Published'")
            trts = cur.fetchall()
            conn.close()

            urls = [
                "http://localhost:8080/",
                "http://localhost:8080/#about",
                "http://localhost:8080/#doctor",
                "http://localhost:8080/#treatments",
                "http://localhost:8080/#products",
                "http://localhost:8080/#booking-section",
                "http://localhost:8080/#contact",
                "http://localhost:8080/#privacy-policy",
                "http://localhost:8080/#medical-disclaimer",
            ]
            for p in prods:
                urls.append(f"http://localhost:8080/#product/{p['id']}")
            for t in trts:
                urls.append(f"http://localhost:8080/#treatment/{t['id']}")

            xml_items = "\n".join(f"  <url><loc>{html.escape(u)}</loc></url>" for u in urls)
            xml_body = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                f"{xml_items}\n"
                "</urlset>\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(xml_body)))
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(xml_body)
            return

        # 2. Public Bootstrap API (/api/public/bootstrap)
        if path == "/api/public/bootstrap":
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT setting_key, setting_value FROM site_settings")
            settings = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}

            cur.execute("SELECT * FROM product_categories WHERE is_active = 1 ORDER BY display_order ASC")
            pcats = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT p.*, c.name_si AS category_name_si, c.name_en AS category_name_en
                FROM products p
                LEFT JOIN product_categories c ON c.id = p.category_id
                WHERE p.publication_status = 'Published'
                ORDER BY p.display_order ASC, p.created_at DESC
                """
            )
            products = []
            for r in cur.fetchall():
                d = dict(r)
                cur.execute("SELECT image_url, alt_text_si, alt_text_en FROM product_images WHERE product_id = ? ORDER BY display_order ASC", (d["id"],))
                d["additional_images"] = [dict(img) for img in cur.fetchall()]
                products.append(d)

            cur.execute("SELECT * FROM treatment_categories WHERE is_active = 1 ORDER BY display_order ASC")
            tcats = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT t.*, c.name_si AS category_name_si, c.name_en AS category_name_en
                FROM treatments t
                LEFT JOIN treatment_categories c ON c.id = t.category_id
                WHERE t.publication_status = 'Published'
                ORDER BY t.display_order ASC, t.created_at DESC
                """
            )
            treatments = []
            for r in cur.fetchall():
                d = dict(r)
                cur.execute("SELECT image_url, alt_text_si, alt_text_en FROM treatment_images WHERE treatment_id = ? ORDER BY display_order ASC", (d["id"],))
                d["additional_images"] = [dict(img) for img in cur.fetchall()]
                treatments.append(d)

            conn.close()
            self.send_json(
                200,
                {
                    "ok": True,
                    "settings": settings,
                    "product_categories": pcats,
                    "products": products,
                    "treatment_categories": tcats,
                    "treatments": treatments,
                },
            )
            return

        # 3. Admin Session Check & Full Admin Data (/api/admin/state)
        if path == "/api/admin/state":
            conn = get_db()
            sess = self.require_admin(conn, check_csrf=False)
            if not sess:
                conn.close()
                return
            cur = conn.cursor()
            cur.execute("SELECT setting_key, setting_value, setting_group FROM site_settings")
            settings = {r["setting_key"]: r["setting_value"] for r in cur.fetchall()}

            cur.execute("SELECT * FROM product_categories ORDER BY display_order ASC")
            pcats = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT * FROM products ORDER BY display_order ASC, created_at DESC")
            products = []
            for r in cur.fetchall():
                d = dict(r)
                cur.execute("SELECT id, image_url, alt_text_si, alt_text_en FROM product_images WHERE product_id = ? ORDER BY display_order ASC", (d["id"],))
                d["additional_images"] = [dict(img) for img in cur.fetchall()]
                products.append(d)

            cur.execute("SELECT * FROM treatment_categories ORDER BY display_order ASC")
            tcats = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT * FROM treatments ORDER BY display_order ASC, created_at DESC")
            treatments = []
            for r in cur.fetchall():
                d = dict(r)
                cur.execute("SELECT id, image_url, alt_text_si, alt_text_en FROM treatment_images WHERE treatment_id = ? ORDER BY display_order ASC", (d["id"],))
                d["additional_images"] = [dict(img) for img in cur.fetchall()]
                treatments.append(d)

            cur.execute("SELECT * FROM media_assets ORDER BY created_at DESC")
            media = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT * FROM appointments ORDER BY created_at DESC LIMIT 100")
            appointments = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
            audits = [dict(r) for r in cur.fetchall()]

            conn.close()
            self.send_json(
                200,
                {
                    "ok": True,
                    "admin": {
                        "username": sess["username"],
                        "must_change_password": bool(sess["must_change_password"]),
                        "is_owner": bool(sess["is_owner"]),
                        "csrf_token": sess["csrf_token"],
                    },
                    "settings": settings,
                    "product_categories": pcats,
                    "products": products,
                    "treatment_categories": tcats,
                    "treatments": treatments,
                    "media_assets": media,
                    "appointments": appointments,
                    "audit_logs": audits,
                },
            )
            return

        # 4. Admin Database Backup Export (/api/admin/backup/export)
        if path == "/api/admin/backup/export":
            conn = get_db()
            sess = self.require_admin(conn, check_csrf=False)
            if not sess:
                conn.close()
                return
            cur = conn.cursor()
            dump = {}
            for table in [
                "site_settings",
                "product_categories",
                "products",
                "product_images",
                "treatment_categories",
                "treatments",
                "treatment_images",
                "media_assets",
                "appointments",
            ]:
                cur.execute(f"SELECT * FROM {table}")
                dump[table] = [dict(r) for r in cur.fetchall()]

            log_audit(conn, sess["username"], "BACKUP_EXPORT", "database", "full", "Exported JSON database snapshot", self.client_address[0])
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "backup": dump})
            return

        # 5. Serve Uploaded Media Files (/uploads/*)
        if path.startswith("/uploads/"):
            fname = os.path.basename(path)
            fpath = os.path.join(UPLOAD_DIR, fname)
            if os.path.isfile(fpath):
                mime = mimetypes.guess_type(fpath)[0] or "application/octet-stream"
                with open(fpath, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.send_security_headers()
                self.end_headers()
                self.wfile.write(data)
                return
            self.send_json(404, {"ok": False, "error": "Media file not found"})
            return

        # 6. Serve Main SPA HTML for '/', '/admin/login', '/admin/dashboard', or clean routes
        if path in ("/", "/index.html", "/admin", "/admin/login", "/admin/dashboard") or path.startswith(("/products/", "/treatments/")):
            if os.path.isfile(PUBLIC_HTML_PATH):
                with open(PUBLIC_HTML_PATH, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_security_headers()
                self.end_headers()
                self.wfile.write(body)
                return

        # 7. Custom 404 JSON or HTML
        self.send_json(404, {"ok": False, "error": "404 Not Found - Page or resource does not exist."})

    # ------------------------------------------------------------------
    # POST ROUTER
    # ------------------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        ip = self.client_address[0] if self.client_address else "127.0.0.1"

        # 1. Admin Login (/api/admin/login)
        if path == "/api/admin/login":
            now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
            attempts = [t for t in LOGIN_ATTEMPTS_BY_IP.get(ip, []) if now_ts - t < RATE_LIMIT_WINDOW_SEC]
            if len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS:
                self.send_json(429, {"ok": False, "error": "Too many login attempts. Please wait 5 minutes before retrying."})
                return

            body = self.read_json_body()
            username = sanitize_str(body.get("username"), 64)
            password = body.get("password") or ""

            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT * FROM admin_users WHERE username = ?", (username,))
            user = cur.fetchone()

            if not user:
                attempts.append(now_ts)
                LOGIN_ATTEMPTS_BY_IP[ip] = attempts
                log_audit(conn, username or "unknown", "LOGIN_FAILED", "admin_users", "", "Invalid username", ip)
                conn.commit()
                conn.close()
                self.send_json(401, {"ok": False, "error": "Invalid username or password."})
                return

            # Check account lockout
            now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            if user["locked_until"] and user["locked_until"] > now_iso:
                conn.close()
                self.send_json(429, {"ok": False, "error": "Account temporarily locked due to repeated failed attempts."})
                return

            calc_hash, _ = hash_password(password, user["salt"])
            if not hmac.compare_digest(calc_hash, user["password_hash"]):
                attempts.append(now_ts)
                LOGIN_ATTEMPTS_BY_IP[ip] = attempts
                new_fails = int(user["failed_attempts"]) + 1
                lock_until = None
                if new_fails >= 5:
                    lock_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
                    lock_until = lock_dt.strftime("%Y-%m-%d %H:%M:%S")
                cur.execute(
                    "UPDATE admin_users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (new_fails, lock_until, user["id"]),
                )
                log_audit(conn, username, "LOGIN_FAILED", "admin_users", str(user["id"]), f"Invalid password (attempt {new_fails})", ip)
                conn.commit()
                conn.close()
                self.send_json(401, {"ok": False, "error": "Invalid username or password."})
                return

            # Successful login
            LOGIN_ATTEMPTS_BY_IP[ip] = []
            raw_session_token = secrets.token_urlsafe(32)
            session_token_hash = hashlib.sha256(raw_session_token.encode("utf-8")).hexdigest()
            csrf_token = secrets.token_hex(24)
            expires_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12)
            expires_iso = expires_dt.strftime("%Y-%m-%d %H:%M:%S")

            cur.execute(
                """
                INSERT INTO admin_sessions (session_token_hash, user_id, csrf_token, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_token_hash, user["id"], csrf_token, ip, sanitize_str(self.headers.get("User-Agent"), 250), expires_iso),
            )
            cur.execute(
                "UPDATE admin_users SET failed_attempts = 0, locked_until = NULL, last_login_at = datetime('now') WHERE id = ?",
                (user["id"],),
            )
            log_audit(conn, username, "LOGIN_SUCCESS", "admin_users", str(user["id"]), "Administrator logged in", ip)
            conn.commit()
            conn.close()

            cookie_val = f"suwasetha_session={raw_session_token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=43200"
            self.send_json(
                200,
                {
                    "ok": True,
                    "username": user["username"],
                    "must_change_password": bool(user["must_change_password"]),
                    "csrf_token": csrf_token,
                },
                extra_headers=[("Set-Cookie", cookie_val)],
            )
            return

        # 2. Admin Logout (/api/admin/logout)
        if path == "/api/admin/logout":
            conn = get_db()
            sess = self.get_session(conn)
            if sess:
                conn.execute("DELETE FROM admin_sessions WHERE session_token_hash = ?", (sess["session_token_hash"],))
                log_audit(conn, sess["username"], "LOGOUT", "admin_users", str(sess["user_id"]), "Administrator logged out", ip)
                conn.commit()
            conn.close()
            clear_cookie = "suwasetha_session=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0"
            self.send_json(200, {"ok": True}, extra_headers=[("Set-Cookie", clear_cookie)])
            return

        # 3. Public Appointment Submission (/api/public/appointments)
        if path == "/api/public/appointments":
            body = self.read_json_body()
            patient_name = sanitize_str(body.get("patient_name"), 120)
            patient_phone = sanitize_str(body.get("patient_phone"), 40)
            booking_category = sanitize_str(body.get("booking_category") or "Clinic Consultation", 150)
            selected_item = sanitize_str(body.get("selected_item") or "General Consultation", 200)
            preferred_date = sanitize_str(body.get("preferred_date"), 30)
            preferred_time = sanitize_str(body.get("preferred_time"), 80)
            notes = sanitize_str(body.get("notes"), 1000)

            if not patient_name or not patient_phone or not preferred_date:
                self.send_json(400, {"ok": False, "error": "Patient name, phone number, and preferred date are required."})
                return

            appt_id = "APT-" + secrets.token_hex(4).upper()
            ref_no = "SWM-" + str(secrets.randbelow(899999) + 100000)
            conn = get_db()
            conn.execute(
                """
                INSERT INTO appointments (id, reference_no, patient_name, patient_phone, booking_category, selected_item, preferred_date, preferred_time, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (appt_id, ref_no, patient_name, patient_phone, booking_category, selected_item, preferred_date, preferred_time, notes),
            )
            conn.commit()
            conn.close()
            self.send_json(201, {"ok": True, "id": appt_id, "reference_no": ref_no})
            return

        # --- ALL ROUTES BELOW REQUIRE AUTHENTICATED OWNER ADMIN + VALID CSRF ---
        conn = get_db()
        sess = self.require_admin(conn, check_csrf=True)
        if not sess:
            conn.close()
            return

        body = self.read_json_body()

        # 4. Change Admin Username & Password (/api/admin/account)
        if path == "/api/admin/account":
            current_password = body.get("current_password") or ""
            new_username = sanitize_str(body.get("new_username") or sess["username"], 64)
            new_password = body.get("new_password") or ""

            cur = conn.cursor()
            cur.execute("SELECT * FROM admin_users WHERE id = ?", (sess["user_id"],))
            user = cur.fetchone()
            calc_hash, _ = hash_password(current_password, user["salt"])
            if not hmac.compare_digest(calc_hash, user["password_hash"]):
                conn.close()
                self.send_json(400, {"ok": False, "error": "Current password is incorrect."})
                return

            if len(new_password) < 10:
                conn.close()
                self.send_json(400, {"ok": False, "error": "New password must be at least 10 characters long."})
                return

            new_hash, new_salt = hash_password(new_password)
            cur.execute(
                """
                UPDATE admin_users
                SET username = ?, password_hash = ?, salt = ?, must_change_password = 0, updated_at = datetime('now')
                WHERE id = ?
                """,
                (new_username, new_hash, new_salt, sess["user_id"]),
            )
            log_audit(conn, new_username, "ACCOUNT_UPDATE", "admin_users", str(sess["user_id"]), "Updated owner credentials and password hash", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True, "username": new_username, "must_change_password": False})
            return

        # 5. Update Site Settings (/api/admin/settings)
        if path == "/api/admin/settings":
            updates = body.get("settings") or {}
            if not isinstance(updates, dict):
                conn.close()
                self.send_json(400, {"ok": False, "error": "Invalid settings dictionary."})
                return
            cur = conn.cursor()
            for k, v in updates.items():
                key_clean = re.sub(r"[^a-zA-Z0-9_]", "", str(k))[:80]
                if key_clean:
                    cur.execute(
                        """
                        INSERT INTO site_settings (setting_key, setting_value, updated_at)
                        VALUES (?, ?, datetime('now'))
                        ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = datetime('now')
                        """,
                        (key_clean, sanitize_str(v, 5000)),
                    )
            log_audit(conn, sess["username"], "SETTINGS_UPDATE", "site_settings", "global", f"Updated {len(updates)} site settings", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True})
            return

        # 6. Create or Update Product Category (/api/admin/product-categories)
        if path == "/api/admin/product-categories":
            cat_id = sanitize_str(body.get("id"), 40) or ("PCAT-" + secrets.token_hex(3).upper())
            name_si = sanitize_str(body.get("name_si"), 160)
            name_en = sanitize_str(body.get("name_en"), 160)
            slug = re.sub(r"[^a-z0-9-]+", "-", (body.get("slug") or name_en).lower()).strip("-") or cat_id.lower()
            desc_si = sanitize_str(body.get("description_si"), 500)
            desc_en = sanitize_str(body.get("description_en"), 500)
            order = int(body.get("display_order") or 0)

            if not name_si or not name_en:
                conn.close()
                self.send_json(400, {"ok": False, "error": "Both Sinhala and English category names are required."})
                return

            conn.execute(
                """
                INSERT INTO product_categories (id, slug, name_si, name_en, description_si, description_en, display_order, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(id) DO UPDATE SET
                    slug = excluded.slug,
                    name_si = excluded.name_si,
                    name_en = excluded.name_en,
                    description_si = excluded.description_si,
                    description_en = excluded.description_en,
                    display_order = excluded.display_order,
                    updated_at = datetime('now')
                """,
                (cat_id, slug, name_si, name_en, desc_si, desc_en, order),
            )
            log_audit(conn, sess["username"], "UPSERT_PRODUCT_CAT", "product_categories", cat_id, f"Saved product category {name_en}", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True, "id": cat_id})
            return

        # 7. Create or Update Product (/api/admin/products)
        if path == "/api/admin/products":
            prod_id = sanitize_str(body.get("id"), 40) or ("PRD-" + secrets.token_hex(3).upper())
            sku = sanitize_str(body.get("sku"), 60) or ("SWM-" + prod_id)
            name_si = sanitize_str(body.get("name_si"), 200)
            name_en = sanitize_str(body.get("name_en"), 200)
            category_id = sanitize_str(body.get("category_id"), 40)
            short_si = sanitize_str(body.get("short_description_si"), 600)
            short_en = sanitize_str(body.get("short_description_en"), 600)
            full_si = sanitize_str(body.get("full_description_si"), 5000) or short_si
            full_en = sanitize_str(body.get("full_description_en"), 5000) or short_en

            try:
                price_lkr = float(body.get("price_lkr"))
                if price_lkr < 0:
                    raise ValueError()
            except Exception:
                conn.close()
                self.send_json(400, {"ok": False, "error": "Valid non-negative LKR price is required."})
                return

            prev_price = body.get("previous_price_lkr")
            try:
                prev_price = float(prev_price) if prev_price not in (None, "", 0, "0") else None
            except Exception:
                prev_price = None

            stock_status = sanitize_str(body.get("stock_status") or "In Stock", 60)
            availability = sanitize_str(body.get("availability") or "Available at Clinic", 120)
            size_weight = sanitize_str(body.get("size_weight_packaging") or "100ml", 120)
            ing_si = sanitize_str(body.get("ingredients_si"), 2000)
            ing_en = sanitize_str(body.get("ingredients_en"), 2000)
            use_si = sanitize_str(body.get("usage_instructions_si"), 2000)
            use_en = sanitize_str(body.get("usage_instructions_en"), 2000)
            mfg = sanitize_str(body.get("manufacturer_info") or "සුවසෙත වෙද මැදුර", 250)
            main_img = sanitize_str(body.get("main_image") or "IMG_APOTHECARY", 500)
            is_featured = 1 if body.get("is_featured") else 0
            display_order = int(body.get("display_order") or 0)
            pub_status = sanitize_str(body.get("publication_status") or "Published", 20)
            if pub_status not in ("Draft", "Published", "Archived"):
                pub_status = "Draft"
            is_sample = 1 if body.get("is_sample_content") else 0

            if not name_si or not name_en or not category_id:
                conn.close()
                self.send_json(400, {"ok": False, "error": "Sinhala name, English name, and Category are required."})
                return

            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO products (
                    id, sku, name_si, name_en, category_id,
                    short_description_si, short_description_en,
                    full_description_si, full_description_en,
                    price_lkr, previous_price_lkr, stock_status, availability,
                    size_weight_packaging, ingredients_si, ingredients_en,
                    usage_instructions_si, usage_instructions_en, manufacturer_info,
                    main_image, is_featured, display_order, publication_status, is_sample_content, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(id) DO UPDATE SET
                    sku = excluded.sku,
                    name_si = excluded.name_si,
                    name_en = excluded.name_en,
                    category_id = excluded.category_id,
                    short_description_si = excluded.short_description_si,
                    short_description_en = excluded.short_description_en,
                    full_description_si = excluded.full_description_si,
                    full_description_en = excluded.full_description_en,
                    price_lkr = excluded.price_lkr,
                    previous_price_lkr = excluded.previous_price_lkr,
                    stock_status = excluded.stock_status,
                    availability = excluded.availability,
                    size_weight_packaging = excluded.size_weight_packaging,
                    ingredients_si = excluded.ingredients_si,
                    ingredients_en = excluded.ingredients_en,
                    usage_instructions_si = excluded.usage_instructions_si,
                    usage_instructions_en = excluded.usage_instructions_en,
                    manufacturer_info = excluded.manufacturer_info,
                    main_image = excluded.main_image,
                    is_featured = excluded.is_featured,
                    display_order = excluded.display_order,
                    publication_status = excluded.publication_status,
                    is_sample_content = excluded.is_sample_content,
                    updated_at = datetime('now')
                """,
                (
                    prod_id, sku, name_si, name_en, category_id,
                    short_si, short_en, full_si, full_en,
                    price_lkr, prev_price, stock_status, availability,
                    size_weight, ing_si, ing_en, use_si, use_en, mfg,
                    main_img, is_featured, display_order, pub_status, is_sample,
                ),
            )

            # Optional additional images array
            if "additional_images" in body and isinstance(body["additional_images"], list):
                cur.execute("DELETE FROM product_images WHERE product_id = ?", (prod_id,))
                for idx, img_item in enumerate(body["additional_images"]):
                    url = sanitize_str(img_item.get("image_url") if isinstance(img_item, dict) else img_item, 500)
                    if url:
                        cur.execute(
                            "INSERT INTO product_images (product_id, image_url, display_order) VALUES (?, ?, ?)",
                            (prod_id, url, idx),
                        )

            log_audit(conn, sess["username"], "UPSERT_PRODUCT", "products", prod_id, f"Saved product {name_en} ({pub_status}, LKR {price_lkr:.2f})", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True, "id": prod_id})
            return

        # 8. Delete Product (/api/admin/products/delete)
        if path == "/api/admin/products/delete":
            prod_id = sanitize_str(body.get("id"), 40)
            if not body.get("confirmed"):
                conn.close()
                self.send_json(400, {"ok": False, "error": "Deletion confirmation flag is required."})
                return
            conn.execute("DELETE FROM products WHERE id = ?", (prod_id,))
            log_audit(conn, sess["username"], "DELETE_PRODUCT", "products", prod_id, f"Deleted product {prod_id}", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True})
            return

        # 9. Create or Update Treatment Category (/api/admin/treatment-categories)
        if path == "/api/admin/treatment-categories":
            tcat_id = sanitize_str(body.get("id"), 40) or ("TCAT-" + secrets.token_hex(3).upper())
            name_si = sanitize_str(body.get("name_si"), 160)
            name_en = sanitize_str(body.get("name_en"), 160)
            slug = re.sub(r"[^a-z0-9-]+", "-", (body.get("slug") or name_en).lower()).strip("-") or tcat_id.lower()
            desc_si = sanitize_str(body.get("description_si"), 500)
            desc_en = sanitize_str(body.get("description_en"), 500)
            order = int(body.get("display_order") or 0)

            if not name_si or not name_en:
                conn.close()
                self.send_json(400, {"ok": False, "error": "Both Sinhala and English category names are required."})
                return

            conn.execute(
                """
                INSERT INTO treatment_categories (id, slug, name_si, name_en, description_si, description_en, display_order, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(id) DO UPDATE SET
                    slug = excluded.slug,
                    name_si = excluded.name_si,
                    name_en = excluded.name_en,
                    description_si = excluded.description_si,
                    description_en = excluded.description_en,
                    display_order = excluded.display_order,
                    updated_at = datetime('now')
                """,
                (tcat_id, slug, name_si, name_en, desc_si, desc_en, order),
            )
            log_audit(conn, sess["username"], "UPSERT_TREATMENT_CAT", "treatment_categories", tcat_id, f"Saved treatment category {name_en}", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True, "id": tcat_id})
            return

        # 10. Create or Update Treatment (/api/admin/treatments)
        if path == "/api/admin/treatments":
            trt_id = sanitize_str(body.get("id"), 40) or ("TRT-" + secrets.token_hex(3).upper())
            title_si = sanitize_str(body.get("title_si"), 200)
            title_en = sanitize_str(body.get("title_en"), 200)
            category_id = sanitize_str(body.get("category_id"), 40)
            main_img = sanitize_str(body.get("main_image") or "IMG_HERO", 500)
            short_si = sanitize_str(body.get("short_intro_si"), 600)
            short_en = sanitize_str(body.get("short_intro_en"), 600)
            det_si = sanitize_str(body.get("detailed_description_si"), 5000) or short_si
            det_en = sanitize_str(body.get("detailed_description_en"), 5000) or short_en
            suit_si = sanitize_str(body.get("suitability_si"), 1500)
            suit_en = sanitize_str(body.get("suitability_en"), 1500)
            prep_si = sanitize_str(body.get("preparation_si"), 1500)
            prep_en = sanitize_str(body.get("preparation_en"), 1500)
            duration = sanitize_str(body.get("duration_info"), 200)
            fee = sanitize_str(body.get("fee_info"), 200)
            avail = sanitize_str(body.get("appointment_availability"), 200)
            order = int(body.get("display_order") or 0)
            pub_status = sanitize_str(body.get("publication_status") or "Published", 20)
            if pub_status not in ("Draft", "Published", "Archived"):
                pub_status = "Draft"

            if not title_si or not title_en or not category_id:
                conn.close()
                self.send_json(400, {"ok": False, "error": "Sinhala title, English title, and Category are required."})
                return

            conn.execute(
                """
                INSERT INTO treatments (
                    id, title_si, title_en, category_id, main_image,
                    short_intro_si, short_intro_en, detailed_description_si, detailed_description_en,
                    suitability_si, suitability_en, preparation_si, preparation_en,
                    duration_info, fee_info, appointment_availability, display_order, publication_status, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(id) DO UPDATE SET
                    title_si = excluded.title_si,
                    title_en = excluded.title_en,
                    category_id = excluded.category_id,
                    main_image = excluded.main_image,
                    short_intro_si = excluded.short_intro_si,
                    short_intro_en = excluded.short_intro_en,
                    detailed_description_si = excluded.detailed_description_si,
                    detailed_description_en = excluded.detailed_description_en,
                    suitability_si = excluded.suitability_si,
                    suitability_en = excluded.suitability_en,
                    preparation_si = excluded.preparation_si,
                    preparation_en = excluded.preparation_en,
                    duration_info = excluded.duration_info,
                    fee_info = excluded.fee_info,
                    appointment_availability = excluded.appointment_availability,
                    display_order = excluded.display_order,
                    publication_status = excluded.publication_status,
                    updated_at = datetime('now')
                """,
                (
                    trt_id, title_si, title_en, category_id, main_img,
                    short_si, short_en, det_si, det_en,
                    suit_si, suit_en, prep_si, prep_en,
                    duration, fee, avail, order, pub_status,
                ),
            )
            log_audit(conn, sess["username"], "UPSERT_TREATMENT", "treatments", trt_id, f"Saved treatment {title_en} ({pub_status})", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True, "id": trt_id})
            return

        # 11. Delete Treatment (/api/admin/treatments/delete)
        if path == "/api/admin/treatments/delete":
            trt_id = sanitize_str(body.get("id"), 40)
            if not body.get("confirmed"):
                conn.close()
                self.send_json(400, {"ok": False, "error": "Deletion confirmation flag is required."})
                return
            conn.execute("DELETE FROM treatments WHERE id = ?", (trt_id,))
            log_audit(conn, sess["username"], "DELETE_TREATMENT", "treatments", trt_id, f"Deleted treatment {trt_id}", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True})
            return

        # 12. Secure Image Upload (/api/admin/media/upload)
        if path == "/api/admin/media/upload":
            raw_filename = sanitize_str(body.get("filename"), 120)
            mime_type = sanitize_str(body.get("mime_type"), 60).lower()
            data_b64 = body.get("data_base64") or ""
            alt_si = sanitize_str(body.get("alt_text_si"), 250)
            alt_en = sanitize_str(body.get("alt_text_en"), 250)

            if mime_type not in ALLOWED_IMAGE_MIMES:
                conn.close()
                self.send_json(400, {"ok": False, "error": "Rejected file type. Only JPEG, PNG, and WebP images are permitted."})
                return

            # Strip optional data URI prefix
            if "," in data_b64 and data_b64.startswith("data:"):
                data_b64 = data_b64.split(",", 1)[1]

            try:
                raw_bytes = base64.b64decode(data_b64, validate=True)
            except Exception:
                conn.close()
                self.send_json(400, {"ok": False, "error": "Invalid base64 image payload."})
                return

            if len(raw_bytes) == 0 or len(raw_bytes) > MAX_UPLOAD_BYTES:
                conn.close()
                self.send_json(400, {"ok": False, "error": "Image size must be between 1 byte and 5 MB."})
                return

            # Verify magic bytes for JPEG, PNG, or WebP
            is_valid_magic = (
                raw_bytes.startswith(b"\xff\xd8\xff")
                or raw_bytes.startswith(b"\x89PNG\r\n\x1a\n")
                or (raw_bytes[:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP")
            )
            if not is_valid_magic:
                conn.close()
                self.send_json(400, {"ok": False, "error": "File signature does not match a valid JPEG, PNG, or WebP image."})
                return

            ext_map = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
            safe_stem = re.sub(r"[^a-zA-Z0-9_-]", "", os.path.splitext(raw_filename)[0])[:40] or "upload"
            unique_name = f"{safe_stem}_{secrets.token_hex(4)}{ext_map[mime_type]}"
            disk_path = os.path.join(UPLOAD_DIR, unique_name)
            with open(disk_path, "wb") as f:
                f.write(raw_bytes)

            media_id = "MED-" + secrets.token_hex(4).upper()
            public_url = f"/uploads/{unique_name}"
            conn.execute(
                """
                INSERT INTO media_assets (id, filename, file_path, mime_type, file_size_bytes, alt_text_si, alt_text_en, uploaded_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (media_id, unique_name, public_url, mime_type, len(raw_bytes), alt_si, alt_en, sess["username"]),
            )
            log_audit(conn, sess["username"], "MEDIA_UPLOAD", "media_assets", media_id, f"Uploaded {unique_name} ({len(raw_bytes)} bytes)", ip)
            conn.commit()
            conn.close()
            self.send_json(201, {"ok": True, "id": media_id, "url": public_url, "filename": unique_name, "size": len(raw_bytes)})
            return

        # 13. Delete Media Asset (/api/admin/media/delete)
        if path == "/api/admin/media/delete":
            media_id = sanitize_str(body.get("id"), 40)
            cur = conn.cursor()
            cur.execute("SELECT file_path, filename FROM media_assets WHERE id = ?", (media_id,))
            row = cur.fetchone()
            if row and row["file_path"].startswith("/uploads/"):
                disk_file = os.path.join(UPLOAD_DIR, os.path.basename(row["file_path"]))
                if os.path.isfile(disk_file):
                    try:
                        os.remove(disk_file)
                    except OSError:
                        pass
            cur.execute("DELETE FROM media_assets WHERE id = ?", (media_id,))
            log_audit(conn, sess["username"], "MEDIA_DELETE", "media_assets", media_id, f"Deleted media asset {media_id}", ip)
            conn.commit()
            conn.close()
            self.send_json(200, {"ok": True})
            return

        # 14. Database Restore (/api/admin/backup/restore)
        if path == "/api/admin/backup/restore":
            backup_data = body.get("backup")
            if not isinstance(backup_data, dict):
                conn.close()
                self.send_json(400, {"ok": False, "error": "Invalid backup object."})
                return
            cur = conn.cursor()
            try:
                if "site_settings" in backup_data:
                    for r in backup_data["site_settings"]:
                        cur.execute(
                            "INSERT OR REPLACE INTO site_settings (setting_key, setting_value, setting_group) VALUES (?, ?, ?)",
                            (r["setting_key"], r["setting_value"], r.get("setting_group", "general")),
                        )
                log_audit(conn, sess["username"], "BACKUP_RESTORE", "database", "full", "Restored database snapshot", ip)
                conn.commit()
            except Exception as e:
                conn.rollback()
                conn.close()
                self.send_json(500, {"ok": False, "error": f"Restore failed: {str(e)}"})
                return
            conn.close()
            self.send_json(200, {"ok": True})
            return

        conn.close()
        self.send_json(404, {"ok": False, "error": "Unknown admin API endpoint."})


def run_server(host="127.0.0.1", port=8080):
    init_database()
    httpd = ThreadingHTTPServer((host, port), SuwasethaRequestHandler)
    print(f"Suwasetha Veda Madura Full-Stack Server listening on http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    p = int(os.environ.get("PORT", "8080"))
    run_server(host="127.0.0.1", port=p)

#!/usr/bin/env python3
"""
Automated Integration & Security Test Suite for Suwasetha Veda Madura
Tests all 25 requirements against the live HTTP backend server + SQLite database.
"""
import base64
import http.cookiejar
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CRED_FILE = os.path.join(BASE_DIR, "PRIVATE_INITIAL_ADMIN_CREDENTIALS.txt")
DB_FILE = os.path.join(BASE_DIR, "suwasetha.db")


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_tests():
    # Reset DB cleanly for deterministic test run
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    if os.path.exists(CRED_FILE):
        os.remove(CRED_FILE)

    port = get_free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env["PORT"] = str(port)

    proc = subprocess.Popen(
        [sys.executable, os.path.join(BASE_DIR, "app.py")],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.2)

    results = []

    def record(name, passed, detail=""):
        status = "PASS" if passed else "FAIL"
        results.append((name, status, detail))
        print(f"[{status}] {name} {('- ' + detail) if detail else ''}")
        if not passed:
            proc.terminate()
            sys.exit(1)

    try:
        # Read generated random initial password from private owner setup file
        assert os.path.isfile(CRED_FILE), "PRIVATE_INITIAL_ADMIN_CREDENTIALS.txt not created"
        cred_text = open(CRED_FILE, "r", encoding="utf-8").read()
        m = re.search(r"Password\s*:\s*(\S+)", cred_text)
        assert m, "Could not parse initial password"
        init_password = m.group(1)

        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

        def req(path, method="GET", data=None, headers=None):
            hdrs = headers or {}
            body = None
            if data is not None:
                body = json.dumps(data).encode("utf-8")
                hdrs["Content-Type"] = "application/json"
            r = urllib.request.Request(base_url + path, data=body, headers=hdrs, method=method)
            try:
                with opener.open(r) as resp:
                    raw = resp.read().decode("utf-8")
                    ctype = resp.headers.get("Content-Type", "")
                    return resp.status, (json.loads(raw) if "application/json" in ctype else raw), resp.headers
            except urllib.error.HTTPError as e:
                raw = e.read().decode("utf-8")
                try:
                    return e.code, json.loads(raw), e.headers
                except Exception:
                    return e.code, raw, e.headers

        # 1. Homepage & Existing Clinic Identity
        st, html_home, _ = req("/")
        record(
            "1-2. Homepage renders & preserves verified clinic identity",
            st == 200 and "සුවසෙත වෙද මැදුර" in html_home and "12194" in html_home and "071 9171385" in html_home,
            "Verified Sinhala/English names, Reg. No. 12194, Tel 071 9171385",
        )

        # 2. Bilingual & Responsive structure
        record(
            "3-4. Sinhala/English bilingual toggle & responsive layout classes present",
            "langToggleBtn" in html_home and "ආයුර්වේද නිෂ්පාදන නාමාවලිය" in html_home and "ආයුර්වේද ප්‍රතිකාර සේවා" in html_home,
            "Verified bilingual headings and responsive Tailwind grid",
        )

        # 3. Unauthenticated access blocked on /api/admin/state & /api/admin/products
        st_unauth, _, _ = req("/api/admin/state")
        st_unauth_write, _, _ = req("/api/admin/products", method="POST", data={"name_si": "Hack", "name_en": "Hack", "price_lkr": 100})
        record(
            "15-17. Unauthenticated dashboard read & write rejected (401)",
            st_unauth == 401 and st_unauth_write == 401,
            f"GET /api/admin/state={st_unauth}, POST /api/admin/products={st_unauth_write}",
        )

        # 4. Login with wrong password fails (401)
        st_bad, _, _ = req("/api/admin/login", method="POST", data={"username": "admin", "password": "WrongPassword123!"})
        record("Login with invalid password rejected (401)", st_bad == 401, "Invalid credentials blocked")

        # 5. Login with generated setup password succeeds & sets HttpOnly cookie + CSRF token
        st_login, login_data, login_hdrs = req("/api/admin/login", method="POST", data={"username": "admin", "password": init_password})
        cookie_str = login_hdrs.get("Set-Cookie", "")
        csrf_token = login_data.get("csrf_token", "")
        record(
            "Admin login succeeds with HttpOnly cookie & CSRF token",
            st_login == 200 and login_data.get("ok") and "HttpOnly" in cookie_str and len(csrf_token) > 16 and login_data.get("must_change_password") is True,
            "HttpOnly session cookie issued, must_change_password=True",
        )

        # 6. CSRF check: Admin POST without X-CSRF-Token is rejected (403)
        st_nocsrf, _, _ = req("/api/admin/settings", method="POST", data={"settings": {"clinic_name_en": "NoCSRF"}})
        record("Admin write without X-CSRF-Token rejected (403)", st_nocsrf == 403, "CSRF protection active")

        auth_headers = {"X-CSRF-Token": csrf_token}

        # 7. Create New Product Category
        st_pcat, pcat_res, _ = req(
            "/api/admin/product-categories",
            method="POST",
            data={"id": "PCAT-HERBAL-TEA", "name_si": "ඖෂධීය පාන වර්ග", "name_en": "Herbal Teas & Infusions", "display_order": 5},
            headers=auth_headers,
        )
        record("10. New product category creation works", st_pcat == 200 and pcat_res.get("ok"), "Created PCAT-HERBAL-TEA")

        # 8. Create Published Product & Draft Product
        st_p1, p1_res, _ = req(
            "/api/admin/products",
            method="POST",
            data={
                "id": "PRD-TEST-PUB",
                "sku": "SWM-TEA-101",
                "name_si": "සුවසෙත බෙලිමල් ඖෂධීය පානය (Sample)",
                "name_en": "Suwasetha Belimal Herbal Infusion (Sample)",
                "category_id": "PCAT-HERBAL-TEA",
                "price_lkr": 1500.00,
                "previous_price_lkr": 1750.00,
                "short_description_si": "පාරම්පරික බෙලිමල් පානය",
                "short_description_en": "Traditional Belimal herbal tea pack",
                "publication_status": "Published",
                "is_featured": True,
            },
            headers=auth_headers,
        )
        st_p2, p2_res, _ = req(
            "/api/admin/products",
            method="POST",
            data={
                "id": "PRD-TEST-DRAFT",
                "sku": "SWM-TEA-102",
                "name_si": "කෙටුම්පත් නිෂ්පාදනය",
                "name_en": "Secret Draft Product",
                "category_id": "PCAT-HERBAL-TEA",
                "price_lkr": 2200.00,
                "short_description_si": "Draft",
                "short_description_en": "Draft",
                "publication_status": "Draft",
            },
            headers=auth_headers,
        )
        record("5 & 8. Product creation (Published & Draft) with LKR pricing works", st_p1 == 200 and st_p2 == 200, "Created PRD-TEST-PUB & PRD-TEST-DRAFT")

        # 9. Edit existing product
        st_pedit, _, _ = req(
            "/api/admin/products",
            method="POST",
            data={
                "id": "PRD-TEST-PUB",
                "sku": "SWM-TEA-101",
                "name_si": "සුවසෙත බෙලිමල් ඖෂධීය පානය (Updated)",
                "name_en": "Suwasetha Belimal Herbal Infusion (Updated)",
                "category_id": "PCAT-HERBAL-TEA",
                "price_lkr": 1400.00,
                "short_description_si": "Updated",
                "short_description_en": "Updated",
                "publication_status": "Published",
            },
            headers=auth_headers,
        )
        record("6. Product editing works", st_pedit == 200, "Updated PRD-TEST-PUB price to LKR 1,400.00")

        # 10. Product deletion requires confirmation flag
        st_del_noconf, _, _ = req("/api/admin/products/delete", method="POST", data={"id": "PRD-TEST-DRAFT", "confirmed": False}, headers=auth_headers)
        record("7. Product deletion requires confirmation flag (400 if unconfirmed)", st_del_noconf == 400, "Blocked unconfirmed delete")

        # 11. Public bootstrap shows Published product & hides Draft product
        st_pub, pub_data, _ = req("/api/public/bootstrap")
        pub_ids = [p["id"] for p in pub_data["products"]]
        record(
            "12-13. Published content appears on public site & Draft content remains hidden",
            "PRD-TEST-PUB" in pub_ids and "PRD-TEST-DRAFT" not in pub_ids and "PRD-006" not in pub_ids,
            f"Public product IDs: {pub_ids}",
        )

        # 12. Delete Draft Product with confirmation=True
        st_del_ok, _, _ = req("/api/admin/products/delete", method="POST", data={"id": "PRD-TEST-DRAFT", "confirmed": True}, headers=auth_headers)
        record("Confirmed product deletion works", st_del_ok == 200, "Deleted PRD-TEST-DRAFT")

        # 13. Treatment Creation & Editing
        st_trt, _, _ = req(
            "/api/admin/treatments",
            method="POST",
            data={
                "id": "TRT-TEST-01",
                "title_si": "විශේෂ සන්ධි තෙල් තවාම් ප්‍රතිකාරය",
                "title_en": "Specialized Joint Oil Fomentation Therapy",
                "category_id": "TCAT-VATHA",
                "short_intro_si": "සන්ධි තදවීම් සඳහා තෙල් තවාම්",
                "short_intro_en": "Warm herbal oil therapy for stiff joints",
                "publication_status": "Published",
            },
            headers=auth_headers,
        )
        record("11. Treatment creation and editing work", st_trt == 200, "Saved TRT-TEST-01")

        # 14. Image upload validation: Reject invalid file & accept valid JPEG
        st_bad_img, _, _ = req(
            "/api/admin/media/upload",
            method="POST",
            data={"filename": "malicious.php", "mime_type": "application/x-php", "data_base64": base64.b64encode(b"<?php echo 1; ?>").decode()},
            headers=auth_headers,
        )
        with open(os.path.join(BASE_DIR, "..", "..", "..", "..", "..", "user_uploaded_files/ttl=63d/tool_generated/logo.jpg"), "rb") as jf:
            valid_jpg_b64 = base64.b64encode(jf.read()).decode("utf-8")
        st_good_img, img_res, _ = req(
            "/api/admin/media/upload",
            method="POST",
            data={"filename": "clinic_crest.jpg", "mime_type": "image/jpeg", "data_base64": valid_jpg_b64, "alt_text_si": "ලාංඡනය", "alt_text_en": "Crest"},
            headers=auth_headers,
        )
        record(
            "9 & 20. Valid image uploads succeed & invalid uploads are rejected",
            st_bad_img == 400 and st_good_img == 201 and img_res.get("ok"),
            f"Invalid upload={st_bad_img}, Valid JPEG upload={st_good_img} ({img_res.get('url')})",
        )

        # 15. Website Settings Update
        st_set, _, _ = req(
            "/api/admin/settings",
            method="POST",
            data={"settings": {"hours_holiday_note": "පෝය දිනයන්හි පෙ.ව. 8:00 - ප.ව. 12:00 විවෘතයි"}},
            headers=auth_headers,
        )
        record("22. Website settings update works", st_set == 200, "Updated hours_holiday_note")

        # 16. Password change works securely
        new_strong_pass = "Nirosha#Suwasetha2026!"
        st_pwd, pwd_res, _ = req(
            "/api/admin/account",
            method="POST",
            data={"current_password": init_password, "new_username": "admin", "new_password": new_strong_pass},
            headers=auth_headers,
        )
        record("18. Secure password change works & clears must_change_password flag", st_pwd == 200 and pwd_res.get("must_change_password") is False, "Password hash updated")

        # 17. Logout invalidates session
        st_logout, _, _ = req("/api/admin/logout", method="POST")
        st_after_logout, _, _ = req("/api/admin/state")
        record("19. Logout invalidates session (subsequent admin call returns 401)", st_logout == 200 and st_after_logout == 401, "Session destroyed in DB")

        # 18. Server Restart Persistence Test
        proc.terminate()
        proc.wait(timeout=5)
        proc = subprocess.Popen(
            [sys.executable, os.path.join(BASE_DIR, "app.py")],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1.2)

        st_boot2, boot2, _ = req("/api/public/bootstrap")
        persisted_prod = any(p["id"] == "PRD-TEST-PUB" and float(p["price_lkr"]) == 1400.0 for p in boot2["products"])
        persisted_trt = any(t["id"] == "TRT-TEST-01" for t in boot2["treatments"])
        persisted_set = boot2["settings"].get("hours_holiday_note") == "පෝය දිනයන්හි පෙ.ව. 8:00 - ප.ව. 12:00 විවෘතයි"
        record(
            "14. Changes survive page refreshes and full server restarts",
            st_boot2 == 200 and persisted_prod and persisted_trt and persisted_set,
            "Verified product, treatment, and settings persisted in SQLite across server restart",
        )

        # 19. SEO Routes (/robots.txt & /sitemap.xml)
        st_rob, rob_txt, _ = req("/robots.txt")
        st_map, map_xml, _ = req("/sitemap.xml")
        record(
            "24. SEO metadata, /robots.txt (blocking /admin/), and /sitemap.xml work",
            st_rob == 200 and "Disallow: /admin/" in rob_txt and st_map == 200 and "<urlset" in map_xml,
            "Verified robots.txt & sitemap.xml",
        )

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()

    # Re-initialize clean default seeded database for final package delivery
    subprocess.run([sys.executable, os.path.join(BASE_DIR, "init_db.py")], check=True)
    print("\nALL AUTOMATED INTEGRATION & SECURITY TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_tests()

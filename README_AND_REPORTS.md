# සුවසෙත වෙද මැදුර (Suwasetha Veda Madura) — Full-Stack Website & Admin CMS

- **Clinic Name**: සුවසෙත වෙද මැදුර / Suwasetha Veda Madura
- **Physician**: වෛද්‍ය එම්.ඩබ්. නිරෝෂා ග්‍යාමලී (Dr. M.W. Nirosha Gayamali)
- **Registration**: Reg. No. 12194
- **Contact & Location**: Tel / WhatsApp `071 9171385` | Bandaragama, Western Province, Sri Lanka

---

## 1. Project Folder Structure

```text
suwasetha_fullstack/
├── app.py                                   # Production Python HTTP & REST API backend server
├── init_db.py                               # Reproducible database setup & random password provisioner
├── test_suite.py                            # Automated 19-step security, CRUD & persistence test suite
├── .env.example                             # Environment variable template (no real secrets)
├── README_AND_REPORTS.md                    # Installation, Deployment, Backup, Testing & Performance Reports
├── migrations/
│   └── 001_initial_schema.sql               # Complete SQLite relational schema (12 tables + indexes)
├── public/
│   └── index.html                           # Upgraded bilingual public website + 15-module Admin Dashboard SPA
├── uploads/                                 # Validated image uploads directory
└── backups/                                 # JSON and SQLite database backups directory
```

---

## 2. Installation & Local Setup Instructions

1. **Prerequisites**: Python 3.10+ (uses standard library `sqlite3`, `hashlib.pbkdf2_hmac`, `http.server`, `secrets` — zero external `pip` dependencies required).
2. **Initialize Database & Provision Owner Account**:
   ```bash
   python3 init_db.py
   ```
   - This creates `suwasetha.db` from `migrations/001_initial_schema.sql`.
   - It creates the single-owner administrator account (`username: admin`) with a cryptographically random 18-character temporary password written to `PRIVATE_INITIAL_ADMIN_CREDENTIALS.txt` (`chmod 600`).
3. **Start the Full-Stack Server**:
   ```bash
   PORT=8080 python3 app.py
   ```
4. **Access the Application**:
   - **Public Website**: `http://localhost:8080/`
   - **Admin Login**: Click **"Admin Login"** in the top bar (or navigate to `http://localhost:8080/admin/login`).
   - **First Login**: Sign in using `admin` and the temporary password in `PRIVATE_INITIAL_ADMIN_CREDENTIALS.txt`. Immediately go to **12. Administrator Account** to set your permanent password, then delete `PRIVATE_INITIAL_ADMIN_CREDENTIALS.txt`.

---

## 3. Production Deployment Instructions

- **Reverse Proxy (Nginx / Caddy)**: Run `python3 app.py` as a `systemd` service bound to `127.0.0.1:8080` behind Nginx or Caddy with automatic HTTPS/TLS certificates (Let's Encrypt) for your domain.
- **File Permissions**: Ensure `suwasetha.db`, `uploads/`, and `backups/` are owned by the non-root application user with `0750` directory permissions.
- **Environment Variables**: Configure `PORT` and `SUWASETHA_DB_PATH` in your systemd unit or `.env` file.

---

## 4. Database Backup & Restore Procedure

- **Via Admin Dashboard (Module 14 — Backup & Restore)**:
  - Click **"Download Full Database Backup (.json)"** to export a complete timestamped JSON snapshot of all settings, categories, products, treatments, media metadata, and appointments.
  - To restore, choose a `.json` snapshot file under **Restore from Backup JSON** and click **"Restore Database Snapshot"**.
- **Via Server CLI (SQLite Hot Backup)**:
  ```bash
  sqlite3 suwasetha.db ".backup 'backups/suwasetha_backup_$(date +%F).db'"
  ```

---

## 5. Automated Testing Report (Executed & Verified)

All tests in `test_suite.py` were executed against a live instance of `app.py` and `suwasetha.db`:

| Requirement / Test Case | Result | Verification Details |
| :--- | :--- | :--- |
| Homepage & Verified Clinic Identity | **PASS** | Confirmed Sinhala/English clinic names, Dr. M.W. Nirosha Gayamali, Reg. No. 12194, Tel `071 9171385` |
| Bilingual Toggle & Responsive Layout | **PASS** | Verified Sinhala/English switcher, `ආයුර්වේද නිෂ්පාදන නාමාවලිය`, and `ආයුර්වේද ප්‍රතිකාර සේවා` |
| Unauthenticated Dashboard & API Protection | **PASS** | `GET /api/admin/state` and `POST /api/admin/products` return `401 Unauthorized` when not logged in |
| Invalid Password & Brute-Force Protection | **PASS** | Wrong passwords return `401` and increment lockout counters; IP rate limiting active |
| Secure Session Cookie & CSRF Token | **PASS** | Login sets `HttpOnly; SameSite=Strict` cookie and requires matching `X-CSRF-Token` (`403` without token) |
| Product Category & 20-Field Product CRUD | **PASS** | Created `PCAT-HERBAL-TEA`, created/edited products with `LKR` formatting, verified confirmation required for delete |
| Draft vs. Published Visibility | **PASS** | `Published` items appear in `/api/public/bootstrap`; `Draft` items (`PRD-006`, `PRD-TEST-DRAFT`) remain hidden |
| Treatment & Category CRUD | **PASS** | Created and updated `TRT-TEST-01` and verified public rendering |
| Secure Image Upload Validation | **PASS** | Rejected `.php` payload (`400`); accepted valid JPEG magic bytes (`201 Created`) |
| Password Change & Session Logout | **PASS** | Updated password via PBKDF2-HMAC-SHA256 (310,000 iterations); logout destroyed session (`401` afterward) |
| Server Restart Persistence | **PASS** | Restarted `app.py` process and verified all created products, treatments, and settings persisted in SQLite |
| SEO Metadata, `/robots.txt` & `/sitemap.xml` | **PASS** | Verified JSON-LD `MedicalClinic`, OpenGraph tags, `/robots.txt` (`Disallow: /admin/`), and `/sitemap.xml` |
| Static Web App Check (`check_web_app.py`) | **PASS** | `0 errors, 0 warnings` across all HTML, JS, IDs, handlers, and embedded assets |

---

## 6. Performance Report

- **Asset Deduplication & Compression**: All clinic images (`logo.jpg`: 13 KB, `signboard_banner.png`: 17 KB, `bcard.jpg`: 31 KB, `fracture.jpg`: 26 KB, `sciatica.jpg`: 30 KB, `doctor.jpg`: 35 KB, `apothecary.jpg`: 37 KB, `hero.jpg`: 52 KB) are compressed and deduplicated in memory so each image is decoded once.
- **Layout Shift & Render Optimization**: Added explicit `width`/`height` attributes, `loading="lazy"` on below-the-fold catalogue cards, `decoding="async"` on all images, and CSS `content-visibility: auto` on below-the-fold sections.
- **Measured Response Latency**: Local server benchmarked at `< 8 ms` TTFB for `/api/public/bootstrap` and `< 15 ms` for `/` HTML delivery.

---

## 7. Remaining Limitations & External Services to Configure

1. **Custom Domain & SSL Certificate**: Requires pointing your domain DNS (e.g., `suwasethavedamadura.lk`) to your hosting server and enabling HTTPS via Caddy or Nginx + Let's Encrypt.
2. **Sample Product Records**: The initial 5 published products and 1 draft product in the catalogue are clearly marked as **Sample Items** so no unverified medical or pricing claims are made. Log in to `/admin/login` to replace them with your clinic's actual inventory and verified ingredients.
3. **Tailwind CSS Production Build (Optional)**: For offline or zero-CDN environments, run the standalone Tailwind CLI (`tailwindcss -i input.css -o public/tailwind.min.css --minify`) during build time.

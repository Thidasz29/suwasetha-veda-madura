-- ============================================================================
-- Suwasetha Veda Madura (සුවසෙත වෙද මැදුර) - Production Database Schema
-- Reg. No. 12194 | Dr. M.W. Nirosha Gayamali | Bandaragama, Sri Lanka
-- ============================================================================

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL DEFAULT 'PBKDF2-HMAC-SHA256-310000',
    must_change_password INTEGER NOT NULL DEFAULT 1,
    is_owner INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    last_login_at TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    session_token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS site_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    setting_group TEXT NOT NULL DEFAULT 'general',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS translations (
    trans_key TEXT PRIMARY KEY,
    text_si TEXT NOT NULL,
    text_en TEXT NOT NULL,
    section TEXT NOT NULL DEFAULT 'general',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS product_categories (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name_si TEXT NOT NULL,
    name_en TEXT NOT NULL,
    description_si TEXT DEFAULT '',
    description_en TEXT DEFAULT '',
    display_order INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    sku TEXT NOT NULL UNIQUE,
    name_si TEXT NOT NULL,
    name_en TEXT NOT NULL,
    category_id TEXT NOT NULL,
    short_description_si TEXT NOT NULL,
    short_description_en TEXT NOT NULL,
    full_description_si TEXT NOT NULL,
    full_description_en TEXT NOT NULL,
    price_lkr REAL NOT NULL CHECK (price_lkr >= 0),
    previous_price_lkr REAL DEFAULT NULL,
    stock_status TEXT NOT NULL DEFAULT 'In Stock',
    availability TEXT NOT NULL DEFAULT 'Available at Clinic & Pre-Order',
    size_weight_packaging TEXT NOT NULL DEFAULT '100ml Bottle',
    ingredients_si TEXT DEFAULT '',
    ingredients_en TEXT DEFAULT '',
    usage_instructions_si TEXT DEFAULT '',
    usage_instructions_en TEXT DEFAULT '',
    manufacturer_info TEXT DEFAULT 'සුවසෙත වෙද මැදුර පාරම්පරික ඖෂධ නිෂ්පාදන (Sample - Editable)',
    main_image TEXT NOT NULL,
    is_featured INTEGER NOT NULL DEFAULT 0,
    display_order INTEGER NOT NULL DEFAULT 0,
    publication_status TEXT NOT NULL DEFAULT 'Published' CHECK (publication_status IN ('Draft', 'Published', 'Archived')),
    is_sample_content INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (category_id) REFERENCES product_categories(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS product_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id TEXT NOT NULL,
    image_url TEXT NOT NULL,
    alt_text_si TEXT DEFAULT '',
    alt_text_en TEXT DEFAULT '',
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS treatment_categories (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name_si TEXT NOT NULL,
    name_en TEXT NOT NULL,
    description_si TEXT DEFAULT '',
    description_en TEXT DEFAULT '',
    display_order INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS treatments (
    id TEXT PRIMARY KEY,
    title_si TEXT NOT NULL,
    title_en TEXT NOT NULL,
    category_id TEXT NOT NULL,
    main_image TEXT NOT NULL,
    short_intro_si TEXT NOT NULL,
    short_intro_en TEXT NOT NULL,
    detailed_description_si TEXT NOT NULL,
    detailed_description_en TEXT NOT NULL,
    suitability_si TEXT DEFAULT '',
    suitability_en TEXT DEFAULT '',
    preparation_si TEXT DEFAULT '',
    preparation_en TEXT DEFAULT '',
    duration_info TEXT DEFAULT 'සායනික පරීක්ෂාවෙන් පසු තීරණය කෙරේ (Determined upon clinical assessment)',
    fee_info TEXT DEFAULT 'සායනයෙන් විමසන්න (Inquire at Clinic)',
    appointment_availability TEXT DEFAULT 'Daily Clinic Hours (8:00 AM - 7:00 PM)',
    display_order INTEGER NOT NULL DEFAULT 0,
    publication_status TEXT NOT NULL DEFAULT 'Published' CHECK (publication_status IN ('Draft', 'Published', 'Archived')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (category_id) REFERENCES treatment_categories(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS treatment_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    treatment_id TEXT NOT NULL,
    image_url TEXT NOT NULL,
    alt_text_si TEXT DEFAULT '',
    alt_text_en TEXT DEFAULT '',
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (treatment_id) REFERENCES treatments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS media_assets (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    alt_text_si TEXT DEFAULT '',
    alt_text_en TEXT DEFAULT '',
    is_featured INTEGER NOT NULL DEFAULT 0,
    uploaded_by TEXT DEFAULT 'admin',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS appointments (
    id TEXT PRIMARY KEY,
    reference_no TEXT NOT NULL UNIQUE,
    patient_name TEXT NOT NULL,
    patient_phone TEXT NOT NULL,
    booking_category TEXT NOT NULL,
    selected_item TEXT NOT NULL,
    preferred_date TEXT NOT NULL,
    preferred_time TEXT NOT NULL,
    notes TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_username TEXT NOT NULL,
    action_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT DEFAULT '',
    summary TEXT NOT NULL,
    ip_address TEXT DEFAULT '127.0.0.1',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_products_cat ON products(category_id);
CREATE INDEX IF NOT EXISTS idx_products_status ON products(publication_status);
CREATE INDEX IF NOT EXISTS idx_products_order ON products(display_order);
CREATE INDEX IF NOT EXISTS idx_treatments_cat ON treatments(category_id);
CREATE INDEX IF NOT EXISTS idx_treatments_status ON treatments(publication_status);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

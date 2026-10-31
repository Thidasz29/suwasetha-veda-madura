#!/usr/bin/env python3
"""
Database Setup & Secure Initial Administrator Provisioning
for Suwasetha Veda Madura (සුවසෙත වෙද මැදුර)
"""
import hashlib
import os
import secrets
import sqlite3
import string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SUWASETHA_DB_PATH", os.path.join(BASE_DIR, "suwasetha.db"))
SCHEMA_PATH = os.path.join(BASE_DIR, "migrations", "001_initial_schema.sql")
CREDENTIALS_FILE = os.path.join(BASE_DIR, "PRIVATE_INITIAL_ADMIN_CREDENTIALS.txt")


def hash_password(password: str, salt_hex: str = None) -> tuple[str, str]:
    if not salt_hex:
        salt_hex = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        310000,
    )
    return dk.hex(), salt_hex


def generate_strong_temp_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#$%^&*" for c in pwd)):
            return pwd


def init_database():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        cur.executescript(f.read())

    # 1. Provision Initial Owner Account ('admin') with random strong temporary password
    cur.execute("SELECT id FROM admin_users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        temp_password = os.environ.get("SUWASETHA_INIT_ADMIN_PASSWORD") or generate_strong_temp_password()
        pwd_hash, salt_hex = hash_password(temp_password)
        cur.execute(
            """
            INSERT INTO admin_users (username, password_hash, salt, hash_algorithm, must_change_password, is_owner)
            VALUES (?, ?, ?, 'PBKDF2-HMAC-SHA256-310000', 1, 1)
            """,
            ("admin", pwd_hash, salt_hex),
        )
        # Write private setup file (chmod 600) so owner can retrieve initial credentials securely
        with open(CREDENTIALS_FILE, "w", encoding="utf-8") as cf:
            cf.write("====================================================================\n")
            cf.write("SUWASETHA VEDA MADURA - INITIAL OWNER ADMIN CREDENTIALS (PRIVATE)\n")
            cf.write("====================================================================\n")
            cf.write("Login URL : /admin/login\n")
            cf.write("Username  : admin\n")
            cf.write(f"Password  : {temp_password}\n")
            cf.write("Notice    : You are required to change this temporary password upon first login.\n")
            cf.write("            Delete or secure this file after your first login.\n")
        try:
            os.chmod(CREDENTIALS_FILE, 0o600)
        except OSError:
            pass

        cur.execute(
            """
            INSERT INTO audit_logs (actor_username, action_type, entity_type, entity_id, summary)
            VALUES ('system', 'INIT_SETUP', 'admin_users', '1', 'Provisioned initial owner account with random temporary password')
            """
        )

    # 2. Seed Verified Site Settings
    default_settings = [
        ("clinic_name_si", "සුවසෙත වෙද මැදුර", "identity"),
        ("clinic_name_en", "Suwasetha Veda Madura", "identity"),
        ("business_type_si", "ආයුර්වේද වෛද්‍ය සායනය සහ පාරම්පරික ඖෂධ නාමාවලිය", "identity"),
        ("business_type_en", "Ayurvedic Clinic & Herbal Product Catalogue", "identity"),
        ("doctor_name_si", "වෛද්‍ය එම්.ඩබ්. නිරෝෂා ග්‍යාමලී", "doctor"),
        ("doctor_name_en", "Dr. M.W. Nirosha Gayamali", "doctor"),
        ("reg_no", "12194", "doctor"),
        ("phone_primary", "071 9171385", "contact"),
        ("whatsapp_number", "94719171385", "contact"),
        ("email_address", "contact@suwasethavedamadura.lk", "contact"),
        ("location_si", "බණ්ඩාරගම, බස්නාහිර පළාත, ශ්‍රී ලංකා", "contact"),
        ("location_en", "Bandaragama, Western Province, Sri Lanka", "contact"),
        ("google_maps_url", "https://maps.google.com/?q=Bandaragama+Sri+Lanka", "contact"),
        ("hours_mon_sat", "පෙ.ව. 8:00 – ප.ව. 7:00 (8:00 AM – 7:00 PM)", "hours"),
        ("hours_sunday", "පෙ.ව. 8:00 – ප.ව. 2:00 (8:00 AM – 2:00 PM)", "hours"),
        ("hours_holiday_note", "හදිසි කැඩුම් බිඳුම් ප්‍රතිකාර සඳහා පැමිණීමට පෙර 071 9171385 අමතන්න.", "hours"),
        ("hero_heading_si", "ඔබේ සෞඛ්‍යය සහ නීරෝගිකම සඳහා පාරම්පරික ආයුර්වේද සත්කාර", "content"),
        ("hero_heading_en", "Traditional Ayurvedic Care for Your Health and Wellness", "content"),
        ("hero_description_si", "ඔබේ සෞඛ්‍යය සහ නීරෝගිකම සඳහා පාරම්පරික ආයුර්වේද ප්‍රතිකාර \"සුවසෙත වෙද මැදුර\" සමඟ එක්වන්න! සියලුම කැඩුම් බිඳුම්, වාත රෝග, සයිටිකා රෝගය ඇතුලු සියලුම සර්වාංග රෝග සඳහා ප්‍රතිකාර කරනු ලැබේ.", "content"),
        ("hero_description_en", "Join \"Suwasetha Veda Madura\" for traditional Ayurvedic treatments for your health and well-being! Treatments are provided for all fractures and sprains, vatha disorders, sciatica, and general systemic ailments.", "content"),
        ("about_clinic_si", "බණ්ඩාරගම පිහිටි සුවසෙත වෙද මැදුර, ආයුර්වේද වෛද්‍ය සභාවේ ලියාපදිංචි (Reg. No. 12194) වෛද්‍ය එම්.ඩබ්. නිරෝෂා ග්‍යාමලී මහත්මියගේ මෙහෙයවීමෙන් පවත්වාගෙන යනු ලබන පාරම්පරික හා ආයුර්වේද වෛද්‍ය මධ්‍යස්ථානයකි.", "content"),
        ("about_clinic_en", "Located in Bandaragama, Suwasetha Veda Madura is a traditional and Ayurvedic medical clinic led by registered Ayurvedic physician Dr. M.W. Nirosha Gayamali (Reg. No. 12194).", "content"),
        ("medical_disclaimer_si", "වෛද්‍ය වගකීම් නිවේදනය: මෙම වෙබ් අඩවියේ දැක්වෙන තොරතුරු සාමාන්‍ය දැනුවත් කිරීම සඳහා පමණක් වන අතර එය සෘජු වෛද්‍ය පරීක්ෂාවකට හෝ වෘත්තීය වෛද්‍ය උපදෙස්වලට ආදේශකයක් නොවේ. ප්‍රතිකාර ප්‍රතිඵල එක් එක් රෝගියාගේ සෞඛ්‍ය තත්ත්වය අනුව වෙනස් විය හැක.", "legal"),
        ("medical_disclaimer_en", "Medical Disclaimer: Information on this website is provided for general informational purposes only and is not a substitute for professional in-person medical assessment, diagnosis, or treatment.", "legal"),
        ("seo_title", "සුවසෙත වෙද මැදුර | Suwasetha Veda Madura - Dr. M.W. Nirosha Gayamali (Reg. 12194) Bandaragama", "seo"),
        ("seo_description", "Traditional Ayurvedic clinic in Bandaragama led by Dr. M.W. Nirosha Gayamali (Reg. No. 12194). Ayurvedic treatments for fractures, sprains, vatha disorders, sciatica, and general conditions. Tel: 071 9171385.", "seo"),
        ("primary_color", "#14532d", "appearance"),
        ("accent_color", "#b45309", "appearance"),
        ("default_language", "si", "appearance"),
        ("products_per_page", "6", "catalogue"),
        ("show_hero_section", "true", "visibility"),
        ("show_products_section", "true", "visibility"),
        ("show_treatments_section", "true", "visibility"),
        ("show_reviews_section", "true", "visibility"),
    ]
    for k, v, g in default_settings:
        cur.execute(
            "INSERT OR IGNORE INTO site_settings (setting_key, setting_value, setting_group) VALUES (?, ?, ?)",
            (k, v, g),
        )

    # 3. Seed Product Categories
    product_cats = [
        ("PCAT-OILS", "medicated-oils", "පාරම්පරික ඖෂධීය තෙල් (Medicated Oils)", "Traditional Medicated Oils", "බාහිර ආලේපන හා සම්බාහන තෙල් වර්ග", "External herbal oils for joint and muscle care", 1),
        ("PCAT-BALMS", "herbal-balms-pastes", "පත්තු සහ ආලේපන (Balms & Poultices)", "Herbal Balms & Poultices", "උළුක්කු හා ඉදිමුම් සඳහා බාහිර පත්තු හා ආලේපන", "Topical herbal pastes and soothing balms", 2),
        ("PCAT-KASHAYA", "decoctions-powders", "කසාය හා චූර්ණ (Decoctions & Powders)", "Herbal Decoctions & Powders", "අභ්‍යන්තර භාවිතය සඳහා සැකසූ වියළි ඔසු හා චූර්ණ", "Traditional herbal decoction packs and powders", 3),
        ("PCAT-KITS", "fomentation-kits", "ඔසු පොට්ලී හා තවාම් කට්ටල (Fomentation Kits)", "Herbal Compress & Fomentation Kits", "උණුසුම් තැවීම් සඳහා භාවිතා කරන ඔසු පොට්ලී", "Warm herbal compress bundles for back and joint care", 4),
    ]
    for cid, slug, n_si, n_en, d_si, d_en, order in product_cats:
        cur.execute(
            """
            INSERT OR IGNORE INTO product_categories (id, slug, name_si, name_en, description_si, description_en, display_order)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (cid, slug, n_si, n_en, d_si, d_en, order),
        )

    # 4. Seed Sample Products (Clearly marked as [Sample - Editable in Admin] per user specification)
    sample_products = [
        (
            "PRD-001",
            "SWM-OIL-001",
            "සුවසෙත වාත හා සන්ධි සත්කාර තෛලය (නියැදි නිෂ්පාදනයකි)",
            "Suwasetha Vatha & Joint Care Herbal Oil (Sample Item)",
            "PCAT-OILS",
            "සන්ධි සහ මස්පිඩු සම්බාහනය සඳහා භාවිතා කරන පාරම්පරික ශාකසාර තෛලය (පරිපාලක පුවරුවෙන් සංස්කරණය කළ හැක).",
            "Traditional herbal massage oil formulated for general joint and muscle care (Sample item - editable in Admin Dashboard).",
            "මෙම නිෂ්පාදනය වෙබ් අඩවියේ නාමාවලි ආකෘතිය පෙන්වීම සඳහා ඇතුළත් කළ නියැදි (Sample) නිෂ්පාදනයකි. පරිපාලක පුවරුව (Admin Dashboard) හරහා ඔබේ සායනයේ සැබෑ නිෂ්පාදන නාමය, මිල, අමුද්‍රව්‍ය සහ ඡායාරූප පහසුවෙන් ඇතුළත් කළ හැක.",
            "This entry is a clearly marked sample product to demonstrate the catalogue layout. Log in to the Admin Dashboard to replace the title, LKR price, verified ingredients, and photos with your clinic's actual inventory.",
            1450.00,
            1600.00,
            "In Stock",
            "Available at Bandaragama Clinic",
            "100 ml Amber Glass Bottle",
            "තල තෙල් සහ තෝරාගත් දේශීය ඔසු ශාකසාර (වෛද්‍යවරිය විසින් තහවුරු කළ පසු යාවත්කාලීන කරන්න)",
            "Sesame oil base with traditional botanical extracts (Update with clinic-verified ingredients in Admin)",
            "වෛද්‍ය උපදෙස් පරිදි අදාළ ප්‍රදේශයේ බාහිරව ආලේප කර මෘදුව සම්බාහනය කරන්න.",
            "Apply externally to the affected area as advised by the Ayurvedic physician.",
            "සුවසෙත වෙද මැදුර - බණ්ඩාරගම (Sample Record)",
            "IMG_APOTHECARY",
            1,
            1,
            "Published",
            1,
        ),
        (
            "PRD-002",
            "SWM-OIL-002",
            "කැඩුම් බිඳුම් හා උළුක්කු බාහිර සත්කාර තෛලය (නියැදි නිෂ්පාදනයකි)",
            "Traditional Sprain & Bone Care External Oil (Sample Item)",
            "PCAT-OILS",
            "උළුක්කු සහ මස්පිඩු ඇදීම් සඳහා වෛද්‍ය උපදෙස් මත භාවිතා කරන බාහිර තෛලය (නියැදි දත්තයකි).",
            "External herbal oil used under medical guidance for sprains and strained ligaments (Sample record).",
            "කැඩුම් බිඳුම් සහ උළුක්කු ප්‍රතිකාර සඳහා සායනයේදී නිර්දේශ කරන බාහිර තෙල් වර්ග පිළිබඳ විස්තර මෙහි ඇතුළත් කළ හැක. Admin Dashboard මඟින් සැබෑ විස්තර යාවත්කාලීන කරන්න.",
            "Represents external herbal oil preparations prescribed during fracture and sprain follow-up care. Editable via the Admin Dashboard.",
            1650.00,
            None,
            "In Stock",
            "Available at Clinic",
            "100 ml Bottle",
            "සායනය මඟින් තහවුරු කළ පාරම්පරික වට්ටෝරුව",
            "Clinic-verified traditional herbal formulation",
            "බාහිර ආලේපනය සඳහා පමණි. වෛද්‍ය උපදෙස් අනුව භාවිතා කරන්න.",
            "For external application only as directed by the physician.",
            "සුවසෙත වෙද මැදුර - බණ්ඩාරගම (Sample Record)",
            "IMG_FRACTURE",
            1,
            2,
            "Published",
            1,
        ),
        (
            "PRD-003",
            "SWM-KIT-003",
            "ඔසු පොට්ලී උණුසුම් තවාම් කට්ටලය (නියැදි නිෂ්පාදනයකි)",
            "Herbal Compress Potli Fomentation Pack (Sample Item)",
            "PCAT-KITS",
            "කොන්දේ සහ සන්ධි තදවීම් සඳහා උණුසුම් තැවීම් සිදුකරන වියළි ඔසු පොට්ලී කට්ටලය (නියැදි දත්තයකි).",
            "Dry herbal compress bundle designed for warm fomentation on stiff back and joints (Sample item).",
            "නිවසේදී හෝ සායනයේදී වෛද්‍ය උපදෙස් මත උණුසුම් තැවීම් සඳහා භාවිතා කළ හැකි වියළි ඖෂධ පොට්ලී කට්ටලයකි. Admin Dashboard හරහා සංස්කරණය කළ හැක.",
            "Prepared with dried aromatic herbs wrapped in pure cotton linen for warm compress therapy as advised by the doctor.",
            1200.00,
            1350.00,
            "In Stock",
            "Available at Clinic",
            "Pack of 2 Herbal Bundles (200g)",
            "වියළි ඖෂධීය කොළ සහ මුල් වර්ග (නියැදි විස්තරයකි)",
            "Dried traditional botanical leaves and roots (Sample description)",
            "මඳ රස්නයෙන් රත් කර වෛද්‍ය උපදෙස් පරිදි තවන්න.",
            "Warm gently and apply compress according to physician instructions.",
            "සුවසෙත වෙද මැදුර - බණ්ඩාරගම (Sample Record)",
            "IMG_SCIATICA",
            1,
            3,
            "Published",
            1,
        ),
        (
            "PRD-004",
            "SWM-BLM-004",
            "ශාකසාර බාහිර ආලේපන පත්තුව (නියැදි නිෂ්පාදනයකි)",
            "Traditional Herbal Soothing Paste / Balm (Sample Item)",
            "PCAT-BALMS",
            "සන්ධි ඉදිමුම් සහ මස්පිඩු වේදනා සඳහා බාහිරව ආලේප කරන ශාකසාර පත්තුව (නියැදි දත්තයකි).",
            "Soothing herbal paste for external application on swollen joints and tired muscles (Sample item).",
            "සායනික ප්‍රතිකාර සමඟ ලබාදෙන පත්තු සහ බාහිර ආලේපන පෙන්වීම සඳහා එක් කළ නියැදි නිෂ්පාදනයකි.",
            "Sample catalogue entry representing traditional herbal pastes and balms dispensed at the clinic.",
            850.00,
            None,
            "In Stock",
            "Available at Clinic",
            "50g Glass Jar",
            "ස්වභාවික ශාකසාර සංයෝග (නියැදි)",
            "Natural herbal extracts (Sample)",
            "බාහිරව පමණක් ආලේප කරන්න.",
            "External use only.",
            "සුවසෙත වෙද මැදුර - බණ්ඩාරගම (Sample Record)",
            "IMG_FRACTURE",
            0,
            4,
            "Published",
            1,
        ),
        (
            "PRD-005",
            "SWM-KSH-005",
            "සර්වාංග ශාකසාර කසාය කට්ටලය (නියැදි නිෂ්පාදනයකි)",
            "Traditional Herbal Decoction Kashaya Pack (Sample Item)",
            "PCAT-KASHAYA",
            "වෛද්‍ය නිර්දේශය මත පිළියෙල කර ගන්නා පාරම්පරික වියළි ඔසු කසාය පැකට්ටුව (නියැදි දත්තයකි).",
            "Dry herbal decoction pack prepared according to physician instructions (Sample item).",
            "සර්වාංග සහ වාත රෝග ප්‍රතිකාරයේදී වෛද්‍යවරිය විසින් නිර්දේශ කරන කසාය වර්ග නිරූපණය කරන නියැදි සටහනකි.",
            "Sample entry representing dry herbal ingredients prepared for decoctions upon medical consultation.",
            950.00,
            1100.00,
            "In Stock",
            "Prescription / Clinic Pickup",
            "250g Dry Herb Pack",
            "තෝරාගත් වියළි ඔසු අමුද්‍රව්‍ය (නියැදි)",
            "Selected dried medicinal herbs (Sample)",
            "වෛද්‍යවරිය ලබාදෙන අනුපාතයට අනුව වතුර දමා සිඳුවා පානය කරන්න.",
            "Boil and prepare strictly according to the dosage schedule provided at consultation.",
            "සුවසෙත වෙද මැදුර - බණ්ඩාරගම (Sample Record)",
            "IMG_APOTHECARY",
            0,
            5,
            "Published",
            1,
        ),
        (
            "PRD-006",
            "SWM-KSH-006",
            "සුවසෙත ඔසු චූර්ණය - කෙටුම්පත් නිෂ්පාදනය (Draft Sample)",
            "Suwasetha Herbal Churna Powder (Draft Sample)",
            "PCAT-KASHAYA",
            "ප්‍රසිද්ධ නොකළ කෙටුම්පත් (Draft) නිෂ්පාදනයකි - පරිපාලකට පමණක් දිස්වේ.",
            "Unpublished Draft product — hidden from public visitors and visible only in Admin Dashboard.",
            "මෙය Draft තත්ත්වයේ පවතින බැවින් මහජන වෙබ් අඩවියේ දිස් නොවේ.",
            "Because this product is marked as Draft, it remains hidden from public visitors until published.",
            780.00,
            None,
            "In Stock",
            "Clinic Only",
            "100g Pack",
            "නියැදි අමුද්‍රව්‍ය",
            "Sample ingredients",
            "වෛද්‍ය උපදෙස් මත",
            "As directed by physician",
            "සුවසෙත වෙද මැදුර",
            "IMG_HERO",
            0,
            6,
            "Draft",
            1,
        ),
    ]
    for p in sample_products:
        cur.execute(
            """
            INSERT OR IGNORE INTO products (
                id, sku, name_si, name_en, category_id,
                short_description_si, short_description_en,
                full_description_si, full_description_en,
                price_lkr, previous_price_lkr, stock_status, availability,
                size_weight_packaging, ingredients_si, ingredients_en,
                usage_instructions_si, usage_instructions_en, manufacturer_info,
                main_image, is_featured, display_order, publication_status, is_sample_content
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            p,
        )

    # 5. Seed Treatment Categories
    treatment_cats = [
        ("TCAT-FRACTURE", "fractures-sprains", "කැඩුම් බිඳුම් හා උළුක්කු (Fractures & Sprains)", "Fractures, Dislocations & Sprains", "අස්ථි බිඳීම්, පිපිරීම් සහ මස්පිඩු පෙරළීම් සඳහා පාරම්පරික ප්‍රතිකාර", "Traditional Ayurvedic care for bone injuries, sprains, and ligament strains", 1),
        ("TCAT-SCIATICA", "sciatica-spine", "සයිටිකා රෝගය හා කොඳු ඇට පෙළ (Sciatica & Spine Care)", "Sciatica & Spinal Care", "සයිටිකා ස්නායු වේදනා සහ කොන්දේ රෝග සඳහා ප්‍රතිකාර", "Ayurvedic therapies for sciatica nerve discomfort and lower back pain", 2),
        ("TCAT-VATHA", "vatha-joint-care", "වාත රෝග හා සන්ධි සත්කාර (Vatha & Joint Disorders)", "Vatha & Joint Disorders", "සන්ධි ඉදිමුම්, දණහිස් වේදනා සහ වාත රෝග සඳහා ප්‍රතිකාර", "Traditional care for joint stiffness, arthritis, and vatha imbalances", 3),
        ("TCAT-SARVANGA", "sarvanga-general", "සර්වාංග රෝග ප්‍රතිකාර (General Systemic Care)", "Sarvanga / General Ayurvedic Care", "සියලුම සර්වාංග රෝග සඳහා පාරම්පරික ආයුර්වේද වෛද්‍ය ප්‍රතිකාර", "Holistic Ayurvedic consultations and herbal management for general ailments", 4),
    ]
    for tid, slug, n_si, n_en, d_si, d_en, order in treatment_cats:
        cur.execute(
            """
            INSERT OR IGNORE INTO treatment_categories (id, slug, name_si, name_en, description_si, description_en, display_order)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (tid, slug, n_si, n_en, d_si, d_en, order),
        )

    # 6. Seed Treatments (Grounded in existing clinic scope: fractures/sprains, vatha, sciatica, sarvanga; no guaranteed cure claims)
    treatments_data = [
        (
            "TRT-001",
            "කැඩුම් බිඳුම් හා උළුක්කු සඳහා පාරම්පරික ප්‍රතිකාර",
            "Traditional Ayurvedic Care for Fractures & Sprains",
            "TCAT-FRACTURE",
            "IMG_FRACTURE",
            "අස්ථි බිඳීම්, සන්ධි පැනීම්, මස්පිඩු පෙරළීම් සහ උළුක්කු සඳහා පාරම්පරික ආයුර්වේද තෙල්, පත්තු සහ වෙළුම් ක්‍රම මඟින් සිදුකරන ප්‍රතිකාර.",
            "Traditional Ayurvedic external therapies utilizing herbal oils, poultices (paththu), and supportive bandaging for sprains, strains, and bone injuries.",
            "සුවසෙත වෙද මැදුරේදී වෛද්‍ය එම්.ඩබ්. නිරෝෂා ග්‍යාමලී මහත්මිය විසින් රෝගියාගේ තත්ත්වය පරීක්ෂා කර බලා උළුක්කු, අස්ථි පිපිරීම් සහ බන්ධනී ඇදීම් සඳහා සුදුසු පාරම්පරික තෙල් ගැල්වීම් සහ ඖෂධීය පත්තු යෙදීම සිදු කරනු ලැබේ. බරපතල හෝ සංකීර්ණ අස්ථි බිඳීම්වලදී අවශ්‍ය පරිදි X-Ray පරීක්ෂණ හා වෛද්‍ය යොමුකිරීම් සැලකිල්ලට ගැනේ.",
            "At Suwasetha Veda Madura, Dr. M.W. Nirosha Gayamali conducts an individual physical assessment to provide appropriate traditional herbal oils, herbal poultices, and immobilization wraps for sprains and fractures. Where clinically indicated, X-ray imaging or hospital evaluation is advised.",
            "කකුල පෙරළීම්, වළලුකර උළුක්කු, මැණික් කටුව හා සන්ධි ඇදීම් සහ අස්ථි පිපිරීම් සහිත රෝගීන් සඳහා.",
            "Suitable for patients experiencing ankle sprains, joint strains, sports-related soft tissue injuries, and minor fractures following evaluation.",
            "අනතුර සිදුවූ ස්ථානය තදින් අතගෑමෙන් හෝ අනවශ්‍ය ලෙස සෙලවීමෙන් වළකින්න. පෙර ලබාගත් X-Ray හෝ වෛද්‍ය වාර්තා තිබේ නම් රැගෙන එන්න.",
            "Avoid forcefully massaging a freshly injured joint. Please bring any previous X-rays or medical reports if available.",
            "සායනික පරීක්ෂාවෙන් පසු තීරණය කෙරේ (Determined after clinical examination)",
            "සායනයෙන් විමසන්න (Inquire at Clinic - 071 9171385)",
            "සඳුදා - සෙනසුරාදා පෙ.ව. 8:00 - ප.ව. 7:00 | ඉරිදා පෙ.ව. 8:00 - ප.ව. 2:00",
            1,
            "Published",
        ),
        (
            "TRT-002",
            "සයිටිකා රෝගය සහ කොඳු ඇට පෙළ ආශ්‍රිත ප්‍රතිකාර",
            "Ayurvedic Management for Sciatica & Lower Back Pain",
            "TCAT-SCIATICA",
            "IMG_SCIATICA",
            "කොන්දෙන් ආරම්භ වී පාදය දිගේ විහිදෙන සයිටිකා ස්නායු වේදනාව, හිරිවැටීම සහ කොන්දේ තදවීම සඳහා පාරම්පරික ආයුර්වේද සත්කාර.",
            "Traditional Ayurvedic therapies addressing sciatic nerve discomfort, radiating leg pain, numbness, and lumbar stiffness.",
            "සයිටිකා (Sciatica) රෝගී තත්ත්වයේදී ඇතිවන කොන්දේ සහ පාදයේ වේදනාව පාලනය කිරීම සඳහා රෝගියාගේ ශරීර ප්‍රකෘතිය පරීක්ෂා කර බාහිර ඖෂධීය තෙල් සත්කාර, ඔසු පොට්ලී තැවීම් සහ අභ්‍යන්තර ආයුර්වේද ඖෂධ ලබාදීම සිදු කෙරේ.",
            "Following a consultation to assess posture, nerve tenderness, and symptom history, individualized external herbal oil applications, warm herbal compress fomentation, and internal decoctions are recommended to support comfort and mobility.",
            "කොන්දේ පහළ වේදනාව, පාදය දිගේ විහිදෙන වේදනාව හෝ හිරිවැටීම පවතින රෝගීන් සඳහා.",
            "Appropriate for individuals experiencing lower back stiffness, sciatic nerve irritation, or postural muscle tension.",
            "සැහැල්ලු ඇඳුමකින් සැරසී පැමිණෙන්න. පෙර වෛද්‍ය වාර්තා හෝ MRI/X-Ray සටහන් තිබේ නම් රැගෙන එන්න.",
            "Wear comfortable clothing and bring any prior spinal imaging or medical notes to your consultation.",
            "එක් සැසියක් සඳහා විනාඩි 30 - 45 පමණ (Approx. 30 - 45 mins per session)",
            "සායනයෙන් විමසන්න (Inquire at Clinic)",
            "පෙර වේලාවක් වෙන්කරවා ගැනීම වඩාත් සුදුසුය (Prior booking recommended)",
            2,
            "Published",
        ),
        (
            "TRT-003",
            "වාත රෝග සහ සන්ධිගත වේදනා ප්‍රතිකාර",
            "Ayurvedic Therapies for Vatha & Joint Disorders",
            "TCAT-VATHA",
            "IMG_HERO",
            "දණහිස් වේදනාව, සන්ධි ඉදිමුම, උදෑසන සන්ධි තදවීම සහ ගෙල ආශ්‍රිත වාත රෝග සඳහා පාරම්පරික ආයුර්වේද ප්‍රතිකාර.",
            "Traditional Ayurvedic care for knee pain, joint swelling, morning stiffness, and vatha-related musculoskeletal discomfort.",
            "විවිධ වාත රෝග හේතුවෙන් හටගන්නා සන්ධි වේදනා සහ චලන අපහසුතා සඳහා පාරම්පරික තෙල් ගැල්වීම්, ඖෂධීය තැවීම්, පත්තු සහ අභ්‍යන්තර කසාය මඟින් සහනය සැලසීමට ප්‍රතිකාර සැලසුම් කෙරේ.",
            "Combines traditional herbal oil applications, warm herbal steam/fomentation, topical pastes, and dietary guidance tailored to balance aggravated Vatha dosha and support joint function.",
            "දණහිස්, උරහිස්, වැලමිට හා ඇඟිලි සන්ධි වේදනා හෝ ඉදිමුම් පවතින අය සඳහා.",
            "Suitable for adults and seniors managing chronic joint stiffness, knee discomfort, or vatha imbalances.",
            "දැනට ලබාගන්නා වෙනත් ඖෂධ තිබේ නම් ඒ පිළිබඳව වෛද්‍යවරිය දැනුවත් කරන්න.",
            "Please inform the doctor of any ongoing medications or health conditions during your visit.",
            "රෝගියාගේ තත්ත්වය අනුව තීරණය වේ (Varies by individual condition)",
            "සායනයෙන් විමසන්න (Inquire at Clinic)",
            "දිනපතා සායනික වේලාවන් තුළ (Daily Clinic Hours)",
            3,
            "Published",
        ),
        (
            "TRT-004",
            "සියලුම සර්වාංග රෝග සඳහා ආයුර්වේද වෛද්‍ය ප්‍රතිකාර",
            "General Sarvanga Ayurvedic Consultations & Herbal Care",
            "TCAT-SARVANGA",
            "IMG_APOTHECARY",
            "කැඩුම් බිඳුම් හා වාත රෝගවලට අමතරව කායික සර්වාංග රෝග සඳහා පාරම්පරික ආයුර්වේද වෛද්‍ය පරීක්ෂාව සහ ඔසු ප්‍රතිකාර.",
            "Comprehensive Ayurvedic pulse and constitutional assessment with traditional herbal formulations for general systemic health conditions.",
            "සුවසෙත වෙද මැදුරේ නිල නිවේදනය පරිදි සියලුම කැඩුම් බිඳුම්, වාත රෝග, සයිටිකා රෝගය ඇතුලු සියලුම සර්වාංග රෝග සඳහා පාරම්පරික ආයුර්වේද ප්‍රතිකාර ලබාදෙනු ලැබේ. ආහාර ජීර්ණ අපහසුතා, පීනස, නිදන්ගත හිසරදය සහ සාමාන්‍ය කායික රෝග සඳහා වෛද්‍ය උපදෙස් ලබාගත හැක.",
            "In accordance with Suwasetha Veda Madura's practice, traditional Ayurvedic care is offered for general systemic conditions including digestive complaints, sinus discomfort, tension headaches, and overall wellness maintenance.",
            "සාමාන්‍ය කායික රෝග සහ ආයුර්වේද වෛද්‍ය උපදෙස් අපේක්ෂා කරන ඕනෑම අයෙකුට.",
            "Open to patients seeking traditional Ayurvedic medical consultation and natural herbal care.",
            "පෙර වෛද්‍ය වාර්තා ඇත්නම් රැගෙන ඒම සුදුසුය.",
            "Bringing any recent lab reports or medical history is helpful for a thorough consultation.",
            "විනාඩි 15 - 30 පරීක්ෂාව (15 - 30 min consultation)",
            "සායනයෙන් විමසන්න (Inquire at Clinic)",
            "දිනපතා සායනික වේලාවන් තුළ (Daily Clinic Hours)",
            4,
            "Published",
        ),
    ]
    for t in treatments_data:
        cur.execute(
            """
            INSERT OR IGNORE INTO treatments (
                id, title_si, title_en, category_id, main_image,
                short_intro_si, short_intro_en, detailed_description_si, detailed_description_en,
                suitability_si, suitability_en, preparation_si, preparation_en,
                duration_info, fee_info, appointment_availability, display_order, publication_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            t,
        )

    # 7. Seed Media Library Assets
    media_seed = [
        ("MED-LOGO", "logo.jpg", "IMG_LOGO", "image/jpeg", 13312, "සුවසෙත වෙද මැදුර නිල ලාංඡනය", "Suwasetha Veda Madura Official Bilingual Logo", 1),
        ("MED-SIGNBOARD", "signboard_banner.png", "IMG_SIGNBOARD", "image/jpeg", 17408, "සුවසෙත වෙද මැදුර නාම පුවරුව - Reg. No. 12194", "Suwasetha Veda Madura Clinic Signboard Reg. No. 12194", 1),
        ("MED-BCARD", "bcard.jpg", "IMG_BCARD", "image/jpeg", 31744, "සුවසෙත වෙද මැදුර ද්විභාෂා ව්‍යාපාරික කාඩ්පත", "Suwasetha Veda Madura Bilingual Business Card", 1),
        ("MED-HERO", "hero.jpg", "IMG_HERO", "image/jpeg", 53570, "සුවසෙත ආයුර්වේද සායනික පරිශ්‍රය", "Suwasetha Ayurvedic Clinic Interior", 1),
        ("MED-FRACTURE", "fracture.jpg", "IMG_FRACTURE", "image/jpeg", 26777, "කැඩුම් බිඳුම් සහ උළුක්කු පත්තු ප්‍රතිකාරය", "Traditional Fracture & Sprain Herbal Poultice Care", 0),
        ("MED-SCIATICA", "sciatica.jpg", "IMG_SCIATICA", "image/jpeg", 30867, "සයිටිකා සහ කොඳු ඇට පෙළ ඔසු පොට්ලී ප්‍රතිකාරය", "Sciatica & Back Herbal Compress Therapy", 0),
        ("MED-APOTHECARY", "apothecary.jpg", "IMG_APOTHECARY", "image/jpeg", 38273, "පාරම්පරික ආයුර්වේද තෙල් සහ ඖෂධ එකතුව", "Traditional Ayurvedic Oils & Herbal Apothecary", 0),
        ("MED-DOCTOR", "doctor.jpg", "IMG_DOCTOR", "image/jpeg", 36055, "ආයුර්වේද වෛද්‍ය නිරූපණ ඡායාරූපය", "Ayurvedic Physician Representation Portrait", 0),
    ]
    for mid, fname, fpath, mime, fsize, alt_si, alt_en, feat in media_seed:
        cur.execute(
            """
            INSERT OR IGNORE INTO media_assets (id, filename, file_path, mime_type, file_size_bytes, alt_text_si, alt_text_en, is_featured)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (mid, fname, fpath, mime, fsize, alt_si, alt_en, feat),
        )

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


if __name__ == "__main__":
    init_database()

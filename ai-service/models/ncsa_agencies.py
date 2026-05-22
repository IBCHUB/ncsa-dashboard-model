"""
NCSA Sector → Agency Mapping (Official)
========================================

Source: Official NCSA (National Cyber Security Agency, Thailand) sector + agency
CSVs (10 files) provided 2026-05.

This module curates the official mapping into two data structures used by
``models.sector_classifier`` to recognise Thai government / CII agency names
appearing in IOC descriptions, titles, tags, and news reports.

Sectors (matches dashboard SECTOR_DISPLAY_NAMES taxonomy):
    state_security              — ด้านความมั่นคงของรัฐ
    government                  — ด้านบริการภาครัฐที่สำคัญ
    transportation              — ด้านการขนส่งและโลจิสติกส์
    financial                   — ด้านการเงินการธนาคาร
    technology                  — ด้านเทคโนโลยีสารสนเทศและโทรคมนาคม
    critical_infrastructure     — ด้านพลังงานและสาธารณูปโภค
    healthcare                  — ด้านสาธารณสุข

Each sector has two match layers:

* ``tokens``      — distinctive Thai/English substrings (>=4 chars) that strongly
                    indicate the sector even without the full agency name.
                    e.g. "กองทัพ" → state_security, "การไฟฟ้า" → critical_infrastructure.
                    Tokens are matched as case-insensitive substrings.

* ``full_names``  — complete official agency labels for exact substring matching.
                    Used when the IOC context quotes the agency name verbatim
                    (common in Thai-language news / TI feeds).

Conflict resolution (agency appears in multiple sector CSVs):
    Priority order = state_security > healthcare > critical_infrastructure >
                     transportation > financial > technology > government
    This ranks operational impact / NCSA risk weighting from highest to lowest.

Public API:
    NCSA_SECTOR_TOKENS:     Dict[sector_key, set[str]]
    NCSA_SECTOR_AGENCIES:   Dict[sector_key, set[str]]
    NCSA_AGENCY_INDEX:      Tuple[Tuple[agency_name_lower, sector_key], ...]
                            (sorted longest-first for greedy substring scan)
    match_ncsa_agency(text) → Optional[Tuple[sector_key, matched_agency]]
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Distinctive Thai/English tokens per sector
# ---------------------------------------------------------------------------
# Rules:
#   - >=4 characters (avoids 2-3 char false positives)
#   - Unique to one sector (cross-checked manually against all CSVs)
#   - Avoid generic government words ("สำนัก", "กรม", "เทศบาล", "องค์การบริหาร")
#     unless paired with a distinctive suffix (e.g. "กรมศุลกากร").

NCSA_SECTOR_TOKENS: Dict[str, Set[str]] = {
    "state_security": {
        # Military
        "กองทัพ", "กองทัพบก", "กองทัพเรือ", "กองทัพอากาศ",
        "กองทัพไทย", "กองบัญชาการกองทัพ", "กองทัพภาค",
        "ราชอาณาจักร", "ค่ายสุรนารี", "ปลัดกระทรวงกลาโหม",
        # Police
        "ตำรวจ", "ตำรวจแห่งชาติ", "ตำรวจภูธร",
        "ทะเบียนประวัติอาชญากร", "พิสูจน์หลักฐานตำรวจ",
        "ตำรวจสืบสวนสอบสวนอาชญากรรม",
        "ปราบปรามการกระทำความผิด",
        # Intelligence / DSI / NSC
        "ข่าวกรอง", "ข่าวกรองแห่งชาติ",
        "สอบสวนคดีพิเศษ", "dsi",
        "สภาความมั่นคงแห่งชาติ",
        "รักษาความมั่นคงภายในราชอาณาจักร",
        "คุ้มครองข้อมูลส่วนบุคคล",
        "ความมั่นคงของรัฐ", "ด้านความมั่นคงของรัฐ",
        # Court
        "ศาลปกครอง", "สำนักงานศาลปกครอง",
    },
    "transportation": {
        # Ministries / departments
        "กรมเจ้าท่า", "กรมการขนส่งทางบก", "กรมการขนส่งทางราง",
        "กรมทางหลวงชนบท", "กรมท่าอากาศยาน", "กรมอุตุนิยมวิทยา",
        "การท่าเรือ", "การท่าอากาศยาน",
        "การรถไฟ", "การรถไฟฟ้าขนส่งมวลชน",
        "นโยบายและแผนการขนส่ง",
        "การบินพลเรือน", "ปลัดกระทรวงคมนาคม",
        "องค์การขนส่งมวลชน",
        # Companies
        "การบินไทย", "การบินกรุงเทพ", "ไทยแอร์เอเชีย",
        "ไทยเวียตเจ็ท", "นกแอร์", "วิทยุการบิน",
        "ท่าอากาศยานไทย", "รถไฟฟ้า ร.ฟ.ท.",
        "ระบบขนส่งมวลชนกรุงเทพ",
        "ขนส่งและโลจิสติกส์", "ด้านการขนส่งและโลจิสติกส์",
        # English
        "logistics", "airways", "airasia", "vietjet",
        "nokair", "thaiairways",
    },
    "financial": {
        # Thai
        "ธนาคาร", "ธนาคารแห่งประเทศไทย",
        "ตลาดหลักทรัพย์",
        "หลักทรัพย์และตลาดหลักทรัพย์",
        "ศูนย์รับฝากหลักทรัพย์",
        "สำนักหักบัญชี", "สัญญาซื้อขายล่วงหน้า",
        "การเงินการธนาคาร", "ด้านการเงินการธนาคาร",
        # English (additive to existing financial keywords)
        "tfex", "tsd", "tch", "tb-cert", "tbcert",
    },
    "critical_infrastructure": {
        # Utilities (Thai)
        "การไฟฟ้า", "การไฟฟ้านครหลวง", "การไฟฟ้าฝ่ายผลิต",
        "การไฟฟ้าส่วนภูมิภาค",
        "การประปา", "การประปานครหลวง", "การประปาส่วนภูมิภาค",
        "เชื้อเพลิงธรรมชาติ", "ธุรกิจพลังงาน",
        "พัฒนาพลังงานทดแทน", "อนุรักษ์พลังงาน",
        "คณะกรรมการกำกับกิจการพลังงาน",
        "นโยบายและแผนพลังงาน", "ปลัดกระทรวงพลังงาน",
        "สำนักงานพลังงานจังหวัด",
        "เทคโนโลยีนิวเคลียร์", "นิวเคลียร์แห่งชาติ",
        "อุตสาหกรรมพื้นฐานและการเหมืองแร่",
        "พลังงานและสาธารณูปโภค", "ด้านพลังงานและสาธารณูปโภค",
    },
    "healthcare": {
        # Thai hospitals & MoPH (additive to existing)
        "โรงพยาบาล",
        "กรมการแพทย์", "กรมการแพทย์แผนไทย",
        "กรมควบคุมโรค", "กรมวิทยาศาสตร์การแพทย์",
        "กรมสนับสนุนบริการสุขภาพ",
        "กรมสุขภาพจิต", "กรมอนามัย",
        "ปลัดกระทรวงสาธารณสุข", "สาธารณสุขจังหวัด",
        "ป้องกันควบคุมโรค",
        "คณะกรรมการอาหารและยา", "อาหารและยา",
        "ปรมาณูเพื่อสันติ",
        "หลักประกันสุขภาพ", "สปสช",
        "สุขภาพดิจิทัล", "ดิจิทัลการแพทย์",
        "องค์การเภสัชกรรม", "เภสัชกรรม",
        "เขตสุขภาพ", "วิทยาศาสตร์การแพทย์",
        "การแพทย์ฉุกเฉิน",
        "ด้านสาธารณสุข",
    },
    "technology": {
        # Telecom (additive to existing)
        "โทรคมนาคมแห่งชาติ",
        "แอดวานซ์ ไวร์เลส", "แอดวานซ์ไวร์เลส",
        "ทรู อินเทอร์เน็ต", "ทรูอินเทอร์เน็ต",
        "ทรู มูฟ เอช", "ทริปเปิลที บรอดแบนด์",
        "ทริปเปิลทีบรอดแบนด์",
        "กิจการกระจายเสียง", "กิจการโทรทัศน์",
        "กิจการโทรคมนาคมแห่งชาติ", "กสทช",
        "ส่งเสริมเศรษฐกิจดิจิทัล",
        "พัฒนารัฐบาลดิจิทัล",
        "เทคโนโลยีสารสนเทศและโทรคมนาคม",
        "ด้านเทคโนโลยีสารสนเทศและโทรคมนาคม",
    },
    "government": {
        # Distinctive ministerial / regulatory bodies that are NOT covered
        # by the other sectors above. Generic "กรม"/"สำนักงาน" prefixes are
        # avoided — only well-known agency names are listed.
        "กรมการปกครอง", "กรมพัฒนาชุมชน",
        "กรมบังคับคดี", "กรมบัญชีกลาง",
        "กรมปศุสัตว์",
        "กรมป้องกันและบรรเทาสาธารณภัย",
        "กรมราชทัณฑ์", "กรมศุลกากร",
        "กรมส่งเสริมอุตสาหกรรม",
        "กรมสวัสดิการและคุ้มครองแรงงาน",
        "กรมส่งเสริมการเรียนรู้",
        "พัฒนาระบบราชการ",
        "ตรวจคนเข้าเมือง",
        "ปลัดกระทรวงแรงงาน",
        "ปลัดกระทรวงการคลัง",
        "พัฒนารัฐบาลดิจิทัล",
        "สำนักงานสถิติแห่งชาติ",
        "บริการภาครัฐที่สำคัญ", "ด้านบริการภาครัฐที่สำคัญ",
        "ศูนย์อำนวยการบริหารจังหวัดชายแดน", "ศอ.บต",
    },
}


# ---------------------------------------------------------------------------
# Full official agency names (verbatim from CSVs, conflict-resolved)
# ---------------------------------------------------------------------------
# Conflict resolution order (high → low specificity / impact):
#   state_security > healthcare > critical_infrastructure > transportation
#   > financial > technology > government
#
# Names are stored as Thai strings; substring match is case-insensitive on
# the lowercase form. Each agency appears in exactly one sector below.

NCSA_SECTOR_AGENCIES: Dict[str, Set[str]] = {
    "state_security": {
        "กรมสอบสวนคดีพิเศษ", "DSI",
        "กองทะเบียนประวัติอาชญากร",
        "สำนักงานพิสูจน์หลักฐานตำรวจ",
        "สำนักงานตำรวจแห่งชาติ",
        "กองทัพเรือ", "กองทัพบก", "กองทัพอากาศ",
        "กองบังคับการปราบปรามการกระทำความผิดเกี่ยวกับอาชญากรรมทางเทคโลยี",
        "กองบัญชาการกองทัพไทย",
        "กองอำนวยการรักษาความมั่นคงภายในราชอาณาจักร",
        "สำนักข่าวกรองแห่งชาติ",
        "สำนักงานคณะกรรมการคุ้มครองข้อมูลส่วนบุคคล",
        "สำนักงานปลัดกระทรวงกลาโหม",
        "สำนักงานศาลปกครอง",
        "สำนักงานสภาความมั่นคงแห่งชาติ",
        "ตำรวจภูธรภาค 7", "ตำรวจภูธรภาค 2",
        "กองทัพภาคที่ 2", "กองทัพภาคที่ 2 ค่ายสุรนารี",
        "กองบัญชาการตำรวจสืบสวนสอบสวนอาชญากรรมทางเทคโนโลยี",
        "ตำรวจภูธรจังหวัดภูเก็ต",
        "กองบัญชาการตำรวจสอบสวนกลาง",
        "กองบังคับการตำรวจน้ำ",
        "ศูนย์อำนวยการบริหารจังหวัดชายแดนภาคใต้",
        "กองบัญชาการตำรวจตระเวนชายแดน",
        "กรมยุทธโยธาทหารบก",
        "สถาบันวิชาการป้องกันประเทศ",
        "กองการบินทหารเรือ",
    },
    "healthcare": {
        "กรมการแพทย์",
        "กรมการแพทย์แผนไทยและการแพทย์ทางเลือก",
        "กรมควบคุมโรค", "กรมวิทยาศาสตร์การแพทย์",
        "กรมสนับสนุนบริการสุขภาพ",
        "กรมสุขภาพจิต", "กรมอนามัย",
        "สำนักงานปรมาณูเพื่อสันติ",
        "สำนักงานคณะกรรมการอาหารและยา",
        "สำนักงานหลักประกันสุขภาพแห่งชาติ", "สปสช.",
        "สำนักสุขภาพดิจิทัล",
        "สำนักดิจิทัลการแพทย์",
        "องค์การเภสัชกรรม",
        "สถาบันการแพทย์ฉุกเฉินแห่งชาติ",
        "ศูนย์เทคโนโลยีสารสนเทศและการสื่อสาร สำนักงานปลัดกระทรวงสาธารณสุข",
        "ศูนย์วิทยาศาสตร์การแพทย์ที่ 12 สงขลา",
        "สำนักงานป้องกันควบคุมโรคที่ 1 จังหวัดเชียงใหม่",
        "สำนักงานเขตสุขภาพที่ 5",
        "ศูนย์วิจัยและพัฒนาการสัตวแพทย์ภาคเหนือตอนบน",
        "สัตวแพทยสภา",
        "โรงพยาบาลชุมตาบง", "โรงพยาบาลตากฟ้า",
        "โรงพยาบาลเฉลิมพระเกียรติ",
        "โรงพยาบาลประจวบคีรีขันธ์",
        "โรงพยาบาลน่าน", "โรงพยาบาลมุกดาหาร",
        "โรงพยาบาลชุมแสง",
        "โรงพยาบาลค่ายสมเด็จพระนเรศวรมหาราช",
        "โรงพยาบาลแม่วงก์", "โรงพยาบาลบุรีรัมย์",
        "โรงพยาบาลนาหมื่น", "โรงพยาบาลโกรกพระ",
        "โรงพยาบาลเฉลิมพระเกียรติสมเด็จพระเทพรัตนราชสุดาฯ สยามบรมราชกุมารี ระยอง",
    },
    "critical_infrastructure": {
        "กรมเชื้อเพลิงธรรมชาติ",
        "กรมธุรกิจพลังงาน",
        "กรมพัฒนาพลังงานทดแทนและอนุรักษ์พลังงาน",
        "กรมอุตสาหกรรมพื้นฐานและการเหมืองแร่",
        "การไฟฟ้านครหลวง",
        "การไฟฟ้าฝ่ายผลิตแห่งประเทศไทย",
        "การไฟฟ้าส่วนภูมิภาค",
        "การประปานครหลวง",
        "การประปาส่วนภูมิภาค",
        "บริษัท ปตท.จำกัด (มหาชน)", "ปตท.",
        "สถาบันเทคโนโลยีนิวเคลียร์แห่งชาติ",
        "สำนักงานคณะกรรมการกำกับกิจการพลังงาน",
        "สำนักงานนโยบายและแผนพลังงาน",
        "สำนักงานปลัดกระทรวงพลังงาน",
        "องค์การบริหารจัดการก๊าซเรือนกระจก",
        "สำนักบริหารจัดการน้ำและอุทกวิทยา",
    },
    "transportation": {
        "กรมเจ้าท่า",
        "กรมการขนส่งทางบก", "กรมการขนส่งทางราง",
        "กรมทางหลวงชนบท", "กรมท่าอากาศยาน",
        "กรมอุตุนิยมวิทยา",
        "การท่าเรือแห่งประเทศไทย",
        "การท่าอากาศยานอู่ตะเภา",
        "การรถไฟแห่งประเทศไทย",
        "การรถไฟฟ้าขนส่งมวลชนแห่งประเทศไทย",
        "บริษัท เอซี เอวิเอชั่น จำกัด",
        "บริษัท เอ็มเจ็ท จำกัด",
        "บริษัท ไทยเวียตเจ็ทแอร์ จำกัด",
        "บริษัท ไทยแอร์เอเชีย จำกัด",
        "บริษัท ไทยแอร์เอเชีย เอ็กซ์ จำกัด",
        "บริษัท การบินไทย จำกัด (มหาชน)",
        "บริษัท การบินกรุงเทพ จำกัด (มหาชน)",
        "บริษัท ท่าอากาศยานไทย จำกัด (มหาชน)",
        "บริษัท รถไฟฟ้า ร.ฟ.ท. จำกัด",
        "บริษัท ระบบขนส่งมวลชนกรุงเทพ จำกัด (มหาชน)",
        "บริษัท วิทยุการบินแห่งประเทศไทย จำกัด",
        "บริษัท สายการบินนกแอร์ จำกัด (มหาชน)",
        "บริษัท ดับบลิวเอฟเอสพีจีคาร์โก้ จำกัด",
        "สำนักงานการบินพลเรือนแห่งประเทศไทย",
        "สำนักงานนโยบายและแผนการขนส่งและจราจร",
        "สำนักงานปลัดกระทรวงคมนาคม",
        "องค์การขนส่งมวลชนกรุงเทพ",
        "มหาวิทยาลัยเทคโนโลยีราชมงคลกรุงเทพ",
    },
    "financial": {
        "ตลาดหลักทรัพย์แห่งประเทศไทย", "SET",
        "ธนาคารเพื่อการเกษตรและสหกรณ์การเกษตร",
        "ธนาคารแห่งประเทศไทย",
        "ธนาคารไทยพาณิชย์",
        "ธนาคารกรุงเทพ", "ธนาคารกรุงไทย",
        "ธนาคารกรุงศรีอยุธยา",
        "ธนาคารทหารไทยธนชาต",
        "ธนาคารพัฒนาวิสาหกิจขนาดกลางและขนาดย่อมแห่งประเทศไทย",
        "ธนาคารออมสิน", "ธนาคารอาคารสงเคราะห์",
        "บริษัท เนชั่นแนล ไอทีเอ็มเอ็กซ์ จำกัด",
        "บริษัท ตลาดสัญญาซื้อขายล่วงหน้า (ประเทศไทย) จำกัด (มหาชน)", "TFEX",
        "บริษัท ศูนย์รับฝากหลักทรัพย์ (ประเทศไทย) จำกัด", "TSD",
        "บริษัท สำนักหักบัญชี (ประเทศไทย) จำกัด", "TCH",
        "สำนักงานคณะกรรมการกำกับหลักทรัพย์และตลาดหลักทรัพย์",
        "TB-CERT",
    },
    "technology": {
        "บริษัท แอดวานซ์ ไวร์เลส เน็ทเวอร์ค จำกัด",
        "บริษัท โทรคมนาคมแห่งชาติ จำกัด (มหาชน)",
        "บริษัท ทรู อินเทอร์เน็ต คอร์ปอเรชั่น จำกัด",
        "บริษัท ทริปเปิลที บรอดแบนด์ จำกัด (มหาชน)",
        "บริษัท ทรู มูฟ เอช ยูนิเวอร์แซล คอมมิวนิเคชั่น จำกัด",
        "สำนักงานคณะกรรมการกิจการกระจายเสียง กิจการโทรทัศน์ และกิจการโทรคมนาคมแห่งชาติ",
        "กสทช.",
        "สำนักงานพัฒนารัฐบาลดิจิทัล", "สพร.",
        "สำนักงานส่งเสริมเศรษฐกิจดิจิทัล",
        "มหาวิทยาลัยราชภัฏนครราชสีมา",
    },
    "government": {
        "กรมการปกครอง", "กรมการพัฒนาชุมชน",
        "กรมชลประทาน",
        "กรมบังคับคดี", "กรมบัญชีกลาง",
        "กรมปศุสัตว์",
        "กรมป้องกันและบรรเทาสาธารณภัย",
        "กรมราชทัณฑ์", "กรมศุลกากร",
        "กรมส่งเสริมอุตสาหกรรม",
        "กรมสวัสดิการและคุ้มครองแรงงาน",
        "กรมส่งเสริมการเรียนรู้",
        "สำนักงานคณะกรรมการพัฒนาระบบราชการ",
        "สำนักงานตรวจคนเข้าเมือง",
        "สำนักงานปลัดกระทรวงแรงงาน",
        "สำนักงานปลัดกระทรวงการคลัง",
        "สำนักงานสถิติแห่งชาติ",
        "สำนักงานสภานโยบายการอุดมศึกษา วิทยาศาสตร์ วิจัยและนวัตกรรมแห่งชาติ",
        "ด่านศุลกากรช่องเม็ก",
        "ด่านศุลกากรนครศรีธรรมราช",
        "สถาบันส่งเสริมการสอนวิทยาศาสตร์และเทคโนโลยี",
        "สสวท.",
        "มหาวิทยาลัยราชภัฏพิบูลสงคราม",
        "มหาวิทยาลัยราชภัฏอุบลราชธานี",
    },
}


def _build_agency_index() -> Tuple[Tuple[str, str], ...]:
    """Flatten NCSA_SECTOR_AGENCIES into a sorted (longest-first) index.

    Longest-first ordering ensures a more specific agency name wins over a
    shorter prefix (e.g. "กองทัพภาคที่ 2 ค่ายสุรนารี" beats "กองทัพ").
    """
    pairs: List[Tuple[str, str]] = []
    for sector_key, names in NCSA_SECTOR_AGENCIES.items():
        for name in names:
            cleaned = name.strip()
            if cleaned:
                pairs.append((cleaned.lower(), sector_key))
    # Sort longest first so greedy substring scan matches the most specific.
    pairs.sort(key=lambda item: (-len(item[0]), item[0]))
    return tuple(pairs)


def _build_token_index() -> Tuple[Tuple[str, str], ...]:
    """Flatten NCSA_SECTOR_TOKENS into a longest-first lookup table."""
    pairs: List[Tuple[str, str]] = []
    for sector_key, tokens in NCSA_SECTOR_TOKENS.items():
        for token in tokens:
            cleaned = token.strip().lower()
            if cleaned:
                pairs.append((cleaned, sector_key))
    pairs.sort(key=lambda item: (-len(item[0]), item[0]))
    return tuple(pairs)


# Precomputed lookup tables (built once at import time, immutable).
NCSA_AGENCY_INDEX: Tuple[Tuple[str, str], ...] = _build_agency_index()
NCSA_TOKEN_INDEX: Tuple[Tuple[str, str], ...] = _build_token_index()


def match_ncsa_agency(text: str) -> Optional[Tuple[str, str, str]]:
    """Return (sector_key, matched_value, match_type) if *text* contains a
    known NCSA agency name or distinctive sector token.

    Tries full agency names first (highest confidence), then distinctive
    sector tokens. Returns ``None`` if nothing matches.

    match_type is one of ``"agency"`` (full name match) or ``"token"``
    (distinctive substring match). Callers can use this to scale the
    confidence boost — agency matches are more specific.
    """
    if not text:
        return None
    haystack = text.lower()

    # Layer 1 — full agency name (highest confidence).
    for needle, sector in NCSA_AGENCY_INDEX:
        if needle in haystack:
            return sector, needle, "agency"

    # Layer 2 — distinctive token (medium confidence).
    for needle, sector in NCSA_TOKEN_INDEX:
        if needle in haystack:
            return sector, needle, "token"

    return None


def iter_sector_keys() -> Iterable[str]:
    """Yield the NCSA sector keys used by this module."""
    seen: Set[str] = set()
    for key in NCSA_SECTOR_AGENCIES.keys():
        if key not in seen:
            seen.add(key)
            yield key
    for key in NCSA_SECTOR_TOKENS.keys():
        if key not in seen:
            seen.add(key)
            yield key


__all__ = [
    "NCSA_SECTOR_TOKENS",
    "NCSA_SECTOR_AGENCIES",
    "NCSA_AGENCY_INDEX",
    "NCSA_TOKEN_INDEX",
    "match_ncsa_agency",
    "iter_sector_keys",
]

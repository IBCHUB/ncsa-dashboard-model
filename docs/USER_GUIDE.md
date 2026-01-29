# 🖥️ Dashboard User Guide

คู่มือการใช้งาน TCTI Dashboard

---

## 🏠 หน้าแรก (Dashboard)

URL: `/`

แสดงภาพรวมของภัยคุกคามทั้งหมด:

- **Statistics Cards** - จำนวน IOC แต่ละประเภท
- **Severity Chart** - กราฟแสดงระดับความรุนแรง
- **Threat Map** - แผนที่ภัยคุกคามทั่วโลก
- **Recent Alerts** - แจ้งเตือนล่าสุด

---

## 🔍 IOC Explorer

URL: `/ioc`

ค้นหาและกรอง IOC:

### การค้นหา
- พิมพ์ IP, Domain, Hash ในช่องค้นหา
- รองรับ partial matching

### Filter Options
| Filter | Description |
|--------|-------------|
| Type | ip, domain, hash, url |
| Severity | critical, high, medium, low |
| Source | แหล่งข้อมูล |
| Date Range | ช่วงเวลา |

### IOC Detail Page
คลิกที่ IOC เพื่อดูรายละเอียด:
- Risk Score & Breakdown
- AI Classification
- Related Entities
- Threat Graph
- Actions (Create Ticket, Export)

---

## 🗺️ Threat Map

URL: `/map`

แผนที่แสดงภัยคุกคามตามภูมิศาสตร์:
- 🔴 Critical - สีแดง
- 🟠 High - สีส้ม
- 🟡 Medium - สีเหลือง
- 🟢 Low - สีเขียว

---

## 🔗 Threat Graph

URL: `/graph`

กราฟความสัมพันธ์ระหว่าง IOC:

### Node Types
- 🔵 **IOC** - IP, Domain, Hash
- 🔴 **Threat Actor** - กลุ่มผู้โจมตี
- 🟣 **Entity** - องค์กร, Malware

### การใช้งาน
- **Zoom** - Mouse wheel
- **Pan** - Click and drag
- **Focus** - Click on node

### Filter
- IOCs with Threat Actors
- IOCs with Any Entities
- All IOCs

---

## 📊 Reports & Export

URL: `/reports`

### Generate Report
1. เลือก **Report Type**
   - Full Analysis
   - IOC Summary
   - Threat Actors
   - Geographic Distribution

2. เลือก **Filter** (optional)
   - Severity Level
   - IOC Type
   - Date Range

3. คลิก **Generate Report**

### Export Formats

| Format | Use Case |
|--------|----------|
| **CSV** | Excel / Spreadsheet |
| **JSON** | API / Integration |
| **Suricata** | IDS Rules |
| **Snort** | IDS Rules |
| **Text** | Human-readable |
| **Blocklist** | Firewall |

---

## 🚨 Alerts Center

URL: `/alerts`

ศูนย์แจ้งเตือนภัยคุกคาม:
- Critical alerts แสดงก่อน
- Mark as read/unread
- Create HelpDesk ticket

---

## 📰 Cyber News

URL: `/news`

ข่าวสารด้านความปลอดภัย:
- ดึงจาก RSS feeds
- กรองตามหมวดหมู่
- Link ไปยังแหล่งข่าว

---

## ⚙️ การตั้งค่า

### Theme
- Dark Mode (default)
- Light Mode

### Language
- English
- Thai (coming soon)

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Focus search |
| `Esc` | Close modal |
| `←` `→` | Navigate pages |

---

## 🔒 Security

- ระบบใช้ API Key authentication
- Session หมดอายุใน 24 ชั่วโมง
- Data transfer ผ่าน HTTPS

---

## 🆘 Support

มีปัญหาการใช้งาน ติดต่อ Admin

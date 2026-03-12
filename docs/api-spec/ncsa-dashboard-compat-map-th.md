# Compat Mapping สำหรับ `ncsa-dashboard-web`

เอกสารนี้ใช้สำหรับช่วงเปลี่ยนผ่านจาก flat endpoint ของ PoC เดิม ไปสู่ canonical API แบบ `/api/v1/...`

## 1. หลักการ compat

- frontend ตัวใหม่ควรใช้ canonical path เป็นหลัก
- backend สามารถเปิด alias เดิมไว้ชั่วคราวเพื่อให้ PoC หรือเครื่องมือเก่ายังใช้งานได้
- canonical response ใช้มาตรฐาน

```json
{
  "data": {},
  "meta": {},
  "error": null
}
```

- alias flat endpoint อาจห่อ response แบบเก่าได้เป็น

```json
{
  "res_result": {},
  "res_meta": {},
  "error": null
}
```

- ถ้า alias เดิมคาดหวัง array ตรง ๆ ใน `res_result` ให้ map จาก `data.items` หรือ `data` ตามตารางด้านล่าง

## 2. ตาราง mapping จาก PoC เดิม

| PoC Path | Method | Canonical Path | Canonical Field ที่ใช้ | หมายเหตุ |
|----------|--------|----------------|------------------------|----------|
| `/login` | `POST` | `/api/v1/auth/login` | `data.access_token` | alias ควรคืน `token` เพิ่มเพื่อให้ frontend PoC เดิมใช้งานได้ทันที |
| `/threat-type` | `GET` | `/api/v1/lookups/threat-types` | `data.items` | ใช้กับ dropdown หลายหน้า |
| `/severity` | `GET` | `/api/v1/lookups/severities` | `data.items` | ใช้กับ dropdown severity |
| `/rick-level` | `GET` | `/api/v1/lookups/risk-levels` | `data.items` | path เดิมสะกด `rick` ตาม PoC |
| `/source` | `GET` | `/api/v1/lookups/sources` | `data.items` | ใช้กับ source dropdown และข่าว |
| `/export-type` | `GET` | `/api/v1/lookups/export-formats` | `data.items` | ใช้กับหน้ารายงาน |
| `/dashboard` | `GET` | `/api/v1/operations/dashboard` | `data.overview` | ใช้สรุป KPI ของ operations dashboard |
| `/incidentbyseverity` | `GET` | `/api/v1/operations/dashboard` | `data.incident_by_severity` | alias ควรดึงเฉพาะชุดข้อมูล pie/donut |
| `/attacktime` | `GET` | `/api/v1/operations/dashboard` | `data.attack_time_heatmap` | ใช้กับ operations dashboard |
| `/attacktime` | `GET` | `/api/v1/operations/attack-time-report` | `data.heatmap` | ใช้กับหน้า report แบบ detail |
| `/intelligencesources` | `GET` | `/api/v1/operations/dashboard` | `data.top_intelligence_sources` | top intelligence sources |
| `/threattype` | `GET` | `/api/v1/operations/dashboard` | `data.top_threat_types` | top threat types |
| `/countriesbythreatassociation` | `GET` | `/api/v1/operations/dashboard` | `data.top_attack_origins` | ฝั่ง canonical ใช้ชื่อ domain ว่า attack origins |
| `/targetsectors` | `GET` | `/api/v1/operations/dashboard` | `data.target_sectors` | top sectors |

## 3. กติกาการแปลง response

### 3.1 Lookup alias

canonical:

```json
{
  "data": {
    "items": [
      { "value": "malware", "label": "Malware" }
    ]
  },
  "meta": {
    "timezone": "Asia/Bangkok"
  },
  "error": null
}
```

alias:

```json
{
  "res_result": [
    { "Value": "malware", "Name": "Malware" }
  ],
  "res_meta": {
    "timezone": "Asia/Bangkok"
  },
  "error": null
}
```

### 3.2 Login alias

canonical:

```json
{
  "data": {
    "access_token": "jwt-token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "user_id": "usr-001",
      "name": "Natakarn",
      "role_name": "Admin"
    }
  },
  "meta": {},
  "error": null
}
```

alias:

```json
{
  "token": "jwt-token",
  "user": {
    "user_id": "usr-001",
    "name": "Natakarn",
    "role_name": "Admin"
  }
}
```

### 3.3 Operations dashboard aliases

- `/dashboard` คืนเฉพาะ `overview`
- `/incidentbyseverity` คืนเฉพาะ `incident_by_severity`
- `/attacktime` ในหน้า dashboard คืนเฉพาะ `attack_time_heatmap`
- `/intelligencesources` คืนเฉพาะ `top_intelligence_sources`
- `/threattype` คืนเฉพาะ `top_threat_types`
- `/countriesbythreatassociation` คืนเฉพาะ `top_attack_origins`
- `/targetsectors` คืนเฉพาะ `target_sectors`

ตัวอย่าง alias ของ `/dashboard`

```json
{
  "res_result": {
    "ActiveIOC": 12458,
    "CriticalIOCActive": 124,
    "NewIOC": 89,
    "SourcesActive": "12"
  },
  "res_meta": {
    "timezone": "Asia/Bangkok"
  },
  "error": null
}
```

## 4. คำแนะนำการใช้งาน

1. ถ้า frontend ใหม่จะเริ่มเชื่อม API ให้เรียก canonical path เท่านั้น
2. ถ้าจำเป็นต้องรองรับ PoC เก่า ให้ทำ alias เป็นชั้น adapter แยกจาก domain service หลัก
3. อย่าออกแบบ backend ใหม่ให้ยึด `res_result` เป็นมาตรฐานระยะยาว
4. เมื่อทีม frontend ย้ายออกจาก flat endpoint ครบแล้ว ให้ประกาศ deprecate alias เดิมเป็นรอบถัดไป

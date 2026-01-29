# 📚 TCTI Code Walkthrough - เข้าใจทุกบรรทัด

เอกสารนี้อธิบายโค้ดทั้งหมดแบบละเอียด เพื่อให้คุณเข้าใจว่า **ทำไม** ถึงทำแบบนี้ ไม่ใช่แค่ **อะไร** ที่ทำ

---

## 📖 สารบัญ

1. [ภาพรวมระบบ](#1-ภาพรวมระบบ)
2. [Data Layer - Elasticsearch](#2-data-layer---elasticsearch)
3. [AI Service - Python Backend](#3-ai-service---python-backend)
4. [Dashboard - Next.js Frontend](#4-dashboard---nextjs-frontend)
5. [Data Pipeline - การไหลของข้อมูล](#5-data-pipeline---การไหลของข้อมูล)

---

## 1. ภาพรวมระบบ

### 🤔 ทำไมถึงเลือก Stack นี้?

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Next.js 14    │───▶│    FastAPI      │───▶│  Elasticsearch  │
│   (Frontend)    │    │   (AI Backend)  │    │   (Database)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

| Technology | ทำไมถึงเลือก? |
|------------|---------------|
| **Next.js 14** | React framework ที่ทันสมัย, Server-side rendering ทำให้โหลดเร็ว, API Routes ในตัว |
| **FastAPI** | Python framework ที่เร็วที่สุด, รองรับ async, Auto-generate API docs, เหมาะกับ ML/AI |
| **Elasticsearch** | Full-text search เร็วมาก, รองรับข้อมูลล้าน records, ดู "Big Data" ตาม TOR |

### 🤔 ทำไมต้องแยก Frontend กับ Backend?

**เหตุผล:**
1. **Separation of Concerns** - Frontend ดูแลเรื่อง UI, Backend ดูแลเรื่อง Logic
2. **Scalability** - สามารถ scale แต่ละส่วนแยกกันได้
3. **Technology Match** - Python เหมาะกับ AI/ML มากกว่า JavaScript

---

## 2. Data Layer - Elasticsearch

### 📁 ไฟล์: `docker-compose.yml`

```yaml
# Elasticsearch - ทำหน้าที่เป็น "ฐานข้อมูล" หลัก
elasticsearch:
  image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
  environment:
    - discovery.type=single-node  # ใช้ node เดียว (ไม่ต้อง cluster)
    - xpack.security.enabled=false  # ปิด security สำหรับ dev
    - "ES_JAVA_OPTS=-Xms2g -Xmx2g"  # จอง RAM 2GB สำหรับ Elasticsearch
```

### 🤔 ทำไมใช้ Elasticsearch แทน Database ทั่วไป?

| เปรียบเทียบ | MySQL/PostgreSQL | Elasticsearch |
|-------------|------------------|---------------|
| Full-text Search | ช้า | **เร็วมาก** ✅ |
| JSON Storage | ต้อง normalize | **Native JSON** ✅ |
| Analytics | ต้องเขียน Query ยาก | **Built-in aggregations** ✅ |
| Scale | ต้อง shard เอง | **Auto-sharding** ✅ |

**สำหรับ Threat Intelligence ที่ต้องค้นหา IP, Domain, Hash ตลอดเวลา → Elasticsearch เหมาะที่สุด**

---

### 📁 ไฟล์: `ai-service/elastic_client.py`

```python
# ทำไมต้องสร้าง Client แยก?
# → เพื่อ "รวมศูนย์" การติดต่อ Elasticsearch ไว้ที่เดียว
# → ถ้าต้องเปลี่ยนวิธีเชื่อมต่อ แก้ไขแค่ไฟล์นี้

class ElasticClient:
    def __init__(self, url: str):
        self.url = url
        self.datalake_index = "tcti-datalake"      # ข้อมูลดิบ
        self.warehouse_index = "tcti-warehouse"    # ข้อมูลที่ AI ประมวลผลแล้ว
```

### 🤔 ทำไมต้องมี 2 Index (Data Lake vs Data Warehouse)?

```
┌────────────────────┐         ┌────────────────────┐
│    DATA LAKE       │   AI    │   DATA WAREHOUSE   │
│  (tcti-datalake)   │ ──────▶ │  (tcti-warehouse)  │
│                    │ Process │                    │
│ • ข้อมูลดิบ        │         │ • ข้อมูลที่ enriched │
│ • ยังไม่ classify   │         │ • มี risk_score     │
│ • หลาย format      │         │ • มี threat_types   │
└────────────────────┘         └────────────────────┘
```

**เหตุผล:**
1. **Data Lake** = เก็บข้อมูลดิบไว้ก่อน ไม่แก้ไข ← จะได้กลับมาดูได้ถ้ามีปัญหา
2. **Data Warehouse** = ข้อมูลที่พร้อมใช้งาน ← Dashboard ดึงจากตรงนี้

---

## 3. AI Service - Python Backend

### 📁 ไฟล์: `ai-service/main.py`

```python
# FastAPI Application
app = FastAPI(
    title="Thailand Cyber Threat Intelligence - AI Service",
    description="NLP Classification and Risk Scoring for IOCs",
    version="1.0.0"
)
```

### 🤔 ทำไมใช้ FastAPI?

| เปรียบเทียบ | Flask | FastAPI |
|-------------|-------|---------|
| Speed | ช้ากว่า | **2-3x เร็วกว่า** ✅ |
| Async | ต้อง config เพิ่ม | **Built-in** ✅ |
| Type Hints | ไม่มี | **มี + Auto-validate** ✅ |
| API Docs | ต้องติดตั้งเพิ่ม | **Auto-generate (Swagger)** ✅ |

---

### 📁 ไฟล์: `ai-service/models/classifier.py`

```python
# ทำไมใช้ BART-Large-MNLI?
# → เป็นโมเดลขนาดใหญ่ (400M params) ที่เข้าใจบริบทภาษาดีที่สุด
# → รองรับ Zero-shot classification (แม่นยำกว่า DistilBERT มาก)
# → เป็น Industry Standard สำหรับงานจำแนกข้อความ

from transformers import pipeline

def get_classifier():
    return pipeline(
        "zero-shot-classification",
        model="facebook/bart-large-mnli"
    )
```

### 🤔 Zero-shot Classification คืออะไร?

**Traditional ML:**
```
Training Data (1000+ ตัวอย่าง) → Train Model → Classify
```

**Zero-shot:**
```
Pre-trained Model + Labels → Classify ทันที (ไม่ต้อง train!)
```

**ข้อดี:**
- ไม่ต้องมี training data
- เพิ่ม/ลบ labels ได้เลย ไม่ต้อง retrain
- เหมาะกับ POC ที่ไม่มีข้อมูลเก่า

```python
# วิธีใช้: บอก labels ที่ต้องการ
THREAT_LABELS = [
    "ransomware",      # มัลแวร์เรียกค่าไถ่
    "phishing",        # หลอกเอาข้อมูล
    "apt",             # Advanced Persistent Threat
    "malware",         # มัลแวร์ทั่วไป
    "c2",              # Command & Control
    "data_breach"      # ข้อมูลรั่ว
]

# Model จะให้คะแนนแต่ละ label ว่าข้อความนี้ตรงกับอันไหนมากที่สุด
result = classifier(
    "Ransomware attack via phishing email detected",
    candidate_labels=THREAT_LABELS
)
# Output: {"ransomware": 0.85, "phishing": 0.72, ...}
```

---

### 📁 ไฟล์: `ai-service/models/scorer.py`

```python
# Risk Scoring - คำนวณคะแนนความเสี่ยง 0-100
def calculate_risk_score(
    ioc_value: str,
    ioc_type: str,
    description: str,
    sources: list,
    country_code: str,
    ...
):
```

### 🤔 ทำไมต้องมี Risk Score?

**ปัญหา:** IOC มีหลายพันตัว จะดูอันไหนก่อน?

**วิธีแก้:** ให้คะแนนความเสี่ยง แล้วเรียงจากมากไปน้อย

```
Risk Score = Σ (Factor × Weight)
```

### 📊 ปัจจัยที่ใช้คำนวณ

| Factor | Weight | ทำไมถึงสำคัญ? |
|--------|--------|---------------|
| **IOC Type** | 25% | Domain อันตรายกว่า IP เพราะ dynamic |
| **Source Reputation** | 20% | ข้อมูลจาก CERT-TH น่าเชื่อถือกว่า unknown |
| **Threat Classification** | 25% | APT อันตรายกว่า spam |
| **Geographic Risk** | 15% | บางประเทศมี threat actors มากกว่า |
| **Temporal Factors** | 15% | IOC ใหม่อาจอันตรายกว่าของเก่า |

```python
# ตัวอย่างการคำนวณ
base_score = 35  # Domain type
source_score = 25  # 3 sources confirmed
threat_score = 30  # APT detected
geo_score = 15  # High-risk country
temporal_score = 10  # New (< 7 days)

risk_score = 35 + 25 + 30 + 15 + 10 = 115 → cap at 100
severity = "critical"  # 85-100 = critical
```

---

### 📁 ไฟล์: `ai-service/utils/translator.py`

```python
# ทำไมใช้ OpenAI GPT แทน Google Translate?

# Google Translate:
"Lateral movement detected" → "ตรวจพบการเคลื่อนไหวด้านข้าง" ❌ (แปลตรงตัว)

# OpenAI GPT (with context):
"Lateral movement detected" → "ตรวจพบการแพร่กระจายในเครือข่าย" ✅ (เข้าใจ context)
```

**หลักการ:**
```python
system_prompt = """คุณเป็นนักแปลผู้เชี่ยวชาญด้าน cybersecurity...
- Lateral movement = การแพร่กระจายในเครือข่าย
- C2 beacon = สัญญาณติดต่อเซิร์ฟเวอร์ควบคุม
- Data exfiltration = การขโมยข้อมูลออก
"""

# GPT เข้าใจ context แล้วแปลได้ถูกต้อง
```

---

## 4. Dashboard - Next.js Frontend

### 📁 โครงสร้าง: `dashboard/src/app/`

```
src/app/
├── page.tsx          # หน้าแรก (Dashboard)
├── ioc/
│   └── page.tsx      # IOC Explorer
├── graph/
│   └── page.tsx      # Threat Graph
├── reports/
│   └── page.tsx      # Reports & Export
└── api/
    ├── iocs/
    │   └── route.ts  # API สำหรับดึงข้อมูล IOC
    └── stats/
        └── route.ts  # API สำหรับ statistics
```

### 🤔 ทำไมใช้ Next.js App Router?

**App Router (Next.js 13+) vs Pages Router:**

| Feature | Pages Router | App Router |
|---------|--------------|------------|
| Routing | `pages/index.js` | `app/page.tsx` ✅ |
| API Routes | `pages/api/` | `app/api/` ✅ |
| Server Components | ไม่มี | **มี (เร็วกว่า)** ✅ |
| Loading States | ต้องเขียนเอง | **Built-in** ✅ |

---

### 📁 ไฟล์: `dashboard/src/app/api/iocs/route.ts`

```typescript
// API Route - ดึงข้อมูล IOC จาก Elasticsearch

export async function GET(request: NextRequest) {
    // 1. ลองดึงจาก Elasticsearch ก่อน
    const { events, fromElasticsearch } = await loadAllEvents();
    
    // 2. ถ้า Elasticsearch ไม่พร้อม → ใช้ JSON ไฟล์แทน
    if (!fromElasticsearch) {
        // fallback to local JSON files
    }
    
    // 3. ส่งข้อมูลกลับ
    return NextResponse.json({ data: events, total: events.length });
}
```

### 🤔 ทำไมต้องมี Fallback?

**เหตุผล:**
- Elasticsearch อาจ down หรือยังไม่ได้ start
- ต้องการให้ Dashboard ยังใช้งานได้
- ช่วย development ตอนที่ไม่ได้รัน Docker

```typescript
// Pattern: Try Primary → Fallback to Secondary
try {
    return await getFromElasticsearch();  // Primary
} catch (error) {
    return await getFromJSONFiles();       // Fallback
}
```

---

### 📁 ไฟล์: `dashboard/src/lib/graph/build-graph-data.ts`

```typescript
// สร้างกราฟความสัมพันธ์จากข้อมูล IOC

export function buildGraphFromEvents(events: ThreatEvent[]): GraphData {
    const nodes: Map<string, GraphNode> = new Map();
    const links: GraphLink[] = [];
    
    for (const event of events) {
        // 1. สร้าง Node สำหรับ IOC
        const iocNode = createIOCNode(event);
        nodes.set(iocNode.id, iocNode);
        
        // 2. ถ้ามี Threat Actor → สร้าง Node และ Link
        for (const actor of event.aiThreatActors) {
            const actorNode = createActorNode(actor);
            nodes.set(actorNode.id, actorNode);
            
            // Link: IOC → attributed_to → Threat Actor
            links.push({
                source: iocNode.id,
                target: actorNode.id,
                type: "attributed_to"
            });
        }
    }
    
    return { nodes: [...nodes.values()], links };
}
```

### 🤔 ทำไมใช้ Force-directed Graph?

**ข้อดี:**
- Nodes จะจัดตัวเองอัตโนมัติ
- เห็นความสัมพันธ์ชัดเจน
- Interactive (zoom, drag, click)

```
     ┌────────────┐
     │  APT-29    │ ← Threat Actor
     └──────┬─────┘
            │ attributed_to
     ┌──────▼─────┐
     │  malware.com│ ← IOC (Domain)
     └──────┬─────┘
            │ resolves_to
     ┌──────▼─────┐
     │ 192.168.1.1│ ← IOC (IP)
     └────────────┘
```

---

## 5. Data Pipeline - การไหลของข้อมูล

### 🔄 Full Pipeline

```
Step 1: Import                Step 2: AI Process            Step 3: Display
──────────────────────────────────────────────────────────────────────────

┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  JSON Files │───▶│  Data Lake  │───▶│ AI Service  │───▶│  Warehouse  │
│  (Raw IOCs) │    │ (Elasticsearch)│   │ (Classify)  │    │ (Enriched)  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                                 │
                                                                 ▼
                                                          ┌─────────────┐
                                                          │  Dashboard  │
                                                          │  (Display)  │
                                                          └─────────────┘
```

---

### Step 1: Import to Data Lake

📁 **ไฟล์:** `ai-service/scripts/import_to_datalake.py`

```python
# 1. อ่านไฟล์ JSON จาก data_lake/
json_files = list(DATA_LAKE_PATH.glob("*.json"))

# 2. แปลง format ให้ตรงกัน (Normalize)
for file in json_files:
    data = json.load(file)
    normalized = normalize_ioc(data)  # ทำให้ field ตรงกัน
    
    # 3. ส่งเข้า Elasticsearch
    elastic_client.index(index="tcti-datalake", body=normalized)
```

### 🤔 ทำไมต้อง Normalize?

**ปัญหา:** ข้อมูลจากแหล่งต่างๆ มี format ไม่เหมือนกัน

```json
// Source A
{ "ip_address": "192.168.1.1", "threat_level": "high" }

// Source B  
{ "ioc_value": "192.168.1.1", "severity": "HIGH" }

// Source C
{ "indicator": "192.168.1.1", "risk": 3 }
```

**วิธีแก้:** Normalize ให้เป็น format เดียวกัน

```json
// Unified Format
{
    "ioc_value": "192.168.1.1",
    "ioc_type": "ip",
    "severity": "high",
    "source_name": "Source A"
}
```

---

### Step 2: AI Processing Pipeline

📁 **ไฟล์:** `ai-service/main.py` → `/pipeline/run`

```python
@app.post("/pipeline/run")
async def run_pipeline(batch_size: int = 50):
    # 1. ดึง IOC ที่ยังไม่ได้ process จาก Data Lake
    unprocessed = elastic_client.get_unprocessed_iocs(limit=batch_size)
    
    for ioc in unprocessed:
        # 2. Classify ด้วย AI
        classification = classify_threat(ioc["description"])
        
        # 3. คำนวณ Risk Score
        score = calculate_risk_score(ioc)
        
        # 4. รวมข้อมูล (Enrich)
        enriched = {
            **ioc,
            "ai_threat_types": classification["threat_types"],
            "ai_risk_score": score["risk_score"],
            "ai_severity": score["severity"],
            "processed_at": datetime.now()
        }
        
        # 5. บันทึกลง Data Warehouse
        elastic_client.save_to_warehouse(enriched)
        
        # 6. Mark ว่า process แล้ว ไม่ต้องทำซ้ำ
        elastic_client.mark_as_processed(ioc["_id"])
```

### 🤔 ทำไมต้อง Mark as Processed?

**เหตุผล:**
- ป้องกันการ process ซ้ำ
- รู้ว่ายังเหลือกี่ตัวที่ยังไม่ได้ทำ
- สามารถ resume ได้ถ้าหยุดกลางคัน

```python
# Query เฉพาะที่ยังไม่ได้ process
query = {"bool": {"must": [{"term": {"ai_processed": False}}]}}
```

---

### Step 3: Dashboard Display

📁 **ไฟล์:** `dashboard/src/app/api/iocs/route.ts`

```typescript
// Dashboard ดึงข้อมูลจาก Warehouse (ที่ enriched แล้ว)

async function loadFromElasticsearch(): Promise<ThreatEvent[]> {
    const response = await fetch(
        `${ELASTICSEARCH_URL}/tcti-warehouse/_search`,
        {
            method: "POST",
            body: JSON.stringify({
                query: { match_all: {} },
                sort: [{ ai_risk_score: "desc" }],  // เรียงจากอันตรายสูงสุด
                size: 1000
            })
        }
    );
    
    const data = await response.json();
    return data.hits.hits.map(hit => transformToThreatEvent(hit._source));
}
```

### 🤔 ทำไมเรียงตาม Risk Score?

**เหตุผล:**
- ผู้ใช้อยากเห็นภัยคุกคามร้ายแรงก่อน
- Critical/High ควรแก้ไขก่อน Low
- ช่วยในการ prioritize งาน

---

## 🎯 สรุปสิ่งที่เรียนรู้

### 1. Design Patterns ที่ใช้

| Pattern | ใช้ที่ไหน | ทำไม |
|---------|----------|------|
| **Separation of Concerns** | Frontend/Backend แยก | Maintainability |
| **ETL Pipeline** | Data Lake → AI → Warehouse | Data quality |
| **Fallback Pattern** | ES → JSON files | Reliability |
| **Caching** | Translation cache | Performance |
| **Singleton** | Elasticsearch client | Resource efficiency |

### 2. Technology Choices

| Choice | Alternative | ทำไมเลือกสิ่งนี้ |
|--------|-------------|-----------------|
| Next.js | React + Express | SSR, API routes ในตัว |
| FastAPI | Flask | Faster, async, auto-docs |
| Elasticsearch | PostgreSQL | Full-text search, JSON native |
| BART-Large | DistilBERT | แม่นยำสูง, เข้าใจบริบทดีกว่า (Zero-shot) |
| OpenAI | Google Translate | Context-aware translation |

### 3. Best Practices

1. **Always have fallback** - ถ้า A ไม่ work ให้มี B
2. **Normalize data early** - แปลง format ตั้งแต่ import
3. **Separate raw from processed** - Data Lake vs Warehouse
4. **Cache expensive operations** - Translation, AI calls
5. **Log everything** - ช่วย debug

---

## 📝 แบบฝึกหัด

ลองตอบคำถามเหล่านี้เพื่อทดสอบความเข้าใจ:

1. ถ้าต้องการเพิ่ม IOC type ใหม่ (เช่น `email`) ต้องแก้ไฟล์ไหนบ้าง?
2. ถ้า Elasticsearch down จะเกิดอะไรขึ้นกับ Dashboard?
3. ทำไม risk_score ถึง cap ที่ 100?
4. ถ้าต้องการเพิ่มภาษาใหม่ในการแปล ต้องทำอย่างไร?
5. Data Lake กับ Data Warehouse ต่างกันอย่างไร?

---

*เอกสารนี้สร้างโดย AI เพื่อช่วยให้คุณเข้าใจโค้ดที่ AI สร้าง*

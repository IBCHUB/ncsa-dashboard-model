# Trend Prediction Documentation

> **Last Updated:** 2026-01-29  
> **Source:** [trend_predictor.py](file:///Users/mm/Desktop/Cyber/ai-service/models/trend_predictor.py)

## ภาพรวม

ระบบ Trend Prediction ใช้ **Linear Regression** คำนวณแนวโน้มภัยคุกคามและพยากรณ์ 7 วันข้างหน้า

---

## วิธีคำนวณ

### 1. รวบรวมข้อมูลรายวัน
```python
daily_counts[date][threat_type] = count
```

### 2. Linear Regression
**สมการ:** `y = mx + b`

| ตัวแปร | ความหมาย |
|--------|----------|
| m (slope) | ความชัน (+ = เพิ่ม, - = ลด) |
| b (intercept) | จุดตัดแกน Y |
| x | ลำดับวัน (0, 1, 2, ...) |
| y | จำนวน IOC |

### 3. คำนวณ % เปลี่ยนแปลง
```python
change_percent = (slope × 7 / average) × 100
```

### 4. R-Squared (Confidence)
```python
r_squared = 1 - (ss_res / ss_tot)
```
- **1.0** = เส้นตรงเหมาะสมสมบูรณ์
- **0.0** = ข้อมูลกระจาย ไม่เหมาะสม

---

## Trend Direction

| Slope | Direction | ความหมาย |
|-------|-----------|----------|
| > 0.5 | ↑ Increasing | แนวโน้มเพิ่มขึ้น |
| < -0.5 | ↓ Decreasing | แนวโน้มลดลง |
| -0.5 to 0.5 | → Stable | คงที่ |

---

## Output Format

### predictions.json
```json
{
  "meta": {
    "generated": "2026-01-29T01:00:00Z",
    "date_range": { "start": "2025-11-13", "end": "2026-01-23" }
  },
  "predictions": [
    {
      "threat_type": "APT",
      "direction": "increasing",
      "change_percent": 562.4,
      "confidence": 0.424,
      "prediction_text": "APT มีแนวโน้มเพิ่มขึ้น +562% ในสัปดาห์หน้า"
    }
  ],
  "forecast_chart": {
    "labels": ["2025-11-13", "2025-11-14", ...],
    "datasets": { "APT": { "historical": [...], "forecast": [...] } }
  }
}
```

---

## ข้อจำกัด

1. **ต้องมีข้อมูลอย่างน้อย 2 วัน** - ไม่สามารถคำนวณได้ถ้ามีแค่ 1 วัน
2. **Outlier Effect** - ถ้ามีวันที่พุ่งสูงมาก จะส่งผลต่อ % อย่างมาก
3. **Linear Assumption** - สมมติว่าแนวโน้มเป็นเส้นตรง ซึ่งอาจไม่เป็นจริงเสมอ

---

## Dashboard Widgets

### TrendPrediction Widget
แสดง Top 4 ภัยคุกคามที่มีแนวโน้มเพิ่มขึ้น

### TrendChart
กราฟเส้นแสดง:
- **เส้นทึบ** = ข้อมูลจริง (Historical)
- **เส้นประ** = พยากรณ์ (Forecast)

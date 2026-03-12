# Legacy Quarantine

ไฟล์ในโฟลเดอร์นี้ไม่อยู่ใน active runtime path ของ `ai-service` แล้ว

- เก็บไว้เพื่ออ้างอิงย้อนหลัง, manual verification, หรือเทียบพฤติกรรมรุ่นเก่า
- ห้าม import จาก runtime modules (`main.py`, `elastic_client.py`, `models/`, `services/`, `utils/`) โดยไม่มีเหตุผลชัดเจน
- ถ้าจะนำไฟล์ใดกลับมาใช้จริง ให้ย้ายกลับออกจาก `legacy/` พร้อมเพิ่ม tests และอัปเดต README ที่เกี่ยวข้อง

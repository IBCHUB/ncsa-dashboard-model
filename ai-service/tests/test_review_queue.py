import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.review_queue import (  # noqa: E402
    approve_review_document,
    build_review_queue_response,
    reject_review_document,
)


class FakeElasticClient:
    def __init__(self):
        self.documents = {
            "wh-review-1": {
                "ioc_value": "suspicious.example",
                "ioc_type": "domain",
                "validation_status": "needs_review",
                "review_state": "pending",
                "warehouse_eligible": False,
                "review_required": True,
                "validation_reasons": ["missing_trusted_source_corroboration"],
                "ai_risk_score": 55,
                "ai_severity": "high",
                "ai_classification_confidence": 0.87,
                "source_name": "News Feed",
                "processed_at": "2026-03-11T01:00:00Z",
                "reviewed_by": None,
                "reviewed_at": None,
                "review_notes": None,
            }
        }
        self.updated_docs = []

    def get_warehouse_document(self, doc_id):
        document = self.documents.get(doc_id)
        if not document:
            return None
        return {"_id": doc_id, **document}

    def update_warehouse_document(self, doc_id, fields):
        self.updated_docs.append((doc_id, fields))
        if doc_id not in self.documents:
            return False
        self.documents[doc_id].update(fields)
        return True


def test_build_review_queue_response_shapes_items():
    payload = build_review_queue_response(
        {
            "total": 1,
            "data": [
                {
                    "_id": "wh-review-1",
                    "ioc_value": "suspicious.example",
                    "ioc_type": "domain",
                    "validation_status": "needs_review",
                    "review_state": "pending",
                    "warehouse_eligible": False,
                    "review_required": True,
                    "validation_reasons": ["missing_trusted_source_corroboration"],
                    "ai_risk_score": 55,
                    "ai_severity": "high",
                    "ai_classification_confidence": 0.87,
                    "source_name": "News Feed",
                }
            ],
        }
    )

    assert payload["total"] == 1
    assert payload["items"][0]["doc_id"] == "wh-review-1"
    assert payload["items"][0]["review_state"] == "pending"
    assert payload["items"][0]["validation_reasons"] == ["missing_trusted_source_corroboration"]


def test_approve_review_document_promotes_document_to_warehouse():
    fake_client = FakeElasticClient()

    response = approve_review_document(fake_client, "wh-review-1", "mint", "Confirmed by analyst")

    assert response["success"] is True
    assert response["validation_status"] == "validated_manual"
    assert response["warehouse_saved"] is True
    assert fake_client.documents["wh-review-1"]["validation_status"] == "validated_manual"
    assert fake_client.documents["wh-review-1"]["review_state"] == "approved"
    assert fake_client.updated_docs[0][1]["reviewed_by"] == "mint"


def test_reject_review_document_updates_processed_state_only():
    fake_client = FakeElasticClient()

    response = reject_review_document(fake_client, "wh-review-1", "mint", "Insufficient evidence")

    assert response["success"] is True
    assert response["validation_status"] == "rejected_manual"
    assert response["warehouse_saved"] is False
    assert fake_client.updated_docs[0][1]["review_state"] == "rejected"

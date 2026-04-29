import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import elastic_client  # noqa: E402
from elastic_client import ElasticClient  # noqa: E402


def _client_without_init():
    client = ElasticClient.__new__(ElasticClient)
    client.datalake_index = "tcti-feeds"
    client.warehouse_index = "cyber-logs-datawarehouse"
    return client


def test_processed_state_id_uses_source_index_and_doc_id():
    first = ElasticClient._build_processed_state_id({
        "_index": "tcti-feeds",
        "_id": "abc-123",
        "ioc_type": "ip",
        "ioc_value": "1.2.3.4",
    })
    second = ElasticClient._build_processed_state_id({
        "_index": "tcti-feeds",
        "_id": "abc-123",
        "ioc_type": "ip",
        "ioc_value": "9.9.9.9",
    })
    other_index = ElasticClient._build_processed_state_id({
        "_index": "other-feed",
        "_id": "abc-123",
        "ioc_type": "ip",
        "ioc_value": "1.2.3.4",
    })

    assert first == second
    assert first != other_index
    assert first.startswith("src:")


def test_readonly_feed_filters_docs_already_marked_processed(monkeypatch):
    client = _client_without_init()
    monkeypatch.setattr(elastic_client, "DATALAKE_SCAN_BATCH_SIZE", 2)
    monkeypatch.setattr(elastic_client, "DATALAKE_SCAN_MAX_PAGES", 2)

    pages = [
        {
            "hits": {
                "hits": [
                    {"_index": "tcti-feeds", "_id": "done", "_source": {"ioc": {"type": "domain", "value": "done.example"}}},
                    {"_index": "tcti-feeds", "_id": "new", "_source": {"ioc": {"type": "domain", "value": "new.example"}}},
                ]
            }
        }
    ]

    def fake_search(index, body):
        assert index == "tcti-feeds"
        return pages.pop(0) if pages else {"hits": {"hits": []}}

    monkeypatch.setattr(client, "_search_index", fake_search)
    monkeypatch.setattr(client, "is_source_processed", lambda doc: doc["_id"] == "done")

    result = client._get_unprocessed_iocs_from_readonly_feed(limit=1)

    assert [doc["_id"] for doc in result] == ["new"]


def test_processed_status_only_skips_finished_docs(monkeypatch):
    client = _client_without_init()

    monkeypatch.setattr(client, "_get_processed_state", lambda doc: {"status": "processed"})
    assert client.is_source_processed({"_id": "done"})

    monkeypatch.setattr(client, "_get_processed_state", lambda doc: {"status": "rejected"})
    assert client.is_source_processed({"_id": "rejected"})

    monkeypatch.setattr(client, "_get_processed_state", lambda doc: {"status": "failed"})
    assert not client.is_source_processed({"_id": "failed"})

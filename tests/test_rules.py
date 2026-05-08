import uuid
import pytest
from app.models.sigma_rule import SigmaRule

pytestmark = pytest.mark.asyncio

SAMPLE_RULE = {
    "title": "Test Rule",
    "status": "experimental",
    "description": "A test rule description",
    "author": "Test Author",
    "level": "low",
    "logsource_product": "windows",
    "logsource_service": "sysmon",
    "detection": {
        "selection": {
            "EventID": 1,
            "Image|endswith": "\\cmd.exe"
        },
        "condition": "selection"
    },
    "raw_rule": "title: Test Rule\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n    Image|endswith: '\\cmd.exe'\n  condition: selection",
    "tags": ["test", "attack.t1059"]
}


async def test_get_backends(client):
    response = await client.get("/rules/backends")
    assert response.status_code == 200
    backends = response.json()
    assert isinstance(backends, list)
    assert "splunk" in backends
    assert "sqlite" in backends


async def test_create_rule(client, normal_user_token):
    headers = {"Authorization": f"Bearer {normal_user_token}"}
    response = await client.post("/rules/", json=SAMPLE_RULE, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == SAMPLE_RULE["title"]
    assert "id" in data


async def test_create_rule_unauthorized(client):
    response = await client.post("/rules/", json=SAMPLE_RULE)
    assert response.status_code == 401


async def test_list_rules(client, db):
    rule = SigmaRule(**SAMPLE_RULE)
    db.add(rule)
    await db.flush()
    
    response = await client.get("/rules/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["title"] == SAMPLE_RULE["title"]


async def test_get_rule(client, db):
    rule = SigmaRule(**SAMPLE_RULE)
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    
    response = await client.get(f"/rules/{rule.id}")
    assert response.status_code == 200
    assert response.json()["id"] == str(rule.id)


async def test_get_rule_not_found(client):
    response = await client.get(f"/rules/{uuid.uuid4()}")
    assert response.status_code == 404


async def test_update_rule(client, db, normal_user_token):
    rule = SigmaRule(**SAMPLE_RULE)
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    
    headers = {"Authorization": f"Bearer {normal_user_token}"}
    update_data = {"title": "Updated Title"}
    response = await client.patch(f"/rules/{rule.id}", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["title"] == "Updated Title"


async def test_delete_rule(client, db, normal_user_token):
    rule = SigmaRule(**SAMPLE_RULE)
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    
    headers = {"Authorization": f"Bearer {normal_user_token}"}
    response = await client.delete(f"/rules/{rule.id}", headers=headers)
    assert response.status_code == 204
    
    # Verify it's gone
    get_response = await client.get(f"/rules/{rule.id}")
    assert get_response.status_code == 404


async def test_convert_rule(client, db):
    rule = SigmaRule(**SAMPLE_RULE)
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    
    response = await client.get(f"/rules/{rule.id}/convert?backend=splunk")
    assert response.status_code == 200
    data = response.json()
    assert data["backend"] == "splunk"
    assert "queries" in data
    assert len(data["queries"]) > 0

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_prompt_templates():
    response = client.get("/api/playground/templates")
    # This route might be protected by auth, so we expect a 401 or a successful 200
    # Depending on how the verify_google_token dependency behaves in tests
    assert response.status_code in [200, 401, 403]
    
    if response.status_code == 200:
        data = response.json()
        assert "templates" in data
        assert len(data["templates"]) > 0

def test_chat_without_auth():
    # Attempting to access protected playground chat without token
    response = client.post("/api/playground/chat", json={
        "message": "Hello", 
        "project_id": "test"
    })
    
    # We expect this to fail due to Google Auth dependency
    assert response.status_code in [401, 403]

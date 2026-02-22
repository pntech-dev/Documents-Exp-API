import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Group, Category, Document, User, Tag
from utils import hash_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _create_user_and_login(client: AsyncClient, db_session: AsyncSession, email: str) -> dict:
    """Creates a user, logs them in, and returns the Authorization header."""
    hashed = hash_password("password")
    user = User(email=email, password_hash=hashed, is_active=True)
    db_session.add(user)
    await db_session.commit()
    
    response = await client.post("/auth/login", json={"email": email, "password": "password"})
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def _create_structure(db_session: AsyncSession, group_name="G1", cat_name="C1"):
    """Creates a Group and a Category for testing."""
    g = Group(name=group_name)
    db_session.add(g)
    await db_session.commit()
    c = Category(name=cat_name, group_id=g.id)
    db_session.add(c)
    await db_session.commit()
    return g, c


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_document(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "doc_creator@test.com")
    group, category = await _create_structure(db_session)

    data = {
        "category_id": category.id,
        "code": "DOC-001",
        "name": "Test Document",
        "tags": ["important", "2023"],
        "pages": [
            {"order_index": 1, "designation": "P1", "name": "Page 1"}
        ]
    }

    response = await client.post("/app/documents", json=data, headers=headers)
    assert response.status_code == 200
    json_data = response.json()
    
    assert json_data["code"] == "DOC-001"
    assert json_data["name"] == "Test Document"
    assert len(json_data["tags"]) == 2
    
    # Verify DB
    stmt = select(Document).where(Document.code == "DOC-001")
    result = await db_session.execute(stmt)
    doc = result.scalar_one_or_none()
    assert doc is not None
    assert doc.category_id == category.id


@pytest.mark.asyncio
async def test_create_document_duplicate(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "doc_dupe@test.com")
    group, category = await _create_structure(db_session)

    # Create first
    doc = Document(name="Doc", code="001", category_id=category.id)
    db_session.add(doc)
    await db_session.commit()

    data = {
        "category_id": category.id,
        "code": "001",
        "name": "Doc"
    }
    
    response = await client.post("/app/documents", json=data, headers=headers)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_get_documents_filter(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "viewer@test.com")
    
    g1, c1 = await _create_structure(db_session, "G1", "C1")
    g2, c2 = await _create_structure(db_session, "G2", "C2")

    d1 = Document(name="D1", code="1", category_id=c1.id)
    d2 = Document(name="D2", code="2", category_id=c2.id)
    db_session.add_all([d1, d2])
    await db_session.commit()

    # Filter by Group 1
    response = await client.get(f"/app/documents?group_id={g1.id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["documents"]) == 1
    assert data["documents"][0]["code"] == "1"

    # Filter by Category 2
    response = await client.get(f"/app/documents?category_id={c2.id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["documents"]) == 1
    assert data["documents"][0]["code"] == "2"


@pytest.mark.asyncio
async def test_get_document(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "getter@test.com")
    g, c = await _create_structure(db_session)
    
    doc = Document(name="Single", code="S1", category_id=c.id)
    db_session.add(doc)
    await db_session.commit()

    response = await client.get(f"/app/documents/{doc.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["name"] == "Single"


@pytest.mark.asyncio
async def test_update_document(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "updater@test.com")
    g, c = await _create_structure(db_session)
    
    doc = Document(name="Old", code="OLD", category_id=c.id)
    db_session.add(doc)
    await db_session.commit()

    update_data = {
        "name": "New",
        "code": "NEW",
        "tags": ["updated"]
    }

    response = await client.patch(f"/app/documents/{doc.id}", json=update_data, headers=headers)
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["name"] == "New"
    assert json_data["code"] == "NEW"
    assert len(json_data["tags"]) == 1
    assert json_data["tags"][0]["name"] == "updated"


@pytest.mark.asyncio
async def test_delete_document(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "deleter@test.com")
    g, c = await _create_structure(db_session)
    
    doc = Document(name="Del", code="DEL", category_id=c.id)
    db_session.add(doc)
    await db_session.commit()

    response = await client.delete(f"/app/documents/{doc.id}", headers=headers)
    assert response.status_code == 200

    stmt = select(Document).where(Document.id == doc.id)
    result = await db_session.execute(stmt)
    assert result.scalar_one_or_none() is None
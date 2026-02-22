import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from models import Group, Category, Document, Tag, User
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


async def _create_structure(db_session: AsyncSession):
    """Creates a Group and a Category for testing."""
    g = Group(name="Tag Group")
    db_session.add(g)
    await db_session.commit()
    c = Category(name="Tag Cat", group_id=g.id)
    db_session.add(c)
    await db_session.commit()
    return c


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tags_creation_and_reuse(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "tag_reuse@test.com")
    category = await _create_structure(db_session)

    # 1. Create first document with tags ["Python", "FastAPI"]
    data1 = {
        "category_id": category.id,
        "code": "DOC-1",
        "name": "Doc 1",
        "tags": ["Python", "FastAPI"]
    }
    res1 = await client.post("/app/documents", json=data1, headers=headers)
    assert res1.status_code == 200

    # 2. Create second document with tags ["FastAPI", "Docker"]
    data2 = {
        "category_id": category.id,
        "code": "DOC-2",
        "name": "Doc 2",
        "tags": ["FastAPI", "Docker"]
    }
    res2 = await client.post("/app/documents", json=data2, headers=headers)
    assert res2.status_code == 200

    # 3. Verify Tags in DB
    # Should be 3 tags total: Python, FastAPI, Docker (FastAPI is reused)
    result = await db_session.execute(select(func.count(Tag.id)))
    count = result.scalar()
    assert count == 3

    # Verify "FastAPI" tag exists
    stmt = select(Tag).where(Tag.name == "FastAPI")
    result = await db_session.execute(stmt)
    tag = result.scalar_one_or_none()
    assert tag is not None


@pytest.mark.asyncio
async def test_update_tags(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "tag_update@test.com")
    category = await _create_structure(db_session)

    # Create doc
    data = {
        "category_id": category.id,
        "code": "DOC-UP",
        "name": "Update Doc",
        "tags": ["OldTag", "KeepTag"]
    }
    res = await client.post("/app/documents", json=data, headers=headers)
    doc_id = res.json()["id"]

    # Update doc: remove "OldTag", add "NewTag", keep "KeepTag"
    update_data = {
        "tags": ["KeepTag", "NewTag"]
    }
    res = await client.patch(f"/app/documents/{doc_id}", json=update_data, headers=headers)
    assert res.status_code == 200
    
    tags = [t["name"] for t in res.json()["tags"]]
    assert len(tags) == 2
    assert "KeepTag" in tags
    assert "NewTag" in tags
    assert "OldTag" not in tags


@pytest.mark.asyncio
async def test_search_by_tags(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "tag_search@test.com")
    category = await _create_structure(db_session)

    # Create docs
    # D1: [TagA, TagB]
    # D2: [TagB, TagC]
    # D3: [TagA, TagC]
    
    await client.post("/app/documents", json={"category_id": category.id, "code": "D1", "name": "D1", "tags": ["TagA", "TagB"]}, headers=headers)
    await client.post("/app/documents", json={"category_id": category.id, "code": "D2", "name": "D2", "tags": ["TagB", "TagC"]}, headers=headers)
    await client.post("/app/documents", json={"category_id": category.id, "code": "D3", "name": "D3", "tags": ["TagA", "TagC"]}, headers=headers)

    # Search for TagA (should get D1, D3)
    res = await client.get(f"/app/search?query=&tags=TagA&group_id={category.group_id}", headers=headers)
    assert res.status_code == 200
    results = res.json()["result"]
    codes = sorted([r["code"] for r in results])
    assert codes == ["D1", "D3"]

    # Search for TagB (should get D1, D2)
    res = await client.get(f"/app/search?query=&tags=TagB&group_id={category.group_id}", headers=headers)
    results = res.json()["result"]
    codes = sorted([r["code"] for r in results])
    assert codes == ["D1", "D2"]

    # Search for TagA AND TagB (should get D1)
    res = await client.get(f"/app/search?query=&tags=TagA&tags=TagB&group_id={category.group_id}", headers=headers)
    results = res.json()["result"]
    assert len(results) == 1
    assert results[0]["code"] == "D1"
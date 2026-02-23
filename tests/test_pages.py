import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from models import Group, Category, Document, Page, User
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


async def _create_doc_with_pages(db_session: AsyncSession, doc_code="D1"):
    """Creates a Group, Category, Document and 2 Pages."""
    g = Group(name=f"G_{doc_code}")
    db_session.add(g)
    await db_session.commit()
    
    c = Category(name=f"C_{doc_code}", group_id=g.id)
    db_session.add(c)
    await db_session.commit()
    
    d = Document(name=f"Doc {doc_code}", code=doc_code, category_id=c.id)
    db_session.add(d)
    await db_session.commit()
    
    p1 = Page(document_id=d.id, order_index=1, designation=f"{doc_code}-01", name="Page 1")
    p2 = Page(document_id=d.id, order_index=2, designation=f"{doc_code}-02", name="Page 2")
    db_session.add_all([p1, p2])
    await db_session.commit()
    
    return d, [p1, p2]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_pages_list(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "pages_list@test.com")
    await _create_doc_with_pages(db_session, "LIST")
    
    response = await client.get("/app/pages", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["pages"]) == 2


@pytest.mark.asyncio
async def test_get_page_by_id(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "page_get@test.com")
    doc, pages = await _create_doc_with_pages(db_session, "GET")
    target_page = pages[0]
    
    response = await client.get(f"/app/pages/{target_page.id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Page 1"
    assert data["designation"] == "GET-01"
    assert data["document_id"] == doc.id


@pytest.mark.asyncio
async def test_get_document_pages(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "doc_pages@test.com")
    doc, pages = await _create_doc_with_pages(db_session, "DOCP")
    
    response = await client.get(f"/app/documents/{doc.id}/pages", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["pages"]) == 2
    # Verify order
    assert data["pages"][0]["order_index"] == 1
    assert data["pages"][1]["order_index"] == 2


@pytest.mark.asyncio
async def test_page_not_found(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "404@test.com")
    response = await client.get("/app/pages/99999", headers=headers)
    assert response.status_code == 404
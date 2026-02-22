import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Group, Category, User
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_category(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "cat_creator@test.com")
    
    # Create Group first
    group = Group(name="Cat Group")
    db_session.add(group)
    await db_session.commit()
    
    data = {
        "group_id": group.id,
        "name": "New Category",
        "show_for_guest": True
    }
    
    response = await client.post("/app/categories", json=data, headers=headers)
    assert response.status_code == 200
    
    json_data = response.json()
    assert json_data["name"] == "New Category"
    assert json_data["group_id"] == group.id
    
    # Verify DB
    stmt = select(Category).where(Category.name == "New Category")
    result = await db_session.execute(stmt)
    category = result.scalar_one_or_none()
    assert category is not None
    assert category.group_id == group.id


@pytest.mark.asyncio
async def test_create_category_duplicate(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "cat_dupe@test.com")
    
    group = Group(name="Dupe Group")
    db_session.add(group)
    await db_session.commit()
    
    # Create first category
    cat = Category(name="Unique Cat", group_id=group.id)
    db_session.add(cat)
    await db_session.commit()
    
    # Try to create duplicate in same group
    data = {
        "group_id": group.id,
        "name": "Unique Cat",
        "show_for_guest": False
    }
    
    response = await client.post("/app/categories", json=data, headers=headers)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_get_categories_guest_vs_user(client: AsyncClient, db_session: AsyncSession):
    group = Group(name="Visibility Group")
    db_session.add(group)
    await db_session.commit()
    
    c1 = Category(name="Public Cat", group_id=group.id, show_for_guest=True)
    c2 = Category(name="Private Cat", group_id=group.id, show_for_guest=False)
    db_session.add_all([c1, c2])
    await db_session.commit()
    
    # 1. Guest request
    response = await client.get("/app/categories")
    assert response.status_code == 200
    data = response.json()
    assert len(data["categories"]) == 1
    assert data["categories"][0]["name"] == "Public Cat"
    
    # 2. User request
    headers = await _create_user_and_login(client, db_session, "viewer@test.com")
    response = await client.get("/app/categories", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["categories"]) == 2


@pytest.mark.asyncio
async def test_update_category(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "updater@test.com")
    
    group = Group(name="Update Group")
    db_session.add(group)
    await db_session.commit()
    
    cat = Category(name="Old Cat", group_id=group.id, show_for_guest=False)
    db_session.add(cat)
    await db_session.commit()
    
    update_data = {
        "name": "Updated Cat",
        "show_for_guest": True
    }
    
    response = await client.patch(f"/app/categories/{cat.id}", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["name"] == "Updated Cat"
    
    await db_session.refresh(cat)
    assert cat.name == "Updated Cat"
    assert cat.show_for_guest is True


@pytest.mark.asyncio
async def test_delete_category(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "deleter_cat@test.com")
    
    group = Group(name="Delete Group")
    db_session.add(group)
    await db_session.commit()
    
    cat = Category(name="To Delete", group_id=group.id)
    db_session.add(cat)
    await db_session.commit()
    
    response = await client.delete(f"/app/categories/{cat.id}", headers=headers)
    assert response.status_code == 200
    
    stmt = select(Category).where(Category.id == cat.id)
    result = await db_session.execute(stmt)
    assert result.scalar_one_or_none() is None
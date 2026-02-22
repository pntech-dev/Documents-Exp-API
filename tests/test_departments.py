import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Group, User
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
async def test_create_group(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "admin@test.com")
    
    data = {
        "name": "New Department",
        "show_for_guest": True,
        "has_all_docs_search": False
    }
    
    response = await client.post("/app/groups", json=data, headers=headers)
    assert response.status_code == 200
    
    json_data = response.json()
    assert json_data["name"] == data["name"]
    assert json_data["id"] is not None
    
    # Verify DB
    stmt = select(Group).where(Group.name == "New Department")
    result = await db_session.execute(stmt)
    group = result.scalar_one_or_none()
    assert group is not None


@pytest.mark.asyncio
async def test_create_group_duplicate_name(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "admin2@test.com")
    
    # Pre-create group
    group = Group(name="Existing Dept")
    db_session.add(group)
    await db_session.commit()
    
    data = {"name": "Existing Dept", "show_for_guest": False, "has_all_docs_search": False}
    
    response = await client.post("/app/groups", json=data, headers=headers)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_get_groups_guest_vs_user(client: AsyncClient, db_session: AsyncSession):
    # Create groups
    g1 = Group(name="Public Dept", show_for_guest=True)
    g2 = Group(name="Private Dept", show_for_guest=False)
    db_session.add_all([g1, g2])
    await db_session.commit()
    
    # 1. Guest request (no headers)
    response = await client.get("/app/groups")
    assert response.status_code == 200
    data = response.json()
    # Guest should only see public departments
    assert len(data["departments"]) == 1
    assert data["departments"][0]["name"] == "Public Dept"
    
    # 2. User request
    headers = await _create_user_and_login(client, db_session, "user@test.com")
    response = await client.get("/app/groups", headers=headers)
    assert response.status_code == 200
    data = response.json()
    # Authenticated user should see all departments
    assert len(data["departments"]) == 2


@pytest.mark.asyncio
async def test_update_group(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "editor@test.com")
    
    group = Group(name="Old Name", show_for_guest=False, has_all_docs_search=False)
    db_session.add(group)
    await db_session.commit()
    
    update_data = {
        "name": "Updated Name",
        "show_for_guest": True,
        "has_all_docs_search": True
    }
    
    response = await client.patch(f"/app/groups/{group.id}", json=update_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["name"] == "Updated Name"
    
    await db_session.refresh(group)
    assert group.name == "Updated Name"
    assert group.show_for_guest is True


@pytest.mark.asyncio
async def test_delete_group(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "deleter@test.com")
    
    group = Group(name="To Delete")
    db_session.add(group)
    await db_session.commit()
    
    response = await client.delete(f"/app/groups/{group.id}", headers=headers)
    assert response.status_code == 200
    
    # Verify deletion
    stmt = select(Group).where(Group.id == group.id)
    result = await db_session.execute(stmt)
    assert result.scalar_one_or_none() is None
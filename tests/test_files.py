import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Group, Category, Document, DocumentFile, User
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


async def _create_doc(db_session: AsyncSession):
    """Creates a Group, Category, and Document for testing files."""
    g = Group(name="File Group")
    db_session.add(g)
    await db_session.commit()
    
    c = Category(name="File Cat", group_id=g.id)
    db_session.add(c)
    await db_session.commit()
    
    d = Document(name="File Doc", code="FD-1", category_id=c.id)
    db_session.add(d)
    await db_session.commit()
    return d


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_upload_file(client: AsyncClient, db_session: AsyncSession, mock_s3):
    headers = await _create_user_and_login(client, db_session, "uploader@test.com")
    doc = await _create_doc(db_session)
    
    files = {'file': ('test.txt', b'Hello World', 'text/plain')}
    
    response = await client.post(f"/app/documents/{doc.id}/files", files=files, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test.txt"
    assert data["document_id"] == doc.id
    
    # Verify DB
    stmt = select(DocumentFile).where(DocumentFile.id == data["id"])
    result = await db_session.execute(stmt)
    file_record = result.scalar_one_or_none()
    assert file_record is not None
    assert file_record.size == 11 # len("Hello World")
    
    # Verify S3 mock called
    assert mock_s3.upload_file.called


@pytest.mark.asyncio
async def test_upload_blocked_extension(client: AsyncClient, db_session: AsyncSession):
    headers = await _create_user_and_login(client, db_session, "hacker@test.com")
    doc = await _create_doc(db_session)
    
    files = {'file': ('malware.exe', b'MZ...', 'application/x-msdownload')}
    
    response = await client.post(f"/app/documents/{doc.id}/files", files=files, headers=headers)
    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"]


@pytest.mark.asyncio
async def test_download_file(client: AsyncClient, db_session: AsyncSession, mock_s3):
    headers = await _create_user_and_login(client, db_session, "downloader@test.com")
    doc = await _create_doc(db_session)
    
    # Manually create file record
    f = DocumentFile(
        document_id=doc.id,
        file_path="path/to/file.txt",
        filename="download.txt",
        content_type="text/plain",
        size=123
    )
    db_session.add(f)
    await db_session.commit()
    
    response = await client.get(f"/app/files/{f.id}/download", headers=headers)
    assert response.status_code == 200
    assert response.content == b"fake_content"
    assert "attachment; filename*=utf-8''download.txt" in response.headers["content-disposition"]


@pytest.mark.asyncio
async def test_delete_file(client: AsyncClient, db_session: AsyncSession, mock_s3):
    headers = await _create_user_and_login(client, db_session, "deleter@test.com")
    doc = await _create_doc(db_session)
    
    f = DocumentFile(
        document_id=doc.id,
        file_path="path/to/del.txt",
        filename="del.txt",
        content_type="text/plain",
        size=10
    )
    db_session.add(f)
    await db_session.commit()
    
    response = await client.delete(f"/app/files/{f.id}", headers=headers)
    assert response.status_code == 200
    
    # Verify DB
    stmt = select(DocumentFile).where(DocumentFile.id == f.id)
    result = await db_session.execute(stmt)
    assert result.scalar_one_or_none() is None
    
    # Verify S3 mock called
    mock_s3.delete_file.assert_called_with("path/to/del.txt")
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from models import Group, Category, Document, Page


class AppRepository:
    def __init__(self, session: AsyncSession):
        self.session = session


    # ====================
    # Departments
    # ====================

    async def get_groups(self) -> list[Group]:
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        )
        departments = await self.session.execute(query)
        return departments.scalars().all()


    # ====================
    # Categories
    # ====================

    async def get_categories(self) -> list[Category]:
        query = select(Category).options(selectinload(Category.documents))
        categories = await self.session.execute(query)
        return categories.scalars().all()
    

    async def get_category(self, id: int) -> Category | None:
        query = select(Category).options(selectinload(Category.documents)).where(Category.id == id)
        category = await self.session.execute(query)
        return category.scalar_one_or_none()
    

    async def get_group_categories(self, group_id: int) -> list[Category]:
        query = select(Category).options(selectinload(Category.documents)).where(
            Category.group_id == group_id
        )
        categories = await self.session.execute(query)
        return categories.scalars().all()


    # ====================
    # Documents
    # ====================

    async def get_document(self, id: int) -> Document | None:
        query = select(Document).where(Document.id == id)
        document = await self.session.execute(query)
        return document.scalar_one_or_none()


    async def get_documents(self) -> list[Document]:
        query = select(Document)
        documents = await self.session.execute(query)
        return documents.scalars().all()
    

    async def save_document(self, document: Document) -> Document:
        self.session.add(document)
        await self.session.commit()
        await self.session.refresh(document)
        return document
    

    # ====================
    # Pages
    # ====================

    async def get_pages(self) -> list[Page]:
        query = select(Page)
        pages = await self.session.execute(query)
        return pages.scalars().all()
    

    async def get_page(self, id: int) -> Page | None:
        query = select(Page).where(Page.id == id)
        page = await self.session.execute(query)
        return page.scalar_one_or_none()
    

    async def get_document_pages(self, document_id: int) -> list[Page]:
        query = select(Page).where(Page.document_id == document_id)
        pages = await self.session.execute(query)
        return pages.scalars().all()

    async def save_page(self, page: Page) -> Page:
        self.session.add(page)
        await self.session.commit()
        await self.session.refresh(page)
        return page

    async def delete_page(self, page: Page) -> None:
        await self.session.delete(page)
        await self.session.commit()
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
    

    async def get_group_by_id(self, id: int) -> Group | None:
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        ).where(Group.id == id)
        group = await self.session.execute(query)
        return group.scalar_one_or_none()
    

    async def get_group_by_name(self, name: str) -> Group | None:
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        ).where(Group.name == name)
        group = await self.session.execute(query)
        return group.scalar_one_or_none()
    

    async def save_group(self, group: Group) -> Group:
        self.session.add(group)
        await self.session.commit()
        await self.session.refresh(group)
        return group


    async def create_group(self, group_data: dict) -> Group:
        group = Group(**group_data)
        self.session.add(group)
        await self.session.commit()
        
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        ).where(Group.id == group.id)
        result = await self.session.execute(query)
        return result.scalar_one()
    

    async def delete_group(self, group: Group) -> None:
        await self.session.delete(group)
        await self.session.commit()


    # ====================
    # Categories
    # ====================

    async def get_categories(self) -> list[Category]:
        query = select(Category).options(selectinload(Category.documents))
        categories = await self.session.execute(query)
        return categories.scalars().all()
    

    async def get_category(self, id: int) -> Category | None:
        query = select(Category).options(
            selectinload(Category.documents)
        ).where(Category.id == id)
        category = await self.session.execute(query)
        return category.scalar_one_or_none()
    

    async def get_category_by_name(self, name: str) -> Category | None:
        query = select(Category).options(
            selectinload(Category.documents)
        ).where(Category.name == name)
        category = await self.session.execute(query)
        return category.scalar_one_or_none()
    

    async def get_group_categories(self, group_id: int) -> list[Category]:
        query = select(Category).options(
            selectinload(Category.documents)
        ).where(Category.group_id == group_id)
        categories = await self.session.execute(query)
        return categories.scalars().all()
    

    async def get_category_documents(self, category_id: int) -> list[Document]:
        query = select(Document).where(Document.category_id == category_id)
        documents = await self.session.execute(query)
        return documents.scalars().all()
    

    async def create_category(self, category_data: dict) -> Category:
        category = Category(**category_data)
        self.session.add(category)
        await self.session.commit()
        
        query = select(Category).options(
            selectinload(Category.documents)
        ).where(Category.id == category.id)
        result = await self.session.execute(query)
        return result.scalar_one()
    

    async def save_category(self, category: Category) -> Category:
        self.session.add(category)
        await self.session.commit()
        await self.session.refresh(category)
        return category


    async def delete_category(self, category: Category) -> None:
        await self.session.delete(category)
        await self.session.commit()


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
    

    async def delete_document(self, document: Document) -> None:
        await self.session.delete(document)
        await self.session.commit()
    

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
from sqlalchemy import select, delete, or_
from sqlalchemy.orm import selectinload, with_loader_criteria
from sqlalchemy.ext.asyncio import AsyncSession

from models import Group, Category, Document, Page, Tag


class AppRepository:
    """
    Repository layer for database operations.

    Provides methods to interact with Groups, Categories, Documents,
    and Pages in the database.
    """
    def __init__(self, session: AsyncSession):
        self.session = session


    # ====================
    # Search
    # ====================

    async def search_documents(
            self, 
            query: str,
            category_id: int | None = None,
            group_id: int | None = None,
            tags: list[str] | None = None,
            exact_match: bool = False,
            search_fields: list[str] | None = None,
            show_for_guest: bool = False
    ) -> list[Document]:
        """
        Searches for documents in a category or group matching the query.

        Args:
            query (str): The search string (space-separated words).
            category_id (int | None): The category ID to search in.
            group_id (int | None): The group ID to search in.
            tags (list[str] | None): List of tags to filter by (AND logic).
            exact_match (bool): If True, match the whole query string.
            search_fields (list[str] | None): Fields to search in ('name', 'code').

        Returns:
            list[Document]: A list of matching documents.
        """
        stmt = select(Document).options(
            selectinload(Document.tags)
        )

        joined_category = False

        if category_id:
            stmt = stmt.where(Document.category_id == category_id)
        elif group_id:
            stmt = stmt.join(Category, Document.category_id == Category.id).where(Category.group_id == group_id)
            joined_category = True

        if show_for_guest:
            if not joined_category:
                stmt = stmt.join(Category, Document.category_id == Category.id)
                joined_category = True
            stmt = stmt.where(Category.show_for_guest == True)

        if tags:
            for tag in tags:
                stmt = stmt.where(Document.tags.any(Tag.name.ilike(tag)))

        # Determine search columns
        fields_map = {"name": Document.name, "code": Document.code}
        target_columns = []
        if search_fields:
            target_columns = [fields_map[f] for f in search_fields if f in fields_map]
        
        if not target_columns:
            target_columns = [Document.name, Document.code]

        if exact_match:
            # Exact match (whole string, case-insensitive)
            conditions = [col.ilike(query) for col in target_columns]
            if conditions:
                stmt = stmt.where(or_(*conditions))
        else:
            # Word-based partial match
            words = query.split()
            for word in words:
                pattern = f"%{word}%"
                conditions = [col.ilike(pattern) for col in target_columns]
                if conditions:
                    stmt = stmt.where(or_(*conditions))

        stmt = stmt.distinct()
        result = await self.session.execute(stmt)
        return result.scalars().all()
    

    async def search_pages(
            self, 
            query: str, 
            category_id: int | None = None, 
            group_id: int | None = None, 
            tags: list[str] | None = None,
            exact_match: bool = False,
            search_fields: list[str] | None = None,
            show_for_guest: bool = False
    ) -> list[Page]:
        """
        Searches for pages in a category or group matching the query.

        Args:
            query (str): The search string (space-separated words).
            category_id (int | None): The category ID to search in.
            group_id (int | None): The group ID to search in.
            tags (list[str] | None): List of tags to filter by (AND logic).
            exact_match (bool): If True, match the whole query string.
            search_fields (list[str] | None): Fields to search in ('name', 'code').

        Returns:
            list[Page]: A list of matching pages.
        """
        stmt = select(Page).join(
            Document, Document.id == Page.document_id
        )

        joined_category = False

        if category_id:
            stmt = stmt.where(Document.category_id == category_id)
        elif group_id:
            stmt = stmt.join(Category, Document.category_id == Category.id).where(Category.group_id == group_id)
            joined_category = True

        if show_for_guest:
            if not joined_category:
                stmt = stmt.join(Category, Document.category_id == Category.id)
                joined_category = True
            stmt = stmt.where(Category.show_for_guest == True)

        if tags:
            for tag in tags:
                stmt = stmt.where(Document.tags.any(Tag.name.ilike(tag)))

        # Determine search columns (map 'code' to 'designation' for pages)
        fields_map = {"name": Page.name, "code": Page.designation}
        target_columns = []
        if search_fields:
            target_columns = [fields_map[f] for f in search_fields if f in fields_map]
        
        if not target_columns:
            target_columns = [Page.name, Page.designation]

        if exact_match:
            # Exact match (whole string, case-insensitive)
            conditions = [col.ilike(query) for col in target_columns]
            if conditions:
                stmt = stmt.where(or_(*conditions))
        else:
            # Word-based partial match
            words = query.split()
            for word in words:
                pattern = f"%{word}%"
                conditions = [col.ilike(pattern) for col in target_columns]
                if conditions:
                    stmt = stmt.where(or_(*conditions))

        stmt = stmt.distinct()
        result = await self.session.execute(stmt)
        return result.scalars().all()


    # ====================
    # Departments
    # ====================

    async def get_groups(
            self, 
            limit: int | None = None, 
            offset: int | None = None,
            show_for_guest: bool = False
    ) -> list[Group]:
        """
        Retrieves a list of groups with pagination.

        Args:
            limit (int | None): Limit the number of results.
            offset (int | None): Offset for pagination.
            show_for_guest (bool): If True, filter groups visible for guests.

        Returns:
            list[Group]: A list of Group objects.
        """
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        )

        if show_for_guest:
            query = query.where(Group.show_for_guest == True)
            query = query.options(
                with_loader_criteria(Category, Category.show_for_guest == True)
            )

        query = query.order_by(Group.id)
        if limit is not None:
            query = query.limit(limit)
        if offset is not None:
            query = query.offset(offset)
        departments = await self.session.execute(query)
        return departments.scalars().all()
    

    async def get_group_by_id(self, id: int) -> Group | None:
        """
        Retrieves a group by its ID.

        Args:
            id (int): The group ID.

        Returns:
            Group | None: The Group object or None if not found.
        """
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        ).where(Group.id == id)
        group = await self.session.execute(query)
        return group.scalar_one_or_none()
    

    async def get_group_by_name(self, name: str) -> Group | None:
        """
        Retrieves a group by its name.

        Args:
            name (str): The group name.

        Returns:
            Group | None: The Group object or None if not found.
        """
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        ).where(Group.name == name)
        group = await self.session.execute(query)
        return group.scalar_one_or_none()
    

    async def save_group(self, group: Group) -> Group:
        """
        Saves or updates a group in the database.

        Args:
            group (Group): The group object to save.

        Returns:
            Group: The saved group object.
        """
        self.session.add(group)
        await self.session.flush()
        await self.session.refresh(group)
        return group


    async def create_group(
            self, name: str, 
            show_for_guest: bool = False, 
            has_all_docs_search: bool = False
    ) -> Group:
        """
        Creates a new group.

        Args:
            name (str): The name of the new group.
            has_all_docs_search (bool): Flag to enable "All Documents" search.

        Returns:
            Group: The created group object.
        """
        group = Group(
            name=name, 
            show_for_guest=show_for_guest, 
            has_all_docs_search=has_all_docs_search
        )
        self.session.add(group)
        await self.session.flush()
        
        query = select(Group).options(
            selectinload(Group.categories).selectinload(Category.documents)
        ).where(Group.id == group.id)
        result = await self.session.execute(query)
        return result.scalar_one()
    

    async def delete_group(self, group: Group) -> None:
        """
        Deletes a group from the database.

        Args:
            group (Group): The group object to delete.
        """
        await self.session.delete(group)
        await self.session.flush()

    async def get_category_ids_by_group(self, group_id: int) -> list[int]:
        """
        Retrieves IDs of all categories in a group.

        Args:
            group_id (int): The group ID.

        Returns:
            list[int]: A list of category IDs.
        """
        query = select(Category.id).where(Category.group_id == group_id)
        result = await self.session.execute(query)
        return list(result.scalars().all())


    # ====================
    # Categories
    # ====================

    async def get_categories(
            self, 
            limit: int | None = None, 
            offset: int | None = None,
            show_for_guest: bool = False
    ) -> list[Category]:
        """
        Retrieves a list of categories with pagination.

        Args:
            limit (int | None): Limit the number of results.
            offset (int | None): Offset for pagination.
            show_for_guest (bool): If True, filter categories visible for guests.

        Returns:
            list[Category]: A list of Category objects.
        """
        query = select(Category).options(
            selectinload(Category.documents)
        ).order_by(Category.id)

        if show_for_guest:
            query = query.where(Category.show_for_guest == True)
            query = query.options(
                with_loader_criteria(Category, Category.show_for_guest == True)
            )

        if limit is not None:
            query = query.limit(limit)
        if offset is not None:
            query = query.offset(offset)
        categories = await self.session.execute(query)
        return categories.scalars().all()
    

    async def get_category(self, id: int) -> Category | None:
        """
        Retrieves a category by its ID.

        Args:
            id (int): The category ID.

        Returns:
            Category | None: The Category object or None if not found.
        """
        query = select(Category).options(
            selectinload(Category.documents)
        ).where(Category.id == id)
        category = await self.session.execute(query)
        return category.scalar_one_or_none()
    

    async def get_category_by_data(
            self, 
            name: str, 
            group_id: int
    ) -> Category | None:
        """
        Retrieves a category by name and group ID.

        Args:
            name (str): The category name.
            group_id (int): The group ID.

        Returns:
            Category | None: The Category object or None if not found.
        """
        query = select(Category).options(
            selectinload(Category.documents)
        ).where(
            Category.name == name,
            Category.group_id == group_id
        )
        category = await self.session.execute(query)
        return category.scalar_one_or_none()
    

    async def get_group_categories(
            self, 
            group_id: int, 
            limit: int | None = None,
            offset: int | None = None,
            show_for_guest: bool = False
    ) -> list[Category]:
        """
        Retrieves categories for a specific group.

        Args:
            group_id (int): The group ID.
            limit (int | None): Limit the number of results.
            offset (int | None): Offset for pagination.
            show_for_guest (bool): If True, filter categories visible for guests.

        Returns:
            list[Category]: A list of Category objects.
        """
        query = select(Category).options(
            selectinload(Category.documents)
        ).where(Category.group_id == group_id).order_by(Category.id)

        if show_for_guest:
            query = query.where(Category.show_for_guest == True)

        if limit is not None:
            query = query.limit(limit)
        if offset is not None:
            query = query.offset(offset)
        categories = await self.session.execute(query)
        return categories.scalars().all()
    

    async def get_category_documents(self, category_id: int) -> list[Document]:
        """
        Retrieves all documents in a category.

        Args:
            category_id (int): The category ID.

        Returns:
            list[Document]: A list of Document objects.
        """
        query = select(Document).options(
            selectinload(Document.tags)
        ).options(
            selectinload(Document.pages)
        ).where(Document.category_id == category_id)
        documents = await self.session.execute(query)
        return documents.scalars().all()
    

    async def create_category(
            self, 
            name: str, 
            group_id: int,
            show_for_guest: bool = False,
    ) -> Category:
        """
        Creates a new category.

        Args:
            name (str): The category name.
            group_id (int): The ID of the group the category belongs to.
            show_for_guest (bool): Visibility for guests.
            has_all_docs_search (bool): Search flag.

        Returns:
            Category: The created category object.
        """
        category = Category(
            name=name, group_id=group_id,
            show_for_guest=show_for_guest
        )
        self.session.add(category)
        await self.session.flush()
        
        query = select(Category).options(
            selectinload(Category.documents)
        ).where(Category.id == category.id)
        result = await self.session.execute(query)
        return result.scalar_one()
    

    async def save_category(self, category: Category) -> Category:
        """
        Saves or updates a category.

        Args:
            category (Category): The category object to save.

        Returns:
            Category: The saved category object.
        """
        self.session.add(category)
        await self.session.flush()
        await self.session.refresh(category)
        return category


    async def delete_category(self, category: Category) -> None:
        """
        Deletes a category.

        Args:
            category (Category): The category object to delete.
        """
        await self.session.delete(category)
        await self.session.flush()

    async def delete_categories_by_ids(self, category_ids: list[int]) -> None:
        """
        Bulk deletes categories by their IDs.

        Args:
            category_ids (list[int]): A list of category IDs to delete.
        """
        if not category_ids: return
        stmt = delete(Category).where(Category.id.in_(category_ids))
        await self.session.execute(stmt)

    async def get_document_ids_by_categories(self, category_ids: list[int]) -> list[int]:
        """
        Retrieves IDs of all documents in the specified categories.

        Args:
            category_ids (list[int]): A list of category IDs.

        Returns:
            list[int]: A list of document IDs.
        """
        if not category_ids: return []
        query = select(Document.id).where(Document.category_id.in_(category_ids))
        result = await self.session.execute(query)
        return list(result.scalars().all())

    # ====================
    # Documents
    # ====================

    async def get_document(self, id: int) -> Document | None:
        """
        Retrieves a document by its ID.

        Args:
            id (int): The document ID.

        Returns:
            Document | None: The Document object or None if not found.
        """
        query = select(Document).options(
            selectinload(Document.tags)
        ).where(Document.id == id)
        document = await self.session.execute(query)
        return document.scalar_one_or_none()


    async def get_documents(
            self, 
            limit: int | None = None, 
            offset: int | None = None,
            category_id: int | None = None,
            group_id: int | None = None,
            show_for_guest: bool = False
    ) -> list[Document]:
        """
        Retrieves a list of documents with pagination.

        Args:
            limit (int | None): Limit the number of results.
            offset (int | None): Offset for pagination.
            category_id (int | None): Filter by category ID.
            group_id (int | None): Filter by group ID.

        Returns:
            list[Document]: A list of Document objects.
        """
        query = select(Document).options(
            selectinload(Document.tags)
        ).order_by(Document.id)
        
        joined_category = False

        if group_id is not None:
            query = query.join(
                Category, Document.category_id == Category.id
            ).where(Category.group_id == group_id)
            joined_category = True
            
        if show_for_guest:
            if not joined_category:
                query = query.join(Category, Document.category_id == Category.id)
                joined_category = True
            query = query.where(Category.show_for_guest == True)

        if category_id is not None:
            query = query.where(Document.category_id == category_id)
            
        if limit is not None:
            query = query.limit(limit)
        if offset is not None:
            query = query.offset(offset)
        documents = await self.session.execute(query)
        return documents.scalars().all()
    

    async def get_document_by_data(
            self, 
            name: str, 
            code: str, 
            category_id: int
    ) -> Document | None:
        """
        Retrieves a document by name, code, and category ID.

        Args:
            name (str): The document name.
            code (str): The document code.
            category_id (int): The category ID.

        Returns:
            Document | None: The Document object or None if not found.
        """
        query = select(Document).where(
            Document.name == name,
            Document.code == code,
            Document.category_id == category_id
        )
        document = await self.session.execute(query)
        return document.scalar_one_or_none()
    

    async def create_document(
        self, 
        name: str, 
        code: str, 
        category_id: int, 
        tags: list[Tag] = []
    ) -> Document:
        """
        Creates a new document.

        Args:
            name (str): The document name.
            code (str): The document code.
            category_id (int): The category ID.
            tags (list[Tag]): List of tag objects.

        Returns:
            Document: The created document object.
        """
        document = Document(
            name=name,
            code=code,
            category_id=category_id,
            tags=tags
        )
        self.session.add(document)
        await self.session.flush()
        
        query = select(Document).options(
            selectinload(Document.tags),
            selectinload(Document.pages)
        ).where(Document.id == document.id)
        result = await self.session.execute(query)
        return result.scalar_one()
    

    async def save_document(self, document: Document) -> Document:
        """
        Saves or updates a document.

        Args:
            document (Document): The document object to save.

        Returns:
            Document: The saved document object.
        """
        self.session.add(document)
        await self.session.flush()
        
        query = select(Document).options(
            selectinload(Document.tags),
            selectinload(Document.pages)
        ).where(Document.id == document.id)
        result = await self.session.execute(query)
        return result.scalar_one()
    

    async def delete_document(self, document: Document) -> None:
        """
        Deletes a document.

        Args:
            document (Document): The document object to delete.
        """
        await self.session.delete(document)
        await self.session.flush()

    async def delete_documents_by_ids(self, document_ids: list[int]) -> None:
        """
        Bulk deletes documents by their IDs.

        Args:
            document_ids (list[int]): A list of document IDs to delete.
        """
        if not document_ids: return
        stmt = delete(Document).where(Document.id.in_(document_ids))
        await self.session.execute(stmt)
    

    # ====================
    # Pages
    # ====================

    async def get_pages(
            self, 
            limit: int | None = None, 
            offset: int | None = None
    ) -> list[Page]:
        """
        Retrieves a list of pages with pagination.

        Args:
            limit (int | None): Limit the number of results.
            offset (int | None): Offset for pagination.

        Returns:
            list[Page]: A list of Page objects.
        """
        query = select(Page).order_by(Page.id)
        if limit is not None:
            query = query.limit(limit)
        if offset is not None:
            query = query.offset(offset)
        pages = await self.session.execute(query)
        return pages.scalars().all()
    

    async def get_page(self, id: int) -> Page | None:
        """
        Retrieves a page by its ID.

        Args:
            id (int): The page ID.

        Returns:
            Page | None: The Page object or None if not found.
        """
        query = select(Page).where(Page.id == id)
        page = await self.session.execute(query)
        return page.scalar_one_or_none()
    

    async def get_document_pages(
            self, 
            document_id: int, 
            limit: int | None = None, 
            offset: int | None = None
    ) -> list[Page]:
        """
        Retrieves pages for a specific document.

        Args:
            document_id (int): The document ID.
            limit (int | None): Limit the number of results.
            offset (int | None): Offset for pagination.

        Returns:
            list[Page]: A list of Page objects.
        """
        query = select(Page).where(
            Page.document_id == document_id
        ).order_by(Page.order_index)
        if limit is not None:
            query = query.limit(limit)
        if offset is not None:
            query = query.offset(offset)
        pages = await self.session.execute(query)
        return pages.scalars().all()


    async def save_page(self, page: Page) -> Page:
        """
        Saves or updates a page.

        Args:
            page (Page): The page object to save.

        Returns:
            Page: The saved page object.
        """
        self.session.add(page)
        await self.session.flush()
        await self.session.refresh(page)
        return page


    async def delete_page(self, page: Page) -> None:
        """
        Deletes a page.

        Args:
            page (Page): The page object to delete.
        """
        await self.session.delete(page)
        await self.session.flush()

    async def delete_pages_by_document_ids(self, document_ids: list[int]) -> None:
        """
        Bulk deletes pages associated with specific documents.

        Args:
            document_ids (list[int]): A list of document IDs.
        """
        if not document_ids: return
        stmt = delete(Page).where(Page.document_id.in_(document_ids))
        await self.session.execute(stmt)


    # ====================
    # Tags
    # ====================

    async def get_or_create_tags(self, tag_names: list[str]) -> list[Tag]:
        """
        Finds existing tags or creates new ones based on a list of names.
        """
        if not tag_names:
            return []
        
        unique_names = list(set(tag_names))
        
        # Find existing
        query = select(Tag).where(Tag.name.in_(unique_names))
        result = await self.session.execute(query)
        existing_tags = result.scalars().all()
        existing_names = {tag.name for tag in existing_tags}
        
        tags = list(existing_tags)
        
        # Create missing
        for name in unique_names:
            if name not in existing_names:
                new_tag = Tag(name=name)
                self.session.add(new_tag)
                tags.append(new_tag)
        
        return tags
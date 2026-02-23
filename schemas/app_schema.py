from pydantic import BaseModel, ConfigDict, field_validator
from datetime import datetime


class SearchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    result: list[dict]


"""=== Tags ==="""
class TagResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str


"""=== Departments ==="""
class DepartmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    show_for_guest: bool
    has_all_docs_search: bool
    documents_count: int

    @field_validator("show_for_guest", mode="before")
    @classmethod
    def set_show_for_guest(cls, v):
        return v or False

    @field_validator("has_all_docs_search", mode="before")
    @classmethod
    def set_has_all_docs_search(cls, v):
        return v or False


class DepartmentsResponse(BaseModel):
    departments: list[DepartmentResponse]


class DepartmentCreateSchema(BaseModel):
    name: str
    show_for_guest: bool = False
    has_all_docs_search: bool = False


class DepartmentUpdate(BaseModel):
    name: str
    show_for_guest: bool
    has_all_docs_search: bool


"""=== Categories ==="""
class CategoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    group_id: int
    name: str
    show_for_guest: bool
    documents_count: int

    @field_validator("show_for_guest", mode="before")
    @classmethod
    def set_show_for_guest(cls, v):
        return v or False


class CategoriesResponse(BaseModel):
    categories: list[CategoryResponse]


class CategoryCreateSchema(BaseModel):
    group_id: int
    name: str
    show_for_guest: bool = False


class CategoryUpdateSchema(BaseModel):
    name: str
    show_for_guest: bool


"""=== Pages ==="""
class PageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    document_id: int
    order_index: int
    designation: str
    name: str


class PagesResponse(BaseModel):
    pages: list[PageResponse]


class PageUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    order_index: int
    designation: str
    name: str


"""=== Files ==="""
class DocumentFileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    document_id: int
    filename: str
    content_type: str
    size: int
    created_at: datetime


"""=== Documents ==="""
class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    category_id: int
    code: str
    name: str
    tags: list[TagResponse] = []
    files: list[DocumentFileResponse] = []


class DocumentsResponse(BaseModel):
    documents: list[DocumentResponse]


class DocumentCreateSchema(BaseModel):
    category_id: int
    code: str
    name: str
    pages: list[PageUpdate] | None = None
    tags: list[str] = []


class DocumentUpdateSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    code: str | None = None
    name: str | None = None
    pages: list[PageUpdate] | None = None
    tags: list[str] | None = None
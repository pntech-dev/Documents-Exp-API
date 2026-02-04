from pydantic import BaseModel, ConfigDict


"""=== Departments ==="""
class DepartmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    documents_count: int


class DepartmentsResponse(BaseModel):
    departments: list[DepartmentResponse]


"""=== Categories ==="""
class CategoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    group_id: int
    name: str
    documents_count: int


class CategoriesResponse(BaseModel):
    categories: list[CategoryResponse]


"""=== Documents ==="""
class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    category_id: int
    code: str
    name: str


class DocumentsResponse(BaseModel):
    documents: list[DocumentResponse]


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
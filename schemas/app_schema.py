from pydantic import BaseModel, ConfigDict


"""=== Departments ==="""
class DepartmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    documents_count: int


class DepartmentsResponse(BaseModel):
    departments: list[DepartmentResponse]


class DepartmentCreateSchema(BaseModel):
    name: str


class DepartmentUpdate(BaseModel):
    name: str


"""=== Categories ==="""
class CategoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    group_id: int
    name: str
    documents_count: int


class CategoriesResponse(BaseModel):
    categories: list[CategoryResponse]


class CategoryCreateSchema(BaseModel):
    group_id: int
    name: str

class CategoryUpdateSchema(BaseModel):
    name: str


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


"""=== Documents ==="""
class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    category_id: int
    code: str
    name: str


class DocumentsResponse(BaseModel):
    documents: list[DocumentResponse]


class DocumentCreateSchema(BaseModel):
    category_id: int
    code: str
    name: str
    pages: list[PageUpdate] | None = None


class DocumentUpdateSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    code: str | None = None
    name: str | None = None
    pages: list[PageUpdate] | None = None
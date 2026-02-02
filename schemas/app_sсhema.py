from pydantic import BaseModel, ConfigDict


"""=== Departments ==="""
class DepartmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class DepartmentsResponse(BaseModel):
    departments: list[DepartmentResponse]


"""=== Categories ==="""
class CategoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    group_id: int
    name: str


class CategoriesResponse(BaseModel):
    categories: list[CategoryResponse]
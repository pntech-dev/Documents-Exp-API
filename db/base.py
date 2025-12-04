from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Import all models here to register them with the Base
from models import *
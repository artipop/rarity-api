from sqladmin import ModelView
from rarity_api.core.database.models.models import User

class UserAdmin(ModelView, model=User):
    column_list = [User.id, User.email]
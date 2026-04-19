from flask_pymongo import PyMongo
from flask_login import UserMixin
from bson import ObjectId

mongo = PyMongo()


class User(UserMixin):
    """Lightweight user wrapper around a MongoDB document."""

    def __init__(self, doc):
        self._doc = doc

    # --- Flask-Login interface -----------------------------------------------

    def get_id(self):
        return str(self._doc["_id"])

    @property
    def id(self):
        return str(self._doc["_id"])

    @property
    def username(self):
        return self._doc.get("username", "")

    @property
    def email(self):
        return self._doc.get("email", "")

    @property
    def password(self):
        return self._doc.get("password", "")

    # --- Class-level helpers (mirrors SQLAlchemy query API used in auth.py) --

    @classmethod
    def _col(cls):
        return mongo.db.users

    @classmethod
    def find_by_email(cls, email):
        doc = cls._col().find_one({"email": email})
        return cls(doc) if doc else None

    @classmethod
    def find_by_username(cls, username):
        doc = cls._col().find_one({"username": username})
        return cls(doc) if doc else None

    @classmethod
    def find_by_id(cls, user_id):
        try:
            doc = cls._col().find_one({"_id": ObjectId(user_id)})
        except Exception:
            return None
        return cls(doc) if doc else None

    @classmethod
    def create(cls, username, email, hashed_password):
        result = cls._col().insert_one(
            {"username": username, "email": email, "password": hashed_password}
        )
        doc = cls._col().find_one({"_id": result.inserted_id})
        return cls(doc)

    @classmethod
    def ensure_indexes(cls):
        cls._col().create_index("email",    unique=True)
        cls._col().create_index("username", unique=True)
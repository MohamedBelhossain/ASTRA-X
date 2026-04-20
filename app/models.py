from datetime import datetime, timedelta

from bson import ObjectId
from flask_login import UserMixin
from flask_pymongo import PyMongo

mongo = PyMongo()


class User(UserMixin):
    
    def __init__(self, doc):
        self._doc = doc

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

    @property
    def is_verified(self):
        return self._doc.get("is_verified", False)

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
        result = cls._col().insert_one({
            "username":    username,
            "email":       email,
            "password":    hashed_password,
            "is_verified": False
        })
        doc = cls._col().find_one({"_id": result.inserted_id})
        return cls(doc)

    @classmethod
    def set_verified(cls, email):
        cls._col().update_one(
            {"email": email},
            {"$set": {"is_verified": True}}
        )

    @classmethod
    def update_password(cls, email, hashed_password):
        cls._col().update_one(
            {"email": email},
            {"$set": {"password": hashed_password}}
        )

    @classmethod
    def ensure_indexes(cls):
        cls._col().create_index("email",    unique=True)
        cls._col().create_index("username", unique=True)


class ResetToken:
    """Password reset codes stored in MongoDB."""

    @classmethod
    def _col(cls):
        return mongo.db.reset_tokens

    @classmethod
    def create(cls, email, code):
        cls._col().delete_many({"email": email})
        now = datetime.utcnow()
        cls._col().insert_one({
            "email":      email,
            "code":       code,
            "used":       False,
            "created_at": now,
            "expires_at": now + timedelta(minutes=10),
        })

    @classmethod
    def find_valid(cls, email, code):
        doc = cls._col().find_one({
            "email": email,
            "code":  code,
            "used":  False,
        })
        if not doc:
            return None

        expires_at = doc.get("expires_at")
        if expires_at and expires_at <= datetime.utcnow():
            return None

        created_at = doc.get("created_at")
        if created_at and (datetime.utcnow() - created_at).total_seconds() > 600:
            return None

        return doc

    @classmethod
    def mark_used(cls, email, code):
        cls._col().update_one(
            {"email": email, "code": code},
            {"$set": {"used": True}}
        )

    @classmethod
    def ensure_indexes(cls):
        cls._col().create_index("email")
        cls._col().create_index("expires_at")

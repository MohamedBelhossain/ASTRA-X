from flask_pymongo import PyMongo
from flask_login import UserMixin
from bson import ObjectId
import time

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

    @property
    def recent_scan_starts(self):
        timestamps = self._doc.get("recent_scan_starts", [])
        return [float(ts) for ts in timestamps if isinstance(ts, (int, float))]

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
            {
                "username": username,
                "email": email,
                "password": hashed_password,
                "recent_scan_starts": [],
                "created_at": time.time(),
            }
        )
        doc = cls._col().find_one({"_id": result.inserted_id})
        return cls(doc)

    @classmethod
    def consume_scan_quota(cls, user_id, window_seconds, max_scans, now=None):
        now = float(now or time.time())
        window_start = now - window_seconds
        user = cls.find_by_id(user_id)
        if not user:
            return {"allowed": False, "reason": "User not found."}

        recent = [ts for ts in user.recent_scan_starts if ts >= window_start]
        if len(recent) >= max_scans:
            retry_after = max(1, int(recent[0] + window_seconds - now))
            cls._col().update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"recent_scan_starts": recent}},
            )
            return {
                "allowed": False,
                "reason": "Rate limit exceeded.",
                "retry_after": retry_after,
                "remaining": 0,
            }

        updated = recent + [now]
        cls._col().update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"recent_scan_starts": updated}},
        )
        return {
            "allowed": True,
            "remaining": max_scans - len(updated),
            "reset_in": max(0, int(window_seconds - (now - updated[0]))),
        }

    @classmethod
    def get_scan_quota_status(cls, user_id, window_seconds, max_scans, now=None):
        now = float(now or time.time())
        user = cls.find_by_id(user_id)
        if not user:
            return {
                "limit": max_scans,
                "used": 0,
                "remaining": max_scans,
                "window_seconds": window_seconds,
                "reset_in": window_seconds,
            }

        recent = [ts for ts in user.recent_scan_starts if ts >= now - window_seconds]
        if recent != user.recent_scan_starts:
            cls._col().update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"recent_scan_starts": recent}},
            )

        used = len(recent)
        reset_in = max(0, int(window_seconds - (now - recent[0]))) if recent else window_seconds
        return {
            "limit": max_scans,
            "used": used,
            "remaining": max(0, max_scans - used),
            "window_seconds": window_seconds,
            "reset_in": reset_in,
        }

    @classmethod
    def ensure_indexes(cls):
        cls._col().create_index("email",    unique=True)
        cls._col().create_index("username", unique=True)

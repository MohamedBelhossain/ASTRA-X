import time
from datetime import datetime, timedelta

from bson import ObjectId
from flask_login import UserMixin
from flask_pymongo import PyMongo

mongo = PyMongo()


def utcnow():
    return datetime.utcnow()


def serialize_document(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [serialize_document(item) for item in value]
    if isinstance(value, dict):
        return {key: serialize_document(item) for key, item in value.items()}
    return value


class User(UserMixin):
    """Lightweight user wrapper around a MongoDB document."""

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

    @property
    def is_admin(self):
        return self._doc.get("is_admin", False)

    @property
    def pending_email(self):
        return self._doc.get("pending_email", "")

    @property
    def pending_email_expires_at(self):
        return self._doc.get("pending_email_expires_at", 0)

    @property
    def recent_scan_starts(self):
        timestamps = self._doc.get("recent_scan_starts", [])
        return [float(ts) for ts in timestamps if isinstance(ts, (int, float))]

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
                "is_verified": False,
                "is_admin": False,
                "recent_scan_starts": [],
                "created_at": time.time(),
            }
        )
        doc = cls._col().find_one({"_id": result.inserted_id})
        return cls(doc)

    @classmethod
    def ensure_admin(cls, username, email, hashed_password):
        existing = cls.find_by_email(email)
        if existing:
            cls._col().update_one(
                {"_id": ObjectId(existing.id)},
                {
                    "$set": {
                        "username": username,
                        "password": hashed_password,
                        "is_verified": True,
                        "is_admin": True,
                    }
                },
            )
            return cls.find_by_id(existing.id)

        result = cls._col().insert_one(
            {
                "username": username,
                "email": email,
                "password": hashed_password,
                "is_verified": True,
                "is_admin": True,
                "recent_scan_starts": [],
                "created_at": time.time(),
            }
        )
        return cls(cls._col().find_one({"_id": result.inserted_id}))

    @classmethod
    def count_all(cls):
        return cls._col().count_documents({})

    @classmethod
    def count_admins(cls):
        return cls._col().count_documents({"is_admin": True})

    @classmethod
    def list_recent(cls, limit=20):
        cursor = cls._col().find({}).sort("created_at", -1).limit(limit)
        return [serialize_document(doc) for doc in cursor]

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
    def set_verified(cls, email):
        cls._col().update_one({"email": email}, {"$set": {"is_verified": True}})

    @classmethod
    def update_username(cls, user_id, username):
        cls._col().update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"username": username}},
        )

    @classmethod
    def update_password_by_id(cls, user_id, hashed_password):
        cls._col().update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"password": hashed_password}},
        )

    @classmethod
    def update_password(cls, email, hashed_password):
        cls._col().update_one({"email": email}, {"$set": {"password": hashed_password}})

    @classmethod
    def set_pending_email(cls, user_id, email, code_hash, expires_at):
        cls._col().update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "pending_email": email,
                    "pending_email_code_hash": code_hash,
                    "pending_email_expires_at": expires_at,
                }
            },
        )

    @classmethod
    def clear_pending_email(cls, user_id):
        cls._col().update_one(
            {"_id": ObjectId(user_id)},
            {
                "$unset": {
                    "pending_email": "",
                    "pending_email_code_hash": "",
                    "pending_email_expires_at": "",
                }
            },
        )

    @classmethod
    def apply_pending_email(cls, user_id):
        user = cls.find_by_id(user_id)
        if not user or not user.pending_email:
            return False

        cls._col().update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {"email": user.pending_email, "is_verified": True},
                "$unset": {
                    "pending_email": "",
                    "pending_email_code_hash": "",
                    "pending_email_expires_at": "",
                },
            },
        )
        return True

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
        cls._col().create_index("email", unique=True)
        cls._col().create_index("username", unique=True)


class ResetToken:
    """Password reset codes stored in MongoDB."""

    @classmethod
    def _col(cls):
        return mongo.db.reset_tokens

    @classmethod
    def create(cls, email, code_hash):
        cls._col().delete_many({"email": email})
        now = utcnow()
        cls._col().insert_one(
            {
                "email": email,
                "code_hash": code_hash,
                "used": False,
                "created_at": now,
                "expires_at": now + timedelta(minutes=10),
            }
        )

    @classmethod
    def find_valid(cls, email):
        doc = cls._col().find_one({"email": email, "used": False})
        if not doc:
            return None

        expires_at = doc.get("expires_at")
        if expires_at and expires_at <= utcnow():
            return None

        created_at = doc.get("created_at")
        if created_at and (utcnow() - created_at).total_seconds() > 600:
            return None

        return doc

    @classmethod
    def mark_used(cls, email):
        cls._col().update_one({"email": email}, {"$set": {"used": True}})

    @classmethod
    def ensure_indexes(cls):
        cls._col().create_index("email")
        cls._col().create_index("expires_at", expireAfterSeconds=0)


class RateLimitBucket:
    """Ephemeral documents used for auth throttling."""

    @classmethod
    def _col(cls):
        return mongo.db.rate_limit_buckets

    @classmethod
    def check_and_record(cls, namespace, key, limit, window_seconds):
        now = utcnow()
        doc = {
            "namespace": namespace,
            "key": key,
            "created_at": now,
            "expires_at": now + timedelta(seconds=window_seconds),
        }
        cls._col().insert_one(doc)
        count = cls._col().count_documents(
            {
                "namespace": namespace,
                "key": key,
                "created_at": {"$gte": now - timedelta(seconds=window_seconds)},
            }
        )
        retry_after = 0
        if count > limit:
            oldest = cls._col().find_one(
                {
                    "namespace": namespace,
                    "key": key,
                    "created_at": {"$gte": now - timedelta(seconds=window_seconds)},
                },
                sort=[("created_at", 1)],
            )
            if oldest:
                retry_after = max(
                    1,
                    int(
                        (
                            oldest["created_at"]
                            + timedelta(seconds=window_seconds)
                            - now
                        ).total_seconds()
                    ),
                )
        return {
            "allowed": count <= limit,
            "count": count,
            "limit": limit,
            "retry_after": retry_after,
        }

    @classmethod
    def status(cls, namespace, key, limit, window_seconds):
        now = utcnow()
        window_start = now - timedelta(seconds=window_seconds)
        count = cls._col().count_documents(
            {
                "namespace": namespace,
                "key": key,
                "created_at": {"$gte": window_start},
            }
        )
        oldest = cls._col().find_one(
            {
                "namespace": namespace,
                "key": key,
                "created_at": {"$gte": window_start},
            },
            sort=[("created_at", 1)],
        )
        reset_in = window_seconds
        if oldest:
            reset_in = max(
                0,
                int((oldest["created_at"] + timedelta(seconds=window_seconds) - now).total_seconds()),
            )
        return {
            "limit": limit,
            "used": min(count, limit),
            "remaining": max(0, limit - count),
            "window_seconds": window_seconds,
            "reset_in": reset_in,
        }

    @classmethod
    def ensure_indexes(cls):
        cls._col().create_index("expires_at", expireAfterSeconds=0)
        cls._col().create_index([("namespace", 1), ("key", 1), ("created_at", -1)])


class ScanRecord:
    """Persistent scan metadata, event stream, and report data."""

    ACTIVE_STATUSES = {"queued", "running", "cancelling"}
    MAX_EVENTS_PER_SCAN = 2000

    @classmethod
    def _col(cls):
        return mongo.db.scans

    @classmethod
    def _base_report(cls, scan_mode, target_url):
        return {
            "scan_mode": scan_mode,
            "target_url": target_url,
            "pages_scanned": 0,
            "pages": [],
            "open_ports": [],
            "cms_result": {
                "detected": {
                    "detected": False,
                    "name": None,
                    "version": None,
                    "confidence": "none",
                    "evidence": [],
                },
                "cves": [],
                "cve_source": "NVD",
                "cve_lookup": "keyword",
            },
            "header_result": {
                "url": target_url,
                "status": None,
                "headers": {},
                "findings": [],
                "error": None,
            },
            "vulnerabilities": [],
            "xss_vulnerabilities": [],
            "lfi_vulnerabilities": [],
            "bruteforce_result": {
                "waf_detected": False,
                "waf_detail": None,
                "bypass_hints": [],
                "login_forms": 0,
                "attempts": 0,
                "credentials_found": [],
                "blocked_payloads": [],
                "candidate_pages": 0,
                "rate_limit_probe": {
                    "tested": False,
                    "requests_sent": 0,
                    "allowed_before_block": 0,
                    "blocked": False,
                    "blocked_at_request": None,
                    "block_status": None,
                    "average_response_ms": None,
                    "statuses": [],
                },
            },
            "file_findings": [],
            "subdomain_findings": [],
        }

    @classmethod
    def create(cls, scan_id, owner_id, target_url, target_host, resolved_ips, scan_mode):
        now = utcnow()
        doc = {
            "scan_id": scan_id,
            "owner_id": owner_id,
            "target_url": target_url,
            "target_host": target_host,
            "resolved_ips": resolved_ips,
            "scan_mode": scan_mode,
            "status": "queued",
            "cancel_requested": False,
            "created_at": now,
            "started_at": None,
            "finished_at": None,
            "last_error": None,
            "events": [],
            "phases": {},
            "report": cls._base_report(scan_mode, target_url),
        }
        cls._col().insert_one(doc)
        return doc

    @classmethod
    def find_by_scan_id(cls, scan_id):
        return cls._col().find_one({"scan_id": scan_id})

    @classmethod
    def find_owned(cls, scan_id, owner_id):
        return cls._col().find_one({"scan_id": scan_id, "owner_id": owner_id})

    @classmethod
    def mark_running(cls, scan_id):
        cls._col().update_one(
            {"scan_id": scan_id},
            {"$set": {"status": "running", "started_at": utcnow()}},
        )

    @classmethod
    def append_event(cls, scan_id, event_type, data):
        event = {"type": event_type, "data": data, "created_at": utcnow()}
        cls._col().update_one(
            {"scan_id": scan_id},
            {"$push": {"events": {"$each": [event], "$slice": -cls.MAX_EVENTS_PER_SCAN}}},
        )
        return event

    @classmethod
    def update_phase(cls, scan_id, name, status, count=None):
        phase_data = {"status": status}
        if count is not None:
            phase_data["count"] = count
        cls._col().update_one({"scan_id": scan_id}, {"$set": {f"phases.{name}": phase_data}})

    @classmethod
    def update_status(cls, scan_id, status, last_error=None):
        payload = {"status": status}
        if status in {"completed", "failed", "cancelled"}:
            payload["finished_at"] = utcnow()
        if last_error is not None:
            payload["last_error"] = last_error
        cls._col().update_one({"scan_id": scan_id}, {"$set": payload})

    @classmethod
    def request_cancel(cls, scan_id, owner_id):
        result = cls._col().update_one(
            {"scan_id": scan_id, "owner_id": owner_id, "status": {"$in": list(cls.ACTIVE_STATUSES)}},
            {"$set": {"cancel_requested": True, "status": "cancelling"}},
        )
        return bool(result.modified_count)

    @classmethod
    def request_cancel_any(cls, scan_id):
        result = cls._col().update_one(
            {"scan_id": scan_id, "status": {"$in": list(cls.ACTIVE_STATUSES)}},
            {"$set": {"cancel_requested": True, "status": "cancelling"}},
        )
        return bool(result.modified_count)

    @classmethod
    def is_cancel_requested(cls, scan_id):
        doc = cls.find_by_scan_id(scan_id)
        return bool(doc and doc.get("cancel_requested"))

    @classmethod
    def finalize_report(cls, scan_id, report):
        serializable_report = serialize_document(report)
        cls._col().update_one({"scan_id": scan_id}, {"$set": {"report": serializable_report}})

    @classmethod
    def count_active_for_user(cls, owner_id):
        return cls._col().count_documents(
            {"owner_id": owner_id, "status": {"$in": list(cls.ACTIVE_STATUSES)}}
        )

    @classmethod
    def mark_interrupted_active(cls, message):
        docs = list(cls._col().find({"status": {"$in": list(cls.ACTIVE_STATUSES)}}))
        now = utcnow()
        for doc in docs:
            scan_id = doc["scan_id"]
            cls._col().update_one(
                {"scan_id": scan_id},
                {
                    "$set": {
                        "status": "failed",
                        "finished_at": now,
                        "last_error": message,
                        "cancel_requested": False,
                    },
                    "$push": {
                        "events": {
                            "$each": [
                                {
                                    "type": "log",
                                    "data": {"msg": message, "level": "error"},
                                    "created_at": now,
                                },
                                {
                                    "type": "done",
                                    "data": {
                                        "scan_id": scan_id,
                                        "status": "failed",
                                        "error": message,
                                    },
                                    "created_at": now,
                                },
                            ]
                        }
                    },
                },
            )
        return len(docs)

    @classmethod
    def list_for_user(cls, owner_id, limit=20):
        cursor = cls._col().find({"owner_id": owner_id}).sort("created_at", -1).limit(limit)
        return [serialize_document(doc) for doc in cursor]

    @classmethod
    def list_recent(cls, limit=20):
        cursor = cls._col().find({}).sort("created_at", -1).limit(limit)
        return [serialize_document(doc) for doc in cursor]

    @classmethod
    def count_all(cls):
        return cls._col().count_documents({})

    @classmethod
    def count_by_status(cls):
        statuses = {}
        for item in cls._col().aggregate([{"$group": {"_id": "$status", "count": {"$sum": 1}}}]):
            statuses[item["_id"] or "unknown"] = item["count"]
        return statuses

    @classmethod
    def _serializable_report_from_doc(cls, doc):
        if not doc:
            return None
        report = serialize_document(doc.get("report") or cls._base_report(doc.get("scan_mode", "deep"), doc.get("target_url", "")))
        report.update(
            {
                "scan_id": doc["scan_id"],
                "status": doc.get("status", "unknown"),
                "cancel_requested": doc.get("cancel_requested", False),
                "created_at": serialize_document(doc.get("created_at")),
                "started_at": serialize_document(doc.get("started_at")),
                "finished_at": serialize_document(doc.get("finished_at")),
                "target_host": doc.get("target_host"),
                "resolved_ips": doc.get("resolved_ips", []),
                "last_error": doc.get("last_error"),
                "phases": serialize_document(doc.get("phases", {})),
            }
        )
        return report

    @classmethod
    def serializable_report(cls, scan_id):
        return cls._serializable_report_from_doc(cls.find_by_scan_id(scan_id))

    @classmethod
    def serializable_report_for_owner(cls, scan_id, owner_id):
        return cls._serializable_report_from_doc(cls.find_owned(scan_id, owner_id))

    @classmethod
    def serialized_events_for_owner(cls, scan_id, owner_id):
        doc = cls.find_owned(scan_id, owner_id)
        if not doc:
            return None
        return [serialize_document(event) for event in doc.get("events", [])]

    @classmethod
    def ensure_indexes(cls):
        cls._col().create_index("scan_id", unique=True)
        cls._col().create_index([("owner_id", 1), ("created_at", -1)])
        cls._col().create_index([("status", 1), ("owner_id", 1)])

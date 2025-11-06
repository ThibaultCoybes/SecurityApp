# security/audit.py
import json
import os
from datetime import datetime
from typing import Optional, Dict, Any
from flask import request

LOG_DIR = os.getenv("AUDIT_LOG_DIR", "logs")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")

os.makedirs(LOG_DIR, exist_ok=True)

class SecurityAuditLogger:
    def __init__(self, path: Optional[str] = None):
        self.path = path or LOG_FILE
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def _now_iso(self) -> str:
        return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    def _safe_user(self, user: Optional[str]) -> Optional[str]:
        if user is None:
            return None
        u = str(user)
        return u if len(u) <= 200 else u[:200]

    def log(self, event_type: str,
                  user: Optional[str],
                  ip_address: Optional[str],
                  severity: str = "INFO",
                  details: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "timestamp": self._now_iso(),
            "event_type": event_type,
            "user": self._safe_user(user),
            "ip_address": ip_address or (request.remote_addr if request else "0.0.0.0"),
            "severity": severity,
            "details": details or {}
        }
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as e:
            print("Audit log write error:", e, "payload:", payload)

    def log_login_attempt(self, user: Optional[str], ip_address: Optional[str], success: bool, extra: Optional[Dict[str, Any]] = None):
        details = {"success": success}
        if extra:
            details.update(extra)
        self.log("LOGIN_ATTEMPT", user, ip_address, "INFO" if success else "WARNING", details)

    def log_access_violation(self, user: Optional[str], ip_address: Optional[str], route: str, extra: Optional[Dict[str, Any]] = None):
        details = {"route": route}
        if extra:
            details.update(extra)
        self.log("ACCESS_DENIED", user, ip_address, "ALERT", details)

    def log_injection_detected(self, user: Optional[str], ip_address: Optional[str], route: str, payload: Optional[str] = None, tool: Optional[str] = None):
        details = {"route": route}
        if payload:
            details["payload_sample"] = (payload[:1000] + "...") if len(payload) > 1000 else payload
        if tool:
            details["tool"] = tool
        self.log("INJECTION_DETECTED", user, ip_address, "HIGH", details)

    def log_db_error(self, user: Optional[str], ip_address: Optional[str], route: str, error_message: str):
        self.log("DB_ERROR", user, ip_address, "ERROR", {"route": route, "error": error_message})

    def log_event(self, event_type: str, user: Optional[str], ip_address: Optional[str], severity: str, details: Optional[Dict[str, Any]] = None):
        self.log(event_type, user, ip_address, severity, details)
    
    def log_route_visit(self, event_type: str, user: Optional[str], ip_address: Optional[str], route: str, user_agent: str):
        """Helper pour logger les visites de routes."""
        self.log(event_type, user, ip_address, "INFO", {"route": route, "ua": user_agent})
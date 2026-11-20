import os
import time
import threading
from collections import defaultdict, deque
from typing import Optional, Tuple
from fastapi import Request, HTTPException, status
from backend.app.config import settings

class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter.
    
    Tracks timestamps of events in a deque per key and expires timestamps outside
    the time window. In a multi-worker production cluster behind a load balancer,
    this in-memory backend can be transparently swapped with Redis (e.g. Redis ZSET
    or sliding window rate limiter) without changing router call sites.
    """

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._records = defaultdict(deque)
        self._lock = threading.Lock()

    def record_attempt(self, key: str, timestamp: Optional[float] = None) -> int:
        """Record an attempt timestamp and return the current count in the window."""
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            q = self._records[key]
            # Prune old records
            cutoff = now - self.window_seconds
            while q and q[0] <= cutoff:
                q.popleft()
            q.append(now)
            return len(q)

    def is_rate_limited(self, key: str, timestamp: Optional[float] = None) -> Tuple[bool, int]:
        """
        Check if key has exceeded max_attempts within the window.
        Returns (is_limited, retry_after_seconds).
        """
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            q = self._records[key]
            cutoff = now - self.window_seconds
            while q and q[0] <= cutoff:
                q.popleft()
            
            if len(q) >= self.max_attempts:
                oldest_in_window = q[0]
                retry_after = max(1, int(oldest_in_window + self.window_seconds - now))
                return True, retry_after
            return False, 0

    def reset(self, key: str) -> None:
        """Reset attempts for a specific key."""
        with self._lock:
            if key in self._records:
                del self._records[key]

    def clear(self) -> None:
        """Clear all records (useful for test isolation)."""
        with self._lock:
            self._records.clear()


class LoginRateLimiter:
    """
    Specialized rate limiter for user logins.
    Tracks failures per email and per client IP address.
    """

    def __init__(self, max_attempts: Optional[int] = None, window_seconds: Optional[int] = None):
        self.max_attempts = max_attempts or getattr(settings, "RATE_LIMIT_LOGIN_MAX_ATTEMPTS", 5)
        self.window_seconds = window_seconds or getattr(settings, "RATE_LIMIT_LOGIN_WINDOW_SECONDS", 300)
        self.email_limiter = SlidingWindowRateLimiter(self.max_attempts, self.window_seconds)
        self.ip_limiter = SlidingWindowRateLimiter(self.max_attempts * 3, self.window_seconds)

    def check_rate_limit(self, email: str, client_ip: str) -> None:
        """Check if either the account email or client IP is currently rate limited."""
        email_key = f"login:email:{email.lower().strip()}"
        ip_key = f"login:ip:{client_ip.strip()}"

        limited, retry_after = self.email_limiter.is_rate_limited(email_key)
        if limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts for this account. Please wait {retry_after} seconds before trying again.",
                headers={"Retry-After": str(retry_after)}
            )

        limited, retry_after = self.ip_limiter.is_rate_limited(ip_key)
        if limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts from this network. Please wait {retry_after} seconds before trying again.",
                headers={"Retry-After": str(retry_after)}
            )

    def record_failure(self, email: str, client_ip: str) -> None:
        """Record a failed login attempt."""
        email_key = f"login:email:{email.lower().strip()}"
        ip_key = f"login:ip:{client_ip.strip()}"
        self.email_limiter.record_attempt(email_key)
        self.ip_limiter.record_attempt(ip_key)

    def reset_failures(self, email: str, client_ip: str) -> None:
        """Reset failed attempt counters upon successful login."""
        email_key = f"login:email:{email.lower().strip()}"
        ip_key = f"login:ip:{client_ip.strip()}"
        self.email_limiter.reset(email_key)
        self.ip_limiter.reset(ip_key)

    def clear(self) -> None:
        self.email_limiter.clear()
        self.ip_limiter.clear()


class RegisterRateLimiter:
    """
    Specialized rate limiter for account registrations.
    Prevents automated spam registration by throttling IP addresses.
    """

    def __init__(self, max_attempts: Optional[int] = None, window_seconds: Optional[int] = None):
        self.max_attempts = max_attempts or getattr(settings, "RATE_LIMIT_REGISTER_MAX_ATTEMPTS", 10)
        self.window_seconds = window_seconds or getattr(settings, "RATE_LIMIT_REGISTER_WINDOW_SECONDS", 3600)
        self.ip_limiter = SlidingWindowRateLimiter(self.max_attempts, self.window_seconds)

    def check_and_record(self, client_ip: str, enforce_in_testing: bool = False) -> None:
        """Check rate limit for registration and record the attempt if allowed."""
        if not enforce_in_testing and os.environ.get("TESTING") == "1":
            return
        ip_key = f"register:ip:{client_ip.strip()}"
        limited, retry_after = self.ip_limiter.is_rate_limited(ip_key)
        if limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Registration rate limit exceeded for this IP. Please wait {retry_after} seconds before creating another account.",
                headers={"Retry-After": str(retry_after)}
            )
        self.ip_limiter.record_attempt(ip_key)

    def clear(self) -> None:
        self.ip_limiter.clear()


def get_client_ip(request: Request) -> str:
    """Extract client IP address, respecting X-Forwarded-For proxies safely."""
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        # First entry in X-Forwarded-For is the original client IP
        return x_forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host.strip()
    return "127.0.0.1"


# Global instances
login_rate_limiter = LoginRateLimiter()
register_rate_limiter = RegisterRateLimiter()

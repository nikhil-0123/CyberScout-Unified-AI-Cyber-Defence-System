"""
In-Memory Sliding Window Rate Limiter for CyberScout.
Protects sensitive endpoints (authentication, live forensics, ML inference)
against brute-force and Denial-of-Service (DoS) abuse without external dependencies.
"""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, Deque
from fastapi import Request, HTTPException, status

class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60, name: str = "default"):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.name = name
        self.lock = threading.Lock()
        self.requests: Dict[str, Deque[float]] = defaultdict(deque)
        self.last_cleanup = time.time()

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, taking into account X-Forwarded-For if behind a reverse proxy."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # First IP in the comma-separated chain is the client IP
            return forwarded_for.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    def _cleanup_stale(self, current_time: float):
        """Purge stale IPs that have had no requests in the current window."""
        stale_keys = [
            ip for ip, q in self.requests.items()
            if not q or (current_time - q[-1]) > self.window_seconds
        ]
        for ip in stale_keys:
            del self.requests[ip]
        self.last_cleanup = current_time

    def __call__(self, request: Request):
        current_time = time.time()
        client_ip = self._get_client_ip(request)

        with self.lock:
            # Run periodic memory cleanup every 5 minutes
            if current_time - self.last_cleanup > 300:
                self._cleanup_stale(current_time)

            timestamps = self.requests[client_ip]

            # Pop timestamps outside the sliding window
            while timestamps and (current_time - timestamps[0]) > self.window_seconds:
                timestamps.popleft()

            # Check threshold
            if len(timestamps) >= self.max_requests:
                oldest_timestamp = timestamps[0]
                retry_after = int(self.window_seconds - (current_time - oldest_timestamp)) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for {self.name}. Maximum {self.max_requests} requests per {self.window_seconds}s.",
                    headers={"Retry-After": str(max(1, retry_after))}
                )

            # Record this request
            timestamps.append(current_time)

# Pre-configured rate limiters for CyberScout endpoints
# Auth endpoints: 10 requests / 60 seconds (prevents brute-force)
auth_rate_limiter = SlidingWindowRateLimiter(max_requests=10, window_seconds=60, name="authentication")

# Scan/Analysis endpoints: 30 requests / 60 seconds (prevents resource exhaustion)
scan_rate_limiter = SlidingWindowRateLimiter(max_requests=30, window_seconds=60, name="threat scanning")

# General read endpoints: 120 requests / 60 seconds
general_rate_limiter = SlidingWindowRateLimiter(max_requests=120, window_seconds=60, name="general API")

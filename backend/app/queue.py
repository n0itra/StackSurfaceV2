import json
from redis import Redis
from .config import settings

JOB_QUEUE = "stacksurface:jobs"

redis_client = Redis.from_url(
    settings.redis_url,
    decode_responses=True,
    socket_timeout=None,
    socket_connect_timeout=5,
    retry_on_timeout=True,
)


def enqueue_scan(scan_id: str) -> None:
    redis_client.rpush(
        JOB_QUEUE,
        json.dumps({
            "type": "scan",
            "scan_id": scan_id,
        }),
    )


def enqueue_ffuf(run_id: str) -> None:
    redis_client.rpush(
        JOB_QUEUE,
        json.dumps({
            "type": "ffuf",
            "run_id": run_id,
        }),
    )


def publish_stop(scan_id: str) -> None:
    redis_client.publish(
        f"stacksurface:stop:{scan_id}",
        "stop",
    )
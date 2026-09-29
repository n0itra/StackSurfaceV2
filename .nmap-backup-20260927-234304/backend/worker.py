from __future__ import annotations

import asyncio
import json
import logging
import time

from .app.pipeline import run_scan, run_ffuf, recover_stale_jobs
from .app.queue import redis_client, JOB_QUEUE

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def main() -> None:
    logging.info(
        "StackSurface worker started; one active job at a time"
    )

    recover_stale_jobs()

    while True:
        try:
            item = redis_client.lpop(JOB_QUEUE)

            if not item:
                time.sleep(0.5)
                continue

            payload = json.loads(item)
            job_type = payload.get("type")

            try:
                if job_type == "scan":
                    asyncio.run(
                        run_scan(payload["scan_id"])
                    )

                elif job_type == "ffuf":
                    asyncio.run(
                        run_ffuf(payload["run_id"])
                    )

                else:
                    logging.warning(
                        "Unknown job type: %r",
                        job_type,
                    )

            except Exception:
                logging.exception(
                    "Job failed: %s",
                    payload,
                )

        except Exception:
            logging.exception(
                "Worker queue error; retrying..."
            )
            time.sleep(2)


if __name__ == "__main__":
    main()
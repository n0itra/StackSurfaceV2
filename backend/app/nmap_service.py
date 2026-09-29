from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import signal
import shlex
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import select

from .db import SessionLocal
from .models import NmapRun, OpenPort


SCAN_TYPES = {
    "syn": ["-sS"],
    "connect": ["-sT"],
    "udp": ["-sU"],
    "tcp_udp": ["-sS", "-sU"],
    "ack": ["-sA"],
    "window": ["-sW"],
    "fin": ["-sF"],
    "null": ["-sN"],
    "xmas": ["-sX"],
    "maimon": ["-sM"],
}


SAFE_SCRIPT_CATEGORIES = {
    "default",
    "safe",
    "discovery",
    "version",
}


def utcnow():
    return datetime.now(timezone.utc)


def _int(value, minimum, maximum, default):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default

    return max(minimum, min(maximum, value))


def _float_string(value, default=""):
    if value is None:
        return default

    value = str(value).strip()

    if not value:
        return default

    if not re.fullmatch(r"\d+(?:\.\d+)?", value):
        raise ValueError(f"Invalid numeric value: {value}")

    return value


def _time_value(value, default=""):
    if value is None:
        return default

    value = str(value).strip()

    if not value:
        return default

    if not re.fullmatch(
        r"\d+(?:\.\d+)?(?:ms|s|m|h)?",
        value,
        re.IGNORECASE,
    ):
        raise ValueError(f"Invalid time value: {value}")

    return value


def validate_ports(value):
    if value is None:
        return ""

    value = str(value).strip()

    if not value:
        return ""

    if not re.fullmatch(
        r"[0-9A-Za-z*:_,-]+",
        value,
    ):
        raise ValueError("Invalid Nmap port specification")

    return value


def validate_scripts(value):
    if value is None:
        return ""

    value = str(value).strip()

    if not value:
        return ""

    parts = [
        x.strip()
        for x in value.split(",")
        if x.strip()
    ]

    if len(parts) > 32:
        raise ValueError("Too many NSE selections")

    for item in parts:
        if item.lower() == "all":
            raise ValueError(
                "The 'all' NSE selection is disabled in StackSurface"
            )

        if item.lower() not in SAFE_SCRIPT_CATEGORIES:
            if not re.fullmatch(
                r"[A-Za-z0-9_.*-]+",
                item,
            ):
                raise ValueError(
                    f"Invalid NSE script/category: {item}"
                )

    return ",".join(parts)


def normalize_config(config: dict | None) -> dict:
    config = dict(config or {})

    scan_type = str(
        config.get("scan_type", "syn")
    ).lower()

    if scan_type not in SCAN_TYPES:
        raise ValueError("Invalid Nmap scan type")

    port_mode = str(
        config.get("port_mode", "top")
    ).lower()

    if port_mode not in {
        "default",
        "top",
        "all",
        "custom",
    }:
        raise ValueError("Invalid port mode")

    normalized = {
        "scan_type": scan_type,
        "port_mode": port_mode,
        "top_ports": _int(
            config.get("top_ports"),
            1,
            65535,
            1000,
        ),
        "ports": validate_ports(
            config.get("ports")
        ),
        "host_discovery": bool(
            config.get("host_discovery", True)
        ),
        "service_detection": bool(
            config.get("service_detection", True)
        ),
        "version_intensity": _int(
            config.get("version_intensity"),
            0,
            9,
            7,
        ),
        "os_detection": bool(
            config.get("os_detection", False)
        ),
        "default_scripts": bool(
            config.get("default_scripts", False)
        ),
        "scripts": validate_scripts(
            config.get("scripts")
        ),
        "timing": _int(
            config.get("timing"),
            0,
            5,
            3,
        ),
        "ipv6": bool(
            config.get("ipv6", False)
        ),
        "no_dns": bool(
            config.get("no_dns", False)
        ),
        "resolve_all": bool(
            config.get("resolve_all", False)
        ),
        "reason": bool(
            config.get("reason", True)
        ),
        "traceroute": bool(
            config.get("traceroute", False)
        ),
        "open_only": bool(
            config.get("open_only", True)
        ),
        "verbose": _int(
            config.get("verbose"),
            0,
            3,
            1,
        ),
        "max_retries": _int(
            config.get("max_retries"),
            0,
            20,
            0,
        ),
        "min_rate": _float_string(
            config.get("min_rate")
        ),
        "max_rate": _float_string(
            config.get("max_rate")
        ),
        "host_timeout": _time_value(
            config.get("host_timeout")
        ),
        "scan_delay": _time_value(
            config.get("scan_delay")
        ),
        "max_scan_delay": _time_value(
            config.get("max_scan_delay")
        ),
    }

    if (
        normalized["port_mode"] == "custom"
        and not normalized["ports"]
    ):
        raise ValueError(
            "Custom port mode requires a port specification"
        )

    if (
        normalized["min_rate"]
        and normalized["max_rate"]
        and float(normalized["min_rate"])
        > float(normalized["max_rate"])
    ):
        raise ValueError(
            "Minimum rate cannot exceed maximum rate"
        )

    return normalized


def build_nmap_args(
    target: str,
    config: dict,
    xml_path: str,
) -> list[str]:

    config = normalize_config(config)

    args = [
        "nmap"
    ]

    args.extend(
        SCAN_TYPES[config["scan_type"]]
    )

    if config["port_mode"] == "all":
        args.extend(["-p-"])

    elif config["port_mode"] == "top":
        args.extend(
            [
                "--top-ports",
                str(config["top_ports"]),
            ]
        )

    elif config["port_mode"] == "custom":
        args.extend(
            [
                "-p",
                config["ports"],
            ]
        )

    if not config["host_discovery"]:
        args.append("-Pn")

    if config["service_detection"]:
        args.append("-sV")
        args.extend(
            [
                "--version-intensity",
                str(config["version_intensity"]),
            ]
        )

    if config["os_detection"]:
        args.append("-O")

    if config["default_scripts"]:
        args.append("-sC")

    if config["scripts"]:
        args.extend(
            [
                "--script",
                config["scripts"],
            ]
        )

    args.append(
        f"-T{config['timing']}"
    )

    if config["ipv6"]:
        args.append("-6")

    if config["no_dns"]:
        args.append("-n")

    if config["resolve_all"]:
        args.append("--resolve-all")

    if config["reason"]:
        args.append("--reason")

    if config["traceroute"]:
        args.append("--traceroute")

    if config["open_only"]:
        args.append("--open")

    if config["verbose"]:
        args.extend(
            ["-v"] * config["verbose"]
        )

    if config["max_retries"]:
        args.extend(
            [
                "--max-retries",
                str(config["max_retries"]),
            ]
        )

    if config["min_rate"]:
        args.extend(
            [
                "--min-rate",
                config["min_rate"],
            ]
        )

    if config["max_rate"]:
        args.extend(
            [
                "--max-rate",
                config["max_rate"],
            ]
        )

    if config["host_timeout"]:
        args.extend(
            [
                "--host-timeout",
                config["host_timeout"],
            ]
        )

    if config["scan_delay"]:
        args.extend(
            [
                "--scan-delay",
                config["scan_delay"],
            ]
        )

    if config["max_scan_delay"]:
        args.extend(
            [
                "--max-scan-delay",
                config["max_scan_delay"],
            ]
        )

    # Periodic runtime information for the UI.
    args.extend(
        [
            "--stats-every",
            "1s",
        ]
    )

    # XML is the machine-readable source of truth.
    args.extend(
        [
            "-oX",
            xml_path,
        ]
    )

    args.append(target)

    return args


def command_string(args: list[str]) -> str:
    return shlex.join(args)


def parse_nmap_xml(xml_text: str) -> list[dict]:
    if not xml_text.strip():
        return []

    root = ET.fromstring(xml_text)

    results = []

    for host in root.findall("host"):

        addresses = [
            x.attrib.get("addr")
            for x in host.findall("address")
            if x.attrib.get("addr")
        ]

        ip = next(
            (
                x.attrib.get("addr")
                for x in host.findall("address")
                if x.attrib.get("addrtype") in {
                    "ipv4",
                    "ipv6",
                }
            ),
            None,
        )

        hostname = None

        hostnames = host.find("hostnames")

        if hostnames is not None:
            hostname_node = hostnames.find("hostname")

            if hostname_node is not None:
                hostname = hostname_node.attrib.get(
                    "name"
                )

        status_node = host.find("status")

        host_state = (
            status_node.attrib.get("state")
            if status_node is not None
            else None
        )

        os_matches = []

        os_node = host.find("os")

        if os_node is not None:
            for match in os_node.findall("osmatch"):
                os_matches.append(
                    {
                        "name": match.attrib.get("name"),
                        "accuracy": match.attrib.get("accuracy"),
                    }
                )

        ports_node = host.find("ports")

        if ports_node is None:
            continue

        for port_node in ports_node.findall("port"):

            protocol = port_node.attrib.get(
                "protocol",
                "tcp",
            )

            try:
                port = int(
                    port_node.attrib["portid"]
                )
            except (KeyError, ValueError):
                continue

            state_node = port_node.find("state")

            state = (
                state_node.attrib.get("state")
                if state_node is not None
                else None
            )

            service_node = port_node.find("service")

            service = None
            version = None
            product = None
            extrainfo = None

            if service_node is not None:
                service = service_node.attrib.get(
                    "name"
                )

                product = service_node.attrib.get(
                    "product"
                )

                version_number = service_node.attrib.get(
                    "version"
                )

                extrainfo = service_node.attrib.get(
                    "extrainfo"
                )

                parts = [
                    x
                    for x in [
                        product,
                        version_number,
                        extrainfo,
                    ]
                    if x
                ]

                version = " ".join(parts) or None

            scripts = []

            for script in port_node.findall("script"):
                scripts.append(
                    {
                        "id": script.attrib.get("id"),
                        "output": script.attrib.get("output"),
                    }
                )

            results.append(
                {
                    "ip": ip,
                    "addresses": addresses,
                    "hostname": hostname,
                    "host_state": host_state,
                    "port": port,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version,
                    "reason": (
                        state_node.attrib.get("reason")
                        if state_node is not None
                        else None
                    ),
                    "scripts": scripts,
                    "os": os_matches,
                }
            )

    return results


async def _is_stopping(run_id: str) -> bool:
    with SessionLocal() as db:
        run = db.get(NmapRun, run_id)

        return bool(
            run
            and run.status == "stopping"
        )


def _terminate(proc):
    if proc.returncode is not None:
        return

    try:
        os.killpg(
            proc.pid,
            signal.SIGTERM,
        )
    except ProcessLookupError:
        pass


async def run_nmap(run_id: str):
    db = SessionLocal()

    run = db.get(
        NmapRun,
        run_id,
    )

    if not run:
        db.close()
        return

    if run.status == "stopping":
        run.status = "cancelled"
        run.error = (
            "Nmap stopped before execution"
        )
        run.finished_at = utcnow()
        db.commit()
        db.close()
        return

    if run.status != "queued":
        db.close()
        return

    run.status = "running"
    run.started_at = utcnow()

    try:
        config = normalize_config(
            run.config
        )

        xml_path = (
            f"/tmp/stacksurface-nmap-{run.id}.xml"
        )

        args = build_nmap_args(
            run.target,
            config,
            xml_path,
        )

        run.command = command_string(args)

        db.commit()

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        async def stop_watch():
            while proc.returncode is None:
                if await _is_stopping(run_id):
                    _terminate(proc)
                    return True

                await asyncio.sleep(0.5)

            return False

        stop_task = asyncio.create_task(
            stop_watch()
        )

        communicate_task = asyncio.create_task(
            proc.communicate()
        )

        done, _ = await asyncio.wait(
            {
                stop_task,
                communicate_task,
            },
            return_when=asyncio.FIRST_COMPLETED,
        )

        cancelled = False

        if stop_task in done:
            cancelled = bool(
                stop_task.result()
            )

            if communicate_task not in done:
                stdout_b, stderr_b = (
                    await communicate_task
                )
            else:
                stdout_b, stderr_b = (
                    communicate_task.result()
                )

        else:
            stdout_b, stderr_b = (
                communicate_task.result()
            )

            stop_task.cancel()

        stdout = stdout_b.decode(
            errors="replace"
        )

        stderr = stderr_b.decode(
            errors="replace"
        )

        run.output = stdout[-50000:]

        if stderr:
            run.output += (
                "\n\n--- STDERR ---\n"
                + stderr[-20000:]
            )

        run.exit_code = (
            -15
            if cancelled
            else proc.returncode
        )

        if cancelled:
            run.status = "cancelled"
            run.error = (
                "Nmap stopped by user"
            )
            run.finished_at = utcnow()
            db.commit()
            return

        xml_text = ""

        if Path(xml_path).exists():
            xml_text = Path(
                xml_path
            ).read_text(
                encoding="utf-8",
                errors="replace",
            )

        run.xml_output = xml_text[-200000:]

        results = parse_nmap_xml(
            xml_text
        )

        run.results = results

        if proc.returncode != 0:
            run.status = "failed"
            run.error = (
                stderr[-10000:]
                or "Nmap exited with a non-zero status"
            )
        else:
            run.status = "completed"

        run.finished_at = utcnow()

        db.commit()

        # --------------------------------------------------
        # Normalize Nmap into the existing Ports section.
        # --------------------------------------------------

        for item in results:

            if item.get("state") not in {
                "open",
                "open|filtered",
            }:
                continue

            ip = (
                item.get("ip")
                or item.get("hostname")
            )

            port = item.get("port")
            protocol = item.get(
                "protocol",
                "tcp",
            )

            if not ip or not port:
                continue

            existing = db.scalar(
                select(OpenPort).where(
                    OpenPort.scan_id == run.scan_id,
                    OpenPort.ip == ip,
                    OpenPort.port == port,
                    OpenPort.protocol == protocol,
                )
            )

            raw = {
                "nmap_run_id": run.id,
                "nmap": item,
            }

            if existing:

                old_sources = [
                    x.strip()
                    for x in str(
                        existing.source or ""
                    ).split(",")
                    if x.strip()
                ]

                if "nmap" not in old_sources:
                    old_sources.append(
                        "nmap"
                    )

                existing.source = ",".join(
                    sorted(
                        set(old_sources)
                    )
                )

                if item.get("service"):
                    existing.service = item[
                        "service"
                    ]

                if item.get("version"):
                    existing.version = item[
                        "version"
                    ]

                old_raw = (
                    existing.raw
                    if isinstance(
                        existing.raw,
                        dict,
                    )
                    else {}
                )

                existing.raw = {
                    **old_raw,
                    "nmap": item,
                    "nmap_run_id": run.id,
                }

            else:

                db.add(
                    OpenPort(
                        scan_id=run.scan_id,
                        ip=ip,
                        port=port,
                        protocol=protocol,
                        service=item.get(
                            "service"
                        ),
                        version=item.get(
                            "version"
                        ),
                        source="nmap",
                        raw=raw,
                    )
                )

        db.commit()

    except asyncio.CancelledError:
        raise

    except Exception as exc:
        db.rollback()

        run = db.get(
            NmapRun,
            run_id,
        )

        if run:
            run.status = "failed"
            run.error = str(exc)[
                :10000
            ]
            run.finished_at = utcnow()
            db.commit()

    finally:

        try:
            if "xml_path" in locals():
                Path(xml_path).unlink(
                    missing_ok=True
                )
        except Exception:
            pass

        db.close()

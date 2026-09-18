import base64
import ipaddress
import os
from datetime import date, datetime
from urllib.parse import urlparse

import requests
import whois


TIMEOUT = 10

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def make_result(
    source,
    status="unknown",
    verdict="unknown",
    summary="",
    data=None,
    error=None,
):
    return {
        "source": source,
        "status": status,
        "verdict": verdict,
        "summary": summary,
        "data": data or {},
        "error": error,
    }


def normalize_target(target):
    target = str(target or "").strip()

    if not target:
        return ""

    if "://" not in target:
        return target

    parsed = urlparse(target)

    return parsed.hostname or target


def detect_target_type(target):
    target = str(target or "").strip()

    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    if "://" in target:
        parsed = urlparse(target)

        if parsed.hostname:
            return "url"

    return "domain"


def validate_target(target, target_type):
    if not target:
        return False, "Target is empty."

    try:
        if target_type == "ip":
            ipaddress.ip_address(target)
            return True, None

        if target_type == "url":
            parsed = urlparse(target)

            if not parsed.hostname:
                return False, "Invalid URL."

            return True, None

        if target_type == "domain":
            parts = target.split(".")

            if len(parts) < 2:
                return False, "Invalid domain."

            return True, None

    except Exception as exc:
        return False, str(exc)

    return False, "Unsupported target type."


def _hostname(target, target_type):
    if target_type == "url":
        return urlparse(target).hostname

    return target


def _serialize(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, set):
        return list(value)

    if isinstance(value, (list, tuple)):
        return [_serialize(v) for v in value]

    if isinstance(value, dict):
        return {
            str(k): _serialize(v)
            for k, v in value.items()
        }

    return value


def check_virustotal(target, target_type):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return make_result(
            "virustotal",
            status="unavailable",
            verdict="unknown",
            summary="VirusTotal API key is not configured.",
            error="VT_API_KEY is missing.",
        )

    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    try:
        if target_type == "ip":
            endpoint = (
                f"{VT_BASE_URL}/ip_addresses/{target}"
            )

        elif target_type == "domain":
            endpoint = (
                f"{VT_BASE_URL}/domains/{target}"
            )

        elif target_type == "url":
            encoded = base64.urlsafe_b64encode(
                target.encode()
            ).decode().rstrip("=")

            endpoint = (
                f"{VT_BASE_URL}/urls/{encoded}"
            )

        else:
            return make_result(
                "virustotal",
                status="error",
                verdict="unknown",
                error="Unsupported target type.",
            )

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=TIMEOUT,
        )

        if response.status_code in (401, 403):
            return make_result(
                "virustotal",
                status="error",
                verdict="unknown",
                error=(
                    "VirusTotal authentication or "
                    "permission error."
                ),
            )

        if response.status_code == 404:
            return make_result(
                "virustotal",
                status="success",
                verdict="unknown",
                summary=(
                    "VirusTotal has no existing report "
                    "for this target."
                ),
            )

        if response.status_code == 429:
            return make_result(
                "virustotal",
                status="error",
                verdict="unknown",
                error="VirusTotal rate limit reached.",
            )

        response.raise_for_status()

        payload = response.json()

        attributes = (
            payload.get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        malicious = int(
            stats.get("malicious", 0)
        )

        suspicious = int(
            stats.get("suspicious", 0)
        )

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "safe"

        data = {
            "reputation": attributes.get(
                "reputation"
            ),
            "analysis_stats": stats,
        }

        return make_result(
            "virustotal",
            status="success",
            verdict=verdict,
            summary=(
                f"VirusTotal reports "
                f"{malicious} malicious and "
                f"{suspicious} suspicious detections."
            ),
            data=data,
        )

    except requests.Timeout:
        return make_result(
            "virustotal",
            status="error",
            verdict="unknown",
            error="VirusTotal request timed out.",
        )

    except requests.RequestException as exc:
        return make_result(
            "virustotal",
            status="error",
            verdict="unknown",
            error=str(exc),
        )

    except Exception as exc:
        return make_result(
            "virustotal",
            status="error",
            verdict="unknown",
            error=str(exc),
        )


def check_whois(target, target_type):
    hostname = _hostname(
        target,
        target_type,
    )

    if not hostname:
        return make_result(
            "whois",
            status="error",
            verdict="unknown",
            error="Unable to determine hostname.",
        )

    try:
        result = whois.whois(hostname)

        data = {
            "domain": hostname,
            "registrar": _serialize(
                result.get("registrar")
            ),
            "creation_date": _serialize(
                result.get("creation_date")
            ),
            "expiration_date": _serialize(
                result.get("expiration_date")
            ),
            "updated_date": _serialize(
                result.get("updated_date")
            ),
            "name_servers": _serialize(
                result.get("name_servers")
            ),
            "status": _serialize(
                result.get("status")
            ),
        }

        return make_result(
            "whois",
            status="success",
            verdict="unknown",
            summary=(
                "WHOIS registration information "
                "retrieved."
            ),
            data=data,
        )

    except Exception as exc:
        return make_result(
            "whois",
            status="unavailable",
            verdict="unknown",
            summary=(
                "WHOIS information could not "
                "be retrieved."
            ),
            error=str(exc),
        )


SOURCE_REGISTRY = {
    "virustotal": check_virustotal,
    "whois": check_whois,
}

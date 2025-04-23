# src/resource_blocker.py
import os
from typing import List, Set
from selenium.webdriver.chrome.webdriver import WebDriver

_VALID_TYPES: Set[str] = {
    "Document","Stylesheet","Image","Media","Font","Script","TextTrack","XHR",
    "Fetch","EventSource","WebSocket","Manifest","SignedExchange","Ping",
    "CSPViolationReport","Preflight","Other"
}

def _csv_env(name: str) -> List[str]:
    v = os.getenv(name, "")
    return [item.strip() for item in v.split(",") if item.strip()]

def apply_request_blocking(driver: WebDriver) -> None:
    """Read FS_* env vars and install DevTools request-blocking rules."""
    # ---------- URL / extension blacklist ----------
    url_globs = _csv_env("FS_BLOCK_URLS")
    url_globs += [
        f"*{ext.lower()}" if ext.startswith(".") else ext
        for ext in _csv_env("FS_BLOCK_EXT")
    ]
    if url_globs:
        driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": url_globs})

    # ---------- resourceType interception ----------
    types = {t.capitalize() for t in _csv_env("FS_BLOCK_TYPES")}
    if os.getenv("FS_BLOCK_DEFAULTS", "false").lower() == "true":
        types |= {"Image", "Media", "Font"}

    # Keep only the values DevTools understands
    types &= _VALID_TYPES
    if not types:
        return

    driver.execute_cdp_cmd("Network.enable", {})
    patterns = [
        {
            "urlPattern": "*",
            "resourceType": t,
            "interceptionStage": "HeadersReceived",
        }
        for t in types
    ]
    driver.execute_cdp_cmd("Network.setRequestInterception", {"patterns": patterns})

    # Abort intercepted requests
    def _abort(message):
        if message.get("method") != "Network.requestIntercepted":
            return
        p = message["params"]
        driver.execute_cdp_cmd(
            "Network.continueInterceptedRequest",
            {"interceptionId": p["interceptionId"], "errorReason": "Failed"},
        )

    if getattr(driver, "add_cdp_listener", None):
        driver.add_cdp_listener("*", _abort)

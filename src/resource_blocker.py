import os, json, re
from typing import List
from selenium.webdriver.chrome.webdriver import WebDriver

def _csv_env(name: str) -> List[str]:
    v = os.getenv(name, "")
    return [item.strip() for item in v.split(",") if item.strip()]

def apply_request_blocking(driver: WebDriver) -> None:
    """Reads FS_* env vars and programs Chrome DevTools accordingly."""
    url_globs = _csv_env("FS_BLOCK_URLS")
    url_globs += [f"*{ext.lower()}" if ext.startswith(".") else ext
                  for ext in _csv_env("FS_BLOCK_EXT")]

    types = {t.strip().capitalize() for t in _csv_env("FS_BLOCK_TYPES")}
    if os.getenv("FS_BLOCK_DEFAULTS", "false").lower() == "true":
        types |= {"Image", "Media", "Font"}

    # 1️⃣  Blanket URL blocking (fast – no JS executed, no on-DOMContentLoaded):
    if url_globs:
        driver.execute_cdp_cmd("Network.setBlockedURLs",
                               {"urls": url_globs})

    # 2️⃣  Fine-grained resource-type blocking:
    if types:
        driver.execute_cdp_cmd("Network.enable", {})
        patterns = [{"urlPattern": "*", "resourceType": t, "interceptionStage": "HeadersReceived"}
                    for t in types]
        driver.execute_cdp_cmd("Network.setRequestInterception",
                               {"patterns": patterns})

        # Abort the intercepted requests
        def _abort_requests(message):
            if message["method"] != "Network.requestIntercepted":
                return
            interception_id = message["params"]["interceptionId"]
            try:
                driver.execute_cdp_cmd("Network.continueInterceptedRequest",
                                       {"interceptionId": interception_id,
                                        "errorReason": "Failed"})
            except Exception:
                pass   # we're in a best-effort path – ignore races

        # Undetected-chromedriver already wires the Reactor thread;
        # just register our callback on every session:
        if getattr(driver, "add_cdp_listener", None):
            driver.add_cdp_listener("*", _abort_requests)
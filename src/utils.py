import json
import logging
import os
import platform
import re
import shutil
import sys
import tempfile
import urllib.parse
from functools import partial

from selenium.webdriver.chrome.webdriver import WebDriver
import undetected_chromedriver as uc

FLARESOLVERR_VERSION = None
PLATFORM_VERSION = None
CHROME_EXE_PATH = None
CHROME_MAJOR_VERSION = None
USER_AGENT = None
XVFB_DISPLAY = None
PATCHED_DRIVER_PATH = None


def get_config_log_html() -> bool:
    return os.environ.get('LOG_HTML', 'false').lower() == 'true'


def get_config_headless() -> bool:
    return os.environ.get('HEADLESS', 'true').lower() == 'true'


def get_flaresolverr_version() -> str:
    global FLARESOLVERR_VERSION
    if FLARESOLVERR_VERSION is not None:
        return FLARESOLVERR_VERSION

    package_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, 'package.json')
    if not os.path.isfile(package_path):
        package_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'package.json')
    with open(package_path) as f:
        FLARESOLVERR_VERSION = json.loads(f.read())['version']
        return FLARESOLVERR_VERSION

def get_current_platform() -> str:
    global PLATFORM_VERSION
    if PLATFORM_VERSION is not None:
        return PLATFORM_VERSION
    PLATFORM_VERSION = os.name
    return PLATFORM_VERSION


def create_proxy_extension(proxy: dict) -> str:
    # --- Keep this function as is ---
    parsed_url = urllib.parse.urlparse(proxy['url'])
    scheme = parsed_url.scheme
    host = parsed_url.hostname
    port = parsed_url.port
    username = proxy['username']
    password = proxy['password']
    manifest_json = """
    {
        "version": "1.0.0",
        "manifest_version": 2,
        "name": "Chrome Proxy",
        "permissions": [
            "proxy",
            "tabs",
            "unlimitedStorage",
            "storage",
            "<all_urls>",
            "webRequest",
            "webRequestBlocking"
        ],
        "background": {"scripts": ["background.js"]},
        "minimum_chrome_version": "76.0.0"
    }
    """

    background_js = """
    var config = {
        mode: "fixed_servers",
        rules: {
            singleProxy: {
                scheme: "%s",
                host: "%s",
                port: %d
            },
            bypassList: ["localhost"]
        }
    };

    chrome.proxy.settings.set({value: config, scope: "regular"}, function() {});

    function callbackFn(details) {
        return {
            authCredentials: {
                username: "%s",
                password: "%s"
            }
        };
    }

    chrome.webRequest.onAuthRequired.addListener(
        callbackFn,
        { urls: ["<all_urls>"] },
        ['blocking']
    );
    """ % (
        scheme,
        host,
        port,
        username,
        password
    )

    proxy_extension_dir = tempfile.mkdtemp()

    with open(os.path.join(proxy_extension_dir, "manifest.json"), "w") as f:
        f.write(manifest_json)

    with open(os.path.join(proxy_extension_dir, "background.js"), "w") as f:
        f.write(background_js)

    return proxy_extension_dir
# --- End of create_proxy_extension ---


# --- NEW FUNCTION: CDP Network Interceptor Callback ---
def _network_interceptor_callback(driver: WebDriver, event_data: dict, blocked_types: set, blocked_url_patterns: list):
    """
    Callback executed by the CDP event listener for each intercepted network request.
    Decides whether to allow or block the request based on resource type or URL pattern.

    Args:
        driver: The WebDriver instance (needed to send CDP commands).
        event_data: The raw event data from the 'Network.requestIntercepted' event.
        blocked_types: A set of lowercase resource types to block (e.g., {'image', 'media'}).
        blocked_url_patterns: A list of regex patterns to block based on URL.
    """
    # Extract necessary info from the event
    # Structure might vary slightly based on undetected-chromedriver version / CDP changes
    # Check the actual event structure if debugging is needed
    try:
        # Using .get() with default empty dicts for safety
        params = event_data.get('params', {})
        interception_id = params.get('interceptionId')
        request_data = params.get('request', {})
        resource_type = params.get('resourceType', '').lower()
        url = request_data.get('url', '')

        # Essential check: We need an interceptionId to respond
        if not interception_id:
            logging.warning("CDP Interceptor: Received event without interceptionId. Raw event: %s", str(event_data)[:200])
            return # Cannot proceed without interceptionId

        should_block = False

        # 1. Check Resource Type
        if resource_type in blocked_types:
            logging.debug(f"CDP Interceptor: BLOCKING type '{resource_type}' for URL: {url[:100]}...")
            should_block = True

        # 2. Check URL Patterns (only if not already blocked by type)
        if not should_block:
            for pattern in blocked_url_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    logging.debug(f"CDP Interceptor: BLOCKING URL pattern '{pattern}' for URL: {url[:100]}...")
                    should_block = True
                    break # No need to check other patterns for this URL

        # 3. Take Action: Block or Continue
        if should_block:
            driver.execute_cdp_cmd('Network.continueInterceptedRequest', {
                'interceptionId': interception_id,
                'errorReason': 'Aborted'  # Tell Chrome to abort the request
            })
        else:
            # Allow all other requests to proceed normally
            # logging.debug(f"CDP Interceptor: Allowing '{resource_type}' request for URL: {url[:100]}...")
            driver.execute_cdp_cmd('Network.continueInterceptedRequest', {
                'interceptionId': interception_id
            })

    except Exception as e:
        # Catch potential errors if the browser context disappears mid-processing or event structure is unexpected
        logging.warning(f"CDP Interceptor: Error processing interception event. Error: {e}. Raw event: {str(event_data)[:200]}")
        # Attempt to continue the request if possible, otherwise it might hang
        if interception_id:
            try:
                driver.execute_cdp_cmd('Network.continueInterceptedRequest', {'interceptionId': interception_id})
            except Exception as inner_e:
                logging.error(f"CDP Interceptor: Failed to even continue request after error: {inner_e}")
# --- END NEW FUNCTION ---


def get_webdriver(proxy: dict = None) -> WebDriver:
    global PATCHED_DRIVER_PATH, USER_AGENT
    logging.debug('Launching web browser...')

    # --- Configuration for Resource Blocking ---
    enable_blocking = os.environ.get('FS_ENABLE_BLOCKING', 'false').lower() == 'true'
    blocked_types_str = os.environ.get('FS_BLOCKED_TYPES', 'image,media,font,manifest,other') # Default list if enabled
    # --- NEW: Add environment variable for URL patterns ---
    blocked_urls_str = os.environ.get('FS_BLOCKED_URL_PATTERNS', r'\.m3u8') # Default: block .m3u8 files
    # ----------------------------------------------------

    blocked_types_set = set()
    blocked_url_patterns_list = []
    if enable_blocking:
        blocked_types_set = {t.strip().lower() for t in blocked_types_str.split(',') if t.strip()}
        # Split URL patterns by comma, treat each as a regex
        blocked_url_patterns_list = [p.strip() for p in blocked_urls_str.split(',') if p.strip()]
        logging.info(f"Resource blocking enabled.")
        if blocked_types_set:
            logging.info(f"Blocking types: {blocked_types_set}")
        if blocked_url_patterns_list:
            logging.info(f"Blocking URL patterns: {blocked_url_patterns_list}")
    # -----------------------------------------

    # undetected_chromedriver
    options = uc.ChromeOptions()
    # --- Add existing options ---
    options.add_argument('--no-sandbox')
    options.add_argument('--window-size=1920,1080')
    options.add_argument('--disable-search-engine-choice-screen')
    options.add_argument('--disable-setuid-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--no-zygote')
    IS_ARMARCH = platform.machine().startswith(('arm', 'aarch'))
    if IS_ARMARCH:
        options.add_argument('--disable-gpu-sandbox')
        options.add_argument('--disable-software-rasterizer')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--ignore-ssl-errors')
    options.add_argument('--use-gl=swiftshader')

    # --- CDP Logging Pre-requisite ---
    # Performance logs are needed for undetected-chromedriver's reactor to catch Network events
    # Ensure this is set BEFORE initializing the driver if blocking is enabled
    logging_prefs = {'performance': 'ALL', 'browser': 'ALL'}
    if enable_blocking:
        options.set_capability('goog:loggingPrefs', logging_prefs)
        logging.debug("Setting goog:loggingPrefs for CDP interception.")
    # --------------------------------

    language = os.environ.get('LANG', None)
    if language is not None:
        options.add_argument('--accept-lang=%s' % language)

    if USER_AGENT is not None:
        options.add_argument('--user-agent=%s' % USER_AGENT)

    proxy_extension_dir = None
    # --- Existing Proxy Logic (Keep As Is) ---
    if proxy and all(key in proxy for key in ['url', 'username', 'password']):
        proxy_extension_dir = create_proxy_extension(proxy)
        options.add_argument("--load-extension=%s" % os.path.abspath(proxy_extension_dir))
    elif proxy and 'url' in proxy:
        proxy_url = proxy['url']
        logging.debug("Using webdriver proxy: %s", proxy_url)
        options.add_argument('--proxy-server=%s' % proxy_url)
    # ---------------------------------------

    windows_headless = False
    # --- Existing Headless Logic (Keep As Is) ---
    if get_config_headless():
        if os.name == 'nt':
            windows_headless = True
        else:
            start_xvfb_display()
    # ---------------------------------------

    # options.add_argument("--auto-open-devtools-for-tabs") # Keep commented unless debugging CDP

    # --- Existing Driver/Browser Path Logic (Keep As Is) ---
    driver_exe_path = None
    version_main = None
    if os.path.exists("/app/chromedriver"):
        driver_exe_path = "/app/chromedriver"
    else:
        version_main = get_chrome_major_version()
        if PATCHED_DRIVER_PATH is not None:
            driver_exe_path = PATCHED_DRIVER_PATH
    browser_executable_path = get_chrome_exe_path()
    # ------------------------------------------------------

    driver = None  # Initialize driver to None
    try:
        # --- Create the Driver Instance ---
        # Pass enable_cdp_events=True if blocking is enabled, otherwise let uc handle it based on caps
        driver = uc.Chrome(options=options, browser_executable_path=browser_executable_path,
                           driver_executable_path=driver_exe_path, version_main=version_main,
                           windows_headless=windows_headless, headless=get_config_headless(),
                           enable_cdp_events=enable_blocking) # Explicitly enable if blocking
        # ---------------------------------

        # --- SETUP CDP INTERCEPTION (if enabled) ---
        if enable_blocking:
            # Check if the reactor (event listener thread) is running. It should be if enable_cdp_events=True or performance logs are enabled.
            if hasattr(driver, 'reactor') and driver.reactor and driver.reactor.is_alive():
                logging.info("Setting up CDP network request interceptor...")
                try:
                    # 1. Enable network interception for all URL patterns.
                    #    The decision to block/allow happens in the callback.
                    #    Do this *before* adding the listener to avoid race conditions.
                    driver.execute_cdp_cmd("Network.setRequestInterception", {"patterns": [{"urlPattern": "*"}]})
                    logging.debug("CDP command Network.setRequestInterception sent.")

                    # 2. Register the callback for the 'Network.requestIntercepted' event
                    #    Use partial to pass the driver, blocked_types, and blocked_urls to the callback.
                    bound_callback = partial(_network_interceptor_callback, driver,
                                             blocked_types=blocked_types_set,
                                             blocked_url_patterns=blocked_url_patterns_list)
                    # The event name is case-sensitive in the listener map
                    driver.add_cdp_listener("Network.requestIntercepted", bound_callback)
                    logging.info("CDP network request interceptor enabled successfully.")

                except Exception as setup_e:
                    logging.error(f"Failed to set up CDP interception: {setup_e}. Resource blocking may not work.", exc_info=True)
                    # Consider raising the exception or disabling blocking if this setup is critical
            else:
                logging.warning("CDP event reactor not found or not running, cannot set up network interception. Resource blocking disabled.")
                # Optionally, disable blocking if reactor is not available: enable_blocking = False
        # ------------------------------------------

    except Exception as e:
        logging.error(f"Error starting Chrome or setting up interceptor: {e}", exc_info=True)
        # Ensure driver is cleaned up if initialization failed mid-way
        if driver is not None:
            try:
                if get_current_platform() == "nt":
                    driver.close()
                driver.quit()
            except Exception as cleanup_e:
                logging.error(f"Error cleaning up driver after failed start: {cleanup_e}")
        raise e  # Re-raise the original exception to signal failure

    # --- Existing Patched Driver Saving Logic (Keep As Is, ensure driver exists) ---
    if driver_exe_path is None and driver is not None and hasattr(driver, 'patcher') and driver.patcher:
        # Ensure data_path and exe_name exist before joining
        if hasattr(driver.patcher, 'data_path') and hasattr(driver.patcher, 'exe_name'):
            PATCHED_DRIVER_PATH = os.path.join(driver.patcher.data_path, driver.patcher.exe_name)
            # Ensure executable_path exists before comparing and copying
            if hasattr(driver.patcher, 'executable_path') and PATCHED_DRIVER_PATH != driver.patcher.executable_path:
                # Check if source exists before copying
                if os.path.exists(driver.patcher.executable_path):
                    try:
                        shutil.copy(driver.patcher.executable_path, PATCHED_DRIVER_PATH)
                    except Exception as copy_e:
                        logging.error(f"Failed to copy patched driver: {copy_e}")
                else:
                    logging.error(f"Source patched driver not found at {driver.patcher.executable_path}")
        else:
             logging.warning("Driver patcher object missing expected attributes (data_path or exe_name). Cannot save patched driver path.")

    # -----------------------------------------------------------------------------

    # --- Existing Proxy Extension Cleanup (Keep As Is) ---
    if proxy_extension_dir is not None:
        try:
            shutil.rmtree(proxy_extension_dir)
        except Exception as rmtree_e:
             logging.warning(f"Could not remove proxy extension directory {proxy_extension_dir}: {rmtree_e}")
    # ----------------------------------------------------

    if driver is None:
        # This should ideally not be reached if exceptions are raised correctly above
        raise Exception("WebDriver initialization failed.")

    return driver


# --- Keep remaining functions (get_chrome_exe_path, get_chrome_major_version, etc.) as they are ---
def get_chrome_exe_path() -> str:
    global CHROME_EXE_PATH
    if CHROME_EXE_PATH is not None:
        return CHROME_EXE_PATH
    # linux pyinstaller bundle
    chrome_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'chrome', "chrome")
    if os.path.exists(chrome_path):
        if not os.access(chrome_path, os.X_OK):
            raise Exception(f'Chrome binary "{chrome_path}" is not executable. '
                            f'Please, extract the archive with "tar xzf <file.tar.gz>".')
        CHROME_EXE_PATH = chrome_path
        return CHROME_EXE_PATH
    # windows pyinstaller bundle
    chrome_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'chrome', "chrome.exe")
    if os.path.exists(chrome_path):
        CHROME_EXE_PATH = chrome_path
        return CHROME_EXE_PATH
    # system
    CHROME_EXE_PATH = uc.find_chrome_executable()
    return CHROME_EXE_PATH


def get_chrome_major_version() -> str:
    global CHROME_MAJOR_VERSION
    if CHROME_MAJOR_VERSION is not None:
        return CHROME_MAJOR_VERSION

    if os.name == 'nt':
        # Example: '104.0.5112.79'
        try:
            complete_version = extract_version_nt_executable(get_chrome_exe_path())
        except Exception:
            try:
                complete_version = extract_version_nt_registry()
            except Exception:
                # Example: '104.0.5112.79'
                complete_version = extract_version_nt_folder()
    else:
        chrome_path = get_chrome_exe_path()
        process = os.popen(f'"{chrome_path}" --version')
        # Example 1: 'Chromium 104.0.5112.79 Arch Linux\n'
        # Example 2: 'Google Chrome 104.0.5112.79 Arch Linux\n'
        complete_version = process.read()
        process.close()

    CHROME_MAJOR_VERSION = complete_version.split('.')[0].split(' ')[-1]
    return CHROME_MAJOR_VERSION


def extract_version_nt_executable(exe_path: str) -> str:
    import pefile
    pe = pefile.PE(exe_path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    return pe.FileInfo[0][0].StringTable[0].entries[b"FileVersion"].decode('utf-8')


def extract_version_nt_registry() -> str:
    stream = os.popen(
        'reg query "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome"')
    output = stream.read()
    google_version = ''
    for letter in output[output.rindex('DisplayVersion    REG_SZ') + 24:]:
        if letter != '\n':
            google_version += letter
        else:
            break
    return google_version.strip()


def extract_version_nt_folder() -> str:
    # Check if the Chrome folder exists in the x32 or x64 Program Files folders.
    for i in range(2):
        path = 'C:\\Program Files' + (' (x86)' if i else '') + '\\Google\\Chrome\\Application'
        if os.path.isdir(path):
            paths = [f.path for f in os.scandir(path) if f.is_dir()]
            for path in paths:
                filename = os.path.basename(path)
                pattern = '\d+\.\d+\.\d+\.\d+'
                match = re.search(pattern, filename)
                if match and match.group():
                    # Found a Chrome version.
                    return match.group(0)
    return ''


def get_user_agent(driver=None) -> str:
    global USER_AGENT
    if USER_AGENT is not None:
        return USER_AGENT

    temp_driver = None
    try:
        if driver is None:
            temp_driver = get_webdriver() # Create a temporary driver if none provided
            driver = temp_driver

        current_ua = driver.execute_script("return navigator.userAgent")
        # Fix for Chrome 117 | https://github.com/FlareSolverr/FlareSolverr/issues/910
        USER_AGENT = re.sub('HEADLESS', '', current_ua, flags=re.IGNORECASE)
        return USER_AGENT
    except Exception as e:
        raise Exception("Error getting browser User-Agent. " + str(e))
    finally:
        # Clean up the temporary driver if we created one
        if temp_driver is not None:
            try:
                if get_current_platform() == "nt":
                    temp_driver.close()
                temp_driver.quit()
            except Exception as cleanup_e:
                logging.error(f"Error cleaning up temporary driver for User-Agent: {cleanup_e}")


def start_xvfb_display():
    global XVFB_DISPLAY
    if XVFB_DISPLAY is None and platform.system() != 'Windows': # Only run on non-Windows
        try:
            from xvfbwrapper import Xvfb
            logging.info("Starting Xvfb display...")
            XVFB_DISPLAY = Xvfb()
            XVFB_DISPLAY.start()
            logging.info("Xvfb display started.")
        except ImportError:
             logging.warning("xvfbwrapper not installed. Cannot start Xvfb. Headless mode might not work correctly on Linux without a display server.")
        except Exception as e:
             logging.error(f"Failed to start Xvfb display: {e}")


def object_to_dict(_object):
    json_dict = json.loads(json.dumps(_object, default=lambda o: o.__dict__))
    # remove hidden fields
    return {k: v for k, v in json_dict.items() if not k.startswith('__')}
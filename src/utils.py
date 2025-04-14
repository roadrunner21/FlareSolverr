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


# --- NEW FUNCTION ---
def _network_interceptor_callback(driver: WebDriver, event_data: dict, blocked_types: set):
    """
    Callback executed by the CDP event listener for each intercepted network request.
    Decides whether to allow or block the request based on resource type.

    Args:
        driver: The WebDriver instance (needed to send CDP commands).
        event_data: The raw event data from the 'Network.requestIntercepted' event.
        blocked_types: A set of lowercase resource types to block (e.g., {'image', 'media'}).
    """
    interception_id = event_data.get('params', {}).get('interceptionId')
    request_data = event_data.get('params', {}).get('request', {})
    resource_type = event_data.get('params', {}).get('resourceType', '').lower()
    url = request_data.get('url', '')

    # Essential check: We need an interceptionId to respond
    if not interception_id:
        logging.error("CDP Interceptor: Received event without interceptionId!")
        return

    try:
        # Decision Logic: Block if the type is in our set
        if resource_type in blocked_types:
            logging.debug(f"CDP Interceptor: BLOCKING '{resource_type}' request for URL: {url[:100]}...") # Log truncated URL
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
        # Catch potential errors if the browser context disappears mid-processing
        logging.warning(f"CDP Interceptor: Error processing interception {interception_id} for {url[:100]}: {e}")
# --- END NEW FUNCTION ---


def get_webdriver(proxy: dict = None) -> WebDriver:
    global PATCHED_DRIVER_PATH, USER_AGENT
    logging.debug('Launching web browser...')

    # --- Configuration for Resource Blocking ---
    enable_blocking = os.environ.get('FS_ENABLE_BLOCKING', 'false').lower() == 'true'
    blocked_types_str = os.environ.get('FS_BLOCKED_TYPES', 'image,media,font,manifest,other') # Default list if enabled
    blocked_types_set = set()
    if enable_blocking:
        blocked_types_set = {t.strip().lower() for t in blocked_types_str.split(',') if t.strip()}
        logging.info(f"Resource blocking enabled. Blocking types: {blocked_types_set}")
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
    logging_prefs = {'performance': 'ALL', 'browser': 'ALL'}
    options.set_capability('goog:loggingPrefs', logging_prefs)
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

    options.add_argument("--auto-open-devtools-for-tabs")

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
        driver = uc.Chrome(options=options, browser_executable_path=browser_executable_path,
                           driver_executable_path=driver_exe_path, version_main=version_main,
                           windows_headless=windows_headless, headless=get_config_headless())
        # ---------------------------------

        # --- SETUP CDP INTERCEPTION (if enabled) ---
        if enable_blocking and driver is not None:
            if driver.reactor:  # Check if the event listener thread is available
                logging.info("Setting up CDP network request interceptor...")
                try:
                    # 1. Register the callback for the 'Network.requestIntercepted' event
                    #    We use partial to pass the driver and the blocked_types set to the callback.
                    bound_callback = partial(_network_interceptor_callback, driver, blocked_types=blocked_types_set)
                    driver.add_cdp_listener("Network.requestIntercepted", bound_callback)

                    # 2. Enable network interception for all URL patterns.
                    #    The decision to block/allow happens in the callback.
                    driver.execute_cdp_cmd("Network.setRequestInterception", {"patterns": [{"urlPattern": "*"}]})
                    logging.info("CDP network request interceptor enabled successfully.")
                except Exception as setup_e:
                    logging.error(f"Failed to set up CDP interception: {setup_e}. Resource blocking will be disabled.")
                    # Optionally, disable blocking if setup fails: enable_blocking = False
            else:
                logging.warning("CDP event reactor not running, cannot set up network interception. Resource blocking disabled.")
                # Optionally, disable blocking if reactor is not available: enable_blocking = False
        # ------------------------------------------

    except Exception as e:
        logging.error(f"Error starting Chrome or setting up interceptor: {e}")
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
    if driver_exe_path is None and driver is not None and driver.patcher:
        PATCHED_DRIVER_PATH = os.path.join(driver.patcher.data_path, driver.patcher.exe_name)
        if PATCHED_DRIVER_PATH != driver.patcher.executable_path:
             # Check if source exists before copying
            if os.path.exists(driver.patcher.executable_path):
                try:
                    shutil.copy(driver.patcher.executable_path, PATCHED_DRIVER_PATH)
                except Exception as copy_e:
                    logging.error(f"Failed to copy patched driver: {copy_e}")
            else:
                logging.error(f"Source patched driver not found at {driver.patcher.executable_path}")
    # -----------------------------------------------------------------------------

    # --- Existing Proxy Extension Cleanup (Keep As Is) ---
    if proxy_extension_dir is not None:
        shutil.rmtree(proxy_extension_dir)
    # ----------------------------------------------------

    if driver is None:
        # This should ideally not be reached if exceptions are raised correctly above
        raise Exception("WebDriver initialization failed.")

    return driver


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

    try:
        if driver is None:
            driver = get_webdriver()
        USER_AGENT = driver.execute_script("return navigator.userAgent")
        # Fix for Chrome 117 | https://github.com/FlareSolverr/FlareSolverr/issues/910
        USER_AGENT = re.sub('HEADLESS', '', USER_AGENT, flags=re.IGNORECASE)
        return USER_AGENT
    except Exception as e:
        raise Exception("Error getting browser User-Agent. " + str(e))
    finally:
        if driver is not None:
            if PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()


def start_xvfb_display():
    global XVFB_DISPLAY
    if XVFB_DISPLAY is None:
        from xvfbwrapper import Xvfb
        XVFB_DISPLAY = Xvfb()
        XVFB_DISPLAY.start()


def object_to_dict(_object):
    json_dict = json.loads(json.dumps(_object, default=lambda o: o.__dict__))
    # remove hidden fields
    return {k: v for k, v in json_dict.items() if not k.startswith('__')}
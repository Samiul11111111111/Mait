import time
import requests
import logging
import json
import os
import re
import sys
import asyncio
from telegram import Bot
from datetime import datetime
from urllib.parse import urlencode
from bs4 import BeautifulSoup

# === CONFIG ===
BOT_TOKEN = '7786073626:AAEIBA4LM025zRm-c546qiBmRYFeAwc_vA8'
CHAT_IDS = ['-1002760500138']  # Support multiple chat IDs
USERNAME = 'siyambro'
PASSWORD = 'siyambro'

# --- NEW: Define your desired date range here ---
# The script will fetch the default day's data but only process messages within this range.
CUSTOM_START_DATE_STR = "2025-10-21 00:00:00"
CUSTOM_END_DATE_STR = "2025-12-21 23:59:59"

BASE_URL = "http://217.182.195.194"
LOGIN_PAGE_URL = BASE_URL + "/ints/login"
LOGIN_POST_URL = BASE_URL + "/ints/signin"
SMSCDR_STATS_URL = BASE_URL + "/ints/client/SMSCDRStats"
DATA_URL = BASE_URL + "/ints/client/res/data_smscdr.php"

# Flag API
FLAG_API_URL = "https://siyamahmmed.shop/flag.php"

CACHE_FILE = "sent_otps_panel2.json"
DEBUG_FILE = "debug_panel2.log"

# --- Define consistent headers ---
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
ACCEPT_LANGUAGE = "en-IT,en-GB;q=0.9,en-US;q=0.8,en;q=0.7"
ACCEPT_ENCODING = "gzip, deflate"


# Initialize Telegram bot
bot = Bot(token=BOT_TOKEN)

# Global session
session = requests.Session()
CURRENT_PHPSESSID = None
FLAG_DATA = {}
CONSECUTIVE_ERRORS = 0

# --- NEW: Parse custom date strings into datetime objects for comparison ---
try:
    CUSTOM_START_DATE = datetime.strptime(CUSTOM_START_DATE_STR, '%Y-%m-%d %H:%M:%S')
    CUSTOM_END_DATE = datetime.strptime(CUSTOM_END_DATE_STR, '%Y-%m-%d %H:%M:%S')
except ValueError as e:
    # Use logger after it's configured
    logging.basicConfig(level=logging.ERROR) # Basic config if logger fails later
    logging.error(f"❌ Invalid date format in CUSTOM_START_DATE_STR or CUSTOM_END_DATE_STR: {e}")
    sys.exit("Please fix the date format (YYYY-MM-DD HH:MM:SS) and restart.")


# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def load_flags_from_api():
    """Load flag data from API at startup"""
    global FLAG_DATA
    try:
        logger.info("🌍 Loading flag data from API...")
        response = requests.get(FLAG_API_URL, timeout=10)

        if response.status_code == 200:
            flags = response.json()

            # Build lookup dictionary with multiple formats
            for entry in flags:
                code = entry.get('code', '').strip()
                emoji = entry.get('emoji', '🌍')
                name = entry.get('name', 'Unknown')

                if code:
                    # Add with + prefix
                    clean_code = code.replace('+', '').replace(' ', '')
                    FLAG_DATA[clean_code] = {
                        'emoji': emoji,
                        'name': name,
                        'code': code
                    }

            logger.info(f"✅ Loaded {len(FLAG_DATA)} country flags")
            return True
        else:
            logger.warning(f"⚠️ Failed to load flags: HTTP {response.status_code}")
            return False

    except Exception as e:
        logger.error(f"❌ Error loading flags: {e}")
        return False


def load_sent_cache():
    """Load previously sent OTPs from cache"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"❌ Failed to load cache: {e}")
            return {}
    return {}


def save_sent_cache(cache):
    """Save sent OTPs to cache"""
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        logger.error(f"❌ Failed to save cache: {e}")


def mask_phone_number(number):
    """Mask phone number with stars"""
    if len(number) >= 9:
        return number[:5] + '⁕⁕⁕⁕' + number[-4:]
    return number


def extract_otp(message):
    """Extract OTP from message"""
    patterns = [
        r'#\s*?(\d{4,8})\b',
        r'\bOTP[:\s]*([0-9]{3,8})\b',
        r'\bPIN[:\s]*([0-9]{3,8})\b',
        r'\b(\d{2,6})[-\s]+(\d{2,6})\b',
        r'\b\d{4,8}\b'
    ]
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            if len(match.groups()) > 1:
                return match.group(1) + match.group(2)
            return match.group(1) if match.groups() else match.group()
    return None


def get_country_from_number(number):
    """Get country flag and name from phone number using FLAG_DATA"""
    clean_num = re.sub(r'\D', '', number)

    if not clean_num:
        return '🌍', 'Unknown'

    # Sort by longest code first to match most specific
    sorted_codes = sorted(FLAG_DATA.keys(), key=len, reverse=True)

    for code in sorted_codes:
        if clean_num.startswith(code):
            country_info = FLAG_DATA[code]
            return country_info['emoji'], country_info['name']

    return '🌍', 'Unknown'

# --- NEW: Function to convert text to fancy bold ---
def to_fancy_bold(text):
    """Converts ASCII letters to their Unicode bold counterparts."""
    normal_upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    bold_upper   = '𝐀𝐁𝐂𝐃𝐄𝐅𝐆𝐇𝐈𐐀𝐊𝐋𝐌𝐍𝐎𝐏𝐐𝐑𝐒𝐓𝐔𝐕𝐖𝐗𝐘𝐙' # Note: Using Mathematical Alphanumeric Symbols block
    normal_lower = 'abcdefghijklmnopqrstuvwxyz'
    bold_lower   = '𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳'

    translation_table = str.maketrans(normal_upper + normal_lower, bold_upper + bold_lower)
    return text.translate(translation_table)

# --- UPDATED: Message format to match PHP example ---
def format_otp_message(entry):
    """Format OTP message for Telegram"""
    masked_number = mask_phone_number(entry.get('number', 'N/A'))
    otp = entry.get('otp', 'N/A')
    platform_raw = entry.get('platform', 'N/A')
    country_raw = entry.get('country', 'Unknown')
    flag = entry.get('flag', '🌍')
    time_str = entry.get('time', '') # Raw time string from data

    # Try to parse and reformat time, fallback to original if error
    try:
        # Assuming input is like 'YYYY-MM-DD HH:MM:SS'
        dt_obj = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
        time_formatted = dt_obj.strftime("%Y-%m-%d %H:%M:%S") # Keeps original format, adjust if needed
    except ValueError:
        time_formatted = time_str # Fallback

    # Apply fancy bold and escape HTML
    platform = html.escape(platform_raw)
    country = html.escape(country_raw)
    bold_country = to_fancy_bold(country_raw)
    bold_platform = to_fancy_bold(platform_raw)

    # Prepare full message block
    original_message = entry.get('message', '').replace('nn', "\n") # Handle 'nn' newline conversion if needed
    message_block = f"<pre><i>💌𝙵𝚞𝚕𝚕-𝙼𝚎𝚜𝚜𝚊𝚐𝚎:</i>\n{html.escape(original_message.strip())}</pre>"

    # Construct the final message
    text = (
        f"🔔 {flag} {bold_country} {bold_platform} <b>𝐎𝐓𝐏 𝐑𝐞𝐜𝐞𝐢𝐯𝐞𝐝...</b>\n\n"
        f"🔑 <b>𝐘𝐨𝐮𝐫 𝐎𝐓𝐏 :</b> <code>{otp}</code>\n\n"
        f"🕔 <b>𝚃𝚒𝚖𝚎 :</b> <code>{time_formatted}</code>\n"
        f"⚙️ <b>𝚂𝚎𝚛𝚟𝚒𝚌𝐞 :</b> <code>{platform}</code>\n"
        f"🌐 <b>𝙲𝚘𝚞𝚗𝚝𝚛𝚢 :</b> {country} {flag}\n"
        f"☎️ <b>𝙽𝚞𝚖𝚋𝚎𝚛 :</b> <code>{masked_number}</code>\n"
        f"{message_block}\n\n"
        f"🚀 <b>𝐁𝐞 𝐀𝐜𝐭𝐢𝐯𝐞 - 𝐍𝐞𝐰 𝐎𝐓𝐏 𝐂𝐨𝐦𝐢𝐧𝐠...</b>"
    )
    return text


def extract_captcha_from_html(html_content):
    """Extract captcha question and calculate answer from HTML"""
    try:
        # Pattern 1: Look for "What is X + Y = ?" format with various spacing
        patterns = [
            r'What\s+is\s+(\d+)\s*\+\s*(\d+)\s*=\s*\?',  # Standard format
            r'What is (\d+) \+ (\d+) = \?',            # With spaces
            r'(\d+)\s*\+\s*(\d+)\s*=\s*\?',            # Just numbers
            r'name=[\'"]capt[\'"][^>]*>\s*What\s+is\s+(\d+)\s*\+\s*(\d+)',  # Before input field
        ]

        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
            if match:
                num1 = int(match.group(1))
                num2 = int(match.group(2))
                answer = num1 + num2
                logger.info(f"✅ Captcha found: {num1} + {num2} = {answer}")
                return answer

        # Pattern 2: Extract from the vicinity of the capt input field
        capt_section = re.search(
            r'What\s+is\s+(\d+)\s*\+\s*(\d+)\s*=\s*\?\s*:\s*<input[^>]*name=[\'"]capt[\'"]',
            html_content,
            re.IGNORECASE | re.DOTALL
        )

        if capt_section:
            num1 = int(capt_section.group(1))
            num2 = int(capt_section.group(2))
            answer = num1 + num2
            logger.info(f"✅ Captcha found (pattern 2): {num1} + {num2} = {answer}")
            return answer

        # If still not found, log a sample of the HTML for debugging
        logger.error("❌ Could not find captcha in response")

        # Find and log the area around 'capt' input
        capt_area = re.search(r'.{0,200}name=[\'"]capt[\'"]{0,200}', html_content, re.DOTALL)
        if capt_area:
            logger.debug(f"Captcha area: {capt_area.group()}")
        else:
            logger.debug(f"Response preview (first 1000 chars): {html_content[:1000]}")

        return None

    except Exception as e:
        logger.error(f"❌ Error extracting captcha: {e}")
        return None


def extract_csstr_from_page(html_content):
    """Extract csstr parameter from SMSCDRStats page JavaScript"""
    try:
        # Look for csstr in the sAjaxSource parameter
        # Pattern: "sAjaxSource": "res/data_smscdr.php?...&csstr=HASH..."
        ajax_pattern = r'sAjaxSource["\s:]+["\']res/data_smscdr\.php\?[^"\']*csstr=([a-f0-9]{32})'
        match = re.search(ajax_pattern, html_content, re.IGNORECASE)

        if match:
            csstr = match.group(1)
            logger.info(f"✅ Found csstr in sAjaxSource: {csstr}")
            return csstr

        logger.warning("⚠️ Could not find csstr in sAjaxSource, trying fallbacks...")
        # Fallback patterns
        patterns = [
            r'csstr=([a-f0-9]{32})',
            r'csstr[\'"]?\s*[:=]\s*[\'"]([a-f0-9]{32})[\'"]',
            r'"csstr"\s*:\s*"([a-f0-9]{32})"',
            r'var\s+csstr\s*=\s*[\'"]([a-f0-9]{32})[\'"]',
        ]

        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                csstr = match.group(1)
                logger.info(f"✅ Found csstr (fallback): {csstr}")
                return csstr

        logger.warning("⚠️ Could not find csstr in page")
        # Save a snippet for debugging
        ajax_section = re.search(r'sAjaxSource.{0,300}', html_content, re.IGNORECASE | re.DOTALL)
        if ajax_section:
            logger.debug(f"Ajax section: {ajax_section.group()}")

        return None

    except Exception as e:
        logger.error(f"❌ Error extracting csstr: {e}")
        return None

def extract_dates_from_page(html_content):
    """Extract default fdate1 and fdate2 from HTML"""
    try:
        fdate1_match = re.search(r"id='datetimepicker1'[^>]*value='([^']+)'", html_content)
        fdate2_match = re.search(r"id='datetimepicker2'[^>]*value='([^']+)'", html_content)

        if fdate1_match and fdate2_match:
            fdate1 = fdate1_match.group(1)
            fdate2 = fdate2_match.group(1)
            logger.info(f"✅ Found default dates: {fdate1} to {fdate2}")
            return fdate1, fdate2
        else:
            logger.error("❌ Could not find default dates in HTML")
            return None, None
    except Exception as e:
        logger.error(f"❌ Error extracting dates: {e}")
        return None, None


def get_session_details():
    """
    Get csstr, fdate1, and fdate2 by visiting SMSCDRStats page.
    Returns (csstr, fdate1, fdate2) or (None, None, None) on failure.
    """
    try:
        logger.info("🔍 Fetching session details (csstr, default dates) from SMSCDRStats page...")

        headers = {
            "User-Agent": USER_AGENT,
            "Referer": BASE_URL + "/ints/client/", # Referer is the dashboard
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": ACCEPT_LANGUAGE,
            "Accept-Encoding": ACCEPT_ENCODING,
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

        resp = session.get(SMSCDR_STATS_URL, headers=headers, timeout=60)

        if resp.status_code == 200:
            # Save for debugging (with error handling)
            try:
                with open("smscdr_page_debug.html", "w", encoding="utf-8") as f:
                    f.write(resp.text)
                logger.info("📝 SMSCDRStats page saved for debugging")
            except PermissionError:
                logger.warning("⚠️ Could not save smscdr_page_debug.html (file may be open)")
            except Exception as e:
                logger.warning(f"⚠️ Could not save debug file: {e}")

            # Extract all three pieces of info
            csstr = extract_csstr_from_page(resp.text)
            fdate1, fdate2 = extract_dates_from_page(resp.text)

            if csstr and fdate1 and fdate2:
                logger.info(f"✅ Session details acquired!")
                return csstr, fdate1, fdate2
            else:
                logger.error("❌ Could not extract all session details (csstr/dates)")
                return None, None, None

        elif resp.status_code == 403 or "login" in resp.text.lower():
            logger.error(f"❌ Session invalid, cannot get session details (Status: {resp.status_code})")
            return None, None, None
        else:
            logger.error(f"❌ Failed to get SMSCDRStats page: {resp.status_code}")
            return None, None, None

    except Exception as e:
        logger.error(f"❌ Error getting session details: {e}")
        return None, None, None


def login():
    """Login to the panel"""
    global CURRENT_PHPSESSID, CONSECUTIVE_ERRORS
    session.cookies.clear()
    logger.info("🍪 Session cookies cleared (pre-login)")
    try:
        logger.info("🔐 Starting login process...")
        logger.info(f"🌐 Login page URL: {LOGIN_PAGE_URL}")

        # Step 1: Get login page
        logger.info("⏳ Fetching login page...")

        login_page_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": ACCEPT_LANGUAGE,
            "Accept-Encoding": ACCEPT_ENCODING,
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        resp = session.get(LOGIN_PAGE_URL, headers=login_page_headers, timeout=60)

        logger.info(f"✅ Login page received (Status: {resp.status_code})")

        if resp.status_code != 200:
            logger.error(f"❌ HTTP {resp.status_code} - Cannot access login page")
            return False

        # Save response for debugging (with error handling)
        try:
            with open("login_page_debug.html", "w", encoding="utf-8") as f:
                f.write(resp.text)
            logger.info("📝 Login page saved to login_page_debug.html")
        except PermissionError:
            logger.warning("⚠️ Could not save login_page_debug.html (file may be open)")
        except Exception as e:
            logger.warning(f"⚠️ Could not save debug file: {e}")

        # Extract captcha answer
        captcha_answer = extract_captcha_from_html(resp.text)

        if captcha_answer is None:
            logger.error("❌ Could not solve captcha")
            return False

        # Step 2: Post login
        logger.info("⏳ Posting login credentials...")
        time.sleep(2)

        payload = {
            "username": USERNAME,
            "password": PASSWORD,
            "capt": str(captcha_answer)
        }

        post_headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": LOGIN_PAGE_URL,
            "Origin": BASE_URL,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": ACCEPT_LANGUAGE,
            "Accept-Encoding": ACCEPT_ENCODING,
            "Upgrade-Insecure-Requests": "1"
        }

        resp = session.post(LOGIN_POST_URL, data=payload, headers=post_headers, timeout=60, allow_redirects=True)

        logger.info(f"✅ Login response received (Status: {resp.status_code})")

        # Check for success
        success_keywords = ["dashboard", "logout", "smscdrstats", "welcome", "facebook2"]
        login_success = any(keyword in resp.text.lower() for keyword in success_keywords)

        if login_success:
            logger.info("✅ Login successful!")

            # Extract PHPSESSID
            if 'PHPSESSID' in session.cookies:
                CURRENT_PHPSESSID = session.cookies['PHPSESSID']
                logger.info(f"✅ PHPSESSID: {CURRENT_PHPSESSID}")

            CONSECUTIVE_ERRORS = 0
            return True
        else:
            logger.error("❌ Login failed")
            return False

    except requests.exceptions.Timeout:
        logger.error("❌ Login timeout")
        CONSECUTIVE_ERRORS += 1
        return False
    except Exception as e:
        logger.error(f"❌ Login error: {e}", exc_info=True)
        CONSECUTIVE_ERRORS += 1
        return False


def fetch_data():
    """Fetch SMS data from panel using default dates"""
    global CONSECUTIVE_ERRORS
    try:
        logger.info("♻️ Refreshing session details (csstr + default dates)...")
        current_csstr, default_start_date, default_end_date = get_session_details()

        if not current_csstr or not default_start_date or not default_end_date:
            logger.error("❌ Could not refresh session details. Assuming session is dead.")
            CONSECUTIVE_ERRORS = 3  # Force re-login
            return None

        timestamp = int(time.time() * 1000)

        # --- Use the DEFAULT dates extracted from the page ---
        base_params = {
            'fdate1': default_start_date,
            'fdate2': default_end_date,
            'frange': '',
            'fnum': '',
            'fcli': '',
            'fgdate': '',
            'fgmonth': '',
            'fgrange': '',
            'fgnumber': '',
            'fgcli': '',
            'fg': '0',
            'csstr': current_csstr
        }
        # Manually encode this part
        base_url_with_filters = DATA_URL + "?" + urlencode(base_params)

        # Part 2: The parameters DataTables *adds* to the request
        ajax_params = {
            'sEcho': '1',
            'iColumns': '7',
            'sColumns': ',,,,,',
            'iDisplayStart': '0',
            'iDisplayLength': '25', # Fetch only 25 at a time initially
            'mDataProp_0': '0',
            'sSearch_0': '',
            'bRegex_0': 'false',
            'bSearchable_0': 'true',
            'bSortable_0': 'true',
            'mDataProp_1': '1',
            'sSearch_1': '',
            'bRegex_1': 'false',
            'bSearchable_1': 'true',
            'bSortable_1': 'true',
            'mDataProp_2': '2',
            'sSearch_2': '',
            'bRegex_2': 'false',
            'bSearchable_2': 'true',
            'bSortable_2': 'true',
            'mDataProp_3': '3',
            'sSearch_3': '',
            'bRegex_3': 'false',
            'bSearchable_3': 'true',
            'bSortable_3': 'true',
            'mDataProp_4': '4',
            'sSearch_4': '',
            'bRegex_4': 'false',
            'bSearchable_4': 'true',
            'bSortable_4': 'true',
            'mDataProp_5': '5',
            'sSearch_5': '',
            'bRegex_5': 'false',
            'bSearchable_5': 'true',
            'bSortable_5': 'true',
            'mDataProp_6': '6',
            'sSearch_6': '',
            'bRegex_6': 'false',
            'bSearchable_6': 'true',
            'bSortable_6': 'true',
            'sSearch': '',
            'bRegex': 'false',
            'iSortCol_0': '0',
            'sSortDir_0': 'desc',
            'iSortingCols': '1',
            '_': str(timestamp)
        }

        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": ACCEPT_LANGUAGE,
            "Accept-Encoding": ACCEPT_ENCODING,
            "Connection": "keep-alive",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": USER_AGENT,
            "Referer": SMSCDR_STATS_URL
        }

        # Make the request with the base URL and the *added* ajax_params
        response = session.get(base_url_with_filters, params=ajax_params, headers=headers, timeout=60)

        if response.status_code == 200:
            try:
                # --- FIX: Check for the "Direct Script Access" error in the response ---
                if "Direct Script Access Not Allowed" in response.text:
                    logger.error("❌ Server blocked request: 'Direct Script Access Not Allowed'")
                    logger.error("This means the browser fingerprint is still wrong.")
                    CONSECUTIVE_ERRORS = 3 # Force re-login and try again
                    return None

                data = response.json()
                if 'aaData' in data:
                    record_count = len(data['aaData'])
                    logger.info(f"✅ Fetched {record_count} records (using default dates)")
                    CONSECUTIVE_ERRORS = 0
                    return data
                else:
                    logger.warning("⚠️ No 'aaData' in response")
                    logger.debug(f"Response: {response.text[:500]}")
                    CONSECUTIVE_ERRORS += 1
                    if "session expired" in response.text.lower() or "login" in response.text.lower():
                        logger.warning("Session expired, forcing re-login")
                        CONSECUTIVE_ERRORS = 3
                    return None
            except json.JSONDecodeError as e:
                logger.error(f"❌ JSON decode error: {e}")
                logger.debug(f"Response: {response.text[:500]}")
                # Also check for HTML error messages if JSON fails
                if "Direct Script Access Not Allowed" in response.text:
                    logger.error("❌ Server blocked request: 'Direct Script Access Not Allowed'")
                    CONSECUTIVE_ERRORS = 3
                elif "session expired" in response.text.lower() or "login" in response.text.lower():
                    logger.warning("Session expired, forcing re-login")
                    CONSECUTIVE_ERRORS = 3
                else:
                    CONSECUTIVE_ERRORS += 1
                return None
        elif response.status_code == 403:
            logger.error("❌ 403 Forbidden - Need re-login")
            CONSECUTIVE_ERRORS = 3  # Force re-login immediately
            return None
        else:
            logger.warning(f"⚠️ Status {response.status_code}")
            CONSECUTIVE_ERRORS += 1
            return None

    except requests.exceptions.Timeout:
        logger.error("❌ Fetch timeout")
        CONSECUTIVE_ERRORS += 1
        return None
    except Exception as e:
        logger.error(f"❌ Fetch error: {e}")
        CONSECUTIVE_ERRORS += 1
        return None


async def process_messages():
    """Check and send new messages, filtering by custom date range"""
    global CONSECUTIVE_ERRORS
    try:
        logger.info("🔍 Checking for new messages...")
        data = fetch_data() # Fetches using default dates from the page

        if data is None:
            logger.warning(f"⚠️ Could not fetch data. Errors: {CONSECUTIVE_ERRORS}")

            # Re-login after 3 consecutive errors
            if CONSECUTIVE_ERRORS >= 3:
                logger.warning("🔄 Attempting re-login...")
                logger.info("🍪 Session cookies will be cleared by login()")

                if login():
                    logger.info("✅ Re-login successful")
                    CONSECUTIVE_ERRORS = 0
                else:
                    logger.error("❌ Re-login failed")
            return

        sent_cache = load_sent_cache()
        new_count = 0
        processed_count = 0

        for row in data.get('aaData', []):
            try:
                processed_count += 1
                if not row or len(row) < 5:
                    continue

                time_str = str(row[0]).strip()
                range_name = str(row[1]).strip()  # Platform/Range name
                number = str(row[2]).strip()
                sender = str(row[3]).strip()
                message = str(row[4]).strip()

                if not number or not message:
                    continue

                # --- NEW: Filter by custom date range ---
                try:
                    message_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                    if not (CUSTOM_START_DATE <= message_time <= CUSTOM_END_DATE):
                        #logger.debug(f"Skipping message outside custom date range: {time_str}")
                        continue # Skip if outside the desired range
                except ValueError:
                    logger.warning(f"⚠️ Could not parse message timestamp: {time_str}. Skipping date check.")
                    continue # Skip if timestamp is invalid


                # Create unique key
                unique_key = f"{time_str}|{number}|{message}"

                # Check if already sent
                if unique_key in sent_cache:
                    continue

                # Extract OTP
                otp = extract_otp(message)
                if not otp:
                    continue

                # Get country info
                flag, country = get_country_from_number(number)

                # Use sender as platform, or range_name if sender is empty
                platform = sender if sender else range_name

                # Prepare entry
                entry = {
                    'time': time_str,
                    'number': number,
                    'platform': platform,
                    'message': message,
                    'otp': otp,
                    'country': country,
                    'flag': flag
                }

                # Format and send message
                formatted_msg = format_otp_message(entry)

                try:
                    for chat_id in CHAT_IDS:
                        await bot.send_message(
                            chat_id=chat_id,
                            text=formatted_msg,
                            parse_mode='HTML'
                        )

                    # Mark as sent
                    sent_cache[unique_key] = True
                    save_sent_cache(sent_cache)

                    logger.info(f"📤 Sent: OTP {otp} from {platform} to {number} ({country})")
                    new_count += 1

                    await asyncio.sleep(0.5)

                except Exception as e:
                    logger.error(f"❌ Telegram send error: {e}")

            except Exception as e:
                logger.error(f"❌ Error processing row: {e}")
                continue
        
        # Log summary
        total_fetched = len(data.get('aaData', []))
        logger.info(f"🔎 Processed {processed_count}/{total_fetched} fetched records.")
        if new_count > 0:
            logger.info(f"📊 Sent {new_count} new messages within custom date range.")
        else:
             logger.info(f"📊 No new messages found within custom date range ({CUSTOM_START_DATE_STR} to {CUSTOM_END_DATE_STR}).")


    except Exception as e:
        logger.error(f"❌ Process error: {e}", exc_info=True)
        CONSECUTIVE_ERRORS += 1


async def main():
    """Main loop"""
    global CONSECUTIVE_ERRORS

    logger.info("=" * 70)
    logger.info("🚀 OTP BOT Panel 2 - ACTIVE MONITORING (v-Fixed-9)")
    logger.info("ℹ️ Using DYNAMIC default dates from page + CLIENT-SIDE filtering")
    logger.info(f"🗓️ Filtering for messages between: {CUSTOM_START_DATE_STR} and {CUSTOM_END_DATE_STR}")
    logger.info(f"📱 Chat IDs: {CHAT_IDS}")
    logger.info(f"🌐 Base URL: {BASE_URL}")
    logger.info("=" * 70)

    # Load flags at startup
    if not load_flags_from_api():
        logger.warning("⚠️ Could not load flags, will use fallback")

    # Initial login
    if not login():
        logger.error("❌ Initial login failed")
        return

    logger.info("✅ Bot initialized!")
    logger.info("🔄 Starting 3-second refresh loop...\n")

    loop_count = 0
    successful_fetches = 0
    failed_fetches = 0

    while True:
        try:
            loop_count += 1
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if loop_count % 20 == 1:
                logger.info(f"--- Loop #{loop_count} at {current_time} | Success: {successful_fetches} | Failed: {failed_fetches} ---")

            await process_messages()

            if CONSECUTIVE_ERRORS == 0:
                successful_fetches += 1
            else:
                failed_fetches += 1

            # 3-second refresh
            await asyncio.sleep(3)

        except KeyboardInterrupt:
            logger.info("\n⚠️ Bot stopped by user")
            break
        except Exception as e:
            logger.error(f"❌ Main loop error: {e}", exc_info=True)
            CONSECUTIVE_ERRORS += 1
            await asyncio.sleep(5)

    logger.info("=" * 70)
    logger.info("📊 FINAL STATISTICS:")
    logger.info(f"Total loops: {loop_count}")
    logger.info(f"Successful fetches: {successful_fetches}")
    logger.info(f"Failed fetches: {failed_fetches}")
    logger.info("=" * 70)


if __name__ == "__main__":
    print("🤖 OTP BOT Panel 2 v2.9-fix - Press Ctrl+C to stop")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n✋ Bot stopped")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
    finally:
        print("👋 Shutdown complete")



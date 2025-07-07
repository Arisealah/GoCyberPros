#!/usr/bin/env python3
"""
TXT Metadata Extraction Tool (Enhanced)

Description: Comprehensive and robust metadata extraction from plain text files,
with advanced validation, detailed error handling, and standardized, enriched output.

Features:
- Extracts encoding, line statistics, word/character counts.
- Validates text file structure rigorously.
- Handles various encodings robustly.
- Outputs standardized, structured metadata including warnings and errors.

Dependencies:
- chardet (pip install chardet)
- python-magic (pip install python-magic)
- ssdeep (pip install ssdeep) - Requires C++ build tools on Windows
- textstat (pip install textstat)
- langdetect (pip install langdetect)
- vaderSentiment (pip install vaderSentiment)
- nltk (pip install nltk) - requires nltk.download('punkt') and nltk.download('stopwords')
- pywin32 (pip install pywin32) - Windows only, for ACLs

Example Usage (CLI):
    python3 txt_extractor.py example.txt --log-level DEBUG -o metadata.json

Author: Gemini (based on provided foundation)
Version: 1.3.0
Last Updated: 2025-06-27
"""

import os
import chardet
import magic
import mimetypes
from datetime import datetime, timezone
# import pytz # For local time conversion if needed, otherwise timezone.tzname is okay
from typing import Dict, Any, Optional, List
import logging
import sys
import argparse
import time
import json
import hashlib
import stat
import math
import re
import string
from collections import Counter
import unicodedata # For Unicode category counts
import base64 # For decoding base64 snippets
import binascii # For decoding hex snippets
import urllib.parse # For URL decoding
import platform # To check OS for ACLs
import nltk
nltk.download('vader_lexicon')


# --- Optional external libraries ---
try:
    import ssdeep
except ImportError:
    ssdeep = None
    logging.warning("ssdeep library not found. Fuzzy hashing (SSDEEP) will not be available.")
try:
    import textstat
except ImportError:
    textstat = None
    logging.warning("textstat library not found. Readability scores will not be available.")
try:
    from langdetect import detect, DetectorFactory
    DetectorFactory.seed = 0 # Ensure consistent results
except ImportError:
    detect = None
    logging.warning("langdetect library not found. Language detection will not be available.")
# try:
#     from nltk.sentiment.vader import SentimentIntensityAnalyzer
#     import nltk
#     try:
#         nltk.data.find('sentiment/vader_lexicon.zip')
#     except nltk.downloader.DownloadError:
#         logging.warning("VADER lexicon not found, downloading NLTK data for sentiment analysis.")
#         nltk.download('vader_lexicon', quiet=True)
#     sid = SentimentIntensityAnalyzer()
# except ImportError:
#     SentimentIntensityAnalyzer = None
#     sid = None
#     logging.warning("vaderSentiment library not found. Sentiment analysis will not be available.")
# except LookupError:
#     SentimentIntensityAnalyzer = None
#     sid = None
#     logging.warning("NLTK 'vader_lexicon' not found. Sentiment analysis will not be available. Run: python -c 'import nltk; nltk.download(\"vader_lexicon\")'")

import logging

try:
    from nltk.sentiment.vader import SentimentIntensityAnalyzer
    import nltk
    try:
        nltk.data.find('sentiment/vader_lexicon.zip')
    except LookupError:
        logging.warning("VADER lexicon not found, downloading NLTK data for sentiment analysis.")
        nltk.download('vader_lexicon', quiet=True)
    sid = SentimentIntensityAnalyzer()
except ImportError:
    SentimentIntensityAnalyzer = None
    sid = None
    logging.warning("vaderSentiment library not found. Sentiment analysis will not be available.")
except LookupError:
    SentimentIntensityAnalyzer = None
    sid = None
    logging.warning("NLTK 'vader_lexicon' not found. Sentiment analysis will not be available. Run: python -c 'import nltk; nltk.download(\"vader_lexicon\")'")


# For Windows ACLs
if platform.system() == "Windows":
    try:
        import win32security
        logging.info("pywin32 (win32security) found for Windows ACLs.")
    except ImportError:
        win32security = None
        logging.warning("pywin32 library not found. Advanced Windows ACLs will not be available.")
else:
    win32security = None # Not on Windows, so set to None


# --- Configuration ---
DEFAULT_LOG_FILE = "txt_extractor.log"
DEFAULT_LOG_LEVEL = "INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Expected TXT MIME types (can vary, so using a broad startswith check)
EXPECTED_TXT_MIME_PREFIX = 'text/'

# Regex patterns for various indicators
REGEX_PATTERNS = {
    "url": r"https?://[^\s\"'>]+",
    "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "windows_path": r"[a-zA-Z]:(?:\\(?:[a-zA-Z0-9_.-]+))+",
    "linux_path": r"(?:\/(?:[a-zA-Z0-9_.-]+))+",
    "md5_hash": r"\b[0-9a-fA-F]{32}\b",
    "sha1_hash": r"\b[0-9a-fA-F]{40}\b", # Added SHA1
    "sha256_hash": r"\b[0-9a-fA-F]{64}\b",
    "ntlm_hash": r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b", # Added NTLM (common format)
    # Generic base64-like and hex_string patterns for detection and attempted decoding
    "base64_like": r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", # At least 10 blocks of 4 chars
    "hex_string": r"\b(?:[0-9a-fA-F]{2}){20,}\b", # At least 20 bytes in hex
    "url_encoded": r"%[0-9a-fA-F]{2}", # For URL encoding detection
    "eval_exec_string": r"\b(?:eval|exec)\s*\(", # Simple eval/exec check
    "common_keywords": r"\b(?:password|confidential|API_KEY|private key|secret|threat actor|CVE-\d{4}-\d{4,}|exploit|malware|shellcode|phishing)\b", # Case-insensitive handled in code
    "markdown_headers": r"^\s*#+\s.*$", # E.g., # Header, ## Subheader
    "markdown_lists": r"^\s*[-\*\+]\s.*$", # E.g., - item, * item
    "json_like_start": r"^\s*[{[]", # Starts with { or [
    "xml_like_start": r"^\s*<[^>]+>", # Starts with <tag>
    "csv_like_delimiters": r"[\t,;]", # Detects common delimiters
    "comments_hash": r"^\s*#.*$",           # Python/bash style comments
    "comments_double_slash": r"^\s*//.*$",  # C/C++/Java/JS style comments
    "comments_sql": r"^\s*--.*$",           # SQL style comments
}

# --- Logging Setup ---
def setup_logging(log_level: str = DEFAULT_LOG_LEVEL):
    """Configures the logging for the extractor."""
    log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers to prevent duplicate output when called multiple times
    if root_logger.handlers:
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)

    # File Handler
    file_handler = logging.FileHandler(DEFAULT_LOG_FILE, encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

# Initial logging setup
setup_logging()
logger = logging.getLogger(__name__)

# --- Custom Exception Classes ---
class TXTMetadataError(Exception):
    """Base class for TXT metadata extraction exceptions."""
    pass

class FileAccessError(TXTMetadataError):
    """Raised for issues accessing the file (e.g., not found, permissions)."""
    pass

class InvalidFileFormatError(TXTMetadataError):
    """Raised when the file is not a valid text file according to checks."""
    pass

class ExtractorProcessingError(TXTMetadataError):
    """Raised for unexpected errors during the TXT extraction process."""
    pass

# --- Main Validation Function ---
def validate_txt_file(file_path: str) -> bool:
    """
    Advanced validation for plain text file.

    Args:
        file_path: Path to the text file.

    Returns:
        True if the file passes all validations.

    Raises:
        FileAccessError: If file doesn't exist or access is restricted.
        InvalidFileFormatError: If file is not deemed a valid text file.
    """
    logger.info(f"Validating file: {file_path}")

    if not os.path.exists(file_path):
        raise FileAccessError(f"File not found: {file_path}")

    if not os.path.isfile(file_path):
        raise FileAccessError(f"Path is not a regular file: {file_path}")

    if not os.access(file_path, os.R_OK):
        raise FileAccessError(f"Access denied (read permission): {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        logger.warning(f"File {file_path} is empty, which might not be a meaningful text file.")
        # An empty text file can still be valid, so not a hard error unless content is expected.
        # For now, mark as warning and continue.

    # MIME Type Check (using both magic and mimetypes)
    mime_type_magic = magic.from_file(file_path, mime=True)
    mime_type_ext = mimetypes.guess_type(file_path)[0]

    is_mime_ok = mime_type_magic.startswith(EXPECTED_TXT_MIME_PREFIX)
    if not is_mime_ok:
        if mime_type_ext and mime_type_ext.startswith(EXPECTED_TXT_MIME_PREFIX):
            logger.warning(f"Magic detected '{mime_type_magic}', but extension suggests text ('{mime_type_ext}'). Proceeding.")
        else:
            raise InvalidFileFormatError(f"Not a recognized text file type by magic ({mime_type_magic}).")

    # Try a small read to ensure basic readability (prevents errors on very odd files)
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            f.read(100) # Try reading first 100 characters
    except Exception as e:
        logger.error(f"Initial read test failed for {file_path}: {e}", exc_info=True)
        raise InvalidFileFormatError(f"File content is unreadable or malformed: {str(e)}") from e

    logger.info(f"File '{file_path}' passed all structural validations.")
    return True

# --- Utility Functions for Enhanced Metadata ---

def human_readable_size(size, decimal_places=2):
    """Convert bytes to human-readable format."""
    for unit in ['B','KB','MB','GB','TB']:
        if size < 1024.0:
            return f"{size:.{decimal_places}f} {unit}"
        size /= 1024.0
    return f"{size:.{decimal_places}f} PB"

def get_file_hashes(file_path):
    """Calculate file hashes (MD5, SHA256, SSDEEP)."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    ssdeep_hash = "N/A"

    try:
        with open(file_path, "rb") as f:
            data = f.read() # Read all for ssdeep, or in chunks for very large files
            md5_hash.update(data)
            sha256_hash.update(data)
            if ssdeep:
                ssdeep_hash = ssdeep.hash(data)
    except Exception as e:
        logger.error(f"Error calculating hashes for {file_path}: {e}")
        return "N/A", "N/A", "N/A"

    return md5_hash.hexdigest(), sha256_hash.hexdigest(), ssdeep_hash

def get_permissions_and_owner_details(file_path):
    """Get file permissions, owner, group, and (attempt) ACLs."""
    perms_octal = "N/A"
    perms_symbolic = "N/A"
    owner_name = "N/A"
    group_name = "N/A"
    acls_info = "Not extracted (requires platform-specific access)"

    try:
        st = os.stat(file_path)
        perms_octal = oct(st.st_mode & 0o777)
        perms_symbolic = stat.filemode(st.st_mode)

        if sys.platform == "win32":
            if win32security:
                try:
                    # Get owner and primary group
                    sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION)
                    owner_sid = sd.GetOwner()
                    group_sid = sd.GetGroup()
                    owner_name, domain, type = win32security.LookupAccountSid(None, owner_sid)
                    group_name, domain, type = win32security.LookupAccountSid(None, group_sid)

                    # Get ACLs (DACL - Discretionary Access Control List)
                    dacl = sd.GetSecurityDescriptorDacl()
                    acls_list = []
                    if dacl:
                        for i in range(dacl.GetAceCount()):
                            ace = dacl.GetAce(i)
                            type, flags, access_mask, sid = ace
                            name, domain, sid_type = win32security.LookupAccountSid(None, sid)
                            acls_list.append({
                                "account": f"{domain}\\{name}" if domain else name,
                                "type": "Allow" if type == win32security.ACCESS_ALLOWED_ACE_TYPE else "Deny",
                                "access_mask": hex(access_mask),
                                "flags": hex(flags)
                            })
                    acls_info = acls_list if acls_list else "No explicit ACLs found."

                except Exception as e:
                    acls_info = f"Error extracting Windows ACLs: {e}"
                    logger.warning(acls_info)
            else:
                acls_info = "pywin32 not installed, cannot extract Windows ACLs."
        else: # Linux/Unix-like
            try:
                import grp
                import pwd
                owner_name = pwd.getpwuid(st.st_uid).pw_name
                group_name = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                owner_name = f"UID:{st.st_uid}"
                group_name = f"GID:{st.st_gid}"
            acls_info = "Not extracted (POSIX ACLs require specific tools/libraries like python-posix-acl, or command-line calls)."

    except Exception as e:
        logger.error(f"Error getting permissions/owner for {file_path}: {e}")

    return perms_octal, perms_symbolic, owner_name, group_name, acls_info


def get_datetime_details(timestamp, local_tz=None):
    """Convert timestamp to UTC and Local ISO format."""
    if timestamp is None:
        return "N/A", "N/A"
    dt_utc = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    
    dt_local = None
    if local_tz:
        try:
            dt_local = dt_utc.astimezone(local_tz)
        except Exception:
            dt_local = datetime.fromtimestamp(timestamp) # Fallback to system local
    else:
        dt_local = datetime.fromtimestamp(timestamp) # System local time

    return dt_utc.isoformat(), dt_local.isoformat(sep=' ', timespec='seconds')


# def detect_filetype_magic(file_path):
#     """Detect file type using magic."""
#     try:
#         return magic.from_file(file_path)
#     except Exception:
#         return "unknown"

def detect_bom(file_path):
    """Detect presence of Byte Order Mark (BOM)."""
    with open(file_path, "rb") as f:
        header = f.read(4) # BOMs are typically 2-4 bytes
        if header.startswith(b'\xef\xbb\xbf'): # UTF-8 BOM
            return True
        if header.startswith(b'\xff\xfe') or header.startswith(b'\xfe\xff'): # UTF-16 BOM
            return True
        if header.startswith(b'\x00\x00\xfe\xff'): # UTF-32 BOM (big-endian)
            return True
        if header.startswith(b'\xff\xfe\x00\x00'): # UTF-32 BOM (little-endian)
            return True
    return False

def get_text_metrics(file_path, encoding):
    """Calculate detailed text metrics."""
    total_lines = 0
    total_words = 0
    total_chars_inc_whitespace_newlines = 0
    total_chars_exc_whitespace = 0 # Only non-whitespace, non-newline
    total_chars_exc_whitespace_and_newlines = 0 # New
    
    non_printable_ascii_count = 0
    high_ascii_invalid_utf8_count = 0
    empty_lines = 0
    lines_with_leading_trailing_whitespace = 0
    multiple_spaces_between_words = 0
    total_comment_lines = 0
    
    all_words = []
    line_lengths = []
    frequent_chars_counter = Counter()
    unicode_category_counts = Counter() # For Unicode categories

    # Newline consistency
    newline_counts = Counter()
    consistent_newlines = True
    first_newline_type_detected = None

    # Indentation consistency
    indent_styles = Counter() # 'spaces', 'tabs', 'mixed'
    space_indent_sizes = Counter() # For 'spaces'
    consistent_indentation = True
    
    try:
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                stripped_line = line.strip()
                trimmed_line_for_length = line.rstrip('\n\r') # Line without its own newline char
                line_lengths.append(len(trimmed_line_for_length))

                # Newline type detection for consistency
                if '\r\n' in line:
                    current_newline = 'CRLF'
                elif '\r' in line:
                    current_newline = 'CR'
                elif '\n' in line:
                    current_newline = 'LF'
                else:
                    current_newline = 'None' # Single-line file or unusual

                newline_counts[current_newline] += 1
                if first_newline_type_detected is None and current_newline != 'None':
                    first_newline_type_detected = current_newline
                elif first_newline_type_detected is not None and current_newline != 'None' and first_newline_type_detected != current_newline:
                    consistent_newlines = False

                # Whitespace analysis
                if line.strip() != line: # Check for any leading/trailing whitespace
                    lines_with_leading_trailing_whitespace += 1
                if re.search(r'\s{2,}', line): # Two or more spaces between words
                    multiple_spaces_between_words += 1

                if not stripped_line:
                    empty_lines += 1

                words = line.split()
                total_words += len(words)
                all_words.extend(words)

                total_chars_inc_whitespace_newlines += len(line)
                total_chars_exc_whitespace += len(stripped_line) # Characters excluding leading/trailing whitespace
                total_chars_exc_whitespace_and_newlines += len(trimmed_line_for_length.replace(' ', '').replace('\t', ''))


                for char in line:
                    char_code = ord(char)
                    # Count non-printable ASCII (excluding common control chars like tab, CR, LF)
                    if 0 < char_code < 32 and char_code not in [9, 10, 13]:
                        non_printable_ascii_count += 1
                    # Count high-ASCII or characters that might be invalid UTF-8 (if encoding is ASCII/single-byte like, and char is >127)
                    elif char_code >= 128:
                        high_ascii_invalid_utf8_count += 1
                    
                    # Unicode Category Counting
                    cat = unicodedata.category(char)
                    unicode_category_counts[cat] += 1

                    frequent_chars_counter[char.lower()] += 1 # Case-insensitive freq

                # Indentation analysis (only for non-empty lines)
                if stripped_line:
                    leading_whitespace = line[:len(line) - len(line.lstrip())]
                    if leading_whitespace:
                        if '\t' in leading_whitespace and ' ' in leading_whitespace:
                            indent_styles['mixed'] += 1
                            consistent_indentation = False
                        elif '\t' in leading_whitespace:
                            indent_styles['tabs'] += 1
                        elif ' ' in leading_whitespace:
                            indent_styles['spaces'] += 1
                            # For space indent size, find the length of the leading whitespace
                            space_indent_sizes[len(leading_whitespace)] += 1
            # --- End of Line Iteration ---

            # Comment line detection (per line, using regex patterns)
            f.seek(0) # Rewind to read for comments
            for line in f:
                if re.match(REGEX_PATTERNS["comments_hash"], line) or \
                   re.match(REGEX_PATTERNS["comments_double_slash"], line) or \
                   re.match(REGEX_PATTERNS["comments_sql"], line):
                    total_comment_lines += 1
                # HTML/XML comments can span lines, harder to count per-line directly.
                # For this simple metric, we primarily count single-line comment patterns.

    except Exception as e:
        logger.error(f"Error during text metrics calculation for {file_path}: {e}")
        return {} # Return empty dict if error

    avg_words_per_line = (total_words / total_lines) if total_lines else 0
    avg_chars_per_word = (total_chars_exc_whitespace / total_words) if total_words else 0
    avg_line_length = (sum(line_lengths) / total_lines) if total_lines else 0
    max_line_length = max(line_lengths) if line_lengths else 0
    lines_over_80_chars = sum(1 for length in line_lengths if length > 80)
    percent_lines_over_80_chars = (lines_over_80_chars / total_lines) * 100 if total_lines else 0

    # Character frequency
    total_effective_chars = sum(frequent_chars_counter.values()) # Should be total_chars_inc_whitespace_newlines
    top_5_char_freq = {k: round((v / total_effective_chars) * 100, 2) for k, v in frequent_chars_counter.most_common(5)}
    
    digit_count = sum(v for k,v in frequent_chars_counter.items() if k in string.digits)
    punctuation_count = sum(v for k,v in frequent_chars_counter.items() if k in string.punctuation)
    
    freq_digits = round((digit_count / total_effective_chars) * 100, 2) if total_effective_chars else 0
    freq_punctuation = round((punctuation_count / total_effective_chars) * 100, 2) if total_effective_chars else 0


    # Indentation style summary
    indent_style_summary = "N/A"
    space_indent_size_summary = "N/A"
    if indent_styles:
        most_common_indent_type = indent_styles.most_common(1)[0][0]
        if len(indent_styles) > 1:
            indent_style_summary = "Mixed"
            consistent_indentation = False # Already set, but explicit
        else:
            indent_style_summary = most_common_indent_type

        if 'spaces' in indent_styles and space_indent_sizes:
            # Pick the most common space indent size
            most_common_space_indent = space_indent_sizes.most_common(1)[0][0]
            if len(space_indent_sizes) > 1:
                space_indent_size_summary = f"Mixed ({most_common_space_indent} dominant)"
                consistent_indentation = False # Already set
            else:
                space_indent_size_summary = most_common_space_indent
    
    # Newline style summary
    detected_newline_style = "Unknown"
    if newline_counts:
        detected_newline_style = newline_counts.most_common(1)[0][0]

    # Readability and Lexical Diversity (requires textstat and NLTK for tokenization)
    text_content = "" # This is for readability, sentiment, language detection
    try:
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            text_content = f.read()
    except Exception as e:
        logger.error(f"Could not re-read file for readability/language analysis: {e}")
        text_content = "" # Ensure empty if failed

    flesch_kincaid = None
    if textstat and text_content:
        try:
            flesch_kincaid = textstat.flesch_kincaid_grade(text_content)
        except Exception as e:
            logger.debug(f"textstat flesch_kincaid_grade failed: {e}")

    type_token_ratio = None
    if len(all_words) > 0:
        type_token_ratio = len(set(all_words)) / len(all_words)

    # Comments ratio
    proportion_comment_lines = (total_comment_lines / total_lines) if total_lines else 0

    return {
        "total_lines": total_lines,
        "total_words": total_words,
        "total_characters_including_whitespace_and_newlines": total_chars_inc_whitespace_newlines,
        "total_characters_excluding_whitespace_and_newlines": total_chars_exc_whitespace_and_newlines,
        "average_words_per_line": round(avg_words_per_line, 2),
        "average_characters_per_word": round(avg_chars_per_word, 2),
        "non_printable_ascii_count": non_printable_ascii_count,
        "high_ascii_or_invalid_utf8_count": high_ascii_invalid_utf8_count,
        "unicode_category_counts": dict(unicode_category_counts), # Convert Counter to dict
        "empty_line_count": empty_lines,
        "proportion_empty_lines": round(empty_lines / total_lines, 4) if total_lines else 0,
        "lines_with_leading_trailing_whitespace_count": lines_with_leading_trailing_whitespace,
        "multiple_spaces_between_words_count": multiple_spaces_between_words,
        "detected_newline_style": detected_newline_style,
        "newline_consistency": "Consistent" if consistent_newlines else "Mixed",
        "average_line_length": round(avg_line_length, 2),
        "max_line_length": max_line_length,
        "percentage_lines_over_80_chars": round(percent_lines_over_80_chars, 2),
        "indentation_style": indent_style_summary,
        "space_indent_size": space_indent_size_summary,
        "indentation_consistency": "Consistent" if consistent_indentation else "Mixed",
        "top_5_most_frequent_characters": top_5_char_freq,
        "frequency_of_digits_percent": freq_digits,
        "frequency_of_punctuation_percent": freq_punctuation,
        "flesch_kincaid_grade_level": flesch_kincaid,
        "type_token_ratio": round(type_token_ratio, 4) if type_token_ratio is not None else None,
        "comment_line_count": total_comment_lines,
        "proportion_comment_lines": round(proportion_comment_lines, 4) if total_lines else 0,
    }

def try_decode_snippet(encoded_string, encoding_type):
    """Attempt to decode a snippet based on its detected type."""
    try:
        if encoding_type == "Base64":
            # Base64 strings are padded with '='. If not, pad them.
            padding_needed = len(encoded_string) % 4
            if padding_needed != 0:
                encoded_string += '=' * (4 - padding_needed)
            return base64.b64decode(encoded_string).decode('utf-8', errors='ignore')
        elif encoding_type == "Hexadecimal":
            return binascii.unhexlify(encoded_string).decode('utf-8', errors='ignore')
        elif encoding_type == "URL Encoding":
            return urllib.parse.unquote(encoded_string)
        # Rot13, etc., would need more specific decoders
    except Exception:
        pass
    return None


def find_text_patterns(file_path, encoding):
    """Identify regex pattern matches and specific text types."""
    found_patterns = {}
    all_content = ""
    try:
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            all_content = f.read()
    except Exception as e:
        logger.error(f"Error reading file for pattern matching: {e}")
        return found_patterns

    # Track distinct obfuscation types detected
    obfuscation_types_detected_set = set()

    for pattern_name, regex_str in REGEX_PATTERNS.items():
        # Skip comment patterns, they are handled in get_text_metrics
        if pattern_name.startswith("comments_"):
            continue

        matches = re.findall(regex_str, all_content, re.IGNORECASE)
        if matches:
            unique_matches = list(set(matches))
            
            pattern_info = {
                "count": len(matches),
                "samples": unique_matches[:5] # Store up to 5 unique samples
            }

            if pattern_name in ["base64_like", "hex_string", "url_encoded", "eval_exec_string"]:
                obfuscated_flag = True
                if pattern_name == "base64_like":
                    obfuscation_types_detected_set.add("Base64")
                elif pattern_name == "hex_string":
                    obfuscation_types_detected_set.add("Hexadecimal")
                elif pattern_name == "url_encoded":
                    obfuscation_types_detected_set.add("URL Encoding")
                elif pattern_name == "eval_exec_string":
                    obfuscation_types_detected_set.add("Eval/Exec String")

                if matches: # For obfuscated blocks, also check length of longest and attempt decode
                    longest_match = max(len(m) for m in matches)
                    pattern_info["longest_block_length"] = longest_match
                    
                    decoded_snippets = []
                    # Attempt to decode up to 3 samples
                    for sample in unique_matches[:3]:
                        decoded = try_decode_snippet(sample, obfuscation_types_detected_set.pop() if obfuscation_types_detected_set else None) # Pop one to pass type
                        if decoded:
                            decoded_snippets.append(decoded)
                    if decoded_snippets:
                        pattern_info["decoded_snippets"] = decoded_snippets
                    else:
                        pattern_info["decoded_snippets"] = ["N/A (Failed to decode)"]


            found_patterns[pattern_name] = pattern_info

    # Specific Text Sub-Type (heuristic guesses)
    specific_text_subtype = "Generic Text"
    if re.search(REGEX_PATTERNS["json_like_start"], all_content.strip()[:100], re.MULTILINE):
        specific_text_subtype = "JSON (fragment/possible)"
    elif re.search(REGEX_PATTERNS["xml_like_start"], all_content.strip()[:100], re.MULTILINE):
        specific_text_subtype = "XML (fragment/possible)"
    elif re.search(r'^\s*\w+:\s*\w+', all_content.strip()[:200], re.MULTILINE) and not specific_text_subtype.startswith(("JSON", "XML")):
        # Simple YAML-like key-value pair check
        specific_text_subtype = "YAML (fragment/possible)"
    elif re.search(r'\[(?:INFO|WARN|ERROR|DEBUG)\]', all_content, re.IGNORECASE) or \
         re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', all_content):
        specific_text_subtype = "Log File (possible)"
    elif re.search(r'^\s*#', all_content, re.MULTILINE) or \
         re.search(r'^\s*//', all_content, re.MULTILINE) or \
         re.search(r'^\s*--', all_content, re.MULTILINE) or \
         all_content.strip().startswith('#!'):
        specific_text_subtype = "Script (possible)"
    elif re.search(REGEX_PATTERNS["markdown_headers"], all_content, re.MULTILINE) or \
         re.search(REGEX_PATTERNS["markdown_lists"], all_content, re.MULTILINE):
        specific_text_subtype = "Markdown (possible)"
    elif re.search(REGEX_PATTERNS["csv_like_delimiters"], all_content):
        # This is a very weak heuristic for CSV, a real CSV sniffer is needed for accuracy
        specific_text_subtype = "Delimited Text (possible CSV/TSV)"


    return {
        "pattern_matches": found_patterns,
        "specific_text_subtype": specific_text_subtype,
        "has_obfuscated_content": bool(obfuscation_types_detected_set),
        "obfuscation_types_detected": list(obfuscation_types_detected_set)
    }

def analyze_sentiment(text_content):
    """Perform sentiment analysis using VADER."""
    if sid and text_content.strip():
        try:
            ss = sid.polarity_scores(text_content)
            # VADER returns 'neg', 'neu', 'pos', 'compound'
            # We can classify based on compound score
            if ss['compound'] >= 0.05:
                overall_sentiment = "Positive"
            elif ss['compound'] <= -0.05:
                overall_sentiment = "Negative"
            else:
                overall_sentiment = "Neutral"
            return {
                "overall_sentiment": overall_sentiment,
                "sentiment_score_compound": ss['compound'],
                "sentiment_score_positive": ss['pos'],
                "sentiment_score_negative": ss['neg'],
                "sentiment_score_neutral": ss['neu']
            }
        except Exception as e:
            logger.debug(f"Sentiment analysis failed: {e}")
            return {}
    return {}

def detect_language(text_content):
    """Detect primary language of the text."""
    if detect and text_content.strip():
        try:
            lang = detect(text_content)
            # langdetect only returns the most probable language
            # For simplicity, returning just the detected language.
            return {"detected_language": lang, "confidence": "N/A (single best guess)"}
        except Exception as e:
            logger.debug(f"Language detection failed: {e}")
            return {}
    return {}

def get_content_previews(file_path, encoding, n_first=10, n_last=5):
    """Get first N and last N lines of the file."""
    first_lines = []
    last_lines = []
    all_lines = []

    try:
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            all_lines = f.readlines()

        # First N lines
        for i in range(min(n_first, len(all_lines))):
            first_lines.append(all_lines[i].rstrip('\n\r'))

        # Last N lines
        if len(all_lines) > n_first: # Avoid duplicating if file is very short
            for i in range(max(0, len(all_lines) - n_last), len(all_lines)):
                last_lines.append(all_lines[i].rstrip('\n\r'))
        elif len(all_lines) <= n_first: # If file is short, last lines are just the first lines (without re-adding)
            last_lines = first_lines[:len(all_lines)] # Ensure it's not longer than actual lines

    except Exception as e:
        logger.error(f"Error getting file previews for {file_path}: {e}")

    return first_lines, last_lines

def extract_anomalous_snippets(file_content, patterns_info, encoding, max_snippets=5):
    """Extract and highlight snippets around detected anomalous patterns."""
    anomalous_snippets = []
    seen_matches = set() # To avoid duplicate snippets for overlapping matches

    # Combine all patterns that indicate anomalies
    anomalous_patterns = {}
    for p_name, p_info in patterns_info.items():
        if p_name in ["base64_like", "hex_string", "url_encoded", "eval_exec_string", "common_keywords", "ipv4", "url"]:
            if "samples" in p_info:
                for sample in p_info["samples"]:
                    anomalous_patterns[sample] = p_name

    # Iterate through lines to find context for each match
    lines = file_content.splitlines()
    for pattern_value, pattern_type in anomalous_patterns.items():
        if len(anomalous_snippets) >= max_snippets:
            break

        # Use re.escape for literal matching if pattern_value could contain regex special chars
        escaped_pattern = re.escape(pattern_value)

        for line_num, line in enumerate(lines):
            # Check if match is already part of an extracted snippet
            if (pattern_value, line_num) in seen_matches:
                continue

            if re.search(escaped_pattern, line, re.IGNORECASE):
                # Found a match in this line. Extract the whole line as snippet.
                snippet = line.strip()
                if snippet:
                    anomalous_snippets.append({
                        "type": pattern_type,
                        "snippet": snippet,
                        "line_number": line_num + 1 # 1-based index
                    })
                    # Mark this pattern and line as seen
                    seen_matches.add((pattern_value, line_num))
                    break # Move to next anomalous pattern
    
    return anomalous_snippets


# --- Enhanced extract_txt_metadata ---

def calculate_entropy(file_path, sample_size=65536):
    """Calculate the byte-level entropy of a file (Shannon entropy)."""
    import math
    try:
        with open(file_path, "rb") as f:
            data = f.read(sample_size)
        if not data:
            return 0.0
        freq = Counter(data)
        total = len(data)
        entropy = -sum((count/total) * math.log2(count/total) for count in freq.values())
        return round(entropy, 4)
    except Exception:
        return None


def extract_txt_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from plain text files.

    Args:
        file_path: Path to the text file.

    Returns:
        A dictionary containing extracted metadata, including:
        - file_info: Basic file system attributes.
        - text_info: Detected encoding and content properties.
        - content_metrics: Linguistic and pattern-based content analysis.
        - structural_metrics: Formatting and layout analysis.
        - content_samples: Previews and extracted snippets.
        - processing: Status, warnings, errors, and time taken.

    Raises:
        TXTMetadataError: For any critical failure during validation or processing.
    """
    result: Dict[str, Any] = {
        "file_info": {},
        "text_info": {},
        "content_metrics": {},
        "structural_metrics": {},
        "content_samples": {},
        "processing": {
            "success": False,
            "warnings": [],
            "errors": [],
            "time_taken_seconds": None,
            "extractor_version": "1.3.0"
        }
    }

    start_time = time.time()
    logger.info(f"Starting TXT metadata extraction for: {file_path}")

    try:
        # --- Stage 1: Validation ---
        validate_txt_file(file_path)

        # --- Stage 2: File System Info ---
        file_stat = os.stat(file_path)
        
        # Get detailed file system info
        perms_octal, perms_symbolic, owner_name, group_name, acls_info = get_permissions_and_owner_details(file_path)
        md5, sha256, ssdeep_hash = get_file_hashes(file_path)
        
        # Determine local timezone for accurate local time display
        local_timezone = datetime.now(timezone.utc).astimezone().tzinfo # Get system's local timezone
        
        created_utc_iso, created_local_iso = get_datetime_details(file_stat.st_ctime, local_timezone)
        modified_utc_iso, modified_local_iso = get_datetime_details(file_stat.st_mtime, local_timezone)
        accessed_utc_iso, accessed_local_iso = get_datetime_details(file_stat.st_atime, local_timezone)

        # Populate file_info
        detected_mime_type_magic = magic.from_file(file_path, mime=True)
        detected_libmagic_output = magic.from_file(file_path) # Full human-readable string
        
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "filename": os.path.basename(file_path),
            "extension": get_filetype_extension(file_path),
            "parent_directory": os.path.dirname(os.path.abspath(file_path)),
            "size_bytes": file_stat.st_size,
            "size_human": human_readable_size(file_stat.st_size),
            "creation_time_utc": created_utc_iso,
            "creation_time_local": created_local_iso,
            "modification_time_utc": modified_utc_iso,
            "modification_time_local": modified_local_iso,
            "last_access_time_utc": accessed_utc_iso,
            "last_access_time_local": accessed_local_iso,
            "owner": owner_name,
            "group": group_name,
            "permissions_octal": perms_octal,
            "permissions_symbolic": perms_symbolic,
            "acls_info": acls_info,
            "checksum_md5": md5,
            "checksum_sha256": sha256,
            "checksum_ssdeep": ssdeep_hash,
            "valid_file_structure": True,
            "filetype_category": get_filetype_category(detected_mime_type_magic),
        }

        # --- Stage 3: File Type & Encoding Intelligence ---
        detected_mime_type_magic = magic.from_file(file_path, mime=True)
        detected_libmagic_output = magic.from_file(file_path) # Full human-readable string
        
        # Encoding detection
        detected_encoding_info = {}
        encoding = 'utf-8' # Default fallback encoding
        confidence = 0.0
        bom_present = detect_bom(file_path)

        try:
            with open(file_path, 'rb') as f:
                raw_data_chunk = f.read(1024 * 10) # Read up to 10KB for detection
                detected_encoding_info = chardet.detect(raw_data_chunk)

            detected_enc = detected_encoding_info.get('encoding')
            detected_conf = detected_encoding_info.get('confidence')

            if detected_enc:
                encoding = detected_enc
                confidence = detected_conf
            else:
                result["processing"]["warnings"].append(f"Could not reliably detect encoding; defaulting to '{encoding}'.")
                logger.warning(f"Chardet failed for {file_path}, defaulting to UTF-8.")

            if confidence < 0.8 and detected_enc: # Threshold for warning
                result["processing"]["warnings"].append(f"Low confidence ({confidence:.2f}) for detected encoding '{encoding}'.")
                logger.debug(f"Low confidence encoding detection for {file_path}: {encoding} (confidence: {confidence})")

            result["text_info"] = {
                "mime_type": detected_mime_type_magic,
                "libmagic_output": detected_libmagic_output,
                "detected_encoding": encoding,
                "encoding_confidence": round(confidence, 4),
                "bom_presence": bom_present
            }

        except Exception as e:
            result["processing"]["errors"].append(f"Encoding detection failed: {str(e)}")
            logger.exception(f"Error detecting encoding for {file_path}")
            # Keep fallback encoding for further processing
            result["text_info"]["detected_encoding"] = f"Fallback ({encoding})"
            result["text_info"]["encoding_confidence"] = 0.0
            result["text_info"]["mime_type"] = detected_mime_type_magic
            result["text_info"]["libmagic_output"] = detected_libmagic_output
            result["text_info"]["bom_presence"] = bom_present


        # --- Stage 4: Content & Linguistic Metrics (Requires reading the file with detected encoding) ---
        file_content_for_analysis = ""
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                file_content_for_analysis = f.read()
        except Exception as e:
            result["processing"]["errors"].append(f"Failed to read file content for detailed analysis: {str(e)}")
            logger.error(f"Failed to read {file_path} for detailed analysis with encoding {encoding}: {e}")
            file_content_for_analysis = "" # Ensure empty if failed

        # Unicode replacement character warning
        if '\uFFFD' in file_content_for_analysis:
            warning_msg = f"Unicode replacement character (�) found in decoded text for {file_path}. Possible decoding issue."
            result["processing"]["warnings"].append(warning_msg)
            logger.warning(warning_msg)

        # Get text metrics (counts, line lengths, char distributions, readability, lexical diversity, Unicode categories)
        text_metrics = get_text_metrics(file_path, encoding)
        result["content_metrics"].update(text_metrics)

        # Entropy Score (byte-level, already calculated earlier as 'entropy')
        # Re-calculate or ensure it's properly captured if the earlier `entropy` variable was not defined.
        # Ensure 'entropy' is available here if needed.
        # For this script, calculate it explicitly within this section as it's content-derived.
        calculated_entropy = calculate_entropy(file_path) # Need to call it again
        result["content_metrics"]["overall_entropy"] = calculated_entropy


        # Language Detection
        lang_data = detect_language(file_content_for_analysis)
        if lang_data:
            result["content_metrics"]["language_detection"] = lang_data
        else:
            result["content_metrics"]["language_detection"] = {"detected_language": "N/A", "confidence": "N/A"}

        # Sentiment Analysis
        sentiment_data = analyze_sentiment(file_content_for_analysis)
        if sentiment_data:
            result["content_metrics"]["sentiment_analysis"] = sentiment_data
        else:
            result["content_metrics"]["sentiment_analysis"] = {"overall_sentiment": "N/A", "sentiment_score_compound": None}


        # --- Stage 5: Structural & Formatting Metrics ---
        # Many of these are derived from get_text_metrics, just structured here
        result["structural_metrics"] = {
            "average_line_length": result["content_metrics"].get("average_line_length"),
            "max_line_length": result["content_metrics"].get("max_line_length"),
            "percentage_lines_over_80_chars": result["content_metrics"].get("percentage_lines_over_80_chars"),
            "excessive_whitespace_flag": result["content_metrics"].get("lines_with_leading_trailing_whitespace_count", 0) > 0 or \
                                         result["content_metrics"].get("multiple_spaces_between_words_count", 0) > 0,
            "count_lines_with_leading_trailing_whitespace": result["content_metrics"].get("lines_with_leading_trailing_whitespace_count"),
            "count_multiple_spaces_between_words": result["content_metrics"].get("multiple_spaces_between_words_count"),
            "empty_line_count": result["content_metrics"].get("empty_line_count"),
            "proportion_empty_lines": result["content_metrics"].get("proportion_empty_lines"),
            "detected_newline_style": result["content_metrics"].get("detected_newline_style"),
            "newline_consistency": result["content_metrics"].get("newline_consistency"),
            "indentation_style": result["content_metrics"].get("indentation_style"),
            "space_indent_size": result["content_metrics"].get("space_indent_size"),
            "indentation_consistency": result["content_metrics"].get("indentation_consistency"),
            "comment_line_count": result["content_metrics"].get("comment_line_count"),
            "proportion_comment_lines": result["content_metrics"].get("proportion_comment_lines"),
        }

        # Regex Pattern Matches (URLs, IPs, Emails, Hashes, Obfuscated Blocks)
        pattern_data = find_text_patterns(file_path, encoding)
        result["content_metrics"]["regex_pattern_matches"] = pattern_data["pattern_matches"]
        result["text_info"]["specific_text_subtype"] = pattern_data["specific_text_subtype"]
        result["content_metrics"]["has_obfuscated_content"] = pattern_data["has_obfuscated_content"]
        result["content_metrics"]["obfuscation_types_detected"] = pattern_data["obfuscation_types_detected"]


        # --- Stage 6: Content Samples ---
        first_lines_preview, last_lines_preview = get_content_previews(file_path, encoding)
        
        anomalous_snippets = extract_anomalous_snippets(file_content_for_analysis, pattern_data["pattern_matches"], encoding)

        result["content_samples"] = {
            "first_n_lines_preview": first_lines_preview,
            "last_n_lines_preview": last_lines_preview,
            "highlighted_anomalous_snippets": anomalous_snippets,
            "extracted_entities": { # Requires NER library (e.g., spacy, stanza, which are heavy dependencies)
                "persons": [],
                "organizations": [],
                "locations": [],
                "dates_times": [],
                "note": "Named Entity Recognition requires significant external NLP libraries and models (e.g., spaCy, Stanza) which are not included to maintain script lightness."
            }
        }
        
        result["processing"]["success"] = True

    except FileAccessError as e:
        result["processing"]["errors"].append(str(e))
        logger.error(f"File Access Error during TXT extraction: {e}")
        result["processing"]["success"] = False
    except InvalidFileFormatError as e:
        result["processing"]["errors"].append(str(e))
        logger.error(f"Invalid TXT Format Error: {e}")
        result["processing"]["success"] = False
    except Exception as e:
        result["processing"]["errors"].append(f"An unhandled critical error occurred: {str(e)}")
        logger.exception(f"An unhandled critical error occurred during extraction for {file_path}")
        result["processing"]["success"] = False
    finally:
        result["processing"]["time_taken_seconds"] = time.time() - start_time
        if not result["processing"]["success"] and not result["processing"]["errors"]:
             # If success is false but no errors recorded, it's an unhandled case that prevented error logging
            result["processing"]["errors"].append("Extraction failed without specific error message (check logs). This might indicate a very early failure.")
        logger.info(f"Extraction finished for {file_path}. Success: {result['processing']['success']}")

    # --- New Section: Clean Up Empty or N/A Fields ---
    for section in ["file_info", "text_info", "content_metrics", "structural_metrics", "content_samples"]:
        for k, v in result.get(section, {}).items():
            if v in ("N/A", "", [], {}):
                result[section][k] = None

    return result

def get_filetype_extension(file_path):
    """Return the file extension (without dot), or empty string if none."""
    base = os.path.basename(file_path)
    if '.' in base:
        return base.rsplit('.', 1)[-1].lower()
    return ""

def get_filetype_category(mime_type):
    """Categorize file type based on MIME type."""
    if mime_type is None:
        return "unknown"
    if mime_type.startswith("text/"):
        return "text"
    if mime_type.startswith("image/"):
        return "image"
    if mime_type.startswith("application/json"):
        return "structured"
    if mime_type.startswith("application/"):
        return "binary"
    return "unknown"

# --- CLI Entry Point ---
def run_cli():
    """Command-line interface for the TXT metadata extractor."""
    parser = argparse.ArgumentParser(
        description="Extract comprehensive metadata from a TXT file. "
                    "Outputs JSON metadata to stdout or a specified file."
    )
    parser.add_argument(
        "file",
        nargs="?", # Optional argument for file path
        help="Path to the TXT file to extract metadata from."
    )
    parser.add_argument(
        "--log-level",
        default=DEFAULT_LOG_LEVEL,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help=f"Set the logging level (default: {DEFAULT_LOG_LEVEL})."
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Write metadata output to this file (JSON). If not set, prints to stdout."
    )
    parser.add_argument(
        "--no-input-prompt",
        action="store_true",
        help="Do not prompt for file path if not provided as argument. Exit instead."
    )

    args = parser.parse_args()

    # Re-setup logging based on CLI argument
    setup_logging(args.log_level)

    file_path = args.file
    if not file_path:
        if args.no_input_prompt:
            logger.error("No file path provided and --no-input-prompt is set. Exiting.")
            sys.exit(1)
        else:
            file_path = input("Enter the path to the TXT file: ").strip()
            if not file_path:
                logger.error("No file path provided. Exiting.")
                sys.exit(1)

    try:
        logger.info(f"Attempting to extract metadata for: {file_path}")
        metadata = extract_txt_metadata(file_path)
        output_json = json.dumps(metadata, indent=2, ensure_ascii=False) # ensure_ascii for proper non-ASCII display

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f: # Ensure UTF-8 output
                f.write(output_json)
            logger.info(f"Metadata successfully written to {args.output}")
            print(f"Metadata written to {args.output}")
        else:
            print(output_json)

        # Indicate non-zero exit code if extraction was not fully successful
        if not metadata["processing"]["success"] or metadata["processing"]["errors"]:
            logger.warning(f"Extraction completed with warnings/errors for {file_path}. Exit code 2.")
            sys.exit(2)
        else:
            logger.info(f"Extraction successful for: {file_path}. Time taken: {metadata['processing']['time_taken_seconds']:.2f}s")

    except Exception as e: # Catch any remaining unhandled exceptions from CLI setup or argparse
        logger.exception(f"A critical error occurred in the CLI for {file_path}: {e}")
        print(f"A critical error occurred: {e}. Check {DEFAULT_LOG_FILE} for details.")
        sys.exit(1)

def main():
    run_cli()

if __name__ == "__main__":
    main()


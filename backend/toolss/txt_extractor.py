
# #!/usr/bin/env python3

# """
# txt Metadata Extraction Tool

# Description: Advanced metadata extraction from text files with comprehensive
# analysis including linguistic, structural, and security metrics.

# Features:
# - Complete file system metadata extraction
# - Advanced text analysis and linguistic metrics
# - Structural and formatting analysis
# - Content pattern recognition and security analysis
# - Unicode and encoding analysis
# - Performance and processing metrics

# Dependencies:
# - chardet (pip install chardet)
# - python-magic (pip install python-magic)
# - ssdeep (pip install ssdeep)
# - textstat (pip install textstat)
# - langdetect (pip install langdetect)
# - vaderSentiment (pip install vaderSentiment)
# - nltk (pip install nltk)
# - spacy (pip install spacy)
# - cryptography (pip install cryptography)

# Author: Enhanced Metadata Extractor
# Version: 2.0.0
# Last Updated: 2025-01-27
# """

# import os
# import sys
# import json
# import time
# import hashlib
# import stat
# import math
# import re
# import string
# import platform
# import psutil
# import unicodedata
# import base64
# import binascii
# import urllib.parse
# import mimetypes
# from datetime import datetime, timezone
# from collections import Counter, defaultdict
# from typing import Dict, Any, List, Optional, Tuple
# import logging
# import argparse


# file_path = "C:\\Users\\Administrator\\Downloads\\Wsite\\samples\\2.txt"  # Replace with your own file

# # External dependencies
# try:
#     import chardet
# except ImportError:
#     chardet = None
#     print("Warning: chardet not installed. Encoding detection will be limited.")

# try:
#     import magic
# except ImportError:
#     magic = None
#     print("Warning: python-magic not installed. MIME type detection will be limited.")

# try:
#     import ssdeep
# except ImportError:
#     ssdeep = None
#     print("Warning: ssdeep not installed. Fuzzy hashing will not be available.")

# try:
#     import textstat
# except ImportError:
#     textstat = None
#     print("Warning: textstat not installed. Readability scores will be limited.")

# try:
#     from langdetect import detect, detect_langs, DetectorFactory
#     DetectorFactory.seed = 0
# except ImportError:
#     detect = None
#     detect_langs = None
#     print("Warning: langdetect not installed. Language detection will not be available.")

# try:
#     from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
#     sentiment_analyzer = SentimentIntensityAnalyzer()
# except ImportError:
#     sentiment_analyzer = None
#     print("Warning: vaderSentiment not installed. Sentiment analysis will not be available.")

# try:
#     import nltk
#     from nltk.tokenize import sent_tokenize, word_tokenize
#     from nltk.corpus import stopwords
#     from nltk.util import ngrams
#     # Download required NLTK data
#     try:
#         nltk.data.find('tokenizers/punkt')
#     except LookupError:
#         nltk.download('punkt', quiet=True)
#     try:
#         nltk.data.find('corpora/stopwords')
#     except LookupError:
#         nltk.download('stopwords', quiet=True)
    
#     english_stopwords = set(stopwords.words('english'))
# except ImportError:
#     nltk = None
#     sent_tokenize = None
#     word_tokenize = None
#     ngrams = None
#     english_stopwords = set()
#     print("Warning: nltk not installed. Advanced text processing will be limited.")

# try:
#     import spacy
#     # Try to load English model
#     try:
#         nlp = spacy.load("en_core_web_sm")
#     except OSError:
#         nlp = None
#         print("Warning: spaCy English model not found. Named entity recognition will not be available.")
# except ImportError:
#     spacy = None
#     nlp = None
#     print("Warning: spaCy not installed. Named entity recognition will not be available.")

# # Platform-specific imports
# if platform.system() == "Windows":
#     try:
#         import win32security
#         import win32api
#         import win32file
#     except ImportError:
#         win32security = None
#         win32api = None
#         win32file = None
#         print("Warning: pywin32 not installed. Windows-specific features will be limited.")
# else:
#     win32security = None
#     win32api = None
#     win32file = None

# # Configuration
# CHUNK_SIZE = 8192
# MAX_SAMPLE_SIZE = 1024 * 1024  # 1MB for analysis
# DEFAULT_ENCODING = 'utf-8'

# # Regex patterns for content analysis
# REGEX_PATTERNS = {
#     "urls": r"https?://[^\s\"'>]+",
#     "emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
#     "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
#     "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
#     "phone_numbers": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
#     "credit_cards": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
#     "ssn": r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
#     "dates": r"\b(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b",
#     "times": r"\b(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?::[0-5][0-9])?\s*(?:AM|PM|am|pm)?\b",
#     "currency": r"[$€£¥₹₽]\s*\d+(?:\.\d{2})?|\b\d+(?:\.\d{2})?\s*(?:USD|EUR|GBP|JPY|INR|RUB)\b",
#     "md5_hashes": r"\b[a-fA-F0-9]{32}\b",
#     "sha1_hashes": r"\b[a-fA-F0-9]{40}\b",
#     "sha256_hashes": r"\b[a-fA-F0-9]{64}\b",
#     "base64": r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
#     "hex_strings": r"\b(?:0x)?[a-fA-F0-9]{8,}\b",
#     "json_objects": r"\{[^{}]*\}",
#     "xml_tags": r"<[^<>]+>",
#     "markdown_headers": r"^#+\s+.+$",
#     "markdown_links": r"\[([^\]]+)\]\(([^)]+)\)",
#     "code_blocks": r"```[\s\S]*?```|`[^`]+`",
#     "html_entities": r"&[a-zA-Z][a-zA-Z0-9]*;|&#[0-9]+;|&#x[0-9a-fA-F]+;",
#     "unicode_escapes": r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}",
#     "escape_sequences": r"\\[nrtbfav\\\"']",
#     "sql_keywords": r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|FROM|WHERE|JOIN|UNION)\b",
#     "programming_keywords": r"\b(?:function|class|import|export|var|let|const|if|else|for|while|return|try|catch)\b",
#     "obfuscated_strings": r"(?:[A-Za-z0-9+/]{20,}={0,2})|(?:(?:%[0-9a-fA-F]{2}){10,})|(?:\\x[0-9a-fA-F]{2}){10,}",
# }

# class MetadataExtractor:
#     def __init__(self):
#         self.start_time = time.time()
#         self.warnings = []
#         self.errors = []
#         self.processing_stage = "initialization"
        
#     def extract_metadata(self, file_path: str) -> Dict[str, Any]:
#         """Extract comprehensive metadata from a file."""
#         try:
#             self.processing_stage = "validation"
#             if not self._validate_file(file_path):
#                 return self._create_error_result("File validation failed")
            
#             metadata = {
#                 "file_info": self._extract_file_info(file_path),
#                 "text_info": self._extract_text_info(file_path),
#                 "content_metrics": self._extract_content_metrics(file_path),
#                 "structural_metrics": self._extract_structural_metrics(file_path),
#                 "content_samples": self._extract_content_samples(file_path),
#                 "processing": self._extract_processing_info()
#             }
            
#             return metadata
            
#         except Exception as e:
#             self.errors.append(f"Critical error during extraction: {str(e)}")
#             return self._create_error_result(str(e))
    
#     def _validate_file(self, file_path: str) -> bool:
#         """Validate file accessibility and basic properties."""
#         if not os.path.exists(file_path):
#             self.errors.append(f"File not found: {file_path}")
#             return False
        
#         if not os.path.isfile(file_path):
#             self.errors.append(f"Path is not a regular file: {file_path}")
#             return False
        
#         if not os.access(file_path, os.R_OK):
#             self.errors.append(f"File is not readable: {file_path}")
#             return False
        
#         return True
    
#     def _extract_file_info(self, file_path: str) -> Dict[str, Any]:
#         """Extract comprehensive file system information."""
#         self.processing_stage = "file_info"
        
#         try:
#             stat_info = os.stat(file_path)
#             abs_path = os.path.abspath(file_path)
            
#             # Basic file information
#             file_info = {
#                 "path": abs_path,
#                 "filename": os.path.basename(file_path),
#                 "extension": self._get_file_extension(file_path),
#                 "parent_directory": os.path.dirname(abs_path),
#                 "size_bytes": stat_info.st_size,
#                 "size_human": self._format_bytes(stat_info.st_size),
#             }
            
#             # Timestamps
#             file_info.update(self._extract_timestamps(stat_info))
            
#             # Permissions and ownership
#             file_info.update(self._extract_permissions(file_path, stat_info))
            
#             # Checksums
#             file_info.update(self._calculate_checksums(file_path))
            
#             # File system details
#             file_info.update(self._extract_filesystem_details(file_path, stat_info))
            
#             # Validation
#             file_info["valid_file_structure"] = True
#             file_info["filetype_category"] = self._determine_file_category(file_path)
            
#             return file_info
            
#         except Exception as e:
#             self.errors.append(f"Error extracting file info: {str(e)}")
#             return {}
    
#     def _extract_text_info(self, file_path: str) -> Dict[str, Any]:
#         """Extract text-specific information and properties."""
#         self.processing_stage = "text_info"
        
#         try:
#             text_info = {}
            
#             # MIME type detection
#             if magic:
#                 text_info["mime_type"] = magic.from_file(file_path, mime=True)
#                 text_info["libmagic_output"] = magic.from_file(file_path)
#             else:
#                 mime_type, _ = mimetypes.guess_type(file_path)
#                 text_info["mime_type"] = mime_type or "text/plain"
#                 text_info["libmagic_output"] = "Magic library not available"
            
#             # Encoding detection
#             encoding_info = self._detect_encoding(file_path)
#             text_info.update(encoding_info)
            
#             # BOM detection
#             text_info["bom_presence"] = self._detect_bom(file_path)
            
#             # Text subtype detection
#             text_info["specific_text_subtype"] = self._detect_text_subtype(file_path)
            
#             # Line ending analysis
#             text_info["line_ending_style"] = self._detect_line_endings(file_path)
            
#             # Content analysis flags
#             content_flags = self._analyze_content_flags(file_path, encoding_info.get("detected_encoding", DEFAULT_ENCODING))
#             text_info.update(content_flags)
            
#             return text_info
            
#         except Exception as e:
#             self.errors.append(f"Error extracting text info: {str(e)}")
#             return {}
    
#     def _extract_content_metrics(self, file_path: str) -> Dict[str, Any]:
#         """Extract comprehensive content and linguistic metrics."""
#         self.processing_stage = "content_metrics"
        
#         try:
#             encoding = self._detect_encoding(file_path).get("detected_encoding", DEFAULT_ENCODING)
            
#             with open(file_path, 'r', encoding=encoding, errors='replace') as f:
#                 content = f.read()
            
#             lines = content.splitlines()
            
#             # Basic counts
#             metrics = {
#                 "total_lines": len(lines),
#                 "total_words": len(content.split()),
#                 "total_characters_including_whitespace_and_newlines": len(content),
#                 "total_characters_excluding_whitespace_and_newlines": len(re.sub(r'\s', '', content)),
#             }
            
#             # Derived metrics
#             metrics.update(self._calculate_basic_metrics(content, lines))
            
#             # Character analysis
#             metrics.update(self._analyze_characters(content))
            
#             # Line and structure analysis
#             metrics.update(self._analyze_lines_and_structure(lines))
            
#             # Linguistic analysis
#             metrics.update(self._analyze_linguistics(content))
            
#             # Pattern matching
#             metrics.update(self._analyze_patterns(content))
            
#             # Advanced metrics
#             metrics.update(self._calculate_advanced_metrics(content, lines))
            
#             return metrics
            
#         except Exception as e:
#             self.errors.append(f"Error extracting content metrics: {str(e)}")
#             return {}
    
#     def _extract_structural_metrics(self, file_path: str) -> Dict[str, Any]:
#         """Extract structural and formatting metrics."""
#         self.processing_stage = "structural_metrics"
        
#         try:
#             encoding = self._detect_encoding(file_path).get("detected_encoding", DEFAULT_ENCODING)
            
#             with open(file_path, 'r', encoding=encoding, errors='replace') as f:
#                 content = f.read()
            
#             lines = content.splitlines()
            
#             # Basic structural metrics
#             metrics = self._calculate_basic_structural_metrics(lines)
            
#             # Advanced structural analysis
#             metrics.update(self._analyze_advanced_structure(lines, content))
            
#             return metrics
            
#         except Exception as e:
#             self.errors.append(f"Error extracting structural metrics: {str(e)}")
#             return {}
    
#     def _extract_content_samples(self, file_path: str) -> Dict[str, Any]:
#         """Extract content samples and examples."""
#         self.processing_stage = "content_samples"
        
#         try:
#             encoding = self._detect_encoding(file_path).get("detected_encoding", DEFAULT_ENCODING)
            
#             with open(file_path, 'r', encoding=encoding, errors='replace') as f:
#                 content = f.read()
            
#             lines = content.splitlines()
            
#             samples = {
#                 "first_n_lines_preview": lines[:10],
#                 "last_n_lines_preview": lines[-5:] if len(lines) > 10 else [],
#                 "highlighted_anomalous_snippets": self._find_anomalous_snippets(content, lines),
#                 "extracted_entities": self._extract_entities(content),
#             }
            
#             # Optional samples
#             samples.update(self._extract_optional_samples(content, lines))
            
#             return samples
            
#         except Exception as e:
#             self.errors.append(f"Error extracting content samples: {str(e)}")
#             return {}
    
#     def _extract_processing_info(self) -> Dict[str, Any]:
#         """Extract processing and performance information."""
#         end_time = time.time()
#         processing_time = end_time - self.start_time
        
#         # Get memory usage
#         process = psutil.Process()
#         memory_info = process.memory_info()
        
#         processing_info = {
#             "success": len(self.errors) == 0,
#             "warnings": self.warnings,
#             "errors": self.errors,
#             "time_taken_seconds": round(processing_time, 4),
#             "extractor_version": "2.0.0",
#             "start_time_utc": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
#             "end_time_utc": datetime.fromtimestamp(end_time, tz=timezone.utc).isoformat(),
#             "memory_usage_mb": round(memory_info.rss / 1024 / 1024, 2),
#             "cpu_time_seconds": round(process.cpu_times().user + process.cpu_times().system, 4),
#             "peak_memory_mb": round(memory_info.peak_wss / 1024 / 1024, 2) if hasattr(memory_info, 'peak_wss') else None,
#             "num_threads_used": 1,
#             "num_files_processed": 1,
#             "num_retries": 0,
#             "python_version": sys.version,
#             "platform_info": platform.platform(),
#             "dependency_versions": self._get_dependency_versions(),
#             "processing_stage": self.processing_stage,
#         }
        
#         return processing_info
    
#     # Helper methods for file info extraction
#     def _get_file_extension(self, file_path: str) -> str:
#         """Get file extension without the dot."""
#         _, ext = os.path.splitext(file_path)
#         return ext.lstrip('.').lower()
    
#     def _format_bytes(self, bytes_size: int) -> str:
#         """Format bytes into human-readable format."""
#         for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
#             if bytes_size < 1024.0:
#                 return f"{bytes_size:.2f} {unit}"
#             bytes_size /= 1024.0
#         return f"{bytes_size:.2f} PB"
    
#     def _extract_timestamps(self, stat_info) -> Dict[str, str]:
#         """Extract and format timestamps."""
#         timestamps = {}
        
#         # Creation time (Windows) or metadata change time (Unix)
#         if hasattr(stat_info, 'st_birthtime'):  # macOS
#             creation_time = stat_info.st_birthtime
#         elif platform.system() == "Windows":
#             creation_time = stat_info.st_ctime
#         else:
#             creation_time = stat_info.st_ctime  # Actually metadata change time on Unix
        
#         timestamps.update({
#             "creation_time_utc": datetime.fromtimestamp(creation_time, tz=timezone.utc).isoformat(),
#             "creation_time_local": datetime.fromtimestamp(creation_time).isoformat(),
#             "modification_time_utc": datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc).isoformat(),
#             "modification_time_local": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
#             "last_access_time_utc": datetime.fromtimestamp(stat_info.st_atime, tz=timezone.utc).isoformat(),
#             "last_access_time_local": datetime.fromtimestamp(stat_info.st_atime).isoformat(),
#         })
        
#         return timestamps
    
#     def _extract_permissions(self, file_path: str, stat_info) -> Dict[str, Any]:
#         """Extract permissions and ownership information."""
#         permissions = {
#             "permissions_octal": oct(stat_info.st_mode)[-3:],
#             "permissions_symbolic": stat.filemode(stat_info.st_mode),
#         }
        
#         # Owner and group
#         if platform.system() != "Windows":
#             try:
#                 import pwd
#                 import grp
#                 permissions["owner"] = pwd.getpwuid(stat_info.st_uid).pw_name
#                 permissions["group"] = grp.getgrgid(stat_info.st_gid).gr_name
#             except (ImportError, KeyError):
#                 permissions["owner"] = str(stat_info.st_uid)
#                 permissions["group"] = str(stat_info.st_gid)
#         else:
#             permissions["owner"] = "N/A (Windows)"
#             permissions["group"] = "N/A (Windows)"
        
#         # ACLs (simplified)
#         permissions["acls_info"] = self._extract_acls(file_path)
        
#         return permissions
    
#     def _extract_acls(self, file_path: str) -> str:
#         """Extract ACL information (platform-specific)."""
#         if platform.system() == "Windows" and win32security:
#             try:
#                 sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
#                 dacl = sd.GetSecurityDescriptorDacl()
#                 if dacl:
#                     return f"DACL with {dacl.GetAceCount()} ACEs"
#                 else:
#                     return "No DACL"
#             except Exception as e:
#                 return f"Error reading ACLs: {str(e)}"
#         else:
#             return "ACL extraction not supported on this platform"
    
#     def _calculate_checksums(self, file_path: str) -> Dict[str, str]:
#         """Calculate various checksums for the file."""
#         checksums = {}
        
#         try:
#             with open(file_path, 'rb') as f:
#                 content = f.read()
            
#             # Standard checksums
#             checksums["checksum_md5"] = hashlib.md5(content).hexdigest()
#             checksums["checksum_sha1"] = hashlib.sha1(content).hexdigest()
#             checksums["checksum_sha256"] = hashlib.sha256(content).hexdigest()
#             checksums["checksum_sha512"] = hashlib.sha512(content).hexdigest()
            
#             # SSDEEP fuzzy hash
#             if ssdeep:
#                 checksums["checksum_ssdeep"] = ssdeep.hash(content)
#             else:
#                 checksums["checksum_ssdeep"] = "N/A (ssdeep not available)"
                
#         except Exception as e:
#             self.errors.append(f"Error calculating checksums: {str(e)}")
#             checksums = {
#                 "checksum_md5": "Error",
#                 "checksum_sha1": "Error",
#                 "checksum_sha256": "Error",
#                 "checksum_sha512": "Error",
#                 "checksum_ssdeep": "Error"
#             }
        
#         return checksums
    
#     def _extract_filesystem_details(self, file_path: str, stat_info) -> Dict[str, Any]:
#         """Extract filesystem-specific details."""
#         details = {
#             "hardlink_count": stat_info.st_nlink,
#             "is_symlink": os.path.islink(file_path),
#             "device_id": str(stat_info.st_dev),
#             "inode_number": str(stat_info.st_ino),
#         }
        
#         # Symlink target
#         if details["is_symlink"]:
#             try:
#                 details["symlink_target"] = os.readlink(file_path)
#             except Exception:
#                 details["symlink_target"] = "Error reading symlink target"
#         else:
#             details["symlink_target"] = None
        
#         # File flags (platform-specific)
#         details["file_flags"] = self._get_file_flags(file_path)
        
#         # Alternate data streams (Windows)
#         if platform.system() == "Windows":
#             details["alternate_data_streams"] = self._get_alternate_data_streams(file_path)
#         else:
#             details["alternate_data_streams"] = "N/A (not Windows)"
        
#         # Compression and encryption (simplified detection)
#         details["compression"] = self._detect_compression(file_path)
#         details["encryption"] = self._detect_encryption(file_path)
        
#         # Filesystem type
#         details["parent_filesystem"] = self._get_filesystem_type(file_path)
        
#         return details
    
#     def _get_file_flags(self, file_path: str) -> str:
#         """Get file flags (platform-specific)."""
#         if platform.system() == "Windows" and win32file:
#             try:
#                 attrs = win32file.GetFileAttributes(file_path)
#                 flags = []
#                 if attrs & win32file.FILE_ATTRIBUTE_HIDDEN:
#                     flags.append("hidden")
#                 if attrs & win32file.FILE_ATTRIBUTE_SYSTEM:
#                     flags.append("system")
#                 if attrs & win32file.FILE_ATTRIBUTE_ARCHIVE:
#                     flags.append("archive")
#                 if attrs & win32file.FILE_ATTRIBUTE_READONLY:
#                     flags.append("readonly")
#                 return ", ".join(flags) if flags else "none"
#             except Exception:
#                 return "Error reading file flags"
#         else:
#             return "N/A (not Windows or pywin32 not available)"
    
#     def _get_alternate_data_streams(self, file_path: str) -> str:
#         """Get alternate data streams (Windows only)."""
#         # This would require more advanced Windows API calls
#         return "Not implemented"
    
#     def _detect_compression(self, file_path: str) -> str:
#         """Detect if file is compressed."""
#         # Simple heuristic based on file extension and magic bytes
#         ext = self._get_file_extension(file_path).lower()
#         if ext in ['gz', 'bz2', 'xz', 'zip', '7z', 'rar']:
#             return f"Possibly compressed ({ext})"
#         return "none"
    
#     def _detect_encryption(self, file_path: str) -> str:
#         """Detect if file is encrypted."""
#         # This is a simplified detection - real encryption detection is complex
#         try:
#             with open(file_path, 'rb') as f:
#                 header = f.read(16)
            
#             # Check for common encryption signatures
#             if header.startswith(b'Salted__'):
#                 return "Possibly encrypted (OpenSSL format)"
#             elif header.startswith(b'\x50\x4b\x03\x04') and b'encrypted' in header:
#                 return "Possibly encrypted (ZIP)"
#             else:
#                 return "none"
#         except Exception:
#             return "unknown"
    
#     def _get_filesystem_type(self, file_path: str) -> str:
#         """Get filesystem type."""
#         if platform.system() == "Windows":
#             try:
#                 import win32api
#                 drive = os.path.splitdrive(file_path)[0] + "\\"
#                 fs_type = win32api.GetVolumeInformation(drive)[4]
#                 return fs_type
#             except Exception:
#                 return "unknown"
#         else:
#             # On Unix-like systems, this is more complex
#             return "unknown (Unix-like)"
    
#     def _determine_file_category(self, file_path: str) -> str:
#         """Determine the general category of the file."""
#         if magic:
#             mime_type = magic.from_file(file_path, mime=True)
#             if mime_type.startswith('text/'):
#                 return "text"
#             elif mime_type.startswith('image/'):
#                 return "image"
#             elif mime_type.startswith('audio/'):
#                 return "audio"
#             elif mime_type.startswith('video/'):
#                 return "video"
#             elif mime_type.startswith('application/'):
#                 return "application"
        
#         # Fallback to extension-based detection
#         ext = self._get_file_extension(file_path).lower()
#         if ext in ['txt', 'log', 'md', 'rst', 'csv', 'tsv', 'json', 'xml', 'yaml', 'yml']:
#             return "text"
#         elif ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg']:
#             return "image"
#         else:
#             return "unknown"
    
#     # Helper methods for text info extraction
#     def _detect_encoding(self, file_path: str) -> Dict[str, Any]:
#         """Detect file encoding with confidence score."""
#         encoding_info = {
#             "detected_encoding": DEFAULT_ENCODING,
#             "encoding_confidence": 0.0
#         }
        
#         if chardet:
#             try:
#                 with open(file_path, 'rb') as f:
#                     raw_data = f.read(min(MAX_SAMPLE_SIZE, os.path.getsize(file_path)))
                
#                 result = chardet.detect(raw_data)
#                 if result and result['encoding']:
#                     encoding_info["detected_encoding"] = result['encoding']
#                     encoding_info["encoding_confidence"] = result['confidence']
#                 else:
#                     self.warnings.append("Encoding detection failed, using UTF-8")
#             except Exception as e:
#                 self.warnings.append(f"Error during encoding detection: {str(e)}")
#         else:
#             self.warnings.append("chardet not available, using UTF-8")
        
#         return encoding_info
    
#     def _detect_bom(self, file_path: str) -> bool:
#         """Detect presence of Byte Order Mark."""
#         try:
#             with open(file_path, 'rb') as f:
#                 header = f.read(4)
            
#             # Check for various BOM signatures
#             bom_signatures = [
#                 b'\xef\xbb\xbf',      # UTF-8
#                 b'\xff\xfe',          # UTF-16 LE
#                 b'\xfe\xff',          # UTF-16 BE
#                 b'\xff\xfe\x00\x00',  # UTF-32 LE
#                 b'\x00\x00\xfe\xff',  # UTF-32 BE
#             ]
            
#             return any(header.startswith(bom) for bom in bom_signatures)
#         except Exception:
#             return False
    
#     def _detect_text_subtype(self, file_path: str) -> str:
#         """Detect specific text file subtype."""
#         ext = self._get_file_extension(file_path).lower()
        
#         # Extension-based detection
#         subtype_map = {
#             'json': 'JSON',
#             'xml': 'XML',
#             'html': 'HTML',
#             'htm': 'HTML',
#             'md': 'Markdown',
#             'rst': 'reStructuredText',
#             'csv': 'CSV',
#             'tsv': 'TSV',
#             'yaml': 'YAML',
#             'yml': 'YAML',
#             'ini': 'INI/Config',
#             'cfg': 'Config',
#             'conf': 'Config',
#             'log': 'Log File',
#             'py': 'Python Script',
#             'js': 'JavaScript',
#             'css': 'CSS',
#             'sql': 'SQL',
#             'sh': 'Shell Script',
#             'bat': 'Batch Script',
#             'ps1': 'PowerShell Script',
#         }
        
#         if ext in subtype_map:
#             return subtype_map[ext]
        
#         # Content-based detection
#         try:
#             encoding = self._detect_encoding(file_path).get("detected_encoding", DEFAULT_ENCODING)
#             with open(file_path, 'r', encoding=encoding, errors='replace') as f:
#                 content = f.read(1024)  # Read first 1KB
            
#             content_lower = content.lower().strip()
            
#             if content_lower.startswith('{') or content_lower.startswith('['):
#                 return 'JSON (possible)'
#             elif content_lower.startswith('<?xml') or content_lower.startswith('<'):
#                 return 'XML/HTML (possible)'
#             elif re.search(r'^#+\s', content, re.MULTILINE):
#                 return 'Markdown (possible)'
#             elif re.search(r'^\[.*\]$', content, re.MULTILINE):
#                 return 'INI/Config (possible)'
#             elif re.search(r'\d{4}-\d{2}-\d{2}', content):
#                 return 'Log File (possible)'
#             else:
#                 return 'Generic Text'
                
#         except Exception:
#             return 'Generic Text'
    
#     def _detect_line_endings(self, file_path: str) -> str:
#         """Detect line ending style."""
#         try:
#             with open(file_path, 'rb') as f:
#                 content = f.read(min(CHUNK_SIZE, os.path.getsize(file_path)))
            
#             crlf_count = content.count(b'\r\n')
#             lf_count = content.count(b'\n') - crlf_count
#             cr_count = content.count(b'\r') - crlf_count
            
#             if crlf_count > lf_count and crlf_count > cr_count:
#                 return 'CRLF'
#             elif cr_count > lf_count and cr_count > crlf_count:
#                 return 'CR'
#             elif lf_count > 0:
#                 return 'LF'
#             else:
#                 return 'Unknown'
                
#         except Exception:
#             return 'Unknown'
    
#     def _analyze_content_flags(self, file_path: str, encoding: str) -> Dict[str, Any]:
#         """Analyze various content flags and properties."""
#         flags = {}
        
#         try:
#             with open(file_path, 'r', encoding=encoding, errors='replace') as f:
#                 content = f.read(min(MAX_SAMPLE_SIZE, os.path.getsize(file_path)))
            
#             # Character type analysis
#             flags["contains_non_ascii"] = any(ord(c) > 127 for c in content)
#             flags["contains_control_chars"] = any(ord(c) < 32 and c not in '\t\n\r' for c in content)
#             flags["contains_right_to_left_text"] = bool(re.search(r'[\u0590-\u05FF\u0600-\u06FF\u0750-\u077F]', content))
#             flags["contains_emoji"] = bool(re.search(r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]', content))
#             flags["contains_markup"] = bool(re.search(r'<[^>]+>|\*\*.*?\*\*|\[.*?\]\(.*?\)', content))
#             flags["contains_urls"] = bool(re.search(REGEX_PATTERNS["urls"], content))
#             flags["contains_emails"] = bool(re.search(REGEX_PATTERNS["emails"], content))
#             flags["contains_dates"] = bool(re.search(REGEX_PATTERNS["dates"], content))
#             flags["contains_currency_symbols"] = bool(re.search(r'[$€£¥₹₽¢]', content))
#             flags["contains_math_symbols"] = bool(re.search(r'[+\-×÷=<>≤≥≠∞∑∏∫√∂∆∇]', content))
#             flags["contains_cjk_characters"] = bool(re.search(r'[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff]', content))
#             flags["contains_rtl_characters"] = bool(re.search(r'[\u0590-\u05FF\u0600-\u06FF]', content))
#             flags["contains_surrogate_pairs"] = bool(re.search(r'[\uD800-\uDBFF][\uDC00-\uDFFF]', content))
#             flags["contains_private_use_area"] = bool(re.search(r'[\uE000-\uF8FF]', content))
#             flags["contains_zero_width_space"] = bool(re.search(r'[\u200B-\u200D\uFEFF]', content))
#             flags["contains_bidi_override"] = bool(re.search(r'[\u202A-\u202E]', content))
            
#             # Unicode normalization forms
#             flags["contains_unicode_normalization_forms"] = self._detect_unicode_normalization(content)
            
#         except Exception as e:
#             self.warnings.append(f"Error analyzing content flags: {str(e)}")
#             # Return default values
#             flags = {key: False for key in [
#                 "contains_non_ascii", "contains_control_chars", "contains_right_to_left_text",
#                 "contains_emoji", "contains_markup", "contains_urls", "contains_emails",
#                 "contains_dates", "contains_currency_symbols", "contains_math_symbols",
#                 "contains_cjk_characters", "contains_rtl_characters", "contains_surrogate_pairs",
#                 "contains_private_use_area", "contains_zero_width_space", "contains_bidi_override"
#             ]}
#             flags["contains_unicode_normalization_forms"] = []
        
#         return flags
    
#     def _detect_unicode_normalization(self, content: str) -> List[str]:
#         """Detect Unicode normalization forms present in the content."""
#         forms = []
#         sample = content[:1000]  # Check first 1000 characters
        
#         try:
#             if unicodedata.normalize('NFC', sample) == sample:
#                 forms.append('NFC')
#             if unicodedata.normalize('NFD', sample) == sample:
#                 forms.append('NFD')
#             if unicodedata.normalize('NFKC', sample) == sample:
#                 forms.append('NFKC')
#             if unicodedata.normalize('NFKD', sample) == sample:
#                 forms.append('NFKD')
#         except Exception:
#             pass
        
#         return forms
    
#     # Helper methods for content metrics
#     def _calculate_basic_metrics(self, content: str, lines: List[str]) -> Dict[str, Any]:
#         """Calculate basic content metrics."""
#         words = content.split()
        
#         metrics = {
#             "average_words_per_line": len(words) / len(lines) if lines else 0,
#             "average_characters_per_word": len(re.sub(r'\s', '', content)) / len(words) if words else 0,
#         }
        
#         return metrics
    
#     def _analyze_characters(self, content: str) -> Dict[str, Any]:
#         """Analyze character distribution and properties."""
#         char_analysis = {}
        
#         # Count different character types
#         char_analysis["non_printable_ascii_count"] = sum(1 for c in content if ord(c) < 32 and c not in '\t\n\r')
#         char_analysis["high_ascii_or_invalid_utf8_count"] = sum(1 for c in content if ord(c) > 127)
        
#         # Unicode category counts
#         unicode_categories = defaultdict(int)
#         for char in content:
#             category = unicodedata.category(char)
#             unicode_categories[category] += 1
#         char_analysis["unicode_category_counts"] = dict(unicode_categories)
        
#         # Character frequency analysis
#         char_counter = Counter(content.lower())
#         total_chars = len(content)
        
#         # Top 5 most frequent characters (excluding whitespace)
#         top_chars = {char: count for char, count in char_counter.most_common(10) if not char.isspace()}
#         char_analysis["top_5_most_frequent_characters"] = dict(list(top_chars.items())[:5])
        
#         # Frequency percentages
#         digit_count = sum(count for char, count in char_counter.items() if char.isdigit())
#         punct_count = sum(count for char, count in char_counter.items() if char in string.punctuation)
        
#         char_analysis["frequency_of_digits_percent"] = (digit_count / total_chars * 100) if total_chars else 0
#         char_analysis["frequency_of_punctuation_percent"] = (punct_count / total_chars * 100) if total_chars else 0
        
#         return char_analysis
    
#     def _analyze_lines_and_structure(self, lines: List[str]) -> Dict[str, Any]:
#         """Analyze line-level structure and formatting."""
#         if not lines:
#             return {}
        
#         analysis = {}
        
#         # Empty lines
#         empty_lines = sum(1 for line in lines if not line.strip())
#         analysis["empty_line_count"] = empty_lines
#         analysis["proportion_empty_lines"] = empty_lines / len(lines)
        
#         # Whitespace issues
#         leading_trailing_ws = sum(1 for line in lines if line != line.strip())
#         multiple_spaces = sum(1 for line in lines if re.search(r'\s{2,}', line))
        
#         analysis["lines_with_leading_trailing_whitespace_count"] = leading_trailing_ws
#         analysis["multiple_spaces_between_words_count"] = multiple_spaces
        
#         # Line length analysis
#         line_lengths = [len(line) for line in lines]
#         analysis["average_line_length"] = sum(line_lengths) / len(line_lengths)
#         analysis["max_line_length"] = max(line_lengths) if line_lengths else 0
        
#         long_lines = sum(1 for length in line_lengths if length > 80)
#         analysis["percentage_lines_over_80_chars"] = (long_lines / len(lines) * 100) if lines else 0
        
#         # Newline consistency
#         analysis.update(self._analyze_newline_consistency(lines))
        
#         # Indentation analysis
#         analysis.update(self._analyze_indentation(lines))
        
#         # Comment analysis
#         analysis.update(self._analyze_comments(lines))
        
#         return analysis
    
#     def _analyze_newline_consistency(self, lines: List[str]) -> Dict[str, str]:
#         """Analyze newline consistency."""
#         # This is simplified since we already have split lines
#         return {
#             "detected_newline_style": "LF",  # Default assumption
#             "newline_consistency": "Consistent"  # Simplified
#         }
    
#     def _analyze_indentation(self, lines: List[str]) -> Dict[str, Any]:
#         """Analyze indentation patterns."""
#         indent_analysis = {}
        
#         space_indents = 0
#         tab_indents = 0
#         mixed_indents = 0
#         indent_sizes = Counter()
        
#         for line in lines:
#             if line.strip():  # Non-empty lines only
#                 leading_ws = line[:len(line) - len(line.lstrip())]
#                 if leading_ws:
#                     if '\t' in leading_ws and ' ' in leading_ws:
#                         mixed_indents += 1
#                     elif '\t' in leading_ws:
#                         tab_indents += 1
#                     elif ' ' in leading_ws:
#                         space_indents += 1
#                         indent_sizes[len(leading_ws)] += 1
        
#         # Determine indentation style
#         if mixed_indents > 0:
#             indent_style = "Mixed"
#         elif tab_indents > space_indents:
#             indent_style = "Tabs"
#         elif space_indents > 0:
#             indent_style = "Spaces"
#         else:
#             indent_style = "None"
        
#         # Most common space indent size
#         space_indent_size = indent_sizes.most_common(1)[0][0] if indent_sizes else 0
        
#         indent_analysis.update({
#             "indentation_style": indent_style,
#             "space_indent_size": space_indent_size,
#             "indentation_consistency": "Consistent" if mixed_indents == 0 else "Mixed"
#         })
        
#         return indent_analysis
    
#     def _analyze_comments(self, lines: List[str]) -> Dict[str, Any]:
#         """Analyze comment patterns."""
#         comment_patterns = [
#             r'^\s*#',      # Python, shell
#             r'^\s*//',     # C++, Java, JavaScript
#             r'^\s*--',     # SQL, Haskell
#             r'^\s*;',      # Assembly, Lisp
#             r'^\s*%',      # LaTeX, MATLAB
#         ]
        
#         comment_lines = 0
#         for line in lines:
#             for pattern in comment_patterns:
#                 if re.match(pattern, line):
#                     comment_lines += 1
#                     break
        
#         return {
#             "comment_line_count": comment_lines,
#             "proportion_comment_lines": comment_lines / len(lines) if lines else 0
#         }
    
#     def _analyze_linguistics(self, content: str) -> Dict[str, Any]:
#         """Perform linguistic analysis."""
#         linguistics = {}
        
#         # Readability scores
#         if textstat:
#             try:
#                 linguistics["flesch_kincaid_grade_level"] = textstat.flesch_kincaid_grade(content)
                
#                 # Additional readability scores
#                 readability_scores = {
#                     "flesch_reading_ease": textstat.flesch_reading_ease(content),
#                     "gunning_fog": textstat.gunning_fog(content),
#                     "coleman_liau_index": textstat.coleman_liau_index(content),
#                     "automated_readability_index": textstat.automated_readability_index(content),
#                     "smog_index": textstat.smog_index(content),
#                     "linsear_write_formula": textstat.linsear_write_formula(content),
#                     "dale_chall_readability_score": textstat.dale_chall_readability_score(content),
#                 }
#                 linguistics["readability_scores"] = readability_scores
#             except Exception as e:
#                 self.warnings.append(f"Error calculating readability scores: {str(e)}")
#                 linguistics["flesch_kincaid_grade_level"] = None
#                 linguistics["readability_scores"] = {}
#         else:
#             linguistics["flesch_kincaid_grade_level"] = None
#             linguistics["readability_scores"] = {}
        
#         # Type-token ratio (lexical diversity)
#         words = content.lower().split()
#         if words:
#             unique_words = set(words)
#             linguistics["type_token_ratio"] = len(unique_words) / len(words)
#             linguistics["unique_word_count"] = len(unique_words)
            
#             # Hapax legomena (words that occur only once)
#             word_counts = Counter(words)
#             hapax_legomena = sum(1 for count in word_counts.values() if count == 1)
#             linguistics["hapax_legomena_count"] = hapax_legomena
            
#             # Lexical density (content words vs function words)
#             if english_stopwords:
#                 content_words = [word for word in words if word not in english_stopwords]
#                 linguistics["lexical_density"] = len(content_words) / len(words)
#                 linguistics["stopword_count"] = len(words) - len(content_words)
#                 linguistics["stopword_ratio"] = (len(words) - len(content_words)) / len(words)
#             else:
#                 linguistics["lexical_density"] = None
#                 linguistics["stopword_count"] = None
#                 linguistics["stopword_ratio"] = None
#         else:
#             linguistics.update({
#                 "type_token_ratio": 0,
#                 "unique_word_count": 0,
#                 "hapax_legomena_count": 0,
#                 "lexical_density": None,
#                 "stopword_count": None,
#                 "stopword_ratio": None
#             })
        
#         # Sentence and paragraph analysis
#         if sent_tokenize:
#             try:
#                 sentences = sent_tokenize(content)
#                 linguistics["sentence_count"] = len(sentences)
                
#                 if sentences:
#                     sentence_lengths = [len(sentence.split()) for sentence in sentences]
#                     linguistics["average_sentence_length"] = sum(sentence_lengths) / len(sentence_lengths)
#                     linguistics["longest_sentence_length"] = max(sentence_lengths)
#                     linguistics["shortest_sentence_length"] = min(sentence_lengths)
#                 else:
#                     linguistics.update({
#                         "average_sentence_length": 0,
#                         "longest_sentence_length": 0,
#                         "shortest_sentence_length": 0
#                     })
#             except Exception as e:
#                 self.warnings.append(f"Error in sentence analysis: {str(e)}")
#                 linguistics.update({
#                     "sentence_count": 0,
#                     "average_sentence_length": 0,
#                     "longest_sentence_length": 0,
#                     "shortest_sentence_length": 0
#                 })
#         else:
#             linguistics.update({
#                 "sentence_count": None,
#                 "average_sentence_length": None,
#                 "longest_sentence_length": None,
#                 "shortest_sentence_length": None
#             })
        
#         # Paragraph analysis
#         paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
#         linguistics["paragraph_count"] = len(paragraphs)
        
#         if paragraphs:
#             paragraph_lengths = [len(paragraph.split()) for paragraph in paragraphs]
#             linguistics["average_paragraph_length"] = sum(paragraph_lengths) / len(paragraph_lengths)
#         else:
#             linguistics["average_paragraph_length"] = 0
        
#         # N-gram analysis
#         if ngrams and words:
#             try:
#                 # Bigrams
#                 bigrams_list = list(ngrams(words, 2))
#                 bigram_counts = Counter(bigrams_list)
#                 linguistics["most_common_bigrams"] = [
#                     [' '.join(bigram), count] for bigram, count in bigram_counts.most_common(10)
#                 ]
                
#                 # Trigrams
#                 trigrams_list = list(ngrams(words, 3))
#                 trigram_counts = Counter(trigrams_list)
#                 linguistics["most_common_trigrams"] = [
#                     [' '.join(trigram), count] for trigram, count in trigram_counts.most_common(10)
#                 ]
#             except Exception as e:
#                 self.warnings.append(f"Error in n-gram analysis: {str(e)}")
#                 linguistics["most_common_bigrams"] = []
#                 linguistics["most_common_trigrams"] = []
#         else:
#             linguistics["most_common_bigrams"] = []
#             linguistics["most_common_trigrams"] = []
        
#         # Language detection
#         if detect:
#             try:
#                 detected_lang = detect(content)
#                 confidence = "High"  # langdetect doesn't provide confidence scores directly
#                 linguistics["language_detection"] = {
#                     "detected_language": detected_lang,
#                     "confidence": confidence
#                 }
#             except Exception as e:
#                 self.warnings.append(f"Error in language detection: {str(e)}")
#                 linguistics["language_detection"] = {
#                     "detected_language": "unknown",
#                     "confidence": "N/A"
#                 }
#         else:
#             linguistics["language_detection"] = {
#                 "detected_language": "N/A",
#                 "confidence": "N/A"
#             }
        
#         # Sentiment analysis
#         if sentiment_analyzer:
#             try:
#                 sentiment_scores = sentiment_analyzer.polarity_scores(content)
                
#                 # Determine overall sentiment
#                 compound = sentiment_scores['compound']
#                 if compound >= 0.05:
#                     overall_sentiment = "Positive"
#                 elif compound <= -0.05:
#                     overall_sentiment = "Negative"
#                 else:
#                     overall_sentiment = "Neutral"
                
#                 linguistics["sentiment_analysis"] = {
#                     "overall_sentiment": overall_sentiment,
#                     "sentiment_score_compound": sentiment_scores['compound'],
#                     "sentiment_score_positive": sentiment_scores['pos'],
#                     "sentiment_score_negative": sentiment_scores['neg'],
#                     "sentiment_score_neutral": sentiment_scores['neu']
#                 }
#             except Exception as e:
#                 self.warnings.append(f"Error in sentiment analysis: {str(e)}")
#                 linguistics["sentiment_analysis"] = {
#                     "overall_sentiment": "N/A",
#                     "sentiment_score_compound": None,
#                     "sentiment_score_positive": None,
#                     "sentiment_score_negative": None,
#                     "sentiment_score_neutral": None
#                 }
#         else:
#             linguistics["sentiment_analysis"] = {
#                 "overall_sentiment": "N/A",
#                 "sentiment_score_compound": None,
#                 "sentiment_score_positive": None,
#                 "sentiment_score_negative": None,
#                 "sentiment_score_neutral": None
#             }
        
#         return linguistics
    
#     def _analyze_patterns(self, content: str) -> Dict[str, Any]:
#         """Analyze content patterns and extract matches."""
#         pattern_analysis = {}
        
#         # Pattern matching
#         regex_matches = {}
#         obfuscation_types = set()
        
#         for pattern_name, pattern in REGEX_PATTERNS.items():
#             try:
#                 matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
#                 if matches:
#                     # Limit samples to avoid huge outputs
#                     samples = list(set(matches))[:10]
#                     regex_matches[pattern_name] = {
#                         "count": len(matches),
#                         "unique_count": len(set(matches)),
#                         "samples": samples
#                     }
                    
#                     # Check for obfuscation indicators
#                     if pattern_name in ["base64", "hex_strings", "obfuscated_strings"]:
#                         obfuscation_types.add(pattern_name)
#             except Exception as e:
#                 self.warnings.append(f"Error matching pattern {pattern_name}: {str(e)}")
        
#         pattern_analysis["regex_pattern_matches"] = regex_matches
#         pattern_analysis["has_obfuscated_content"] = len(obfuscation_types) > 0
#         pattern_analysis["obfuscation_types_detected"] = list(obfuscation_types)
        
#         return pattern_analysis
    
#     def _calculate_advanced_metrics(self, content: str, lines: List[str]) -> Dict[str, Any]:
#         """Calculate advanced metrics."""
#         advanced = {}
        
#         # Entropy calculation
#         if content:
#             char_counts = Counter(content)
#             total_chars = len(content)
#             entropy = -sum((count/total_chars) * math.log2(count/total_chars) 
#                           for count in char_counts.values())
#             advanced["overall_entropy"] = entropy
#         else:
#             advanced["overall_entropy"] = 0
        
#         # Syllable analysis (simplified)
#         words = content.split()
#         if words:
#             syllable_count = sum(self._count_syllables(word) for word in words)
#             advanced["syllable_count"] = syllable_count
#             advanced["average_syllables_per_word"] = syllable_count / len(words)
#         else:
#             advanced["syllable_count"] = 0
#             advanced["average_syllables_per_word"] = 0
        
#         # Palindrome detection
#         words_clean = [re.sub(r'[^a-zA-Z0-9]', '', word.lower()) for word in words]
#         palindromes = [word for word in words_clean if len(word) > 2 and word == word[::-1]]
#         advanced["palindrome_count"] = len(palindromes)
        
#         # Zipf distribution analysis (simplified)
#         if words:
#             word_counts = Counter(words)
#             sorted_counts = sorted(word_counts.values(), reverse=True)
#             zipf_distribution = {}
#             for rank, count in enumerate(sorted_counts[:10], 1):
#                 expected_count = sorted_counts[0] / rank
#                 zipf_distribution[f"rank_{rank}"] = count / expected_count if expected_count > 0 else 0
#             advanced["zipf_frequency_distribution"] = zipf_distribution
#         else:
#             advanced["zipf_frequency_distribution"] = {}
        
#         # Shannon entropy per line and word
#         if lines:
#             line_entropies = []
#             for line in lines:
#                 if line:
#                     char_counts = Counter(line)
#                     total_chars = len(line)
#                     if total_chars > 0:
#                         entropy = -sum((count/total_chars) * math.log2(count/total_chars) 
#                                      for count in char_counts.values())
#                         line_entropies.append(entropy)
            
#             advanced["shannon_entropy_per_line"] = sum(line_entropies) / len(line_entropies) if line_entropies else 0
#         else:
#             advanced["shannon_entropy_per_line"] = 0
        
#         if words:
#             word_entropies = []
#             for word in words:
#                 if word:
#                     char_counts = Counter(word)
#                     total_chars = len(word)
#                     if total_chars > 0:
#                         entropy = -sum((count/total_chars) * math.log2(count/total_chars) 
#                                      for count in char_counts.values())
#                         word_entropies.append(entropy)
            
#             advanced["shannon_entropy_per_word"] = sum(word_entropies) / len(word_entropies) if word_entropies else 0
#         else:
#             advanced["shannon_entropy_per_word"] = 0
        
#         # Text complexity index (custom metric)
#         complexity_factors = [
#             advanced.get("overall_entropy", 0) / 8,  # Normalize entropy
#             len(set(words)) / len(words) if words else 0,  # Lexical diversity
#             advanced.get("average_syllables_per_word", 0) / 3,  # Syllable complexity
#         ]
#         advanced["text_complexity_index"] = sum(complexity_factors) / len(complexity_factors)
        
#         return advanced
    
#     def _count_syllables(self, word: str) -> int:
#         """Count syllables in a word (simplified algorithm)."""
#         word = word.lower()
#         vowels = "aeiouy"
#         syllable_count = 0
#         previous_was_vowel = False
        
#         for char in word:
#             is_vowel = char in vowels
#             if is_vowel and not previous_was_vowel:
#                 syllable_count += 1
#             previous_was_vowel = is_vowel
        
#         # Handle silent 'e'
#         if word.endswith('e') and syllable_count > 1:
#             syllable_count -= 1
        
#         return max(1, syllable_count)
    
#     # Helper methods for structural metrics
#     def _calculate_basic_structural_metrics(self, lines: List[str]) -> Dict[str, Any]:
#         """Calculate basic structural metrics."""
#         if not lines:
#             return {}
        
#         line_lengths = [len(line) for line in lines]
#         empty_lines = sum(1 for line in lines if not line.strip())
        
#         metrics = {
#             "average_line_length": sum(line_lengths) / len(line_lengths),
#             "max_line_length": max(line_lengths),
#             "percentage_lines_over_80_chars": (sum(1 for length in line_lengths if length > 80) / len(lines)) * 100,
#             "empty_line_count": empty_lines,
#             "proportion_empty_lines": empty_lines / len(lines),
#         }
        
#         # Whitespace analysis
#         leading_trailing_ws = sum(1 for line in lines if line != line.strip())
#         multiple_spaces = sum(1 for line in lines if re.search(r'\s{2,}', line))
        
#         metrics.update({
#             "excessive_whitespace_flag": leading_trailing_ws > 0 or multiple_spaces > 0,
#             "count_lines_with_leading_trailing_whitespace": leading_trailing_ws,
#             "count_multiple_spaces_between_words": multiple_spaces,
#         })
        
#         # Copy some metrics from content analysis
#         metrics.update(self._analyze_newline_consistency(lines))
#         metrics.update(self._analyze_indentation(lines))
#         metrics.update(self._analyze_comments(lines))
        
#         return metrics
    
#     def _analyze_advanced_structure(self, lines: List[str], content: str) -> Dict[str, Any]:
#         """Analyze advanced structural features."""
#         structure = {}
        
#         # Mixed indentation detection
#         has_spaces = any(line.startswith(' ') for line in lines)
#         has_tabs = any(line.startswith('\t') for line in lines)
#         structure["has_mixed_indentation"] = has_spaces and has_tabs
        
#         # Whitespace analysis
#         structure["has_trailing_whitespace"] = any(line.endswith((' ', '\t')) for line in lines)
#         structure["has_leading_whitespace"] = any(line.startswith((' ', '\t')) for line in lines)
        
#         # Blank lines at start/end
#         structure["has_blank_lines_at_start"] = lines and not lines[0].strip()
#         structure["has_blank_lines_at_end"] = lines and not lines[-1].strip()
        
#         # Duplicate lines
#         line_counts = Counter(line.strip() for line in lines if line.strip())
#         structure["has_duplicate_lines"] = any(count > 1 for count in line_counts.values())
        
#         # Line length analysis
#         line_lengths = [len(line) for line in lines]
#         structure["has_long_lines"] = any(length > 120 for length in line_lengths)
#         structure["has_short_lines"] = any(0 < length < 10 for length in line_lengths)
        
#         # Uniform line length (low variance)
#         if line_lengths:
#             avg_length = sum(line_lengths) / len(line_lengths)
#             variance = sum((length - avg_length) ** 2 for length in line_lengths) / len(line_lengths)
#             structure["has_uniform_line_length"] = variance < 100  # Arbitrary threshold
#         else:
#             structure["has_uniform_line_length"] = False
        
#         # Content structure detection
#         structure["has_section_headers"] = bool(re.search(r'^#+\s|^[A-Z\s]+$', content, re.MULTILINE))
#         structure["has_table_structures"] = bool(re.search(r'\|.*\|', content))
#         structure["has_code_blocks"] = bool(re.search(r'```|    \w', content))
#         structure["has_list_structures"] = bool(re.search(r'^\s*[-*+]\s|^\s*\d+\.\s', content, re.MULTILINE))
#         structure["has_numbered_lines"] = bool(re.search(r'^\d+[\.:]\s', content, re.MULTILINE))
        
#         # Special characters
#         structure["has_page_breaks"] = '\f' in content
#         structure["has_form_feed_chars"] = '\f' in content
#         structure["has_tabs"] = '\t' in content
        
#         # Line type analysis
#         structure["has_spaces_only"] = any(re.match(r'^ +$', line) for line in lines)
#         structure["has_tabs_only"] = any(re.match(r'^\t+$', line) for line in lines)
        
#         # Line ending analysis
#         structure["has_mixed_line_endings"] = self._detect_mixed_line_endings(content)
#         structure["has_unicode_line_separators"] = bool(re.search(r'[\u2028\u2029]', content))
        
#         return structure
    
#     def _detect_mixed_line_endings(self, content: str) -> bool:
#         """Detect if file has mixed line endings."""
#         has_crlf = '\r\n' in content
#         has_lf = '\n' in content and '\r\n' not in content.replace('\r\n', '')
#         has_cr = '\r' in content and '\r\n' not in content
        
#         return sum([has_crlf, has_lf, has_cr]) > 1
    
#     # Helper methods for content samples
#     def _find_anomalous_snippets(self, content: str, lines: List[str]) -> List[Dict[str, Any]]:
#         """Find anomalous or interesting snippets."""
#         snippets = []
        
#         # Long lines
#         for i, line in enumerate(lines):
#             if len(line) > 200:
#                 snippets.append({
#                     "type": "long_line",
#                     "snippet": line[:100] + "..." if len(line) > 100 else line,
#                     "line_number": i + 1,
#                     "description": f"Line with {len(line)} characters"
#                 })
        
#         # Base64-like content
#         base64_matches = re.finditer(REGEX_PATTERNS["base64"], content)
#         for match in list(base64_matches)[:3]:  # Limit to 3 matches
#             line_num = content[:match.start()].count('\n') + 1
#             snippets.append({
#                 "type": "base64_content",
#                 "snippet": match.group()[:50] + "..." if len(match.group()) > 50 else match.group(),
#                 "line_number": line_num,
#                 "description": "Possible Base64 encoded content"
#             })
        
#         # Hex strings
#         hex_matches = re.finditer(REGEX_PATTERNS["hex_strings"], content)
#         for match in list(hex_matches)[:3]:
#             line_num = content[:match.start()].count('\n') + 1
#             snippets.append({
#                 "type": "hex_content",
#                 "snippet": match.group()[:50] + "..." if len(match.group()) > 50 else match.group(),
#                 "line_number": line_num,
#                 "description": "Hexadecimal string"
#             })
        
#         return snippets[:10]  # Limit total snippets
    
#     def _extract_entities(self, content: str) -> Dict[str, Any]:
#         """Extract named entities from content."""
#         entities = {
#             "persons": [],
#             "organizations": [],
#             "locations": [],
#             "dates_times": [],
#             "note": "Named entity recognition requires spaCy with trained models"
#         }
        
#         if nlp:
#             try:
#                 # Process only first 10000 characters to avoid performance issues
#                 doc = nlp(content[:10000])
                
#                 for ent in doc.ents:
#                     if ent.label_ in ["PERSON"]:
#                         entities["persons"].append(ent.text)
#                     elif ent.label_ in ["ORG"]:
#                         entities["organizations"].append(ent.text)
#                     elif ent.label_ in ["GPE", "LOC"]:
#                         entities["locations"].append(ent.text)
#                     elif ent.label_ in ["DATE", "TIME"]:
#                         entities["dates_times"].append(ent.text)
                
#                 # Remove duplicates and limit results
#                 for key in ["persons", "organizations", "locations", "dates_times"]:
#                     entities[key] = list(set(entities[key]))[:10]
                
#                 entities["note"] = "Extracted using spaCy NLP"
                
#             except Exception as e:
#                 self.warnings.append(f"Error in named entity recognition: {str(e)}")
        
#         # Fallback: extract dates using regex
#         if not entities["dates_times"]:
#             date_matches = re.findall(REGEX_PATTERNS["dates"], content)
#             entities["dates_times"] = list(set(date_matches))[:10]
        
#         return entities
    
#     def _extract_optional_samples(self, content: str, lines: List[str]) -> Dict[str, Any]:
#         """Extract optional content samples."""
#         samples = {}
        
#         # Random line samples
#         import random
#         non_empty_lines = [line for line in lines if line.strip()]
#         if non_empty_lines:
#             sample_size = min(5, len(non_empty_lines))
#             samples["random_line_samples"] = random.sample(non_empty_lines, sample_size)
#         else:
#             samples["random_line_samples"] = []
        
#         # Longest and shortest lines
#         if lines:
#             samples["longest_line_sample"] = max(lines, key=len)
#             non_empty_lines = [line for line in lines if line.strip()]
#             if non_empty_lines:
#                 samples["shortest_line_sample"] = min(non_empty_lines, key=len)
#             else:
#                 samples["shortest_line_sample"] = ""
#         else:
#             samples["longest_line_sample"] = ""
#             samples["shortest_line_sample"] = ""
        
#         # Most frequent line
#         line_counts = Counter(line.strip() for line in lines if line.strip())
#         if line_counts:
#             samples["most_frequent_line_sample"] = line_counts.most_common(1)[0][0]
#         else:
#             samples["most_frequent_line_sample"] = ""
        
#         # Most frequent word
#         words = content.split()
#         if words:
#             word_counts = Counter(word.lower() for word in words)
#             samples["most_frequent_word_sample"] = word_counts.most_common(1)[0][0]
#         else:
#             samples["most_frequent_word_sample"] = ""
        
#         # Sample sentences
#         if sent_tokenize:
#             try:
#                 sentences = sent_tokenize(content)
#                 samples["sample_sentences"] = sentences[:3]
#             except Exception:
#                 samples["sample_sentences"] = []
#         else:
#             samples["sample_sentences"] = []
        
#         # Sample paragraphs
#         paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
#         samples["sample_paragraphs"] = paragraphs[:2]
        
#         # Extract specific content types
#         samples.update(self._extract_content_type_samples(content))
        
#         return samples
    
#     def _extract_content_type_samples(self, content: str) -> Dict[str, List[str]]:
#         """Extract samples of specific content types."""
#         samples = {}
        
#         # Code blocks
#         code_blocks = re.findall(r'```[\s\S]*?```', content)
#         samples["sample_code_blocks"] = code_blocks[:3]
        
#         # URLs
#         urls = re.findall(REGEX_PATTERNS["urls"], content)
#         samples["sample_urls"] = list(set(urls))[:5]
        
#         # Emails
#         emails = re.findall(REGEX_PATTERNS["emails"], content)
#         samples["sample_emails"] = list(set(emails))[:5]
        
#         # Numbers
#         numbers = re.findall(r'\b\d+(?:\.\d+)?\b', content)
#         samples["sample_numbers"] = list(set(numbers))[:10]
        
#         # Dates
#         dates = re.findall(REGEX_PATTERNS["dates"], content)
#         samples["sample_dates"] = list(set(dates))[:5]
        
#         # Currency
#         currency = re.findall(REGEX_PATTERNS["currency"], content)
#         samples["sample_currency"] = list(set(currency))[:5]
        
#         # Unicode sequences
#         unicode_chars = [char for char in content if ord(char) > 127]
#         samples["sample_unicode_sequences"] = list(set(unicode_chars))[:10]
        
#         # Obfuscated content
#         base64_matches = re.findall(REGEX_PATTERNS["base64"], content)
#         hex_matches = re.findall(REGEX_PATTERNS["hex_strings"], content)
#         samples["sample_obfuscated_content"] = (base64_matches + hex_matches)[:5]
        
#         # Comments
#         comment_lines = []
#         for line in content.splitlines():
#             if re.match(r'^\s*[#//;%]', line):
#                 comment_lines.append(line.strip())
#         samples["sample_comments"] = comment_lines[:5]
        
#         # Headers
#         headers = re.findall(r'^#+\s+.*$', content, re.MULTILINE)
#         samples["sample_headers"] = headers[:5]
        
#         # Lists
#         lists = re.findall(r'^\s*[-*+]\s+.*$', content, re.MULTILINE)
#         samples["sample_lists"] = lists[:5]
        
#         # Tables (simplified)
#         table_lines = [line for line in content.splitlines() if '|' in line and line.count('|') >= 2]
#         samples["sample_tables"] = table_lines[:3]
        
#         return samples
    
#     def _get_dependency_versions(self) -> Dict[str, str]:
#         """Get versions of installed dependencies."""
#         versions = {}
        
#         dependencies = [
#             'chardet', 'magic', 'ssdeep', 'textstat', 'langdetect', 
#             'vaderSentiment', 'nltk', 'spacy', 'psutil'
#         ]
        
#         for dep in dependencies:
#             try:
#                 module = __import__(dep)
#                 if hasattr(module, '__version__'):
#                     versions[dep] = module.__version__
#                 else:
#                     versions[dep] = "unknown"
#             except ImportError:
#                 versions[dep] = "not installed"
        
#         return versions
    
#     def _create_error_result(self, error_message: str) -> Dict[str, Any]:
#         """Create an error result structure."""
#         return {
#             "file_info": {},
#             "text_info": {},
#             "content_metrics": {},
#             "structural_metrics": {},
#             "content_samples": {},
#             "processing": {
#                 "success": False,
#                 "warnings": self.warnings,
#                 "errors": self.errors + [error_message],
#                 "time_taken_seconds": time.time() - self.start_time,
#                 "extractor_version": "2.0.0",
#                 "processing_stage": self.processing_stage
#             }
#         }

# def main():
#     """Main function for command-line usage."""
#     parser = argparse.ArgumentParser(description="Extract comprehensive metadata from text files")
#     parser.add_argument("file_path", help="Path to the text file to analyze")
#     parser.add_argument("--output", "-o", help="Output file for JSON results (default: stdout)")
#     parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    
#     args = parser.parse_args()
    
#     # Extract metadata
#     extractor = MetadataExtractor()
#     metadata = extractor.extract_metadata(args.file_path)
    
#     # Output results
#     if args.pretty:
#         json_output = json.dumps(metadata, indent=2, ensure_ascii=False)
#     else:
#         json_output = json.dumps(metadata, ensure_ascii=False)
    
#     if args.output:
#         with open(args.output, 'w', encoding='utf-8') as f:
#             f.write(json_output)
#         print(f"Metadata written to {args.output}")
#     else:
#         print(json_output)
    
#     # Exit with appropriate code
#     if not metadata["processing"]["success"]:
#         sys.exit(1)


# if __name__ == "__main__":
#     main()

# # from typing import Dict, Any

# # class TXTMetadataExtractor:
# #     def __init__(self):
# #         self.processing_stage = None
# #         self.errors = []

# #     def extract_metadata(self, file_path: str) -> Dict[str, Any]:
# #         # Implement logic to extract metadata here
# #         # For now, let's return a placeholder dictionary
# #         return {"file": file_path, "metadata": "sample metadata"}

# #     # other methods...

# # # ✅ Must come AFTER the class definition
# # def extract_txt_metadata(file_path):
# #     extractor = TXTMetadataExtractor()
# #     return extractor.extract_metadata(file_path)

# # # Optional CLI
# # def main():
# #     import sys
# #     file_path = sys.argv[1]
# #     metadata = extract_txt_metadata(file_path)
# #     import json
# #     print(json.dumps(metadata, indent=2))

# # # 👇 Only runs if script is executed directly
# # if __name__ == "__main__":
# #     main()














#!/usr/bin/env python3
"""
FileInsight - Accessible Metadata Extraction Tool
Lightweight metadata extraction from text files with clear output
"""

import os
import sys
import json
import time
import hashlib
import argparse
from datetime import datetime

# Configuration
DEFAULT_ENCODING = 'utf-8'
MAX_SAMPLE_SIZE = 10000  # 10KB for pattern matching

class FileInsight:
    """Main metadata extraction class"""
    def __init__(self):
        self.start_time = time.time()
        self.errors = []
    
    def extract(self, file_path):
        """Main extraction workflow"""
        try:
            # Validate input
            if not self.validate(file_path):
                return self.error_result("File validation failed")
            
            # Extract metadata
            return {
                "file_info": self.get_file_info(file_path),
                "content_analysis": self.analyze_content(file_path),
                "processing": self.get_processing_info()
            }
        except Exception as e:
            return self.error_result(f"Unexpected error: {str(e)}")
    
    def validate(self, file_path):
        """Validate file accessibility"""
        if not os.path.exists(file_path):
            self.errors.append(f"File not found: {file_path}")
            return False
        if not os.access(file_path, os.R_OK):
            self.errors.append(f"Permission denied: {file_path}")
            return False
        if os.path.getsize(file_path) == 0:
            self.errors.append("File is empty")
        return True
    
    def get_file_info(self, file_path):
        """Get basic file information"""
        stat_info = os.stat(file_path)
        return {
            "path": os.path.abspath(file_path),
            "name": os.path.basename(file_path),
            "size_bytes": os.path.getsize(file_path),
            "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "checksums": self.get_checksums(file_path)
        }
    
    def get_checksums(self, file_path):
        """Calculate file hashes"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return {
                    "md5": hashlib.md5(content).hexdigest(),
                    "sha256": hashlib.sha256(content).hexdigest()
                }
        except Exception as e:
            self.errors.append(f"Checksum error: {str(e)}")
            return {}
    
    def analyze_content(self, file_path):
        """Analyze file content"""
        try:
            # Read file content
            with open(file_path, 'r', encoding=DEFAULT_ENCODING, errors='replace') as f:
                content = f.read()
            
            # Basic metrics
            lines = content.splitlines()
            words = content.split()
            char_count = len(content)
            
            # Pattern detection
            patterns = self.detect_patterns(content)
            
            return {
                "line_count": len(lines),
                "word_count": len(words),
                "character_count": char_count,
                "longest_line": max(len(line) for line in lines) if lines else 0,
                "common_phrases": self.find_common_phrases(words),
                "detected_patterns": patterns
            }
        except Exception as e:
            self.errors.append(f"Content analysis error: {str(e)}")
            return {}
    
    def find_common_phrases(self, words, max_items=5):
        """Find most common words and phrases"""
        if not words:
            return []
        
        # Single words
        word_counts = Counter(words)
        common_words = [{"word": w, "count": c} for w, c in word_counts.most_common(max_items)]
        
        return {
            "words": common_words
        }
    
    def detect_patterns(self, content):
        """Detect common patterns in content"""
        # Limit to first 10KB for performance
        sample = content[:MAX_SAMPLE_SIZE]
        
        return {
            "emails": list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', sample))),
            "urls": list(set(re.findall(r'https?://[^\s]+', sample))),
            "ip_addresses": list(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', sample)))
        }
    
    def get_processing_info(self):
        """Get processing metadata"""
        return {
            "success": len(self.errors) == 0,
            "time_seconds": round(time.time() - self.start_time, 2),
            "errors": self.errors
        }
    
    def error_result(self, message):
        """Generate error response"""
        self.errors.append(message)
        return {
            "error": message,
            "processing": self.get_processing_info()
        }

def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description="FileInsight - Extract metadata from text files",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("file_path", help="File to analyze")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    
    args = parser.parse_args()
    
    # Process file
    analyzer = FileInsight()
    result = analyzer.extract(args.file_path)
    
    # Output results
    json_output = json.dumps(result, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(json_output)
        print(f"Results saved to {args.output}")
    elif args.verbose:
        print(json_output)
    else:
        # Simplified output
        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            info = result['file_info']
            analysis = result['content_analysis']
            print(f"File: {info['name']} ({info['size_bytes']} bytes)")
            print(f"Lines: {analysis['line_count']}  Words: {analysis['word_count']}  Characters: {analysis['character_count']}")
            print(f"Checksum (SHA256): {info['checksums']['sha256']}")

if __name__ == "__main__":
    main()
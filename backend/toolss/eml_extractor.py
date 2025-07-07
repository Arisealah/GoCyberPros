#!/usr/bin/env python3
"""
EML Metadata Extraction Tool

Description: Comprehensive metadata extraction from EML email files with validation,
error handling, and standardized output.

Features:
- Extracts email headers, attachments info
- Validates EML structure
- Handles MIME encoded messages
"""

import os
import email
import magic
import json
import argparse
from datetime import datetime
from email.header import decode_header
from typing import Dict, Any, List

class EMLMetadataError(Exception):
    """Base class for EML metadata exceptions"""
    pass

class InvalidEMLError(EMLMetadataError):
    """Raised when file is not a valid EML"""
    pass

class EMLProcessingError(EMLMetadataError):
    """Raised during EML processing failures"""
    pass

def validate_eml_file(file_path: str) -> bool:
    """
    Validate EML file structure and integrity.
    
    Args:
        file_path: Path to the EML file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file access is restricted
        InvalidEMLError: If file is not a valid EML
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Access denied: {file_path}")
    
    mime = magic.from_file(file_path, mime=True)
    if mime not in ('message/rfc822', 'text/plain'):
        raise InvalidEMLError(f"Not an EML file (detected: {mime})")
    
    return True

def decode_email_header(header: str) -> str:
    """Decode email header with multiple encodings"""
    decoded_parts = []
    for part, encoding in decode_header(header):
        if isinstance(part, bytes):
            decoded_parts.append(part.decode(encoding or 'utf-8', errors='replace'))
        else:
            decoded_parts.append(str(part))
    return ' '.join(decoded_parts)

def extract_eml_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from EML files.
    
    Returns:
        Dictionary containing:
        - file_info: Basic file attributes
        - headers: Email headers
        - content_info: Message structure
        - processing: Status information
        
    Raises:
        EMLMetadataError: For any processing failures
    """
    result = {
        "file_info": {},
        "headers": {},
        "content_info": {},
        "processing": {
            "success": False,
            "warnings": [],
            "time_taken": None
        }
    }
    
    start_time = datetime.now()
    
    try:
        validate_eml_file(file_path)
        
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "size_bytes": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "format": "EML",
            "valid": True
        }
        
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            msg = email.message_from_file(f)
            
            # Extract headers
            headers = {}
            for header in ['From', 'To', 'Subject', 'Date', 'CC', 'BCC', 
                         'Message-ID', 'References', 'In-Reply-To']:
                if header in msg:
                    headers[header.lower()] = decode_email_header(msg[header])
            result["headers"] = headers
            
            # Content structure
            content_info = {
                "content_type": msg.get_content_type(),
                "parts": [],
                "attachments": []
            }
            
            # Walk through MIME parts
            for part in msg.walk():
                part_info = {
                    "content_type": part.get_content_type(),
                    "charset": part.get_content_charset(),
                    "disposition": part.get_content_disposition(),
                    "size": len(part.as_bytes()) if part.get_payload(decode=True) else 0
                }
                
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        filename = decode_email_header(filename)
                    content_info["attachments"].append({
                        "filename": filename,
                        **part_info
                    })
                else:
                    content_info["parts"].append(part_info)
            
            result["content_info"] = content_info
            
            if not headers.get('date'):
                result["processing"]["warnings"].append("No date header found")
            
            if not content_info["attachments"] and not content_info["parts"]:
                result["processing"]["warnings"].append("No message content found")
        
        result["processing"]["success"] = True
        
    except FileNotFoundError as e:
        raise EMLMetadataError(f"File error: {str(e)}") from e
    except PermissionError as e:
        raise EMLMetadataError(f"Access error: {str(e)}") from e
    except email.errors.MessageError as e:
        raise InvalidEMLError(f"Invalid EML: {str(e)}") from e
    except Exception as e:
        raise EMLProcessingError(f"Processing failed: {str(e)}") from e
    finally:
        result["processing"]["time_taken"] = (datetime.now() - start_time).total_seconds()
    
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract metadata from an EML file.")
    parser.add_argument("file_path", nargs="?", help="Path to the EML file")
    args = parser.parse_args()

    file_path = args.file_path
    if not file_path:
        file_path = input("Enter the path to the EML file: ").strip()

    try:
        metadata = extract_eml_metadata(file_path)
        print(json.dumps(metadata, indent=2, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
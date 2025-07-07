#!/usr/bin/env python3
"""
ZIP Metadata Extraction Tool

Description: Comprehensive metadata extraction from ZIP archives with validation,
error handling, and standardized output.

Features:
- Extracts file listing, compression info
- Validates ZIP structure
- Handles encrypted archives
- Command-line interface with user prompts
- Error handling with JSON output
- Option to save output to file
"""

import os
import zipfile
import magic
import argparse
import json
from datetime import datetime
from typing import Dict, Any, Optional

class ZIPMetadataError(Exception):
    """Base class for ZIP metadata exceptions"""
    pass

class InvalidZIPError(ZIPMetadataError):
    """Raised when file is not a valid ZIP"""
    pass

class ZIPProcessingError(ZIPMetadataError):
    """Raised during ZIP processing failures"""
    pass

def validate_zip_file(file_path: str) -> bool:
    """
    Validate ZIP file structure and integrity.
    
    Args:
        file_path: Path to the ZIP file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file access is restricted
        InvalidZIPError: If file is not a valid ZIP
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Access denied: {file_path}")
    
    mime = magic.from_file(file_path, mime=True)
    if mime not in ('application/zip', 'application/x-zip-compressed'):
        raise InvalidZIPError(f"Not a ZIP file (detected: {mime})")
    
    return True

def extract_zip_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from ZIP files.
    
    Returns:
        Dictionary containing:
        - file_info: Basic file attributes
        - archive_info: ZIP technical details
        - contents: File listing with metadata
        - processing: Status information
        
    Raises:
        ZIPMetadataError: For any processing failures
    """
    result = {
        "file_info": {},
        "archive_info": {},
        "contents": [],
        "processing": {
            "success": False,
            "warnings": [],
            "time_taken": None
        }
    }
    
    start_time = datetime.now()
    
    try:
        validate_zip_file(file_path)
        
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "size_bytes": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "format": "ZIP",
            "valid": True
        }
        
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # Archive-wide info
            result["archive_info"] = {
                "file_count": len(zip_ref.infolist()),
                "comment": zip_ref.comment.decode('utf-8', errors='replace') if zip_ref.comment else None,
                "test_ok": zip_ref.testzip() is None,
                "encrypted": any(f.flag_bits & 0x1 for f in zip_ref.filelist),
                "compression_methods": {
                    method: method_name 
                    for method, method_name in COMPRESSION_NAMES.items()
                    if any(f.compress_type == method for f in zip_ref.filelist)
                }
            }
            
            # File listing with metadata
            for file_info in zip_ref.infolist():
                file_data = {
                    "filename": file_info.filename,
                    "file_size": file_info.file_size,
                    "compressed_size": file_info.compress_size,
                    "compression_method": COMPRESSION_NAMES.get(file_info.compress_type, "Unknown"),
                    "modified": datetime(*file_info.date_time).isoformat(),
                    "is_dir": file_info.filename.endswith('/'),
                    "crc": hex(file_info.CRC),
                    "encrypted": bool(file_info.flag_bits & 0x1),
                    "system": "Windows" if file_info.create_system == 0 else "Unix" if file_info.create_system == 3 else "Unknown"
                }
                result["contents"].append(file_data)
            
            if result["archive_info"]["encrypted"]:
                result["processing"]["warnings"].append("Archive contains encrypted files - some metadata may be unavailable")
            
            if not result["archive_info"]["test_ok"]:
                result["processing"]["warnings"].append("Archive failed integrity test")
        
        result["processing"]["success"] = True
        
    except FileNotFoundError as e:
        raise ZIPMetadataError(f"File error: {str(e)}") from e
    except PermissionError as e:
        raise ZIPMetadataError(f"Access error: {str(e)}") from e
    except zipfile.BadZipFile as e:
        raise InvalidZIPError(f"Invalid ZIP: {str(e)}") from e
    except Exception as e:
        raise ZIPProcessingError(f"Processing failed: {str(e)}") from e
    finally:
        result["processing"]["time_taken"] = (datetime.now() - start_time).total_seconds()
    
    return result

def save_output_to_file(output: Dict, output_path: Optional[str] = None) -> None:
    """Save the output to a file if requested"""
    if output_path:
        try:
            with open(output_path, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"\nMetadata saved to: {output_path}")
        except Exception as e:
            print(f"\nWarning: Could not save output to file: {str(e)}")

def main():
    """Command-line interface for the ZIP metadata extractor"""
    parser = argparse.ArgumentParser(description='ZIP Metadata Extraction Tool')
    parser.add_argument('file_path', nargs='?', help='Path to the ZIP file')
    parser.add_argument('--output', '-o', help='Path to save the output JSON')
    args = parser.parse_args()
    
    file_path = args.file_path
    if not file_path:
        file_path = input("Enter the path to the ZIP file: ")
    
    try:
        metadata = extract_zip_metadata(file_path)
        print("\nZIP Metadata:")
        print(json.dumps(metadata, indent=2))
        
        if args.output:
            save_output_to_file(metadata, args.output)
        
    except ZIPMetadataError as e:
        error_output = {
            "error": str(e),
            "success": False,
            "file": file_path
        }
        print(json.dumps(error_output, indent=2))
        exit(1)

if __name__ == "__main__":
    COMPRESSION_NAMES = {
        0: "stored",
        8: "deflated",
        9: "deflate64",
        12: "bzip2",
        14: "lzma",
        98: "ppmd"
    }
    main()
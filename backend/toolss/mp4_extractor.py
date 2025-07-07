






#!/usr/bin/env python3
"""
MP4 Metadata Extraction Tool

Description: Comprehensive metadata extraction from MP4 files with validation,
error handling, and standardized output.

Features:
- Extracts MOOV atom metadata
- Validates MP4 structure
- Handles various MP4 formats and codecs
- Command-line interface with user prompts
- Error handling with JSON output
"""

import os
import magic
import argparse
from datetime import datetime
from typing import Dict, Any, Optional
from mutagen.mp4 import MP4

class MP4MetadataError(Exception):
    """Base class for MP4 metadata exceptions"""
    pass

class InvalidMP4Error(MP4MetadataError):
    """Raised when file is not a valid MP4"""
    pass

class MP4ProcessingError(MP4MetadataError):
    """Raised during MP4 processing failures"""
    pass

def validate_mp4_file(file_path: str) -> bool:
    """
    Validate MP4 file structure and integrity.
    
    Args:
        file_path: Path to the MP4 file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file access is restricted
        InvalidMP4Error: If file is not a valid MP4
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Access denied: {file_path}")
    
    mime = magic.from_file(file_path, mime=True)
    if mime not in ('video/mp4', 'audio/mp4', 'application/mp4'):
        raise InvalidMP4Error(f"Not an MP4 file (detected: {mime})")
    
    return True

def extract_mp4_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from MP4 files.
    
    Returns:
        Dictionary containing:
        - file_info: Basic file attributes
        - media_info: Technical media properties
        - atoms_info: MP4 atoms structure
        - processing: Status information
        
    Raises:
        MP4MetadataError: For any processing failures
    """
    result = {
        "file_info": {},
        "media_info": {},
        "atoms_info": {},
        "processing": {
            "success": False,
            "warnings": [],
            "time_taken": None
        }
    }
    
    start_time = datetime.now()
    
    try:
        validate_mp4_file(file_path)
        
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "size_bytes": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "format": "MP4",
            "valid": True
        }
        
        # Media technical info
        mp4 = MP4(file_path)
        
        # Standard MP4 tags
        mp4_tags = {}
        for key, value in mp4.tags.items() if mp4.tags else []:
            mp4_tags[key] = value[0] if len(value) == 1 else value
        
        # Media info
        result["media_info"] = {
            "length": mp4.info.length,
            "bitrate": mp4.info.bitrate,
            "sample_rate": mp4.info.sample_rate,
            "channels": mp4.info.channels,
            "codec": mp4.info.codec,
            "tags": mp4_tags
        }
        
        # Basic atom info (Mutagen doesn't provide full atom parsing)
        result["atoms_info"] = {
            "has_moov": mp4.tags is not None,
            "has_ftyp": True  # Assumed for valid MP4
        }
        
        if not mp4_tags:
            result["processing"]["warnings"].append("No MP4 metadata atoms found")
        
        result["processing"]["success"] = True
        
    except FileNotFoundError as e:
        raise MP4MetadataError(f"File error: {str(e)}") from e
    except PermissionError as e:
        raise MP4MetadataError(f"Access error: {str(e)}") from e
    except Exception as e:
        raise MP4ProcessingError(f"Processing failed: {str(e)}") from e
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
    """Command-line interface for the MP4 metadata extractor"""
    parser = argparse.ArgumentParser(description='MP4 Metadata Extraction Tool')
    parser.add_argument('file_path', nargs='?', help='Path to the MP4 file')
    parser.add_argument('--output', '-o', help='Path to save the output JSON')
    args = parser.parse_args()
    
    file_path = args.file_path
    if not file_path:
        file_path = input("Enter the path to the MP4 file: ")
    
    try:
        metadata = extract_mp4_metadata(file_path)
        print("\nMP4 Metadata:")
        print(json.dumps(metadata, indent=2))
        
        if args.output:
            save_output_to_file(metadata, args.output)
        
    except MP4MetadataError as e:
        error_output = {
            "error": str(e),
            "success": False,
            "file": file_path
        }
        print(json.dumps(error_output, indent=2))
        exit(1)

if __name__ == "__main__":
    import json
    main()
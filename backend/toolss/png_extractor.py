#!/usr/bin/env python3
"""
PNG Metadata Extraction Tool

Description: Comprehensive metadata extraction from PNG files with validation,
error handling, and standardized output.

Features:
- Extracts IHDR, tEXt, zTXt, iTXt chunks
- Validates PNG structure
- Handles various PNG formats
- Command-line interface with user prompts
- Error handling with JSON output
- Option to save output to file
"""

import os
import zlib
import magic
import argparse
import json
from datetime import datetime
from typing import Dict, Any, Optional
from PIL import Image
from PIL.PngImagePlugin import PngInfo

class PNGMetadataError(Exception):
    """Base class for PNG metadata exceptions"""
    pass

class InvalidPNGError(PNGMetadataError):
    """Raised when file is not a valid PNG"""
    pass

class PNGProcessingError(PNGMetadataError):
    """Raised during PNG processing failures"""
    pass

def validate_png_file(file_path: str) -> bool:
    """
    Validate PNG file structure and integrity.
    
    Args:
        file_path: Path to the PNG file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file access is restricted
        InvalidPNGError: If file is not a valid PNG
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Access denied: {file_path}")
    
    mime = magic.from_file(file_path, mime=True)
    if mime != 'image/png':
        raise InvalidPNGError(f"Not a PNG file (detected: {mime})")
    
    return True

def extract_png_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from PNG files.
    
    Returns:
        Dictionary containing:
        - file_info: Basic file attributes
        - image_info: Technical image properties
        - chunk_info: PNG chunk data
        - text_data: Textual metadata
        - processing: Status information
        
    Raises:
        PNGMetadataError: For any processing failures
    """
    result = {
        "file_info": {},
        "image_info": {},
        "chunk_info": {},
        "text_data": {},
        "processing": {
            "success": False,
            "warnings": [],
            "time_taken": None
        }
    }
    
    start_time = datetime.now()
    
    try:
        validate_png_file(file_path)
        
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "size_bytes": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "format": "PNG",
            "valid": True
        }
        
        with Image.open(file_path) as img:
            result["image_info"] = {
                "format": img.format,
                "mode": img.mode,
                "size": img.size,
                "width": img.width,
                "height": img.height,
                "palette": img.palette.mode if img.palette is not None else None,
                "transparency": img.info.get('transparency'),
                "gamma": img.info.get('gamma'),
                "interlace": img.info.get('interlace')
            }
            
            # Extract PNG chunks
            if hasattr(img, 'text'):
                result["text_data"] = dict(img.text)
            
            # For advanced chunk analysis
            if hasattr(img, 'png') and hasattr(img.png, 'chunks'):
                chunks = {}
                for chunk_type, chunk_data in img.png.chunks:
                    if chunk_type not in chunks:
                        chunks[chunk_type] = []
                    chunks[chunk_type].append({
                        "length": len(chunk_data),
                        "crc": zlib.crc32(chunk_data).to_bytes(4, 'big').hex()
                    })
                result["chunk_info"] = chunks
            
            if not hasattr(img, 'text') or not img.text:
                result["processing"]["warnings"].append("No textual metadata found")
        
        result["processing"]["success"] = True
        
    except FileNotFoundError as e:
        raise PNGMetadataError(f"File error: {str(e)}") from e
    except PermissionError as e:
        raise PNGMetadataError(f"Access error: {str(e)}") from e
    except Image.UnidentifiedImageError as e:
        raise InvalidPNGError(f"Invalid PNG: {str(e)}") from e
    except Exception as e:
        raise PNGProcessingError(f"Processing failed: {str(e)}") from e
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
    """Command-line interface for the PNG metadata extractor"""
    parser = argparse.ArgumentParser(description='PNG Metadata Extraction Tool')
    parser.add_argument('file_path', nargs='?', help='Path to the PNG file')
    parser.add_argument('--output', '-o', help='Path to save the output JSON')
    args = parser.parse_args()
    
    file_path = args.file_path
    if not file_path:
        file_path = input("Enter the path to the PNG file: ")
    
    try:
        metadata = extract_png_metadata(file_path)
        print("\nPNG Metadata:")
        print(json.dumps(metadata, indent=2))
        
        if args.output:
            save_output_to_file(metadata, args.output)
        
    except PNGMetadataError as e:
        error_output = {
            "error": str(e),
            "success": False,
            "file": file_path
        }
        print(json.dumps(error_output, indent=2))
        exit(1)

if __name__ == "__main__":
    main()
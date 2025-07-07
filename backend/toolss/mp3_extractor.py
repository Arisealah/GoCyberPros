
#!/usr/bin/env python3
"""
MP3 Metadata Extraction Tool

Description: Comprehensive metadata extraction from MP3 files with validation,
error handling, and standardized output.

Features:
- Extracts ID3v1, ID3v2, and audio technical metadata
- Validates MP3 structure
- Handles various MP3 formats and versions
- Command-line interface with user prompts
- Error handling with JSON output
"""

import os
import magic
import argparse
import json
from datetime import datetime
from typing import Dict, Any, Optional
from mutagen.mp3 import MP3
from mutagen.easyid3 import EasyID3
from mutagen.id3 import ID3

class MP3MetadataError(Exception):
    """Base class for MP3 metadata exceptions"""
    pass

class InvalidMP3Error(MP3MetadataError):
    """Raised when file is not a valid MP3"""
    pass

class MP3ProcessingError(MP3MetadataError):
    """Raised during MP3 processing failures"""
    pass

def validate_mp3_file(file_path: str) -> bool:
    """
    Validate MP3 file structure and integrity.
    
    Args:
        file_path: Path to the MP3 file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file access is restricted
        InvalidMP3Error: If file is not a valid MP3
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Access denied: {file_path}")
    
    mime = magic.from_file(file_path, mime=True)
    if mime not in ('audio/mpeg', 'audio/mp3', 'application/octet-stream'):
        raise InvalidMP3Error(f"Not an MP3 file (detected: {mime})")
    
    return True

def extract_mp3_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from MP3 files.
    
    Returns:
        Dictionary containing:
        - file_info: Basic file attributes
        - audio_info: Technical audio properties
        - id3_tags: ID3 metadata
        - processing: Status information
        
    Raises:
        MP3MetadataError: For any processing failures
    """
    result = {
        "file_info": {},
        "audio_info": {},
        "id3_tags": {},
        "processing": {
            "success": False,
            "warnings": [],
            "time_taken": None
        }
    }
    
    start_time = datetime.now()
    
    try:
        validate_mp3_file(file_path)
        
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "size_bytes": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "format": "MP3",
            "valid": True
        }
        
        # Audio technical info
        audio = MP3(file_path)
        result["audio_info"] = {
            "length": audio.info.length,
            "bitrate": audio.info.bitrate,
            "sample_rate": audio.info.sample_rate,
            "channels": audio.info.channels,
            "layer": audio.info.layer,
            "version": audio.info.version,
            "mode": audio.info.mode,
            "protected": audio.info.protected
        }
        
        # ID3 tags
        id3_data = {}
        
        # EasyID3 tags (standard fields)
        try:
            easy_id3 = EasyID3(file_path)
            for key, value in easy_id3.items():
                id3_data[key] = value[0] if len(value) == 1 else value
        except Exception as e:
            result["processing"]["warnings"].append(f"EasyID3 read failed: {str(e)}")
        
        # Raw ID3 frames (all frames)
        try:
            id3 = ID3(file_path)
            for frame in id3.values():
                frame_id = frame.FrameID
                if frame_id not in id3_data:  # Don't overwrite EasyID3 data
                    try:
                        id3_data[frame_id] = str(frame)
                    except:
                        id3_data[frame_id] = repr(frame)
        except Exception as e:
            result["processing"]["warnings"].append(f"ID3 frames read failed: {str(e)}")
        
        result["id3_tags"] = id3_data
        
        if not id3_data:
            result["processing"]["warnings"].append("No ID3 tags found")
        
        result["processing"]["success"] = True
        
    except FileNotFoundError as e:
        raise MP3MetadataError(f"File error: {str(e)}") from e
    except PermissionError as e:
        raise MP3MetadataError(f"Access error: {str(e)}") from e
    except Exception as e:
        raise MP3ProcessingError(f"Processing failed: {str(e)}") from e
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
    """Command-line interface for the MP3 metadata extractor"""
    parser = argparse.ArgumentParser(description='MP3 Metadata Extraction Tool')
    parser.add_argument('file_path', nargs='?', help='Path to the MP3 file')
    parser.add_argument('--output', '-o', help='Path to save the output JSON')
    args = parser.parse_args()
    
    file_path = args.file_path
    if not file_path:
        file_path = input("Enter the path to the MP3 file: ")
    
    try:
        metadata = extract_mp3_metadata(file_path)
        print("\nMP3 Metadata:")
        print(json.dumps(metadata, indent=2))
        
        if args.output:
            save_output_to_file(metadata, args.output)
        
    except MP3MetadataError as e:
        error_output = {
            "error": str(e),
            "success": False,
            "file": file_path
        }
        print(json.dumps(error_output, indent=2))
        exit(1)

if __name__ == "__main__":
    main()
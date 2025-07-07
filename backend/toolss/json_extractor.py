

# #!/usr/bin/env python3
# """
# JSON Metadata Extraction Tool

# Description: Comprehensive metadata extraction from JSON files with validation,
# error handling, and standardized output.

# Features:
# - Extracts structural metadata, schema analysis
# - Validates JSON syntax
# - Handles large JSON files efficiently
# """

# import os
# import json
# import magic
# from datetime import datetime
# from typing import Dict, Any, List, Union

# class JSONMetadataError(Exception):
#     """Base class for JSON metadata exceptions"""
#     pass

# class InvalidJSONError(JSONMetadataError):
#     """Raised when file is not valid JSON"""
#     pass

# class JSONProcessingError(JSONMetadataError):
#     """Raised during JSON processing failures"""
#     pass

# def validate_json_file(file_path: str) -> bool:
#     """
#     Validate JSON file structure and integrity.
    
#     Args:
#         file_path: Path to the JSON file
        
#     Raises:
#         FileNotFoundError: If file doesn't exist
#         PermissionError: If file access is restricted
#         InvalidJSONError: If file is not valid JSON
#     """
#     if not os.path.exists(file_path):
#         raise FileNotFoundError(f"File not found: {file_path}")
    
#     if not os.access(file_path, os.R_OK):
#         raise PermissionError(f"Access denied: {file_path}")
    
#     mime = magic.from_file(file_path, mime=True)
#     if mime not in ('application/json', 'text/plain'):
#         raise InvalidJSONError(f"Not a JSON file (detected: {mime})")
    
#     # Quick syntax validation
#     try:
#         with open(file_path, 'r') as f:
#             json.load(f)
#     except json.JSONDecodeError as e:
#         raise InvalidJSONError(f"Invalid JSON: {str(e)}")
    
#     return True

# def analyze_json_structure(data: Union[Dict, List], path: str = '') -> Dict[str, Any]:
#     """Recursively analyze JSON structure"""
#     structure = {}
    
#     if isinstance(data, dict):
#         structure[path] = {
#             "type": "object",
#             "count": len(data),
#             "keys": list(data.keys())
#         }
#         for key, value in data.items():
#             new_path = f"{path}.{key}" if path else key
#             structure.update(analyze_json_structure(value, new_path))
#     elif isinstance(data, list):
#         structure[path] = {
#             "type": "array",
#             "count": len(data)
#         }
#         if data:
#             structure.update(analyze_json_structure(data[0], f"{path}[]"))
#     else:
#         structure[path] = {
#             "type": type(data).__name__,
#             "sample": str(data)[:100]
#         }
    
#     return structure

# def extract_json_metadata(file_path: str) -> Dict[str, Any]:
#     """
#     Extract comprehensive metadata from JSON files.
    
#     Returns:
#         Dictionary containing:
#         - file_info: Basic file attributes
#         - structure: JSON schema structure
#         - stats: Statistical information
#         - processing: Status information
        
#     Raises:
#         JSONMetadataError: For any processing failures
#     """
#     result = {
#         "file_info": {},
#         "structure": {},
#         "stats": {},
#         "processing": {
#             "success": False,
#             "warnings": [],
#             "time_taken": None
#         }
#     }
    
#     start_time = datetime.now()
    
#     try:
#         validate_json_file(file_path)
        
#         file_stat = os.stat(file_path)
#         result["file_info"] = {
#             "path": os.path.abspath(file_path),
#             "size_bytes": file_stat.st_size,
#             "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
#             "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
#             "format": "JSON",
#             "valid": True
#         }
        
#         with open(file_path, 'r') as f:
#             data = json.load(f)
            
#             # Analyze structure
#             result["structure"] = analyze_json_structure(data)
            
#             # Collect stats
#             def count_items(obj):
#                 if isinstance(obj, dict):
#                     return 1 + sum(count_items(v) for v in obj.values())
#                 elif isinstance(obj, list):
#                     return 1 + sum(count_items(v) for v in obj)
#                 return 1
            
#             result["stats"] = {
#                 "total_items": count_items(data),
#                 "depth": max(len(k.split('.')) for k in result["structure"].keys()),
#                 "types": {
#                     "object": sum(1 for v in result["structure"].values() if v["type"] == "object"),
#                     "array": sum(1 for v in result["structure"].values() if v["type"] == "array"),
#                     "other": sum(1 for v in result["structure"].values() if v["type"] not in ("object", "array"))
#                 }
#             }
        
#         result["processing"]["success"] = True
        
#     except FileNotFoundError as e:
#         raise JSONMetadataError(f"File error: {str(e)}") from e
#     except PermissionError as e:
#         raise JSONMetadataError(f"Access error: {str(e)}") from e
#     except json.JSONDecodeError as e:
#         raise InvalidJSONError(f"Invalid JSON: {str(e)}") from e
#     except Exception as e:
#         raise JSONProcessingError(f"Processing failed: {str(e)}") from e
#     finally:
#         result["processing"]["time_taken"] = (datetime.now() - start_time).total_seconds()
    
#     return result





























#!/usr/bin/env python3
"""
JSON Metadata Extraction Tool

Description: Comprehensive metadata extraction from JSON files with validation,
error handling, and standardized output.

Features:
- Extracts structural metadata, schema analysis
- Validates JSON syntax
- Handles large JSON files efficiently
- Command-line interface with user prompts
- Error handling with JSON output
"""

import os
import json
import magic
import argparse
from datetime import datetime
from typing import Dict, Any, List, Union, Optional

class JSONMetadataError(Exception):
    """Base class for JSON metadata exceptions"""
    pass

class InvalidJSONError(JSONMetadataError):
    """Raised when file is not valid JSON"""
    pass

class JSONProcessingError(JSONMetadataError):
    """Raised during JSON processing failures"""
    pass

def validate_json_file(file_path: str) -> bool:
    """
    Validate JSON file structure and integrity.
    
    Args:
        file_path: Path to the JSON file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file access is restricted
        InvalidJSONError: If file is not valid JSON
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Access denied: {file_path}")
    
    mime = magic.from_file(file_path, mime=True)
    if mime not in ('application/json', 'text/plain'):
        raise InvalidJSONError(f"Not a JSON file (detected: {mime})")
    
    # Quick syntax validation
    try:
        with open(file_path, 'r') as f:
            json.load(f)
    except json.JSONDecodeError as e:
        raise InvalidJSONError(f"Invalid JSON: {str(e)}")
    
    return True

def analyze_json_structure(data: Union[Dict, List], path: str = '') -> Dict[str, Any]:
    """Recursively analyze JSON structure"""
    structure = {}
    
    if isinstance(data, dict):
        structure[path] = {
            "type": "object",
            "count": len(data),
            "keys": list(data.keys())
        }
        for key, value in data.items():
            new_path = f"{path}.{key}" if path else key
            structure.update(analyze_json_structure(value, new_path))
    elif isinstance(data, list):
        structure[path] = {
            "type": "array",
            "count": len(data)
        }
        if data:
            structure.update(analyze_json_structure(data[0], f"{path}[]"))
    else:
        structure[path] = {
            "type": type(data).__name__,
            "sample": str(data)[:100]
        }
    
    return structure

def extract_json_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from JSON files.
    
    Returns:
        Dictionary containing:
        - file_info: Basic file attributes
        - structure: JSON schema structure
        - stats: Statistical information
        - processing: Status information
        
    Raises:
        JSONMetadataError: For any processing failures
    """
    result = {
        "file_info": {},
        "structure": {},
        "stats": {},
        "processing": {
            "success": False,
            "warnings": [],
            "time_taken": None
        }
    }
    
    start_time = datetime.now()
    
    try:
        validate_json_file(file_path)
        
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "size_bytes": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "format": "JSON",
            "valid": True
        }
        
        with open(file_path, 'r') as f:
            data = json.load(f)
            
            # Analyze structure
            result["structure"] = analyze_json_structure(data)
            
            # Collect stats
            def count_items(obj):
                if isinstance(obj, dict):
                    return 1 + sum(count_items(v) for v in obj.values())
                elif isinstance(obj, list):
                    return 1 + sum(count_items(v) for v in obj)
                return 1
            
            result["stats"] = {
                "total_items": count_items(data),
                "depth": max(len(k.split('.')) for k in result["structure"].keys()),
                "types": {
                    "object": sum(1 for v in result["structure"].values() if v["type"] == "object"),
                    "array": sum(1 for v in result["structure"].values() if v["type"] == "array"),
                    "other": sum(1 for v in result["structure"].values() if v["type"] not in ("object", "array"))
                }
            }
        
        result["processing"]["success"] = True
        
    except FileNotFoundError as e:
        raise JSONMetadataError(f"File error: {str(e)}") from e
    except PermissionError as e:
        raise JSONMetadataError(f"Access error: {str(e)}") from e
    except json.JSONDecodeError as e:
        raise InvalidJSONError(f"Invalid JSON: {str(e)}") from e
    except Exception as e:
        raise JSONProcessingError(f"Processing failed: {str(e)}") from e
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
    """Command-line interface for the JSON metadata extractor"""
    parser = argparse.ArgumentParser(description='JSON Metadata Extraction Tool')
    parser.add_argument('file_path', nargs='?', help='Path to the JSON file')
    parser.add_argument('--output', '-o', help='Path to save the output JSON')
    args = parser.parse_args()
    
    file_path = args.file_path
    if not file_path:
        file_path = input("Enter the path to the JSON file: ")
    
    try:
        metadata = extract_json_metadata(file_path)
        print("\nJSON Metadata:")
        print(json.dumps(metadata, indent=2))
        
        if args.output:
            save_output_to_file(metadata, args.output)
        
    except JSONMetadataError as e:
        error_output = {
            "error": str(e),
            "success": False,
            "file": file_path
        }
        print(json.dumps(error_output, indent=2))
        exit(1)

if __name__ == "__main__":
    main()
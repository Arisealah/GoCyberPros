

#!/usr/bin/env python3
"""
XML Metadata Extraction Tool

Description: Comprehensive metadata extraction from XML files with validation,
error handling, and standardized output.

Features:
- Extracts schema information, element structure
- Validates XML syntax
- Handles namespaces and DTDs
- Command-line interface with user prompts
- Error handling with JSON output
- Option to save output to file
"""

import os
import magic
import argparse
import json
from datetime import datetime
from typing import Dict, Any, Optional
from xml.etree import ElementTree as ET

class XMLMetadataError(Exception):
    """Base class for XML metadata exceptions"""
    pass

class InvalidXMLError(XMLMetadataError):
    """Raised when file is not valid XML"""
    pass

class XMLProcessingError(XMLMetadataError):
    """Raised during XML processing failures"""
    pass

def validate_xml_file(file_path: str) -> bool:
    """
    Validate XML file structure and integrity.
    
    Args:
        file_path: Path to the XML file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file access is restricted
        InvalidXMLError: If file is not valid XML
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Access denied: {file_path}")
    
    mime = magic.from_file(file_path, mime=True)
    if mime not in ('application/xml', 'text/xml', 'text/plain'):
        raise InvalidXMLError(f"Not an XML file (detected: {mime})")
    
    # Quick syntax validation
    try:
        ET.parse(file_path)
    except ET.ParseError as e:
        raise InvalidXMLError(f"Invalid XML: {str(e)}")
    
    return True

def analyze_xml_structure(element: ET.Element, path: str = '') -> Dict[str, Any]:
    """Recursively analyze XML structure"""
    structure = {}
    
    # Current element info
    tag = element.tag.split('}')[-1] if '}' in element.tag else element.tag
    current_path = f"{path}/{tag}" if path else tag
    
    structure[current_path] = {
        "attributes": list(element.attrib.keys()),
        "children": {},
        "text": bool(element.text and element.text.strip())
    }
    
    # Analyze children
    children_tags = set()
    for child in element:
        child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
        children_tags.add(child_tag)
        
    structure[current_path]["children"] = list(children_tags)
    
    # Recurse through children
    for child in element:
        structure.update(analyze_xml_structure(child, current_path))
    
    return structure

def extract_xml_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from XML files.
    
    Returns:
        Dictionary containing:
        - file_info: Basic file attributes
        - structure: XML schema structure
        - namespaces: Namespace declarations
        - processing: Status information
        
    Raises:
        XMLMetadataError: For any processing failures
    """
    result = {
        "file_info": {},
        "structure": {},
        "namespaces": {},
        "processing": {
            "success": False,
            "warnings": [],
            "time_taken": None
        }
    }
    
    start_time = datetime.now()
    
    try:
        validate_xml_file(file_path)
        
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "size_bytes": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "format": "XML",
            "valid": True
        }
        
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Extract namespaces
        nsmap = {}
        if '}' in root.tag:
            nsmap['xmlns'] = root.tag.split('}')[0][1:]
        
        # Additional namespace declarations
        for key, value in root.attrib.items():
            if key.startswith('xmlns:'):
                nsmap[key[6:]] = value
            elif key == 'xmlns':
                nsmap['xmlns'] = value
        
        result["namespaces"] = nsmap
        
        # Analyze structure
        result["structure"] = analyze_xml_structure(root)
        
        # Count elements
        element_count = len(result["structure"])
        result["stats"] = {
            "elements": element_count,
            "depth": max(len(k.split('/')) for k in result["structure"].keys()),
            "attributes": sum(len(v["attributes"]) for v in result["structure"].values())
        }
        
        result["processing"]["success"] = True
        
    except FileNotFoundError as e:
        raise XMLMetadataError(f"File error: {str(e)}") from e
    except PermissionError as e:
        raise XMLMetadataError(f"Access error: {str(e)}") from e
    except ET.ParseError as e:
        raise InvalidXMLError(f"Invalid XML: {str(e)}") from e
    except Exception as e:
        raise XMLProcessingError(f"Processing failed: {str(e)}") from e
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
    """Command-line interface for the XML metadata extractor"""
    parser = argparse.ArgumentParser(description='XML Metadata Extraction Tool')
    parser.add_argument('file_path', nargs='?', help='Path to the XML file')
    parser.add_argument('--output', '-o', help='Path to save the output JSON')
    args = parser.parse_args()
    
    file_path = args.file_path
    if not file_path:
        file_path = input("Enter the path to the XML file: ")
    
    try:
        metadata = extract_xml_metadata(file_path)
        print("\nXML Metadata:")
        print(json.dumps(metadata, indent=2))
        
        if args.output:
            save_output_to_file(metadata, args.output)
        
    except XMLMetadataError as e:
        error_output = {
            "error": str(e),
            "success": False,
            "file": file_path
        }
        print(json.dumps(error_output, indent=2))
        exit(1)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
CSV Metadata Extraction Tool

Description: Comprehensive metadata extraction from CSV files with validation,
error handling, and standardized output.

Features:
- Extracts structural metadata, dialect detection
- Validates CSV structure
- Handles various encodings and dialects
"""

import os
import csv
from csv import Error
import chardet
import magic
import json
import argparse
from datetime import datetime
from typing import Dict, Any, List

class CSVMetadataError(Exception):
    """Base class for CSV metadata exceptions"""
    pass

class InvalidCSVError(CSVMetadataError):
    """Raised when file is not a valid CSV"""
    pass

class CSVProcessingError(CSVMetadataError):
    """Raised during CSV processing failures"""
    pass

def validate_csv_file(file_path: str) -> bool:
    """
    Validate CSV file structure and integrity.
    
    Args:
        file_path: Path to the CSV file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file access is restricted
        InvalidCSVError: If file is not a valid CSV
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Access denied: {file_path}")
    
    mime = magic.from_file(file_path, mime=True)
    if mime not in ('text/plain', 'text/csv', 'application/csv'):
        raise InvalidCSVError(f"Not a CSV file (detected: {mime})")
    
    return True

def detect_csv_dialect(file_path: str, sample_size: int = 1024) -> Dict[str, Any]:
    """Detect CSV dialect and encoding"""
    result = {}
    
    # Detect encoding
    with open(file_path, 'rb') as f:
        raw_data = f.read(sample_size)
        encoding = chardet.detect(raw_data)['encoding']
        result['encoding'] = encoding
    
    # Detect dialect
    with open(file_path, 'r', encoding=encoding, newline='') as f:
        try:
            dialect = csv.Sniffer().sniff(f.read(sample_size))
            result.update({
                'delimiter': dialect.delimiter,
                'quotechar': dialect.quotechar,
                'doublequote': dialect.doublequote,
                'escapechar': dialect.escapechar,
                'lineterminator': repr(dialect.lineterminator),
                'quoting': dialect.quoting,
                'skipinitialspace': dialect.skipinitialspace
            })
        except Error:
            result['warnings'] = ['Could not determine CSV dialect']
    
    return result

def extract_csv_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from CSV files.
    
    Returns:
        Dictionary containing:
        - file_info: Basic file attributes
        - dialect_info: CSV formatting details
        - structure_info: Data structure
        - processing: Status information
        
    Raises:
        CSVMetadataError: For any processing failures
    """
    result = {
        "file_info": {},
        "dialect_info": {},
        "structure_info": {},
        "processing": {
            "success": False,
            "warnings": [],
            "time_taken": None
        }
    }
    
    start_time = datetime.now()
    
    try:
        validate_csv_file(file_path)
        
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "size_bytes": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "format": "CSV",
            "valid": True
        }
        
        # Detect dialect and encoding
        dialect_info = detect_csv_dialect(file_path)
        result["dialect_info"] = dialect_info
        encoding = dialect_info.get('encoding', 'utf-8')
        
        # Analyze structure
        with open(file_path, 'r', encoding=encoding, newline='') as f:
            reader = csv.reader(f)
            try:
                rows = list(reader)
                if not rows:
                    raise InvalidCSVError("Empty CSV file")
                
                result["structure_info"] = {
                    "row_count": len(rows),
                    "column_count": len(rows[0]),
                    "headers": rows[0] if len(rows) > 0 else [],
                    "sample_data": rows[1:6] if len(rows) > 1 else []
                }
                
                # Check for consistency
                col_counts = set(len(row) for row in rows)
                if len(col_counts) > 1:
                    result["processing"]["warnings"].append(
                        f"Inconsistent column counts: {col_counts}")
                
            except Error as e:
                raise InvalidCSVError(f"CSV parsing error: {str(e)}")
        
        result["processing"]["success"] = True
        
    except FileNotFoundError as e:
        raise CSVMetadataError(f"File error: {str(e)}") from e
    except PermissionError as e:
        raise CSVMetadataError(f"Access error: {str(e)}") from e
    except Exception as e:
        raise CSVProcessingError(f"Processing failed: {str(e)}") from e
    finally:
        result["processing"]["time_taken"] = (datetime.now() - start_time).total_seconds()
    
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract metadata from a CSV file.")
    parser.add_argument("file_path", nargs="?", help="Path to the CSV file")
    parser.add_argument("-o", "--output", help="Write metadata output to this file (JSON). If not set, prints to stdout.")
    args = parser.parse_args()

    file_path = args.file_path
    if not file_path:
        file_path = input("Enter the path to the CSV file: ").strip()

    try:
        metadata = extract_csv_metadata(file_path)
        output_json = json.dumps(metadata, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_json)
            print(f"Metadata written to {args.output}")
        else:
            print(output_json)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
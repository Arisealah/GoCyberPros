

#!/usr/bin/env python3
"""
JPG Metadata Extraction Tool (Enhanced)

Description: Comprehensive and robust metadata extraction from JPEG files,
with advanced validation, detailed error handling, and standardized, enriched output.

Features:
- Extracts standard EXIF data (camera, lens, settings).
- Retrieves detailed GPS information, including decimal coordinates.
- Extracts technical image properties (dimensions, format, color mode).
- Validates JPEG structure and integrity rigorously.
- Handles various EXIF versions and formats gracefully.
- Outputs standardized, structured metadata including warnings and errors.

Dependencies:
- Pillow (pip install pillow)
- python-magic (pip install python-magic)

Example Usage (CLI):
    python3 jpg_extractor.py example.jpg --log-level DEBUG -o metadata.json

Author: Gemini (based on provided foundation)
Version: 1.1.0
Last Updated: 2025-06-07
"""

import os
import json
import magic
import mimetypes # For more robust MIME type handling
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, Union, List
from PIL import Image, UnidentifiedImageError
from PIL.ExifTags import TAGS, GPSTAGS
import logging
import sys
import argparse
import time

# --- Configuration ---
DEFAULT_LOG_FILE = "jpg_extractor.log"
DEFAULT_LOG_LEVEL = "INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Expected JPG MIME types
EXPECTED_JPG_MIMES = ['image/jpeg', 'image/jpg']

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
class JPGMetadataError(Exception):
    """Base class for JPG metadata extraction exceptions."""
    pass

class FileAccessError(JPGMetadataError):
    """Raised for issues accessing the file (e.g., not found, permissions)."""
    pass

class InvalidFileFormatError(JPGMetadataError):
    """Raised when the file is not a valid JPEG according to checks."""
    pass

class ExtractorProcessingError(JPGMetadataError):
    """Raised for unexpected errors during the JPEG extraction process."""
    pass

# --- Helper Functions ---
def _convert_exif_date_to_iso(exif_date_str: Optional[str]) -> Optional[str]:
    """
    Converts an EXIF date string (e.g., "YYYY:MM:DD HH:MM:SS") to ISO 8601 format.
    Assumes UTC if no timezone info.
    """
    if not exif_date_str:
        return None
    try:
        # EXIF dates are typically "YYYY:MM:DD HH:MM:SS"
        # We assume they are local time and convert to UTC ISO 8601
        dt_obj = datetime.strptime(exif_date_str, "%Y:%m:%d %H:%M:%S")
        # As EXIF does not store timezone, we assume local time and convert to UTC
        # For simplicity, assuming system's local timezone for conversion.
        # For strictness, one might prompt user for timezone or assume UTC always.
        return dt_obj.replace(tzinfo=datetime.now().astimezone().tzinfo).astimezone(timezone.utc).isoformat()
    except ValueError:
        logger.warning(f"Could not parse EXIF date string: {exif_date_str}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error converting EXIF date '{exif_date_str}': {e}")
        return None

def _convert_rational_to_float(value: Any) -> Any:
    """
    Converts EXIF rational numbers (tuple of numerator/denominator) to float.
    Handles single values, tuples, or lists of tuples.
    """
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], (int, float)) and isinstance(value[1], (int, float)) and value[1] != 0:
        return float(value[0]) / float(value[1])
    elif isinstance(value, list):
        return [_convert_rational_to_float(v) for v in value]
    return value

def _get_decimal_coords(gps_coords: Tuple[Tuple[int, int], ...], gps_refs: str) -> Optional[float]:
    """
    Converts GPS coordinate (degrees, minutes, seconds) tuple to decimal degrees.
    gps_coords example: ((37, 1), (12, 1), (5762, 100))
    gps_refs example: 'N' or 'E'
    """
    if not gps_coords or len(gps_coords) != 3:
        return None

    degrees = _convert_rational_to_float(gps_coords[0])
    minutes = _convert_rational_to_float(gps_coords[1])
    seconds = _convert_rational_to_float(gps_coords[2])

    if any(val is None for val in [degrees, minutes, seconds]):
        return None

    decimal_degrees = float(degrees) + float(minutes) / 60 + float(seconds) / 3600

    if gps_refs in ['S', 'W']:
        return -decimal_degrees
    return decimal_degrees

# --- Main Validation Function ---
def validate_jpg_file(file_path: str) -> bool:
    """
    Advanced validation for JPEG file structure and integrity.

    Args:
        file_path: Path to the JPEG file.

    Returns:
        True if the file passes all validations.

    Raises:
        FileAccessError: If file doesn't exist or access is restricted.
        InvalidFileFormatError: If file is not deemed a valid JPEG.
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
        logger.warning(f"File {file_path} is empty, which is usually an invalid JPEG.")
        raise InvalidFileFormatError(f"File is empty: {file_path}")

    # 1. MIME Type Check (using both magic and mimetypes)
    mime_type_magic = magic.from_file(file_path, mime=True)
    mime_type_ext = mimetypes.guess_type(file_path)[0]

    if mime_type_magic not in EXPECTED_JPG_MIMES:
        if mime_type_ext and mime_type_ext in EXPECTED_JPG_MIMES:
            logger.warning(f"Magic detected '{mime_type_magic}', but extension suggests JPG ('{mime_type_ext}'). Proceeding.")
        else:
            raise InvalidFileFormatError(f"Not a recognized JPEG file type by magic ({mime_type_magic}).")
    
    # 2. Pillow structural validation attempt
    try:
        with Image.open(file_path) as img:
            img.verify()  # Verify integrity
            img.load()    # Load pixel data to catch more issues
            # Attempt to access a common property to force parsing
            _ = img.format
            _ = img.size
            _ = img.info
    except UnidentifiedImageError as e:
        raise InvalidFileFormatError(f"Invalid or corrupted JPEG structure detected by Pillow: {str(e)}") from e
    except Exception as e:
        # Catch any other unexpected errors during Pillow validation attempt
        logger.error(f"Unexpected error during Pillow validation for {file_path}: {e}", exc_info=True)
        raise InvalidFileFormatError(f"Unexpected validation error: {str(e)}") from e

    logger.info(f"File '{file_path}' passed all structural validations.")
    return True

# --- EXIF and GPS Extraction Functions ---
def get_exif_data(image: Image) -> Dict[str, Any]:
    """
    Extract and process EXIF data from PIL Image.
    Converts rational numbers and dates, and decodes tags.
    """
    exif_data = {}
    try:
        info = image._getexif()
        if info:
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                # Apply rational conversion for known tags
                if decoded in ['FNumber', 'ExposureTime', 'ApertureValue', 'FocalLength', 'MaxApertureValue',
                               'FlashEnergy', 'ExposureBiasValue', 'GainControl', 'SubjectDistance']:
                    value = _convert_rational_to_float(value)
                elif isinstance(decoded, str) and 'Date' in decoded and isinstance(value, str):
                    # Handle various date formats including date/time originals, digitizes, etc.
                    value = _convert_exif_date_to_iso(value)
                elif decoded == 'ColorSpace':
                    value = "sRGB" if value == 1 else ("Uncalibrated" if value == 65535 else value)
                elif decoded == 'MakerNote' or decoded == 'UserComment':
                    try:
                        # Try to decode MakerNote/UserComment if it's bytes
                        if isinstance(value, bytes):
                            value = value.decode('utf-8', errors='replace')
                    except Exception:
                        pass # Keep as bytes if decoding fails

                exif_data[decoded] = value
    except Exception as e:
        logger.warning(f"EXIF extraction failed: {str(e)}")
        # Don't raise, just return partial data with a warning
    return exif_data

def get_gps_data(exif_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract and process GPS info from EXIF data.
    Converts raw GPS coordinates to decimal latitude/longitude.
    """
    if 'GPSInfo' not in exif_data:
        return None
    
    raw_gps_info = exif_data['GPSInfo']
    processed_gps_info: Dict[str, Any] = {}
    
    # Decode GPS tags
    for key, value in raw_gps_info.items():
        decoded = GPSTAGS.get(key, key)
        processed_gps_info[decoded] = _convert_rational_to_float(value) # Apply rational conversion to all GPS values

    # Convert to decimal coordinates
    latitude = processed_gps_info.get('GPSLatitude')
    latitude_ref = processed_gps_info.get('GPSLatitudeRef')
    longitude = processed_gps_info.get('GPSLongitude')
    longitude_ref = processed_gps_info.get('GPSLongitudeRef')
    altitude = processed_gps_info.get('GPSAltitude')
    altitude_ref = processed_gps_info.get('GPSAltitudeRef') # 0 for above sea level, 1 for below sea level

    decimal_latitude = None
    if latitude and latitude_ref:
        decimal_latitude = _get_decimal_coords(latitude, latitude_ref)
        processed_gps_info['decimal_latitude'] = decimal_latitude

    decimal_longitude = None
    if longitude and longitude_ref:
        decimal_longitude = _get_decimal_coords(longitude, longitude_ref)
        processed_gps_info['decimal_longitude'] = decimal_longitude
    
    # Convert GPS timestamp if available
    gps_date_stamp = processed_gps_info.get('GPSDateStamp') # 'YYYY:MM:DD'
    gps_time_stamp = processed_gps_info.get('GPSTimeStamp') # tuple of rationals (HH,MM,SS)

    if gps_date_stamp and isinstance(gps_time_stamp, list) and len(gps_time_stamp) == 3:
        try:
            # Reconstruct datetime string
            time_parts = [int(v) for v in gps_time_stamp]
            datetime_str = f"{gps_date_stamp} {time_parts[0]:02}:{time_parts[1]:02}:{time_parts[2]:02}"
            # EXIF GPS timestamp is UTC
            dt_obj = datetime.strptime(datetime_str, "%Y:%m:%d %H:%M:%S").replace(tzinfo=timezone.utc)
            processed_gps_info['timestamp_utc'] = dt_obj.isoformat()
        except Exception as e:
            logger.warning(f"Could not parse GPS timestamp: {gps_date_stamp}, {gps_time_stamp}. Error: {e}")

    # Add simplified altitude interpretation
    if altitude is not None and altitude_ref is not None:
        if altitude_ref == 0: # Above sea level
            processed_gps_info['altitude_description'] = f"{altitude:.2f} meters above sea level"
        elif altitude_ref == 1: # Below sea level
            processed_gps_info['altitude_description'] = f"{altitude:.2f} meters below sea level"
        else:
            processed_gps_info['altitude_description'] = f"{altitude:.2f} meters (unknown reference)"


    return processed_gps_info

# --- Main Extraction Function ---
def extract_jpg_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from JPEG files.

    Args:
        file_path: Path to the JPEG file.

    Returns:
        A dictionary containing extracted metadata, including:
        - file_info: Basic file system attributes.
        - image_info: Technical image properties.
        - exif_data: Detailed EXIF metadata.
        - gps_data: Processed GPS location data.
        - processing: Status, warnings, errors, and time taken.

    Raises:
        JPGMetadataError: For any critical failure during validation or processing.
    """
    result: Dict[str, Any] = {
        "file_info": {},
        "image_info": {},
        "exif_data": {},
        "gps_data": None,
        "processing": {
            "success": False,
            "warnings": [],
            "errors": [],
            "time_taken_seconds": None,
            "extractor_version": "1.1.0"
        }
    }

    start_time = time.time()
    logger.info(f"Starting JPG metadata extraction for: {file_path}")

    try:
        # --- Stage 1: Validation ---
        validate_jpg_file(file_path)
        result["file_info"]["valid"] = True

        # --- Stage 2: File System Info ---
        file_stat = os.stat(file_path)
        result["file_info"] = {
            "path": os.path.abspath(file_path),
            "filename": os.path.basename(file_path),
            "size_bytes": file_stat.st_size,
            "created_utc": datetime.fromtimestamp(file_stat.st_ctime, tz=timezone.utc).isoformat(),
            "modified_utc": datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc).isoformat(),
            "accessed_utc": datetime.fromtimestamp(file_stat.st_atime, tz=timezone.utc).isoformat(),
            "format": "JPEG",
            "detected_mime_type": mimetypes.guess_type(file_path)[0] or magic.from_file(file_path, mime=True),
            "valid": True
        }

        # Handle empty files specifically (validation should catch this, but defensive)
        if file_stat.st_size == 0:
            result["processing"]["warnings"].append("Empty JPG file detected, likely invalid or empty content.")
            result["processing"]["success"] = False # An empty JPG is not "successfully" extracted
            return result

        # --- Stage 3: JPG-specific Metadata Extraction (using Pillow) ---
        img: Optional[Image.Image] = None
        try:
            with Image.open(file_path) as img:
                # Basic Image Info
                result["image_info"] = {
                    "format": img.format,
                    "mode": img.mode, # e.g., 'RGB', 'L', 'CMYK'
                    "color_mode_description": {
                        'L': 'Grayscale', 'RGB': 'True Color', 'CMYK': 'Process Color',
                        'YCbCr': 'Color video format', 'LAB': 'CIE L*a*b*',
                        'HSV': 'Hue, Saturation, Value'
                    }.get(img.mode, 'Other'),
                    "size_pixels": img.size, # (width, height)
                    "width_pixels": img.width,
                    "height_pixels": img.height,
                    "dpi": img.info.get('dpi'), # tuple (x_dpi, y_dpi)
                    "compression": img.info.get('compression'),
                    "progressive": img.info.get('progressive', False),
                    "original_info": dict(img.info) # Include all original info from Pillow
                }
                
                # EXIF data
                exif_data = get_exif_data(img)
                result["exif_data"] = exif_data

                # Add image orientation based on EXIF tag, if present
                orientation_tag = exif_data.get('Orientation')
                if orientation_tag:
                    orientation_map = {
                        1: "Top-left", 2: "Top-right", 3: "Bottom-right", 4: "Bottom-left",
                        5: "Left-top", 6: "Right-top", 7: "Right-bottom", 8: "Left-bottom"
                    }
                    result["image_info"]["orientation"] = orientation_map.get(orientation_tag, f"Unknown ({orientation_tag})")
                else:
                    result["image_info"]["orientation"] = "Normal (1)"

                # GPS data
                if 'GPSInfo' in exif_data:
                    result["gps_data"] = get_gps_data(exif_data)
                
                # Check for common issues
                if not exif_data:
                    result["processing"]["warnings"].append("No EXIF data found in image.")
                
                if img.format != 'JPEG':
                    result["processing"]["warnings"].append(f"Unexpected image format detected by Pillow: {img.format}. Expected JPEG.")
        
        except UnidentifiedImageError as e:
            result["processing"]["errors"].append(f"JPEG content read error: {str(e)}. File might be corrupted or malformed.")
            logger.error(f"Pillow UnidentifiedImageError: {e}")
            result["processing"]["success"] = False # Mark as failed
            return result # Exit early
        except Exception as e:
            result["processing"]["errors"].append(f"Processing failed unexpectedly during image parsing: {str(e)}")
            logger.exception(f"An unexpected error occurred during JPG content processing for {file_path}")
            result["processing"]["success"] = False # Mark as failed
            return result # Exit early

        result["processing"]["success"] = True
        
    except FileAccessError as e:
        result["processing"]["errors"].append(str(e))
        logger.error(f"File Access Error during JPG extraction: {e}")
    except InvalidFileFormatError as e:
        result["processing"]["errors"].append(str(e))
        logger.error(f"Invalid JPG Format Error: {e}")
    except Exception as e:
        # Catch any other unexpected errors that might occur outside specific blocks
        result["processing"]["errors"].append(f"An unhandled critical error occurred: {str(e)}")
        logger.exception(f"An unhandled critical error occurred during extraction for {file_path}")
    finally:
        result["processing"]["time_taken_seconds"] = time.time() - start_time
        if not result["processing"]["success"] and not result["processing"]["errors"]:
             # If success is false but no errors recorded, it's an unhandled case
            result["processing"]["errors"].append("Extraction failed without specific error message (check logs).")
        logger.info(f"Extraction finished for {file_path}. Success: {result['processing']['success']}")

    return result

# --- CLI Entry Point ---
def run_cli():
    """Command-line interface for the JPG metadata extractor."""
    parser = argparse.ArgumentParser(
        description="Extract comprehensive metadata from a JPG file. "
                    "Outputs JSON metadata to stdout or a specified file."
    )
    parser.add_argument(
        "file",
        nargs="?", # Optional argument for file path
        help="Path to the JPG file to extract metadata from."
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
            file_path = input("Enter the path to the JPG file: ").strip()
            if not file_path:
                logger.error("No file path provided. Exiting.")
                sys.exit(1)

    try:
        logger.info(f"Attempting to extract metadata for: {file_path}")
        metadata = extract_jpg_metadata(file_path)
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
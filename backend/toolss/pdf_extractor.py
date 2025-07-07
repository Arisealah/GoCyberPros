





#!/usr/bin/env python3
"""
PDF Metadata Extraction Tool (Enhanced)

Description: Comprehensive and robust metadata extraction from PDF files,
with advanced validation, detailed error handling, and standardized, enriched output.

Features:
- Extracts standard document info (title, author, dates, etc.).
- Retrieves technical PDF details (version, encryption status, page count, viewer preferences).
- Identifies embedded files, outlines/bookmarks, and form data presence.
- Validates PDF integrity and structure rigorously.
- Handles encrypted and corrupted PDFs gracefully, providing warnings or errors.
- Outputs standardized, structured metadata including warnings and errors.

Dependencies:
- PyPDF2 (pip install pypdf2) - Note: 'pypdf' is the actively maintained fork and recommended for new projects.
- python-magic (pip install python-magic)

Example Usage (CLI):
    python3 pdf_extractor.py example.pdf --log-level DEBUG -o metadata.json

Author: Gemini (based on provided foundation)
Version: 1.1.0
Last Updated: 2025-06-07
"""

import os
import json
import magic
import mimetypes # For more robust MIME type handling
from datetime import datetime, timezone
import PyPDF2 # Sticking to PyPDF2 as per original script, but 'pypdf' is generally preferred
from typing import Dict, Any, List, Optional
import logging
import sys
import argparse
import time

# --- Configuration ---
DEFAULT_LOG_FILE = "pdf_extractor.log"
DEFAULT_LOG_LEVEL = "INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Expected PDF MIME types
EXPECTED_PDF_MIMES = ['application/pdf']

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
class PDFMetadataError(Exception):
    """Base class for PDF metadata extraction exceptions."""
    pass

class FileAccessError(PDFMetadataError):
    """Raised for issues accessing the file (e.g., not found, permissions)."""
    pass

class InvalidFileFormatError(PDFMetadataError):
    """Raised when the file is not a valid PDF according to checks."""
    pass

class PDFProcessingError(PDFMetadataError):
    """Raised for unexpected errors during the PDF extraction process."""
    pass

# --- Helper Functions ---
def _convert_pdf_date_to_iso(pdf_date_str: Optional[str]) -> Optional[str]:
    """
    Converts a PDF date string (e.g., "D:20250607152852-04'00'") to ISO 8601 format.
    Handles various PDF date formats and potential parsing errors.
    """
    if not pdf_date_str:
        return None
    
    # Remove 'D:' prefix if present
    if pdf_date_str.startswith("D:"):
        pdf_date_str = pdf_date_str[2:]

    # Remove quotes from timezone offset if present (e.g., -04'00' -> -0400)
    pdf_date_str = pdf_date_str.replace("'", "")

    # Define possible date formats for PDF dates
    date_formats = [
        "%Y%m%d%H%M%S%z", # Full format with timezone (e.g., 20250607152852-0400)
        "%Y%m%d%H%M%S",   # Without timezone (e.g., 20250607152852)
        "%Y%m%d%H%M",     # YYYYMMDDHHMM
        "%Y%m%d",         # YYYYMMDD
    ]

    for fmt in date_formats:
        try:
            # Handle timezone: If the format expects a timezone but it's not present,
            # or vice-versa, parsing might fail.
            # Using astimezone(timezone.utc) ensures consistency.
            if "%z" in fmt:
                dt_obj = datetime.strptime(pdf_date_str, fmt)
            else:
                # Try to parse string without timezone first
                dt_obj = datetime.strptime(pdf_date_str.split('+')[0].split('-')[0], fmt) 
                dt_obj = dt_obj.replace(tzinfo=timezone.utc) # Assume UTC if no timezone is provided in string

            return dt_obj.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
        except Exception as e:
            logger.debug(f"Unexpected error converting PDF date '{pdf_date_str}' with format '{fmt}': {e}")
            continue

    logger.warning(f"Could not parse PDF date string: {pdf_date_str}")
    return None

# --- Main Validation Function ---
def validate_pdf_file(file_path: str) -> bool:
    """
    Advanced validation for PDF file structure and integrity.

    Args:
        file_path: Path to the PDF file.

    Returns:
        True if the file passes all validations.

    Raises:
        FileAccessError: If file doesn't exist or access is restricted.
        InvalidFileFormatError: If file is not deemed a valid PDF.
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
        logger.warning(f"File {file_path} is empty, which is usually an invalid PDF.")
        raise InvalidFileFormatError(f"File is empty: {file_path}")

    # 1. MIME Type Check (using both magic and mimetypes)
    mime_type_magic = magic.from_file(file_path, mime=True)
    mime_type_ext = mimetypes.guess_type(file_path)[0]

    if mime_type_magic not in EXPECTED_PDF_MIMES:
        if mime_type_ext and mime_type_ext == 'application/pdf':
            logger.warning(f"Magic detected '{mime_type_magic}', but extension suggests PDF ('{mime_type_ext}'). Proceeding.")
        else:
            raise InvalidFileFormatError(f"Not a recognized PDF file type by magic ({mime_type_magic}).")
    
    # 2. PyPDF2 structural validation attempt
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            # Attempt to access a property to force parsing and catch early errors
            _ = reader.pages
            _ = reader.metadata
            _ = reader.is_encrypted # Check if it's encrypted
            
            # If it's encrypted and no password was provided, PyPDF2 might not raise error immediately,
            # but operations on pages might fail later. We'll capture it in extract_pdf_metadata.
            if reader.is_encrypted:
                logger.warning(f"PDF {file_path} is encrypted. Full content extraction or some metadata might be unavailable.")

    except PyPDF2.errors.PdfReadError as e:
        raise InvalidFileFormatError(f"Invalid or corrupted PDF structure detected by PyPDF2: {str(e)}") from e
    except Exception as e:
        # Catch any other unexpected errors during PyPDF2 validation attempt
        logger.error(f"Unexpected error during PyPDF2 validation for {file_path}: {e}", exc_info=True)
        raise InvalidFileFormatError(f"Unexpected validation error: {str(e)}") from e

    logger.info(f"File '{file_path}' passed all structural validations.")
    return True

# --- Main Extraction Function ---
def extract_pdf_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from PDF files.

    Args:
        file_path: Path to the PDF file.

    Returns:
        A dictionary containing extracted metadata, including:
        - file_info: Basic file system attributes.
        - document_info: Standard PDF document metadata.
        - technical_info: PDF specific technical details (pages, version, encryption).
        - content_summary: Basic page-level insights (if feasible with PyPDF2).
        - processing: Status, warnings, errors, and time taken.

    Raises:
        PDFMetadataError: For any critical failure during validation or processing.
    """
    result: Dict[str, Any] = {
        "file_info": {},
        "document_info": {},
        "technical_info": {},
        "content_summary": {}, # New: for basic content insights
        "processing": {
            "success": False,
            "warnings": [],
            "errors": [],
            "time_taken_seconds": None,
            "extractor_version": "1.1.0"
        }
    }

    start_time = time.time()
    logger.info(f"Starting PDF metadata extraction for: {file_path}")

    try:
        # --- Stage 1: Validation ---
        validate_pdf_file(file_path)
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
            "format": "PDF",
            "detected_mime_type": mimetypes.guess_type(file_path)[0] or magic.from_file(file_path, mime=True),
            "valid": True
        }

        # Handle empty files specifically (validation should catch this, but defensive)
        if file_stat.st_size == 0:
            result["processing"]["warnings"].append("Empty PDF file detected, likely invalid or empty content.")
            result["processing"]["success"] = False # An empty PDF is not "successfully" extracted
            return result

        # --- Stage 3: PDF-specific Metadata Extraction (using PyPDF2) ---
        pdf_reader: Optional[PyPDF2.PdfReader] = None
        try:
            with open(file_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                
                # Check for encryption first
                if pdf_reader.is_encrypted:
                    result["technical_info"]["is_encrypted"] = True
                    result["processing"]["warnings"].append("Document is encrypted. Some metadata or content analysis may be unavailable without a password.")
                    result["technical_info"]["needs_password"] = True # Assume needs password if still encrypted after default attempts

                # Document Info (Metadata Dictionary)
                doc_info = pdf_reader.metadata or {}
                result["document_info"] = {
                    "title": doc_info.get('/Title'),
                    "author": doc_info.get('/Author'),
                    "subject": doc_info.get('/Subject'),
                    "keywords": doc_info.get('/Keywords'),
                    "creator": doc_info.get('/Creator'),
                    "producer": doc_info.get('/Producer'),
                    "creation_date_utc": _convert_pdf_date_to_iso(doc_info.get('/CreationDate')),
                    "mod_date_utc": _convert_pdf_date_to_iso(doc_info.get('/ModDate')),
                    "trapped": doc_info.get('/Trapped'),
                    "about": doc_info.get('/About'), # Often contains XMP metadata URI
                    "source": doc_info.get('/Source'),
                    "version": doc_info.get('/Version'), # This is usually for the XMP packet version, not PDF version
                    "format": doc_info.get('/Format'),
                    "collection": doc_info.get('/Collection'),
                    "document_id": doc_info.get('/ID') # From the PDF trailer, typically a list of two strings. PyPDF2 might expose as a list.
                }
                # Handle /ID if it's a tuple or list
                if isinstance(result["document_info"].get("document_id"), (list, tuple)):
                    result["document_info"]["document_id"] = [
                        item.hex() if hasattr(item, 'hex') else item for item in result["document_info"]["document_id"]
                    ] # Convert byte strings to hex for readability

                # Technical Info
                pages = len(pdf_reader.pages) if not pdf_reader.is_encrypted else 0 # Page count might be 0 if encrypted and not decrypted
                if pdf_reader.is_encrypted and pages == 0:
                    result["processing"]["warnings"].append("Could not determine page count for encrypted PDF.")

                # Check for embedded files (attachments)
                embedded_files = []
                # PyPDF2.PdfReader.attachments is not a direct attribute. Need to iterate /Names/EmbeddedFiles
                # This often requires traversing the catalog tree.
                # For simplicity, we'll indicate presence if the object exists and warn if not easily accessible.
                try:
                    if hasattr(pdf_reader.trailer, '/Root') and hasattr(pdf_reader.trailer['/Root'], '/Names') and \
                       hasattr(pdf_reader.trailer['/Root']['/Names'], '/EmbeddedFiles'):
                        # This path is complex and might not be directly iterable by PyPDF2 for names.
                        # A more robust check requires deeper PyPDF2 API knowledge or a different library.
                        # For now, we'll just indicate if the /EmbeddedFiles node is found.
                        embedded_files_node = pdf_reader.trailer['/Root']['/Names']['/EmbeddedFiles']
                        if embedded_files_node:
                            # Cannot easily list names without deeper parsing, just note presence
                            embedded_files.append("Embedded files detected (details not extracted by current method).")
                except Exception as e:
                    logger.debug(f"Error checking for embedded files: {e}")
                    result["processing"]["warnings"].append("Could not enumerate embedded files due to parsing error.")


                # Check for outlines/bookmarks
                outlines_count = len(pdf_reader.outline) if hasattr(pdf_reader, 'outline') and pdf_reader.outline else 0

                # Form fields (AcroForms)
                has_forms = False
                try:
                    if hasattr(pdf_reader.trailer, '/Root') and hasattr(pdf_reader.trailer['/Root'], '/AcroForm'):
                        acro_form = pdf_reader.trailer['/Root']['/AcroForm']
                        if acro_form and hasattr(acro_form, '/Fields'):
                            if acro_form['/Fields']:
                                has_forms = True
                except Exception as e:
                    logger.debug(f"Error checking for AcroForms: {e}")
                    result["processing"]["warnings"].append("Could not determine presence of forms due to parsing error.")


                # XMP Metadata (requires a more powerful library like pypdf for full parsing,
                # but we can check for its presence)
                has_xmp_metadata = False
                if hasattr(pdf_reader, 'xmp_metadata') and pdf_reader.xmp_metadata:
                    has_xmp_metadata = True

                result["technical_info"] = {
                    "pages": pages,
                    "pdf_version": float(pdf_reader.pdf_header[1:4]) if pdf_reader.pdf_header else None, # e.g., '%PDF-1.4' -> 1.4
                    "is_encrypted": pdf_reader.is_encrypted,
                    "has_attachments": bool(embedded_files),
                    "embedded_files_summary": embedded_files if embedded_files else None, # Renamed for clarity
                    "has_outlines": bool(outlines_count > 0),
                    "outlines_count": outlines_count,
                    "page_layout": str(pdf_reader.page_layout) if hasattr(pdf_reader, 'page_layout') else None,
                    "page_mode": str(pdf_reader.page_mode) if hasattr(pdf_reader, 'page_mode') else None,
                    "has_forms": has_forms,
                    "has_xmp_metadata": has_xmp_metadata,
                    "is_printable": bool(pdf_reader.get_permissions() & PyPDF2.PdfWriter()._WritePrivileges.PRINT) if not pdf_reader.is_encrypted else None, # Check print permissions
                    "is_modifiable": bool(pdf_reader.get_permissions() & PyPDF2.PdfWriter()._WritePrivileges.MODIFY) if not pdf_reader.is_encrypted else None, # Check modify permissions
                    "can_copy_extract_text": bool(pdf_reader.get_permissions() & PyPDF2.PdfWriter()._WritePrivileges.EXTRACT) if not pdf_reader.is_encrypted else None, # Check text extraction permissions
                }
                
                # Content Summary (basic with PyPDF2 - text extraction can be CPU intensive)
                # We'll extract text from the first and last page as samples
                first_page_text_sample: Optional[str] = None
                last_page_text_sample: Optional[str] = None
                
                if pages > 0 and not pdf_reader.is_encrypted:
                    try:
                        # Extract text from first page
                        first_page = pdf_reader.pages[0]
                        first_page_text_sample = first_page.extract_text()[:1000] # Limit sample size
                        
                        # Extract text from last page if more than one
                        if pages > 1:
                            last_page = pdf_reader.pages[pages - 1]
                            last_page_text_sample = last_page.extract_text()[:1000]

                        # Note: PyPDF2 text extraction is not always perfect for complex PDFs.
                        # For comprehensive text analysis, 'pdfminer.six' or 'pypdf' might be better.
                        
                    except Exception as e:
                        result["processing"]["warnings"].append(f"Failed to extract text sample from pages: {e}")
                        logger.debug(f"Page text extraction error: {e}", exc_info=True)

                result["content_summary"] = {
                    "first_page_text_sample": first_page_text_sample,
                    "last_page_text_sample": last_page_text_sample,
                    # "estimated_total_text_length": total_text_length_estimate, # Add if full text extraction is enabled and optimized
                    # Future: Image count, font list, language detection (requires deeper analysis/libraries)
                }

                if not pdf_reader.metadata:
                    result["processing"]["warnings"].append("No standard metadata found in document.")
                
        except PyPDF2.errors.PdfReadError as e:
            # This handles cases where PyPDF2 cannot even open the file after initial validation
            result["processing"]["errors"].append(f"PDF content read error: {str(e)}. File might be corrupted or malformed.")
            logger.error(f"PDF Read Error: {e}")
            result["processing"]["success"] = False # Mark as failed
            return result # Exit early
        except Exception as e:
            result["processing"]["errors"].append(f"Processing failed unexpectedly: {str(e)}")
            logger.exception(f"An unexpected error occurred during PDF content processing for {file_path}")
            result["processing"]["success"] = False # Mark as failed
            return result # Exit early

        result["processing"]["success"] = True
        
    except FileAccessError as e:
        result["processing"]["errors"].append(str(e))
        logger.error(f"File Access Error during PDF extraction: {e}")
    except InvalidFileFormatError as e:
        result["processing"]["errors"].append(str(e))
        logger.error(f"Invalid PDF Format Error: {e}")
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
    """Command-line interface for the PDF metadata extractor."""
    parser = argparse.ArgumentParser(
        description="Extract comprehensive metadata from a PDF file. "
                    "Outputs JSON metadata to stdout or a specified file."
    )
    parser.add_argument(
        "file",
        nargs="?", # Optional argument for file path
        help="Path to the PDF file to extract metadata from."
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
            file_path = input("Enter the path to the PDF file: ").strip()
            if not file_path:
                logger.error("No file path provided. Exiting.")
                sys.exit(1)

    try:
        logger.info(f"Attempting to extract metadata for: {file_path}")
        metadata = extract_pdf_metadata(file_path)
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













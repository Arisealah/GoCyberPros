# import sys
import sys
import os
import logging

# Add the project root (Wsite) to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# from txt.t3_extractors import extract_txt_metadata
from backend.txt2 import extract_txt_metadata  # Adjusted import to match the new structure

# from backend.toolss.txt_extractor import extract_txt_metadata  # Adjusted import to match the new structure
# Now import using paths relative to the project root
# from txt.t3_extractors import extract_txt_metadata
from backend.toolss.docx_extractor import extract_docx_metadata
from backend.toolss.csv_extractor import extract_csv_metadata
from backend.toolss.eml_extractor import extract_eml_metadata
from backend.toolss.jpg_extractor import extract_jpg_metadata


# import os
# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# import logging

# # from txt.t5 import extract_txt_metadata
# from ..txt.t3_extractors import extract_txt_metadata  # Adjusted import to match the new structure

# from backend.toolss.docx_extractor import extract_docx_metadata
# from backend.toolss.csv_extractor import extract_csv_metadata
# from backend.toolss.eml_extractor import extract_eml_metadata
# from backend.toolss.jpg_extractor import extract_jpg_metadata
from backend.toolss.json_extractor import extract_json_metadata
from backend.toolss.mp3_extractor import extract_mp3_metadata
from backend.toolss.mp4_extractor import extract_mp4_metadata
from backend.toolss.pdf_extractor import extract_pdf_metadata 
from backend.toolss.png_extractor import extract_png_metadata
from backend.toolss.pptx_extractor import extract_pptx_metadata
from backend.toolss.xlsx_extractor import extract_xlsx_metadata  
from backend.toolss.xml_extractor import extract_xml_metadata
from backend.toolss.zip_extractor import extract_zip_metadata

import argparse
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("dispatch.log"),
        logging.StreamHandler()
    ]
)

EXTRACTION_DISPATCH = {
    # '.txt': extract_txt_metadata,
    '.txt': extract_txt_metadata,  # Support for .txtx files
    '.docx': extract_docx_metadata,
    '.csv': extract_csv_metadata,
    '.eml': extract_eml_metadata,
    '.jpg': extract_jpg_metadata,
    '.jpeg': extract_jpg_metadata,
    '.json': extract_json_metadata,
    '.mp3': extract_mp3_metadata,
    '.mp4': extract_mp4_metadata,
    '.pdf': extract_pdf_metadata,
    '.png': extract_png_metadata,
    '.pptx': extract_pptx_metadata,
    '.xlsx': extract_xlsx_metadata,
    '.xml': extract_xml_metadata,
    '.zip': extract_zip_metadata,
}

def get_extractor(filename):
    import os
    ext = os.path.splitext(filename)[1].lower()
    return EXTRACTION_DISPATCH.get(ext)

def run_cli():
    try:
        parser = argparse.ArgumentParser(description="Extract metadata from text files.")
        parser.add_argument("files", nargs="+", help="Text file(s) to process.")
        parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level.")
        parser.add_argument("--output", help="Write metadata output to this file (JSON). If not set, prints to stdout.")
        args = parser.parse_args()

        # Set log level
        logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))

        results = {}
        start_time = time.time()
        success_count = 0
        fail_count = 0

        for filename in args.files:
            extractor = get_extractor(filename)
            if extractor:
                try:
                    logging.info(f"Starting metadata extraction for: {filename}")
                    metadata = extractor(filename)
                    results[filename] = metadata
                    logging.info(f"Extraction successful for: {filename}")
                    success_count += 1
                except Exception as e:
                    logging.exception(f"Extraction failed for {filename}: {e}")
                    results[filename] = {"error": str(e)}
                    fail_count += 1
            else:
                logging.error(f"No extractor found for file type: {filename}")
                results[filename] = {"error": "No extractor found for this file type."}
                fail_count += 1

        # Output results
        import json
        output_json = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output_json)
            print(f"Metadata written to {args.output}")
        else:
            print(output_json)

        elapsed = time.time() - start_time
        logging.info(f"Extraction complete. Success: {success_count}, Failed: {fail_count}, Time: {elapsed:.2f}s")
        print(f"Summary: {success_count} succeeded, {fail_count} failed. Time taken: {elapsed:.2f}s")

    except KeyboardInterrupt:
        logging.warning("Process interrupted by user.")
        print("Process interrupted by user.")
        exit(130)
    except Exception as e:
        logging.exception(f"Fatal error: {e}")
        print(f"Fatal error: {e}. See dispatch.log for details.")
        exit(1)

def main(files=None, log_level="INFO", output=None):
    """
    Programmatic entry point for metadata extraction.
    Args:
        files: list of file paths to process (if None, will prompt for input)
        log_level: logging level as string
        output: output file path (if None, prints to stdout)
    Returns:
        results dict
    """
    logging.getLogger().setLevel(getattr(logging, log_level.upper()))
    if files is None:
        files = [input("Enter the path to the file: ").strip()]
    results = {}
    start_time = time.time()
    success_count = 0
    fail_count = 0
    for filename in files:
        extractor = get_extractor(filename)
        if extractor:
            try:
                logging.info(f"Starting metadata extraction for: {filename}")
                metadata = extractor(filename)
                results[filename] = metadata
                logging.info(f"Extraction successful for: {filename}")
                success_count += 1
            except Exception as e:
                logging.exception(f"Extraction failed for {filename}: {e}")
                results[filename] = {"error": str(e)}
                fail_count += 1
        else:
            logging.error(f"No extractor found for file type: {filename}")
            results[filename] = {"error": "No extractor found for this file type."}
            fail_count += 1
    import json
    output_json = json.dumps(results, indent=2)
    if output:
        with open(output, "w") as f:
            f.write(output_json)
        print(f"Metadata written to {output}")
    else:
        print(output_json)
    elapsed = time.time() - start_time
    logging.info(f"Extraction complete. Success: {success_count}, Failed: {fail_count}, Time: {elapsed:.2f}s")
    print(f"Summary: {success_count} succeeded, {fail_count} failed. Time taken: {elapsed:.2f}s")
    return results

if __name__ == "__main__":
    run_cli()


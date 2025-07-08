

from flask import Flask, request, jsonify, send_from_directory
import os
import tempfile
from flask_cors import CORS # Keep this import
import logging
import sys
from werkzeug.utils import secure_filename

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__) # Ensure only ONE instance of Flask app

# CRITICAL CHANGE: Explicitly allow all origins for /api/ routes
# This is the correct way to initialize CORS. The 'cors(app)' line below it is redundant and incorrect.
CORS(app, resources={r"/api/*": {"origins": "*"}}) # This line is correct and necessary.

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 Megabytes

# Add the project root to sys.path so 'from backend.dispatch import get_extractor' works when running backend/server.py directly.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import get_extractor from dispatch.py (now in backend)
from backend.dispatch import get_extractor

# Basic route to confirm backend is running, prevents 404 if hitting root
@app.route('/')
def hello_world():
    logging.info("Received GET request at /")
    return "<h1>Backend API is running!</h1><p>Access the frontend via Codespaces Live Preview for tools.html</p>"

@app.route('/api/extract', methods=['POST']) # CRITICAL: Ensure POST and OPTIONS are listed
def extract_metadata():
    logging.info("Received request at /api/extract") # This log should now appear if the request hits

    if 'file' not in request.files:
        logging.warning("No file uploaded in the request.")
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    logging.info(f"File '{file.filename}' received.")

    # Get settings from form if present
    output_format = request.form.get('outputFormat', 'json')
    extract_fields = request.form.get('extractFields', 'all')
    deep_scan = request.form.get('deepScan', 'false')
    # Log settings for debugging
    logging.info(f"Settings received: outputFormat={output_format}, extractFields={extract_fields}, deepScan={deep_scan}")

    extractor = get_extractor(file.filename)
    if not extractor:
        logging.warning(f"Unsupported file type for '{file.filename}'.")
        return jsonify({'error': 'Unsupported file type'}), 400

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp)
            tmp_path = tmp.name
        logging.info(f"File saved temporarily to: {tmp_path}")

        metadata = extractor(tmp_path)
        logging.info(f"Successfully extracted metadata for {file.filename}")
        # For now, only JSON is supported. In the future, convert metadata to CSV/XML if requested.
        return jsonify(metadata)
    except Exception as e:
        logging.exception(f"Error processing {file.filename}: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
            logging.info(f"Temporary file {tmp_path} removed.")
        else:
            logging.warning(f"Temporary file {tmp_path} not found for removal.")

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), filename)

@app.route('/styles/<path:filename>')
def serve_styles(filename):
    return send_from_directory(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'style')), filename)

@app.before_request
def log_request_info():
    logging.info(f"Incoming request: {request.method} {request.path} Headers: {dict(request.headers)}")

if __name__ == '__main__':
    logging.info("Starting Flask application...")
    # Use environment variable for port or default to 5000, as recommended for Render
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
    logging.info("Flask application stopped.")

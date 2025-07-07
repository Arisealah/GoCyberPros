document.addEventListener('DOMContentLoaded', () => {
    // --- Modal Elements ---
    const productDemoModal = document.getElementById('product-demo-modal');
    const closeDemoModalButton = document.getElementById('close-demo-modal');
    const demoModalTriggers = document.querySelectorAll('.demo-modal-trigger');
    const demoProductNameSpan = document.getElementById('demo-product-name');
    const body = document.body;

    // Demo steps
    const demoStepUpload = document.getElementById('demo-step-upload');
    const demoStepProcessing = document.getElementById('demo-step-processing');
    const demoStepResults = document.getElementById('demo-step-results');
    const demoStepError = document.getElementById('demo-step-error');

    // Upload elements
    const fileDropZone = document.getElementById('file-drop-zone');
    const fileInput = document.getElementById('file-input');
    const fileNameDisplay = document.getElementById('file-name-display');
    const startExtractionBtn = document.getElementById('start-extraction-btn');

    // Results elements
    const extractedMetadataDisplay = document.getElementById('extracted-metadata-display');
    const clearDemoBtn = document.getElementById('clear-demo-btn');

    // Error elements
    const errorMessageDisplay = document.getElementById('error-message');
    const retryDemoBtn = document.getElementById('retry-demo-btn');

    let currentProductType = '';

    // --- Utility Functions ---
    const showDemoStep = (stepElement) => {
        const allSteps = [demoStepUpload, demoStepProcessing, demoStepResults, demoStepError];
        allSteps.forEach(step => step.classList.add('hidden'));
        stepElement.classList.remove('hidden');
    };

    const resetDemoModal = () => {
        fileInput.value = '';
        fileNameDisplay.textContent = 'No file chosen';
        startExtractionBtn.disabled = true;
        showDemoStep(demoStepUpload);
        extractedMetadataDisplay.textContent = '';
        errorMessageDisplay.textContent = '';
    };

    // --- Modal Logic ---
    const openDemoModal = (productType, productName) => {
        currentProductType = productType;
        demoProductNameSpan.textContent = productName;
        productDemoModal.classList.add('active');
        body.style.overflow = 'hidden';
        productDemoModal.setAttribute('aria-hidden', 'false');
        resetDemoModal();
    };

    const closeDemoModal = () => {
        productDemoModal.classList.remove('active');
        body.style.overflow = '';
        productDemoModal.setAttribute('aria-hidden', 'true');
        resetDemoModal();
    };

    demoModalTriggers.forEach(button => {
        button.addEventListener('click', () => {
            const productType = button.dataset.productType;
            const productName = button.closest('.product-card').querySelector('.card-title').textContent;
            openDemoModal(productType, productName);
        });
    });

    if (closeDemoModalButton) {
        closeDemoModalButton.addEventListener('click', closeDemoModal);
    }
    if (productDemoModal) {
        productDemoModal.addEventListener('click', (event) => {
            if (event.target === productDemoModal) {
                closeDemoModal();
            }
        });
    }

    // --- File Upload & Extraction Logic ---
    if (fileInput) {
        fileInput.addEventListener('change', () => {
            const file = fileInput.files[0];
            if (file) {
                fileNameDisplay.textContent = file.name;
                startExtractionBtn.disabled = false;
            } else {
                fileNameDisplay.textContent = 'No file chosen';
                startExtractionBtn.disabled = true;
            }
        });
    }

    if (fileDropZone) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            fileDropZone.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        fileDropZone.addEventListener('dragenter', () => fileDropZone.classList.add('drag-over'), false);
        fileDropZone.addEventListener('dragover', () => fileDropZone.classList.add('drag-over'), false);
        fileDropZone.addEventListener('dragleave', () => fileDropZone.classList.remove('drag-over'), false);
        fileDropZone.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            fileDropZone.classList.remove('drag-over');
            const dt = e.dataTransfer;
            const file = dt.files[0];
            if (file) {
                fileInput.files = dt.files;
                fileNameDisplay.textContent = file.name;
                startExtractionBtn.disabled = false;
            } else {
                fileNameDisplay.textContent = 'No file chosen';
                startExtractionBtn.disabled = true;
            }
        }

        const browseFilesBtn = fileDropZone.querySelector('label[for="file-input"]');
        if (browseFilesBtn) {
            browseFilesBtn.addEventListener('click', () => {
                fileInput.click();
            });
        }
    }

    if (startExtractionBtn) {
        startExtractionBtn.addEventListener('click', async () => {
            const file = fileInput.files[0];
            if (!file) {
                alert('Please select a file first!');
                return;
            }

            const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB
            if (file.size > MAX_FILE_SIZE) {
                showDemoStep(demoStepError);
                errorMessageDisplay.textContent = `File is too large (${(file.size / (1024 * 1024)).toFixed(2)}MB). Max demo size is ${MAX_FILE_SIZE / (1024 * 1024)}MB.`;
                return;
            }

            showDemoStep(demoStepProcessing);

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('https://github.com/Arisealah/GoCyberPros/tree/master/backend', {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    let errorMsg = `HTTP error! status: ${response.status}`;
                    try {
                        const errorData = await response.json();
                        errorMsg = errorData.error || errorMsg;
                    } catch (e) {}
                    throw new Error(errorMsg);
                }

                const result = await response.json();
                extractedMetadataDisplay.textContent = JSON.stringify(result, null, 2);
                showDemoStep(demoStepResults);
            } catch (error) {
                showDemoStep(demoStepError);
                errorMessageDisplay.textContent = `Extraction failed: ${error.message}. Please try again.`;
            }
        });
    }

    if (clearDemoBtn) {
        clearDemoBtn.addEventListener('click', resetDemoModal);
    }

    if (retryDemoBtn) {
        retryDemoBtn.addEventListener('click', resetDemoModal);
    }

    // --- Unified Extractor Logic ---
    const form = document.getElementById('unified-extractor-form');
    const unifiedFileInput = document.getElementById('unified-file-input');
    const resultDiv = document.getElementById('unified-extractor-result');
    const resultCode = document.getElementById('unified-extracted-metadata');
    const errorDiv = document.getElementById('unified-extractor-error');
    const errorMsg = document.getElementById('unified-error-message');
    const copyBtn = document.getElementById('copy-metadata-btn');
    const downloadBtn = document.getElementById('download-metadata-btn');
    const clearBtn = document.getElementById('clear-metadata-btn');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        resultDiv.style.display = 'none';
        errorDiv.style.display = 'none';

        const file = unifiedFileInput.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/api/extract', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            if (response.ok && !data.error) {
                resultCode.textContent = JSON.stringify(data, null, 2);
                resultDiv.style.display = 'block';
            } else {
                errorMsg.textContent = data.error || 'Extraction failed.';
                errorDiv.style.display = 'block';
            }
        } catch (err) {
            errorMsg.textContent = 'Network or server error.';
            errorDiv.style.display = 'block';
        }
    });

    // Copy to clipboard
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            if (resultCode.textContent) {
                navigator.clipboard.writeText(resultCode.textContent)
                    .then(() => {
                        copyBtn.textContent = 'Copied!';
                        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
                    })
                    .catch(() => alert('Failed to copy metadata.'));
            }
        });
    }

    // Download as JSON
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            const blob = new Blob([resultCode.textContent], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'metadata.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
    }

    // Clear and choose another file
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            resultDiv.style.display = 'none';
            fileInput.value = '';
            form.reset();
        });
    }
});

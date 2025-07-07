


document.addEventListener('DOMContentLoaded', () => {
    // --- Global Elements ---
    const body = document.body;
    const currentYearSpan = document.getElementById('current-year');

    // Set current year in footer
    if (currentYearSpan) {
        currentYearSpan.textContent = new Date().getFullYear();
    }

    // --- Theme Toggle Logic ---
    const themeToggle = document.getElementById('theme-toggle');
    const LOCAL_STORAGE_THEME_KEY = 'saasWebsiteTheme'; // Key for localStorage

    // Function to apply theme
    const applyTheme = (theme) => {
        if (theme === 'dark') {
            body.classList.add('dark-mode');
        } else {
            body.classList.remove('dark-mode');
        }
    };

    // Load theme from localStorage on page load
    const savedTheme = localStorage.getItem(LOCAL_STORAGE_THEME_KEY);
    if (savedTheme) {
        applyTheme(savedTheme);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        // If no saved theme, check system preference
        applyTheme('dark');
    } else {
        // Default to light if no preference
        applyTheme('light');
    }

    // Event listener for theme toggle button
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const newTheme = body.classList.contains('dark-mode') ? 'light' : 'dark';
            applyTheme(newTheme);
            localStorage.setItem(LOCAL_STORAGE_THEME_KEY, newTheme); // Save preference
        });
    }

    // --- Mobile Navigation Logic ---
    const menuToggle = document.querySelector('.menu-toggle');
    const mobileNavOverlay = document.getElementById('mobile-nav-overlay');
    const closeMenuButton = document.querySelector('.close-menu');
    const mobileNavLinks = document.querySelectorAll('.mobile-nav-link');

    // Open mobile menu
    if (menuToggle) {
        menuToggle.addEventListener('click', () => {
            mobileNavOverlay.classList.add('active');
            body.style.overflow = 'hidden'; // Prevent scrolling when menu is open
            mobileNavOverlay.setAttribute('aria-hidden', 'false');
        });
    }

    // Close mobile menu
    const closeMobileMenu = () => {
        mobileNavOverlay.classList.remove('active');
        body.style.overflow = ''; // Restore scrolling
        mobileNavOverlay.setAttribute('aria-hidden', 'true');
    };

    if (closeMenuButton) {
        closeMenuButton.addEventListener('click', closeMobileMenu);
    }

    // Close menu when a link is clicked
    mobileNavLinks.forEach(link => {
        link.addEventListener('click', closeMobileMenu);
    });

    // Close menu if user clicks outside of it (on the overlay background)
    if (mobileNavOverlay) {
        mobileNavOverlay.addEventListener('click', (event) => {
            if (event.target === mobileNavOverlay) {
                closeMobileMenu();
            }
        });
    }

    // --- Settings Modal Logic ---
    const settingsToggle = document.getElementById('settings-toggle');
    const settingsModal = document.getElementById('settings-modal');
    const closeSettingsModalButton = document.getElementById('close-settings-modal');
    const LOCAL_STORAGE_FONT_SIZE_KEY = 'saasWebsiteFontSize';
    const LOCAL_STORAGE_CONTRAST_KEY = 'saasWebsiteContrast';

    // Open settings modal
    if (settingsToggle) {
        settingsToggle.addEventListener('click', () => {
            settingsModal.classList.add('active');
            body.style.overflow = 'hidden'; // Prevent scrolling
            settingsModal.setAttribute('aria-hidden', 'false');
        });
    }

    // Close settings modal
    const closeSettingsModal = () => {
        settingsModal.classList.remove('active');
        body.style.overflow = ''; // Restore scrolling
        settingsModal.setAttribute('aria-hidden', 'true');
    };

    if (closeSettingsModalButton) {
        closeSettingsModalButton.addEventListener('click', closeSettingsModal);
    }

    // Close modal if user clicks outside of it
    if (settingsModal) {
        settingsModal.addEventListener('click', (event) => {
            if (event.target === settingsModal) {
                closeSettingsModal();
            }
        });
    }

    // Handle ESC key to close modals
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            if (mobileNavOverlay.classList.contains('active')) {
                closeMobileMenu();
            }
            if (settingsModal.classList.contains('active')) {
                closeSettingsModal();
            }
        }
    });

    // --- Font Size Adjustment Logic ---
    const fontSizeButtons = document.querySelectorAll('.font-size-btn');

    // Function to apply font size
    const applyFontSize = (size) => {
        body.classList.remove('font-small', 'font-large'); // Remove existing
        if (size === 'small') {
            body.classList.add('font-small');
        } else if (size === 'large') {
            body.classList.add('font-large');
        }
        // Update active state of buttons
        fontSizeButtons.forEach(btn => {
            if (btn.dataset.size === size) {
                btn.classList.remove('btn-outline');
                btn.classList.add('btn-primary');
            } else {
                btn.classList.remove('btn-primary');
                btn.classList.add('btn-outline');
            }
        });
    };

    // Load font size preference from localStorage
    const savedFontSize = localStorage.getItem(LOCAL_STORAGE_FONT_SIZE_KEY);
    if (savedFontSize) {
        applyFontSize(savedFontSize);
    } else {
        applyFontSize('default'); // Apply default on first load
    }

    // Event listeners for font size buttons
    fontSizeButtons.forEach(button => {
        button.addEventListener('click', () => {
            const size = button.dataset.size;
            applyFontSize(size);
            localStorage.setItem(LOCAL_STORAGE_FONT_SIZE_KEY, size); // Save preference
        });
    });

    // --- High Contrast Toggle Logic ---
    const highContrastToggle = document.getElementById('high-contrast-toggle');

    // Function to apply contrast mode
    const applyContrastMode = (isHighContrast) => {
        if (isHighContrast) {
            body.classList.add('high-contrast');
        } else {
            body.classList.remove('high-contrast');
        }
    };

    // Load contrast preference from localStorage
    const savedContrastMode = localStorage.getItem(LOCAL_STORAGE_CONTRAST_KEY);
    if (savedContrastMode === 'true') { // localStorage stores booleans as strings
        highContrastToggle.checked = true;
        applyContrastMode(true);
    } else {
        highContrastToggle.checked = false;
        applyContrastMode(false);
    }

    // Event listener for high contrast toggle
    if (highContrastToggle) {
        highContrastToggle.addEventListener('change', (event) => {
            const isHighContrast = event.target.checked;
            applyContrastMode(isHighContrast);
            localStorage.setItem(LOCAL_STORAGE_CONTRAST_KEY, isHighContrast); // Save preference
        });
    }

    // --- Language Select (Placeholder Logic) ---
    const languageSelect = document.getElementById('language-select');
    const LOCAL_STORAGE_LANGUAGE_KEY = 'saasWebsiteLanguage';

    // Load language preference
    const savedLanguage = localStorage.getItem(LOCAL_STORAGE_LANGUAGE_KEY);
    if (savedLanguage) {
        languageSelect.value = savedLanguage;
        // In a real app, you'd load translations here
        console.log(`Loaded language: ${savedLanguage}`);
    } else {
        languageSelect.value = 'en'; // Default
        console.log('Default language: en');
    }

    // Event listener for language select
    if (languageSelect) {
        languageSelect.addEventListener('change', (event) => {
            const selectedLanguage = event.target.value;
            localStorage.setItem(LOCAL_STORAGE_LANGUAGE_KEY, selectedLanguage);
            // In a real app, you'd trigger a content reload or translation function here
            alert(`Language changed to: ${selectedLanguage}. (Content reload not implemented in frontend demo)`);
            console.log(`Language changed to: ${selectedLanguage}`);
        });
    }

}); // End DOMContentLoaded
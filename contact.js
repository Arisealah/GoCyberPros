



document.addEventListener('DOMContentLoaded', () => {
    const contactForm = document.getElementById('contact-form');
    const formStatus = document.getElementById('form-status');

    if (contactForm) {
        contactForm.addEventListener('submit', function(event) {
            event.preventDefault(); // Prevent default form submission

            clearErrorMessages(); // Clear previous errors
            formStatus.style.display = 'none'; // Hide previous status message

            const name = document.getElementById('name').value.trim();
            const email = document.getElementById('email').value.trim();
            const subject = document.getElementById('subject').value.trim();
            const message = document.getElementById('message').value.trim();

            let isValid = true;

            // Simple validation checks
            if (name === '') {
                displayError('name-error', 'Name is required.');
                isValid = false;
            }

            if (email === '') {
                displayError('email-error', 'Email is required.');
                isValid = false;
            } else if (!isValidEmail(email)) {
                displayError('email-error', 'Please enter a valid email address.');
                isValid = false;
            }

            if (subject === '') {
                displayError('subject-error', 'Subject is required.');
                isValid = false;
            }

            if (message === '') {
                displayError('message-error', 'Message is required.');
                isValid = false;
            }

            if (isValid) {
                // Simulate form submission
                console.log('Form is valid. Simulating submission...');
                console.log('Name:', name);
                console.log('Email:', email);
                console.log('Subject:', subject);
                console.log('Message:', message);

                // Show success message
                showFormStatus('success', 'Thank you for your message! We will get back to you shortly.');
                contactForm.reset(); // Clear the form
            } else {
                showFormStatus('error', 'Please correct the errors in the form.');
            }
        });
    }

    function displayError(elementId, message) {
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }
    }

    function clearErrorMessages() {
        const errorMessages = document.querySelectorAll('.error-message');
        errorMessages.forEach(el => {
            el.textContent = '';
            el.style.display = 'none';
        });
    }

    function isValidEmail(email) {
        // Basic email regex for demonstration
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    function showFormStatus(type, message) {
        formStatus.className = 'form-status'; // Reset classes
        formStatus.classList.add(type); // Add success or error class
        formStatus.textContent = message;
        formStatus.style.display = 'block';
        // Scroll to the status message
        formStatus.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
});
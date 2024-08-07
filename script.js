// Initialize select dropdowns with TomSelect
new TomSelect("#select-backend", {
    controlInput: null,
    valueField: "value",
    labelField: "label",
    sortField: {
        field: "value",
        direction: "asc"
    }
});

new TomSelect("#select-format", {
    controlInput: null,
    valueField: "value",
    labelField: "label"
});

// Handle conversion on click
// Handle conversion on click
document.getElementById('convert-btn').addEventListener('click', async function () {
    const convertButton = document.getElementById('convert-btn');
    const validationStatus = document.getElementById('validation-status');
    convertButton.disabled = true; // Disable the button to prevent multiple clicks
    convertButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Converting...'; // Change button text to show loading
    validationStatus.style.display = 'none'; // Hide the validation status while converting

    const splunkInput = document.getElementById('rule-code').value;

    if (!splunkInput.trim()) {
        alert('Please enter a valid Splunk search.');
        convertButton.disabled = false; // Re-enable the button
        convertButton.innerHTML = 'Convert'; // Reset button text
        return;
    }

    const backend = document.getElementById('select-backend').value;
    const format = document.getElementById('select-format').value;

    try {
        const response = await fetch('http://localhost:5000/convert', {  // Ensure this is pointing to your local backend
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ splunkInput, backend, format })
        });

        const result = await response.json();

        if (response.ok) {
            document.getElementById('query-code').value = result.sigmaRule;
            autoResize(document.getElementById('query-code')); // Trigger auto-resize for output
            validationStatus.textContent = "SigmaC Syntax Validation: Pass";
            validationStatus.classList.remove('fail');
            validationStatus.classList.add('pass');
        } else {
            document.getElementById('query-code').value = result.sigmaRule; // Still show the Sigma rule
            autoResize(document.getElementById('query-code'));
            alert(`Error: ${result.validationErrors}`); // Show the error in an alert
            validationStatus.textContent = `SigmaC Syntax Validation: Fail\n${result.validationErrors}`;
            validationStatus.classList.remove('pass');
            validationStatus.classList.add('fail');
        }
    } catch (error) {
        alert('An error occurred while converting the rule.');
        validationStatus.textContent = "SigmaC Syntax Validation: Fail";
        validationStatus.classList.remove('pass');
        validationStatus.classList.add('fail');
    } finally {
        validationStatus.style.display = 'block'; // Show the validation status
        convertButton.disabled = false; // Re-enable the button
        convertButton.innerHTML = 'Convert'; // Reset button text
    }
});



// Utility function to auto-resize textareas
function autoResize(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = textarea.scrollHeight + 'px';
}

// Utility function to handle placeholder style on focus
function removePlaceholderStyle(textarea) {
    textarea.classList.remove('placeholder-style');
}




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


document.getElementById('convert-btn').addEventListener('click', async function () {
    const convertButton = document.getElementById('convert-btn');
    const validationStatus = document.getElementById('validation-status');
    const queryCodeArea = document.getElementById('query-code');
    const outputSection = document.querySelector('.section-container');

    convertButton.disabled = true; 
    convertButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Converting...'; 
    validationStatus.style.display = 'none'; 

    const splunkInput = document.getElementById('rule-code').value;

    if (!splunkInput.trim()) {
        alert('Please enter a valid Splunk search.');
        convertButton.disabled = false; 
        convertButton.innerHTML = 'Convert'; 
        queryCodeArea.value = ""; 
        return;
    }

    const backend = document.getElementById('select-backend').value;
    const format = document.getElementById('select-format').value;

    try {
        // Request to generate the Sigma rule
        const response = await fetch('https://splunk2sigma-65a4a257f8cf.herokuapp.com/convert', {  
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ splunkInput, backend, format })
        });

        const result = await response.json();

        // Display the generated Sigma rule
        queryCodeArea.value = result.sigmaRule;
        autoResize(queryCodeArea);
        validationStatus.textContent = result.message;
        validationStatus.classList.remove('fail');
        validationStatus.classList.add('info');
        validationStatus.style.display = 'block';

        // Now proceed to validate the Sigma rule
        const validateResponse = await fetch('https://your-heroku-app.herokuapp.com/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sigmaRule: result.sigmaRule })
        });

        const validateResult = await validateResponse.json();

        if (validateResponse.ok) {
            validationStatus.textContent = "SigmaC Syntax Validation: Pass";
            validationStatus.classList.remove('fail');
            validationStatus.classList.add('pass');
        } else {
            validationStatus.textContent = "SigmaC Syntax Validation: Fail. Fixing it...";
            validationStatus.classList.remove('pass');
            validationStatus.classList.add('fail');

            // If the first validation failed and was fixed
            if (validateResult.status === "Passed with Minor Enhancements") {
                queryCodeArea.value = validateResult.sigmaRule;
                validationStatus.textContent = `SigmaC Syntax Validation: Passed with Minor Enhancements\n${validateResult.validationErrors}`;
                validationStatus.classList.remove('fail');
                validationStatus.classList.add('pass');
            }
        }
    } catch (error) {
        alert('An error occurred while converting the rule.');
        validationStatus.textContent = "SigmaC Syntax Validation: Fail";
        validationStatus.classList.remove('pass');
        validationStatus.classList.add('fail');
    } finally {
        convertButton.disabled = false; 
        convertButton.innerHTML = 'Convert'; 
    }
});



function autoResize(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = textarea.scrollHeight + 'px';
}

function removePlaceholderStyle(textarea) {
    textarea.classList.remove('placeholder-style');
}




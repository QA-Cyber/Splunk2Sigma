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
        // Inform user that generation is in progress
        queryCodeArea.value = "Generating Sigma rule. Please wait...";
        autoResize(queryCodeArea);

        // Request to generate the Sigma rule
        const convertResponse = await fetch('https://splunk2sigma-65a4a257f8cf.herokuapp.com/convert', {  
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ splunkInput, backend, format })
        });

        const convertResult = await convertResponse.json();
        queryCodeArea.value = convertResult.sigmaRule; 
        validationStatus.textContent = "Sigma rule generated. Validating syntax now...";
        validationStatus.style.color = "green";
        validationStatus.classList.remove('fail');
        validationStatus.classList.add('info');
        validationStatus.style.display = 'block';
        

        if (convertResponse.ok) {
            // Now proceed to validate the Sigma rule
            const validateResponse = await fetch('https://splunk2sigma-65a4a257f8cf.herokuapp.com/validate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sigmaRule: convertResult.sigmaRule })
            });

            const validateResult = await validateResponse.json();

            if (validateResponse.ok) {
                validationStatus.textContent = "SigmaQ Validator: Pass";
                validationStatus.classList.remove('fail');
                validationStatus.classList.add('pass');
            } else {
                if (validateResult.status === "Passed with Minor Enhancements") {
                    queryCodeArea.value = validateResult.sigmaRule;
                    validationStatus.textContent = `SigmaQ Validator: Passed with Minor Enhancements\n${validateResult.validationErrors}`;
                    validationStatus.classList.remove('fail');
                    validationStatus.classList.add('pass');
                } else {
                    const reason = validateResult.validationErrors.split("\n")[0];  // Extract the first error line as the reason
                    validationStatus.textContent = `SigmaQ Validator: Fail - Reason: ${reason}`;
                    validationStatus.style.color = "black";
                    validationStatus.classList.remove('pass');
                    validationStatus.classList.add('fail');
                }
            }
        } else {
            // Handle errors during conversion
            queryCodeArea.value = convertResult.sigmaRule;
            validationStatus.textContent = `Conversion Success, but Validation Failed: ${convertResult.validationErrors}`;
            validationStatus.style.color = "green";
            validationStatus.classList.remove('info', 'pass');
            validationStatus.classList.add('fail');
        }
    } catch (error) {
        alert('An error occurred while converting the rule.');
        validationStatus.textContent = "SigmaQ Validator: Fail";
        validationStatus.style.color = "black";
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

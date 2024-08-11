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

    queryCodeArea.value = "Converting Splunk query to Sigma rule. Please wait...";
    autoResize(queryCodeArea);

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
        const response = await fetch('https://splunk2sigma-65a4a257f8cf.herokuapp.com/convert', {  
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ splunkInput, backend, format })
        });

        const result = await response.json();

        if (response.ok) {
            queryCodeArea.value = result.sigmaRule;
            autoResize(queryCodeArea); 
            validationStatus.textContent = "SigmaC Syntax Validation: Pass";
            validationStatus.classList.remove('fail');
            validationStatus.classList.add('pass');
        } else {
            queryCodeArea.value = result.sigmaRule;
            autoResize(queryCodeArea);

            validationStatus.textContent = "SigmaC Syntax Validation: Fail. Fixing it...";
            validationStatus.classList.remove('pass');
            validationStatus.classList.add('fail');

            const fixResponse = await fetch('https://splunk2sigma-65a4a257f8cf.herokuapp.com/convert', {  
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ splunkInput: result.sigmaRule, backend, format })
            });

            const fixResult = await fixResponse.json();

            if (fixResponse.ok) {
                queryCodeArea.value = fixResult.sigmaRule;
                validationStatus.textContent = "SigmaC Syntax Validation: Pass";
                validationStatus.classList.remove('fail');
                validationStatus.classList.add('pass');
            } else {
                queryCodeArea.value = fixResult.sigmaRule;
                validationStatus.textContent = `SigmaC Syntax Validation: Fail\n${fixResult.validationErrors}`;
                validationStatus.classList.remove('pass');
                validationStatus.classList.add('fail');
            }
        }
    } catch (error) {
        alert('An error occurred while converting the rule.');
        validationStatus.textContent = "SigmaC Syntax Validation: Fail";
        validationStatus.classList.remove('pass');
        validationStatus.classList.add('fail');
    } finally {
        validationStatus.style.display = 'block'; 
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




document.getElementById('clear-btn').addEventListener('click', function() {
    document.getElementById('splunk-input').value = '';
    document.getElementById('sigma-output').value = '';
    document.getElementById('pipeline-output').value = '';
    document.getElementById('cli-command').innerText = 'sigma-cli ...';
});

document.getElementById('convert-btn').addEventListener('click', async function() {
    const splunkInput = document.getElementById('splunk-input').value;

    if (!splunkInput.trim()) {
        alert('Please enter a valid Splunk search.');
        return;
    }

    const backend = document.getElementById('backend').value;
    const format = document.getElementById('format').value;

    // Send the Splunk input to the backend API for conversion
    const response = await fetch('https://api.yourbackend.com/convert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ splunkInput, backend, format })
    });

    const result = await response.json();

    if (response.ok) {
        document.getElementById('sigma-output').value = result.sigmaRule;
        document.getElementById('cli-command').innerText = result.cliCommand;
    } else {
        alert(`Error: ${result.message}`);
    }
});

function openTab(tabName) {
    const tabs = document.querySelectorAll('.output-text');
    tabs.forEach(tab => tab.classList.add('hidden'));
    document.getElementById(tabName).classList.remove('hidden');

    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => button.classList.remove('active'));
    document.querySelector(`[onclick="openTab('${tabName}')"]`).classList.add('active');
}

document.getElementById('copy-cli-btn').addEventListener('click', function() {
    const cliCommand = document.getElementById('cli-command').innerText;
    navigator.clipboard.writeText(cliCommand).then(() => {
        alert('CLI command copied to clipboard');
    });
});

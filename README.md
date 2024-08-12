```Developed by: Q.A```
# Splunk2Sigma Converter

## Overview

The **Splunk2Sigma Converter** is a web-based tool designed to convert Splunk search queries (`savedsearches.conf`) into Sigma rules (`.yml` format). It leverages AI to ensure that complex Splunk queries are accurately transformed into Sigma rules. The tool includes a custom validator that enhances the generated Sigma rule by checking for common issues and providing auto-corrections. This custom validation process helps ensure that the Sigma rules are both accurate and compliant with Sigma standards, reducing the need for manual fixes.

This tool is particularly useful for threat detection engineers and cybersecurity professionals who need to standardize and share detection rules across different SIEM (Security Information and Event Management) systems.


## Features

- **AI-Powered Conversion**: Utilizes OpenAI to convert Splunk `savedsearches.conf` queries into Sigma rule YAML format.
- **Custom Validation**: Includes a custom validation process that automatically detects and corrects common issues in the generated Sigma rules, ensuring they adhere to Sigma standards.
- **Error Handling**: If the custom validator detects unresolved issues, the rule is sent back to the AI for correction, ensuring higher accuracy and compliance.
- **Responsive Design**: Built using Bootstrap, ensuring compatibility across various devices.



## Project Structure

```
├── config.py # Configuration file for the API key and other settings
├── convert.py # Main Flask application file that handles the conversion and validation logic
├── requirements.txt # List of dependencies required for the backend
├── Procfile # Heroku-specific file for defining the type of application
├── temp_sigma_rule.yml # Temporary file used for validation
├── test_rule.yml # Sample Sigma rule for testing purposes
├── .github/
│ └── workflows/
│ └── deploy.yml # GitHub Actions workflow for deploying the frontend
├── index.html # Main HTML file for the frontend interface
├── script.js # JavaScript file for handling frontend logic and API communication
├── style.css # Custom CSS file for styling the frontend
└── README.md # This file
```

## Installation & Setup

### Launching the App Locally

#### Backend

1. **Clone the repository:**

    ```bash
    git clone https://github.com/QA-Cyber/Splunk2Sigma.git
    cd Splunk2Sigma
    ```

2. **Set up a virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install the required dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Set up environment variables:**
   - Create a `.env` file in the root of your project with your OpenAI API key:

     ```bash
     OPENAI_API_KEY=your_openai_api_key
     ```

5. **Run the Flask app:**

    ```bash
    python convert.py
    ```

6. **Access the app:**
   - Open your browser and go to `http://127.0.0.1:5000`.

#### Frontend

1. **Modify the `script.js`:**
   - Update the `fetch` request URL to point to your local backend:

     ```javascript
     const response = await fetch('http://127.0.0.1:5000/convert', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify({ splunkInput, backend, format })
     });
     ```

2. **Open the `index.html` file:**
   - You can directly open this file in a web browser. The frontend will now interact with the backend running on your local machine.

### Usage

1. **Input the Splunk Query:**
   - In the `savedsearch.conf` text area, input your Splunk query.

2. **Select Query Language & Format:**
   - The default settings are `Splunk` and `savedsearches.conf`, respectively.

3. **Convert:**
   - Click on the `Convert` button. The Sigma rule will be generated and validated automatically.

4. **View the Sigma Rule:**
   - The converted Sigma rule will be displayed on the right side, along with the validation status.



## Troubleshooting

### Common Issues

- **CORS Errors:**
  - Ensure the CORS settings in the Flask app (`convert.py`) allow requests from your frontend origin. You can configure it by updating the `CORS` settings to allow requests from your specific frontend URL.

- **Validation Errors:**
  - If Sigma rule validation fails, ensure that the generated rule adheres to the correct Sigma format. You might need to manually adjust the generated rule or refine the input query.


### Logs and Debugging

- **Backend Logs:**
  - You can view the logs of your Flask app to debug any issues:

    ```bash
    flask run --reload
    ```

- **Browser Console:**
  - Use the browser’s developer tools to inspect any network requests or errors. This is useful for debugging issues with the frontend or API communication.


## Contributing

If you would like to contribute to the Splunk2Sigma Converter project, please follow the steps below:

1. **Fork the repository:**
   - Click on the "Fork" button at the top right of this repository's GitHub page.

2. **Create a new branch:**
   - Create a new branch for your feature or bugfix:

     ```bash
     git checkout -b feature-name
     ```

3. **Make your changes:**
   - Implement your feature or bugfix in your branch.

4. **Commit your changes:**
   - Add and commit your changes with a descriptive commit message:

     ```bash
     git add .
     git commit -m "Description of the feature or fix"
     ```

5. **Push to your branch:**
   - Push your changes to your forked repository:

     ```bash
     git push origin feature-name
     ```

6. **Create a Pull Request:**
   - Go to the original repository on GitHub, and click on the "Pull Requests" tab.
   - Click the "New Pull Request" button, and select your branch from your forked repository.
   - Provide a clear description of your changes and submit the pull request.

Thank you for contributing to the project!


## License

This project is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

For more details, please refer to the [LICENSE](LICENSE) file in the repository.


## Contact

For any questions, suggestions, or issues, please feel free to open an issue in this repository.

You can also follow and interact with the project on GitHub Pages: [Splunk2Sigma](https://splunk2sigma.github.io/).

Developed by: Q.A
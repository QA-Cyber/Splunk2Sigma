```Developed by: Q.A```
# Splunk2Sigma Converter

## Overview

The **Splunk2Sigma Converter** is a web-based tool that allows users to convert Splunk search queries (`savedsearches.conf`) into Sigma rules (`.yml` format). Powered by AI, this tool is particularly useful for threat detection engineers and cybersecurity professionals who need to standardize and share detection rules across different SIEM (Security Information and Event Management) systems.

The conversion process is enhanced with OpenAI's capabilities, ensuring that complex Splunk queries are accurately transformed into Sigma rules. After generating the Sigma rule with AI, the tool runs it through a rule validator checker called [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) to ensure that the rule adheres to the correct format and SIGMA standards.
The project is divided into two main components:
1. **Frontend**: A web interface hosted on GitHub Pages.
2. **Backend**: A Flask-based API hosted on Heroku, which handles the conversion logic.

## Features

- **AI-Powered Conversion**: Leverages OpenAI to convert Splunk `savedsearches.conf` queries into Sigma rule YAML format.
- **Validation**: After conversion, Sigma rules are validated using [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) to ensure correctness and adherence to SIGMA standards.
- **Responsive Design**: Built using Bootstrap, ensuring compatibility across various devices.


## Project Structure

```
├── backend/
│   ├── config.py          # Configuration file for the API key and other settings
│   ├── convert.py         # Main Flask application file that handles the conversion and validation logic
│   ├── requirements.txt   # List of dependencies required for the backend
│   ├── Procfile           # Heroku-specific file for defining the type of application
│   ├── temp_sigma_rule.yml # Temporary file used for validation
│   ├── test_rule.yml      # Sample Sigma rule for testing purposes
├── .github/
│   └── workflows/
│       └── deploy.yml     # GitHub Actions workflow for deploying the frontend
├── index.html             # Main HTML file for the frontend interface
├── script.js              # JavaScript file for handling frontend logic and API communication
├── style.css              # Custom CSS file for styling the frontend
└── README.md              # This file
```

## Installation & Setup

### Backend (Heroku)

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Splunk2Sigma/Splunk2SigmaWeb.git
    cd Splunk2SigmaWeb/backend
    ```

2. **Set up the Heroku app:**
   - Create an account on [Heroku](https://www.heroku.com/).
   - Install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli).
   - Create a new Heroku app:

     ```bash
     heroku create your-app-name
     ```

3. **Set the buildpack:**

    ```bash
    heroku buildpacks:set heroku/python
    ```

4. **Deploy to Heroku:**

    ```bash
    git push heroku main
    ```

5. **Set environment variables:**
   - Add your OpenAI API key to Heroku:

     ```bash
     heroku config:set OPENAI_API_KEY=your_openai_api_key
     ```

6. **Run the app:**

    ```bash
    heroku open
    ```

### Frontend (GitHub Pages)

1. **Fork or clone the repository:**

    ```bash
    git clone https://github.com/Splunk2Sigma/Splunk2SigmaWeb.git
    cd Splunk2SigmaWeb
    ```

2. **Modify the `script.js`:**
   - Update the `fetch` request URL to point to your Heroku backend:

     ```javascript
     const response = await fetch('https://your-heroku-app.herokuapp.com/convert', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify({ splunkInput, backend, format })
     });
     ```

3. **Push changes to GitHub:**
   - Ensure your repository is public.
   - Enable GitHub Pages in the repository settings, pointing to the main branch.

4. **Access the site:**
   - Your frontend should now be live at `https://your-github-username.github.io/Splunk2SigmaWeb`.

## Usage

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
  - Ensure the CORS settings in the Flask app (`convert.py`) allow requests from your GitHub Pages origin. You can configure it by updating the `CORS` settings to allow requests from your specific frontend URL.

- **Validation Errors:**
  - If Sigma rule validation fails, ensure that the generated rule adheres to the correct Sigma format. You might need to manually adjust the generated rule or refine the input query.

### Logs and Debugging

- **Heroku Logs:**
  - You can view the logs for your Heroku app to debug any issues:

    ```bash
    heroku logs --tail
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

You can also follow and interact with the project on GitHub: [Splunk2Sigma](https://github.com/Splunk2Sigma).

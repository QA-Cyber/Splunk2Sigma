from flask import Flask, request, jsonify
from flask_cors import CORS  # Import the CORS module
import subprocess, os
from config import OPENAI_API_KEY
from openai import OpenAI
from datetime import datetime  # Import the datetime module

app = Flask(__name__)
CORS(app)
client = OpenAI(api_key=OPENAI_API_KEY)

@app.route('/convert', methods=['POST'])
def convert_splunk_to_sigma():
    data = request.json
    splunk_input = data['splunkInput']
    backend = data.get('backend', 'splunk')
    format = data.get('format', 'default')

    if not splunk_input:
        return jsonify({"message": "Splunk input is required"}), 400

    def generate_sigma_rule(splunk_input):
        try:
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a threat detection engineer specializing in converting Splunk savedsearch.conf rules to Sigma .yml rules. "
                            "Users will provide you with a Splunk savedsearch.conf rule, and you will convert it to a Sigma .yml rule. \n\n"
                            "**Guidelines:**\n1. Ensure the conversion follows best practices for threat detection and adheres to the Sigma rule format.\n"
                            "2. Always use 'Splunk2Sigma' as the author and set the date to today's date in the format 'yyyy-mm-dd'.\n"
                            "3. Avoid providing explanations. Only the Sigma rule output should be provided.\n"
                            "4. Ensure the output is in YAML format and adheres to the Sigma standard fields (e.g., title, id, description, tags, logsource, detection, falsepositives, level).\n"
                            "5. Refer to the Sigma Rule Creation Guide for standard practices, including how to structure detection logic, use conditions, and select appropriate metadata fields."
                        )
                    },
                    {
                        "role": "user",
                        "content": splunk_input
                    }
                ],
                temperature=0.2,
                max_tokens=2500
            )

            sigma_rule = response.choices[0].message.content.strip()
            sigma_rule = sigma_rule.replace('```yaml', '').replace('```', '').strip()

            current_date = datetime.now().strftime('%Y-%m-%d')
            sigma_rule = sigma_rule.replace("yyyy-mm-dd", current_date)

            if sigma_rule.startswith("```yaml"):
                sigma_rule = sigma_rule[6:].strip()
            if sigma_rule.endswith("```"):
                sigma_rule = sigma_rule[:-3].strip()

            return sigma_rule

        except Exception as e:
            return str(e)

    def validate_sigma_rule(sigma_rule: str) -> str:
        try:
            with open('temp_sigma_rule.yml', 'w') as file:
                file.write(sigma_rule)

            process = subprocess.Popen(['sigma', 'check', 'temp_sigma_rule.yml'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                return stderr.decode('utf-8') if stderr else stdout.decode('utf-8')
            return ""

        except Exception as e:
            return str(e)

    sigma_rule = generate_sigma_rule(splunk_input)
    validation_result = validate_sigma_rule(sigma_rule)

    if validation_result:
        # Retry mechanism if validation fails
        retry_message = (
            "The Sigma rule generated failed validation with the following error:\n"
            f"{validation_result}\n\n"
            "Please correct the rule and try again."
        )
        # Send back to OpenAI to correct
        retry_input = f"{sigma_rule}\n\n{retry_message}"
        sigma_rule = generate_sigma_rule(retry_input)

        # Validate again after correction
        validation_result = validate_sigma_rule(sigma_rule)

        if validation_result:
            return jsonify({
                "sigmaRule": sigma_rule,
                "cliCommand": "",
                "status": "Fail",
                "validationErrors": validation_result
            }), 400
        else:
            return jsonify({
                "sigmaRule": sigma_rule,
                "cliCommand": f"sigma check '{sigma_rule}'",
                "status": "Pass"
            })

    return jsonify({
        "sigmaRule": sigma_rule,
        "cliCommand": f"sigma check '{sigma_rule}'",
        "status": "Pass"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

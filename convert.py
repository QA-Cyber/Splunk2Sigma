from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess, os
from config import OPENAI_API_KEY
from openai import OpenAI
from datetime import datetime
from yaml import safe_load, YAMLError
import re
import uuid
import logging

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
CORS(app)
client = OpenAI(api_key=OPENAI_API_KEY)

def auto_correct_indentation(sigma_rule: str) -> str:
    lines = sigma_rule.split('\n')
    corrected_lines = []
    indentation_level = 0

    for line in lines:
        stripped_line = line.lstrip()
        if stripped_line and not stripped_line.startswith('#'):
            # Determine the level of indentation (number of leading spaces)
            if stripped_line.endswith(':') and not stripped_line.startswith('-'):
                # Increase indentation for next level
                corrected_lines.append('  ' * indentation_level + stripped_line)
                indentation_level += 1
            elif stripped_line.startswith('- '):
                corrected_lines.append('  ' * indentation_level + stripped_line)
            elif stripped_line.startswith('logsource:'):
                indentation_level = 1  # Ensure proper indentation for logsource section
                corrected_lines.append('  ' * indentation_level + stripped_line)
            else:
                corrected_lines.append('  ' * indentation_level + stripped_line)
                if indentation_level > 0:
                    indentation_level -= 1
        else:
            corrected_lines.append(line)

    return "\n".join(corrected_lines)


def pre_validate_yaml(sigma_rule: str) -> str:
    """
    Perform pre-validation on the Sigma rule YAML to identify and fix common issues.
    """
    try:
        # Attempt to parse the YAML to identify any errors
        safe_load(sigma_rule)
        
        # Initialize common issues list
        issues = []
        
        # Check for common issues in Sigma rules
        lines = sigma_rule.split('\n')
        
        # Issue: Ensure no line ends with a colon (incomplete mapping)
        for i, line in enumerate(lines):
            if line.strip().endswith(':'):
                issues.append(f"YAML formatting error on line {i+1}: '{line.strip()}' appears to be an incomplete key.")

            # Check for improperly indented fields (indentation should be a multiple of 2 spaces)
            if len(line) - len(line.lstrip()) % 2 != 0:
                issues.append(f"YAML indentation error on line {i+1}: '{line.strip()}' should be indented with spaces.")

            # Check for missing or incorrect logsource fields
            if "logsource" in line and not any(field in line for field in ["product", "service", "category"]):
                issues.append(f"YAML logsource error on line {i+1}: 'logsource' field should include at least one of 'product', 'service', or 'category'.")

            # Ensure detection condition is included
            if "detection:" in line and "condition:" not in sigma_rule:
                issues.append("YAML error: 'condition' field is missing in the detection section.")

            # Ensure no duplicate keys in the same level of the YAML hierarchy
            if ":" in line and sigma_rule.count(line.strip()) > 1:
                issues.append(f"YAML duplicate key error: The key '{line.strip().split(':')[0]}' appears more than once.")

            # Ensure that UUIDs are valid
            if "id:" in line:
                try:
                    uuid.UUID(line.split("id:")[1].strip())
                except ValueError:
                    issues.append(f"YAML UUID error on line {i+1}: '{line.strip()}' is not a valid UUID.")

            # Ensure that the status field is valid
            if "status:" in line:
                if line.split("status:")[1].strip() not in ["stable", "test", "experimental", "deprecated", "unsupported"]:
                    issues.append(f"YAML status error on line {i+1}: '{line.strip()}' is not a valid status.")

            # Ensure there are no escaped wildcards or control characters in string values
            if re.search(r'[\\*\\?]', line):
                issues.append(f"YAML error on line {i+1}: Found an escaped wildcard in '{line.strip()}'. Ensure the escape is intentional.")
            if re.search(r'[\x00-\x1f]', line):
                issues.append(f"YAML error on line {i+1}: Found a control character in '{line.strip()}'. Check for missing slashes.")

            # Ensure 'all of them' is not used; suggest 'all of selection*' instead
            if "all of them" in line:
                issues.append(f"YAML error on line {i+1}: The phrase 'all of them' is discouraged. Use 'all of selection*' instead.")

            # Check for common logsource to generic logsource mappings issues
            if "logsource:" in line:
                if "sysmon" in sigma_rule and "EventID" in sigma_rule:
                    issues.append(f"YAML logsource error: Consider using a generic log source instead of specific event identifiers for Sysmon.")

        return "\n".join(issues) if issues else ""  # Return issues if any

    except YAMLError as e:
        # Handle specific common errors here
        error_message = str(e)

        # Example of common issue handling:
        if "mapping values are not allowed here" in error_message:
            return "YAML parsing error: Incorrect key-value mapping or unexpected character."

        # General error return
        return f"YAML parsing error: {error_message}"

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
        logging.error(f"Failed to generate Sigma rule: {str(e)}")
        return str(e)

def validate_sigma_rule(sigma_rule: str) -> str:
    try:
        with open('temp_sigma_rule.yml', 'w') as file:
            file.write(sigma_rule)

        process = subprocess.Popen(['sigma', 'check', 'temp_sigma_rule.yml'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.warning(f"Validation failed with error: {stderr.decode('utf-8')}")
            return stderr.decode('utf-8') if stderr else stdout.decode('utf-8')
        return ""

    except Exception as e:
        logging.error(f"Validation process encountered an error: {str(e)}")
        return str(e)

@app.route('/convert', methods=['POST'])
def convert_splunk_to_sigma():
    data = request.json
    splunk_input = data['splunkInput']
    backend = data.get('backend', 'splunk')
    format = data.get('format', 'default')

    if not splunk_input:
        return jsonify({"message": "Splunk input is required"}), 400

    # Generate the Sigma rule
    sigma_rule = generate_sigma_rule(splunk_input)
    # Auto-correct indentation
    sigma_rule = auto_correct_indentation(sigma_rule)
    # Perform pre-validation on the generated Sigma rule
    pre_validation_result = pre_validate_yaml(sigma_rule)
    if pre_validation_result:
        # If pre-validation fails, return the error
        return jsonify({
            "sigmaRule": sigma_rule,
            "status": "Fail",
            "validationErrors": pre_validation_result
        }), 400
    # Proceed with sigma-cli validation
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
                "status": "Passed with Minor Enhancements",
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
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

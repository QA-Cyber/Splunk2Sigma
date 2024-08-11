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
    expected_indentation = 0
    previous_indentation = None

    for line in lines:
        stripped_line = line.lstrip()

        # Determine the actual indentation level of the current line
        actual_indentation = (len(line) - len(stripped_line)) // 2

        # Check if line is a list item
        if stripped_line.startswith('- '):
            # Indent list items based on the expected indentation level
            corrected_lines.append('  ' * expected_indentation + stripped_line)
        elif stripped_line.endswith(':') and not stripped_line.startswith('-'):
            # Increase expected indentation level for new blocks
            corrected_lines.append('  ' * expected_indentation + stripped_line)
            expected_indentation += 1
        else:
            # Align fields that belong to the current block
            corrected_lines.append('  ' * expected_indentation + stripped_line)

        # Adjust expected indentation for the next line
        if actual_indentation > expected_indentation:
            expected_indentation = actual_indentation

        # Decrease indentation if a block ends and expected indentation needs to be adjusted
        if previous_indentation is not None and actual_indentation < previous_indentation:
            expected_indentation = actual_indentation

        previous_indentation = actual_indentation

    return "\n".join(corrected_lines)



def pre_validate_yaml(sigma_rule: str) -> str:
    try:
        safe_load(sigma_rule)
        issues = []
        lines = sigma_rule.split('\n')
        
        for i, line in enumerate(lines):
            if line.strip().endswith(':') and i + 1 < len(lines) and not lines[i + 1].strip().startswith('-'):
                issues.append(f"YAML formatting error on line {i+1}: '{line.strip()}' appears to be an incomplete key.")

            if (len(line) - len(line.lstrip())) % 2 != 0:
                issues.append(f"YAML indentation error on line {i+1}: '{line.strip()}' should be indented with spaces.")

            if "logsource" in line and not any(field in line for field in ["product", "service", "category"]):
                issues.append(f"YAML logsource error on line {i+1}: 'logsource' field should include at least one of 'product', 'service', or 'category'.")

            if line.strip() == 'logsource:':
                if i + 1 < len(lines) and not lines[i + 1].startswith('  '):
                    issues.append(f"YAML indentation error: Fields under 'logsource' should be indented.")
            if line.strip() == 'tags:':
                if i + 1 < len(lines) and not lines[i + 1].startswith('  - '):
                    issues.append(f"YAML indentation error: Tags under 'tags' should be indented and listed.")

            if "detection:" in line and "condition:" not in sigma_rule:
                issues.append("YAML error: 'condition' field is missing in the detection section.")

            if ":" in line and sigma_rule.count(line.strip()) > 1:
                issues.append(f"YAML duplicate key error: The key '{line.strip().split(':')[0]}' appears more than once.")

            if "id:" in line:
                try:
                    uuid.UUID(line.split("id:")[1].strip())
                except ValueError:
                    issues.append(f"YAML UUID error on line {i+1}: '{line.strip()}' is not a valid UUID.")

            if "status:" in line:
                if line.split("status:")[1].strip() not in ["stable", "test", "experimental", "deprecated", "unsupported"]:
                    issues.append(f"YAML status error on line {i+1}: '{line.strip()}' is not a valid status.")

            if re.search(r'[\\*\\?]', line):
                issues.append(f"YAML error on line {i+1}: Found an escaped wildcard in '{line.strip()}'. Ensure the escape is intentional.")
            if re.search(r'[\x00-\x1f]', line):
                issues.append(f"YAML error on line {i+1}: Found a control character in '{line.strip()}'. Check for missing slashes.")

            if "all of them" in line:
                issues.append(f"YAML error on line {i+1}: The phrase 'all of them' is discouraged. Use 'all of selection*' instead.")

            if "logsource:" in line:
                if "sysmon" in sigma_rule and "EventID" in sigma_rule:
                    issues.append(f"YAML logsource error: Consider using a generic log source instead of specific event identifiers for Sysmon.")

        return "\n".join(issues) if issues else ""

    except YAMLError as e:
        error_message = str(e)
        if "mapping values are not allowed here" in error_message:
            return "YAML parsing error: Incorrect key-value mapping or unexpected character."
        return f"YAML parsing error: {error_message}"

def generate_sigma_rule(splunk_input):
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a threat detection engineer specializing in converting Splunk savedsearch.conf rules to Sigma .yml rules. "
                        "Convert the provided Splunk savedsearch.conf rule into a Sigma .yml rule following these guidelines:\n\n"
                        "1. Use 'Splunk2Sigma' as the author and today's date in 'yyyy-mm-dd' format.\n"
                        "2. Output only the Sigma rule in YAML format without additional explanations.\n"
                        "3. Ensure proper indentation with 2 spaces per level and no line ending with a colon without a value.\n"
                        "4. Validate that UUIDs in the 'id' field are correct.\n"
                        "5. Include at least one of 'product', 'service', or 'category' in the 'logsource' section.\n"
                        "6. The 'detection' section must include a 'condition' field.\n"
                        "7. Correct common issues like improper indentation, invalid UUIDs, or missing fields before finalizing."
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
        return jsonify({
            "sigmaRule": sigma_rule,
            "status": "Fail",
            "validationErrors": pre_validation_result
        }), 400

    # Optionally, perform full validation here using sigma-cli if desired
    validation_result = validate_sigma_rule(sigma_rule)
    if validation_result:
        return jsonify({
            "sigmaRule": sigma_rule,
            "status": "Fail",
            "validationErrors": validation_result
        }), 400

    return jsonify({
        "sigmaRule": sigma_rule,
        "status": "Pass"
    })

@app.route('/validate', methods=['POST', 'OPTIONS'])
def validate_sigma():
    if request.method == 'OPTIONS':
        return '', 204  # Return no content for preflight requests
    
    data = request.json
    sigma_rule = data.get('sigmaRule')

    if not sigma_rule:
        return jsonify({"message": "Sigma rule is required"}), 400

    validation_result = validate_sigma_rule(sigma_rule)

    if validation_result:
        return jsonify({
            "status": "Fail",
            "validationErrors": validation_result
        }), 400
    else:
        return jsonify({
            "status": "Pass"
        })
    

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

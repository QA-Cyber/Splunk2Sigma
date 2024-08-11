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
    logsource_detected = False
    tags_detected = False

    for line in lines:
        stripped_line = line.lstrip()
        
        if stripped_line:
            if stripped_line.startswith('- '):
                # Keep the current indentation for list items
                corrected_lines.append('  ' * indentation_level + stripped_line)
            elif stripped_line.endswith(':') and not stripped_line.startswith('-'):
                # This is a new block, increase the indentation
                corrected_lines.append('  ' * indentation_level + stripped_line)
                indentation_level += 1
                if stripped_line == 'logsource:':
                    logsource_detected = True
                if stripped_line == 'tags:':
                    tags_detected = True
            elif stripped_line.startswith('logsource:'):
                # Ensure proper indentation for the logsource section
                indentation_level = 1
                corrected_lines.append('  ' * indentation_level + stripped_line)
                logsource_detected = True
            elif stripped_line.startswith('tags:'):
                # Ensure proper indentation for the tags section
                indentation_level = 1
                corrected_lines.append('  ' * indentation_level + stripped_line)
                tags_detected = True
            elif logsource_detected and (stripped_line.startswith('product:') or stripped_line.startswith('service:')):
                # Correct indentation for product and service under logsource
                corrected_lines.append('  ' * (indentation_level) + stripped_line)
            elif tags_detected and stripped_line.startswith('- '):
                # Correct indentation for tags list
                corrected_lines.append('  ' * (indentation_level) + stripped_line)
            else:
                # Normal line or decrease indentation if we reach a new block
                if indentation_level > 0 and (':' in stripped_line or not stripped_line.startswith('- ')):
                    indentation_level -= 1
                corrected_lines.append('  ' * indentation_level + stripped_line)
        else:
            corrected_lines.append(line)

    return "\n".join(corrected_lines)



def pre_validate_yaml(sigma_rule: str) -> str:
    try:
        # Attempt to parse the YAML to identify any errors
        safe_load(sigma_rule)
        
        # Initialize common issues list
        issues = []
        
        # Check for common issues in Sigma rules
        lines = sigma_rule.split('\n')
        
        for i, line in enumerate(lines):
            if line.strip().endswith(':') and i + 1 < len(lines) and not lines[i + 1].strip().startswith('-'):
                issues.append(f"YAML formatting error on line {i+1}: '{line.strip()}' appears to be an incomplete key.")

            # Check for improperly indented fields (indentation should be a multiple of 2 spaces)
            if (len(line) - len(line.lstrip())) % 2 != 0:
                issues.append(f"YAML indentation error on line {i+1}: '{line.strip()}' should be indented with spaces.")

            # Check for missing or incorrect logsource fields
            if "logsource" in line and not any(field in line for field in ["product", "service", "category"]):
                issues.append(f"YAML logsource error on line {i+1}: 'logsource' field should include at least one of 'product', 'service', or 'category'.")

            # Check for correct indentation under logsource and tags
            if line.strip() == 'logsource:':
                if i + 1 < len(lines) and not lines[i + 1].startswith('  '):
                    issues.append(f"YAML indentation error: Fields under 'logsource' should be indented.")
            if line.strip() == 'tags:':
                if i + 1 < len(lines) and not lines[i + 1].startswith('  - '):
                    issues.append(f"YAML indentation error: Tags under 'tags' should be indented and listed.")

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

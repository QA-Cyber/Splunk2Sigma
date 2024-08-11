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

def validate_original_yaml(sigma_rule: str) -> str:
    try:
        # Attempt to parse the original YAML
        safe_load(sigma_rule)
        return ""
    except YAMLError as e:
        return f"YAML parsing error: {str(e)}"

def auto_correct_indentation(sigma_rule: str) -> str:
    lines = sigma_rule.split('\n')
    corrected_lines = []
    indentation_stack = [0]
    expected_indentation = 0

    for line in lines:
        stripped_line = line.lstrip()
        actual_indentation = (len(line) - len(stripped_line)) // 2

        if stripped_line.startswith('- '):
            corrected_lines.append('  ' * expected_indentation + stripped_line)
        elif stripped_line.endswith(':') and not stripped_line.startswith('-'):
            corrected_lines.append('  ' * expected_indentation + stripped_line)
            indentation_stack.append(expected_indentation + 1)
        else:
            if actual_indentation < expected_indentation:
                while indentation_stack and actual_indentation < expected_indentation:
                    indentation_stack.pop()
                    expected_indentation = indentation_stack[-1]
            corrected_lines.append('  ' * expected_indentation + stripped_line)

    return "\n".join(corrected_lines)


def pre_validate_yaml(sigma_rule: str) -> str:
    try:
        # Attempt to parse the original YAML to catch any unhandled errors
        safe_load(sigma_rule)
        issues = []
        corrected_lines = []
        lines = sigma_rule.split('\n')
        
        for i, line in enumerate(lines):
            line_content = line.strip()
            next_line = lines[i + 1].strip() if i + 1 < len(lines) else ""

            # Handle incomplete keys (Keys ending with ':')
            if line_content.endswith(':') and (not next_line or next_line.startswith('-')):
                issues.append(f"YAML formatting error on line {i+1}: '{line_content}' appears to be an incomplete key.")
                # Auto-fix: Add a placeholder value to complete the key
                corrected_lines.append(line + " <value>")
                continue

            # Handle escaped wildcards or control characters in string values
            if re.search(r'[\\*\\?]', line_content):
                issues.append(f"YAML error on line {i+1}: Found an escaped wildcard in '{line_content}'. Ensure the escape is intentional.")
                # Auto-fix: Remove unnecessary escape characters
                line_content = re.sub(r'\\([*?])', r'\1', line_content)

            # Handle improper indentation (Ensure proper 2-space indentation)
            actual_indentation = len(line) - len(line.lstrip())
            if actual_indentation % 2 != 0:
                issues.append(f"YAML indentation error on line {i+1}: '{line_content}' should be indented with spaces.")
                # Auto-fix: Correct the indentation
                corrected_lines.append('  ' * (actual_indentation // 2) + line_content)
                continue

            # Handle duplicate keys within the same level
            if ":" in line_content and sigma_rule.count(line_content) > 1:
                issues.append(f"YAML duplicate key error: The key '{line_content.split(':')[0]}' appears more than once.")
                # Auto-fix: Append a unique suffix to the duplicate key
                unique_key = line_content.split(':')[0] + f"_duplicate_{i+1}"
                corrected_lines.append(unique_key + ": " + line_content.split(':', 1)[1].strip())
                continue

            # Validate 'logsource' block (Ensure 'logsource' includes 'product', 'service', or 'category')
            if line_content == 'logsource:' and not any(field in next_line for field in ["product", "service", "category"]):
                issues.append(f"YAML logsource error on line {i+1}: 'logsource' field should include at least one of 'product', 'service', or 'category'.")
                # Auto-fix: Add a default 'product' value if missing
                corrected_lines.append(line)
                corrected_lines.append('  product: windows')
                continue

            # Validate 'detection' block (Ensure 'condition' is present)
            if line_content == 'detection:' and 'condition:' not in sigma_rule:
                issues.append("YAML error: 'condition' field is missing in the detection section.")
                # Auto-fix: Add a placeholder 'condition' field
                corrected_lines.append(line)
                corrected_lines.append('  condition: selection')
                continue

            corrected_lines.append(line)

        # Return the auto-corrected Sigma rule if any issues were fixed
        if issues:
            corrected_sigma_rule = "\n".join(corrected_lines)
            return f"Issues found:\n{'\n'.join(issues)}\n\nAuto-corrected Sigma Rule:\n{corrected_sigma_rule}"

        return ""

    except YAMLError as e:
        return f"YAML parsing error: {str(e)}"

def send_back_to_ai_for_correction(sigma_rule: str, errors: str) -> str:
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a threat detection engineer. A Sigma rule was generated but it has validation errors. "
                        "Correct the following Sigma rule, making sure to fix the errors described:\n\n"
                        f"Errors:\n{errors}\n\nSigma Rule:\n{sigma_rule}\n\n"
                        "Return only the corrected Sigma rule in YAML format."
                    )
                }
            ],
            temperature=0.2,
            max_tokens=2500
        )

        corrected_sigma_rule = response.choices[0].message.content.strip()
        corrected_sigma_rule = corrected_sigma_rule.replace('```yaml', '').replace('```', '').strip()

        current_date = datetime.now().strftime('%Y-%m-%d')
        corrected_sigma_rule = corrected_sigma_rule.replace("yyyy-mm-dd", current_date)

        if corrected_sigma_rule.startswith("```yaml"):
            corrected_sigma_rule = corrected_sigma_rule[6:].strip()
        if corrected_sigma_rule.endswith("```"):
            corrected_sigma_rule = corrected_sigma_rule[:-3].strip()
        print("Corrected Sigma Rule: ", corrected_sigma_rule)
        return corrected_sigma_rule

    except Exception as e:
        logging.error(f"Failed to correct Sigma rule via AI: {str(e)}")
        return sigma_rule
    
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
            return stderr.decode('utf-8') if stderr else stdout.decode('utf-8')
        return ""

    except Exception as e:
        return str(e)

@app.route('/convert', methods=['POST'])
def convert_splunk_to_sigma():
    data = request.json
    splunk_input = data['splunkInput']

    if not splunk_input:
        return jsonify({"message": "Splunk input is required"}), 400

    sigma_rule = generate_sigma_rule(splunk_input)
    sigma_rule = auto_correct_indentation(sigma_rule)
    pre_validation_result = pre_validate_yaml(sigma_rule)

    if pre_validation_result:
        sigma_rule = send_back_to_ai_for_correction(sigma_rule, pre_validation_result)
        pre_validation_result = pre_validate_yaml(sigma_rule)
        if pre_validation_result:
            return jsonify({
                "sigmaRule": sigma_rule,
                "status": "NA:",
                "validationErrors": pre_validation_result
            }), 200

    return jsonify({
        "sigmaRule": sigma_rule,
        "status": "Pass"
    })

@app.route('/validate', methods=['POST', 'OPTIONS'])
def validate_sigma():
    if request.method == 'OPTIONS':
        return '', 204
    
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

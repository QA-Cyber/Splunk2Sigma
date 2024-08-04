from flask import Flask, request, jsonify
import openai
import subprocess

app = Flask(__name__)

openai.api_key = 'YOUR_OPENAI_API_KEY'


@app.route('/convert', methods=['POST'])
def convert_splunk_to_sigma():
    data = request.json
    splunk_input = data['splunkInput']
    backend = data.get('backend', 'splunk')
    format = data.get('format', 'default')

    # Call OpenAI API
    response = openai.Completion.create(
        engine="gpt-4o",
        prompt=f"Convert the following Splunk savedsearch.conf rule to a Sigma .yml rule:\n{splunk_input}\n\n{backend}, {format}",
        max_tokens=2500,
        temperature=0.2,
        stop=None
    )

    sigma_rule = response.choices[0].text.strip()

    # Validate Sigma Rule with sigmac
    validation_result = validate_sigma_rule(sigma_rule)

    if validation_result:
        return jsonify({"message": "Invalid Sigma rule", "errors": validation_result}), 400

    cli_command = f"sigmac --validate '{sigma_rule}'"

    return jsonify({"sigmaRule": sigma_rule, "cliCommand": cli_command})


def validate_sigma_rule(sigma_rule: str) -> str:
    try:
        process = subprocess.Popen(['sigmac', '--validate', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=sigma_rule.encode('utf-8'))
        return stderr.decode('utf-8') if stderr else ""
    except Exception as e:
        return str(e)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

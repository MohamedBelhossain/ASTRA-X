import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

session = requests.Session()


def get_forms(url):

    forms = []

    try:

        response = session.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):

            form_details = {}

            action = form.get("action")
            action = urljoin(url, action) if action else url

            method = form.get("method", "get").lower()

            inputs = []

            for input_tag in form.find_all("input"):

                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                input_value = input_tag.get("value", "")

                inputs.append({
                    "name": input_name,
                    "type": input_type,
                    "value": input_value
                })

            for textarea in form.find_all("textarea"):

                inputs.append({
                    "name": textarea.get("name"),
                    "type": "textarea",
                    "value": ""
                })

            for select in form.find_all("select"):

                inputs.append({
                    "name": select.get("name"),
                    "type": "select",
                    "value": ""
                })

            form_details["action"] = action
            form_details["method"] = method
            form_details["inputs"] = inputs

            forms.append(form_details)

    except Exception as e:
        print("Form parsing error:", e)

    return forms
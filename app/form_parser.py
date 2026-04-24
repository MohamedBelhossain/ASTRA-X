import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from app.scanner.common import session_headers

session = requests.Session()
session.headers.update(session_headers())


def _select_value(select_tag):
    selected = select_tag.find("option", selected=True)
    if selected and selected.get("value") is not None:
        return selected.get("value")
    first = select_tag.find("option")
    if first and first.get("value") is not None:
        return first.get("value")
    return ""


def get_forms(url):
    forms = []

    try:
        response = session.get(url, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action")
            action = urljoin(response.url, action) if action else response.url
            method = form.get("method", "get").lower().strip()

            inputs = []

            for input_tag in form.find_all("input"):
                inputs.append(
                    {
                        "name": input_tag.get("name"),
                        "type": input_tag.get("type", "text").lower(),
                        "value": input_tag.get("value", ""),
                    }
                )

            for textarea in form.find_all("textarea"):
                inputs.append(
                    {
                        "name": textarea.get("name"),
                        "type": "textarea",
                        "value": textarea.text or "",
                    }
                )

            for select in form.find_all("select"):
                inputs.append(
                    {
                        "name": select.get("name"),
                        "type": "select",
                        "value": _select_value(select),
                    }
                )

            forms.append(
                {
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                    "id": form.get("id"),
                    "classes": form.get("class", []),
                }
            )

    except Exception as exc:
        print("Form parsing error:", exc)

    return forms

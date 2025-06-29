from flask import Flask, request, jsonify
import joblib
import pandas as pd
import re
from bs4 import BeautifulSoup
import requests

app = Flask(__name__)
model = joblib.load("xss_model.pkl")
feature_names = pd.read_csv("Data_66_featurs.csv").drop(columns=["Label"]).columns.tolist()

def extract_features_from_html(html, url):
    soup = BeautifulSoup(html, "html.parser")
    features = []
    features.append(len(url))
    features.append(len(re.findall(r"[^\w\s]", url)))
    features.append(html.count("<script"))
    features.append(html.count("<iframe"))
    features.append(html.count("src="))
    features.append(html.count("onload"))
    features.append(html.count("onmouseover"))
    features.append("cookie" in html.lower())
    features.append(len(re.findall(r"[?&](\w+)=([^&]+)", url)))
    features.append(len(url.split("/")[2].split(".")))
    features += [
        html.count("<a"), html.count("form"), html.count("input"), html.count("button"),
        html.count("div"), html.count("span"), html.count("img"), html.count("style"),
        html.count("link"), html.count("meta"), html.count("onclick"), html.count("onerror"),
        html.count("onfocus"), html.count("onblur"), html.count("onchange"), html.count("onsubmit"),
        html.count("alert("), html.count("eval("), html.count("fromCharCode"), html.count("confirm(")
    ]
    js_matches = re.findall(r"<script.*?>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
    js_code = "\n".join(js_matches)
    features += [
        len(js_code),
        len(re.findall(r"function\s+\w+", js_code)),
        len(re.findall(r"\w+\s*\(", js_code)),
        max([len(s) for s in re.findall(r"'[^']*'|\"[^\"]*\"", js_code)] + [0]),
        len(html)
    ]
    while len(features) < 67:
        features.append(0)
    return pd.DataFrame([features], columns=feature_names)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url")

    try:
        html = requests.get(url, timeout=5).text
        features_df = extract_features_from_html(html, url)
        prediction = model.predict(features_df)[0]

        result = {
            "url": url,
            "risk_level": "High" if prediction == 1 else "Low",
            "suggested_fix": "Escape <, >, &; use DOMPurify or server-side sanitization with CSP headers"
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)

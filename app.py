from flask import Flask, render_template, request, jsonify
from phishing_detector import detect_phishing_advanced
from google import genai  # AI Studio SDK
import os

app = Flask(__name__)

# -------------------------------
# Gemini API configuration via SDK
# -------------------------------
GENAI_API_KEY = "AIzaSyAKv0_wRAEXJCBgsYJwRo83ta3B5vKl090"  # <-- Directly put your API key here

client = genai.Client(api_key=GENAI_API_KEY)  # AI Studio mode

# -------------------------------
# Routes
# -------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    data = request.json
    email_text = data.get('email', '').strip()
    if not email_text:
        return jsonify({"error": "Email text is empty"}), 400
    try:
        analysis = detect_phishing_advanced(email_text)
        return jsonify(analysis)
    except Exception as e:
        print("Email analysis error:", e)
        return jsonify({"error": "Failed to analyze email."}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    user_message = data.get('message', '').strip()
    if not user_message:
        return jsonify({"error": "Message is empty"}), 400
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=user_message
        )
        return jsonify({"reply": response.text})
    except Exception as e:
        print("Gemini API error:", e)
        return jsonify({"error": "Failed to get response from chatbot."}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)

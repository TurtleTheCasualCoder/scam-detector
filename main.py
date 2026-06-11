from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from google import genai
import easyocr
import requests
import re
import os
import tempfile
import json
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

reader = easyocr.Reader(['en', 'hi'])

def extract_urls(text):
    return re.findall(r'https?://\S+|bit\.ly/\S+|tinyurl\S+', text)

def check_url_virustotal(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    headers = {"x-apikey": api_key}
    resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    if resp.status_code == 200:
        analysis_id = resp.json()["data"]["id"]
        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        stats = result.json()["data"]["attributes"]["stats"]
        return stats.get("malicious", 0) > 0
    return None

def heuristic_check(text):
    red_flags = [
        r'\botp\b', r'\bpin\b', r'\burgent\b', r'\bimmediately\b',
        r'account.{0,10}block', r'kyc.{0,10}expir', r'click.{0,20}link',
        r'win(ner|ning)', r'lottery', r'reward', r'verify.{0,10}now'
    ]
    found = []
    for pattern in red_flags:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(pattern.replace(r'\b','').replace('.{0,10}','...'))
    return found

def analyze_with_gemini(text):
    prompt = f"""
You are a scam detection expert for Indian users. Analyze this message for scam indicators.

Message: "{text}"

Look for:
1. Urgency / Fear / Greed psychological triggers
2. Requests for OTP, PIN, password, or bank details
3. Suspicious links or spoofed sender identity
4. KYC scams, job offer scams, UPI scams, electricity/gas bill scams

Return ONLY valid JSON (no markdown, no extra text):
{{
  "score": <0-100 integer>,
  "type": "<UPI/KYC/Job/Phishing/Safe/Other>",
  "reasoning": "<2-3 sentence explanation>",
  "red_flags": ["<flag1>", "<flag2>"],
  "safe_indicators": ["<indicator1>"]
}}
"""
    try:
        response = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
        clean = response.text.strip().replace("```json","").replace("```","")
        return json.loads(clean)
    except Exception as e:
        err = str(e)
        if "429" in err or "RESOURCE_EXHAUSTED" in err:
            msg = "Gemini API quota exceeded. Heuristic analysis only — red flags and URL scan still active."
        elif "404" in err:
            msg = "AI model unavailable. Heuristic analysis only."
        else:
            msg = "AI analysis temporarily unavailable. Heuristic analysis only."
        return {
            "score": 50,
            "type": "Other",
            "reasoning": msg,
            "red_flags": [],
            "safe_indicators": []
        }

@app.post("/analyze")
async def analyze(
    text: str = Form(None),
    file: UploadFile = File(None)
):
    extracted_text = text or ""

    if file:
        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name
        results = reader.readtext(tmp_path, detail=0)
        extracted_text = " ".join(results)
        os.unlink(tmp_path)

    if not extracted_text.strip():
        return {"error": "No text provided or could not extract text from image."}

    heuristics = heuristic_check(extracted_text)
    gemini_result = analyze_with_gemini(extracted_text)

    urls = extract_urls(extracted_text)
    url_malicious = False
    for url in urls:
        result = check_url_virustotal(url)
        if result:
            url_malicious = True
            break

    final_score = 100 if url_malicious else gemini_result["score"]

    return {
        "score": final_score,
        "type": gemini_result["type"],
        "reasoning": gemini_result["reasoning"],
        "red_flags": gemini_result["red_flags"] + heuristics,
        "safe_indicators": gemini_result.get("safe_indicators", []),
        "urls_found": urls,
        "url_malicious": url_malicious,
        "extracted_text": extracted_text
    } 



#cd C:\Users\HP\scam-detector-ui
#npm start

#cd C:\Users\HP\scam-detector
#uvicorn main:app --reload
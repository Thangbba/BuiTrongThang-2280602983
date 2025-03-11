import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'Cipher'))

from cipher.caesar import CaesarCipher
from flask import Flask, render_template, request, json

app = Flask(__name__)

@app.route("/")
def home():
    return render_template('index.html')

@app.route("/caesar")
def caesar():
    return render_template('caesar.html')
@app.route("/encrypt", methods=['POST'])
def caesar_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    caesar_cipher = CaesarCipher()
    encrypt_text = caesar_cipher.encrypt_text(text, key)
    return f"text: {text}<br/>key: {key}<br/>encrypted text: {encrypt_text}"


@app.route("/decrypt", methods=['POST'])
def caesar_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    caesar_cipher = CaesarCipher()
    decrypted_text = caesar_cipher.decrypy_text(text, key)
    return f"cipher text: {text}<br/>key: {key}<br/>decrypted text: {decrypted_text}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
from flask import Flask, request, render_template, jsonify, redirect, url_for, flash, session, get_flashed_messages
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64
import secrets
import string
import requests
import logging
import xmltodict

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session management

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Generate a random alphanumeric key of length 24 (DES3 key should be 16 or 24 bytes long)
def generate_key(length=24):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for i in range(length))

# Encrypt data using DES3
def encrypt(data, key):
    cipher = DES3.new(key.encode('utf-8'), DES3.MODE_ECB)
    padded_data = pad(data.encode('utf-8'), DES3.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode('utf-8')

# Decrypt data using DES3
def decrypt(data, key):
    data = base64.b64decode(data)
    cipher = DES3.new(key.encode('utf-8'), DES3.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(data), DES3.block_size)
    return decrypted_data.decode('utf-8')

import logging 
# Send SMS using Africa's Talking API
def send_sms(phone_number, message):
    url = "https://api.sandbox.africastalking.com/version1/messaging"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "apiKey": "atsk_4d7836c7a1db68b8137f25b21dddc253e4a57501be5560a5774918ec8a42fc2e26e5b183"  # Replace with your actual sandbox API key
    }
    payload = {
        "username": "sandbox",  # Username for sandbox environment
        "to": phone_number,
        "message": message
     }
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()  # Check for HTTP errors
        
        # Parse XML response
        response_data = xmltodict.parse(response.content)
        sms_data = response_data.get('AfricasTalkingResponse', {}).get('SMSMessageData', {})
        status_message = sms_data.get('Message', '')

        # Log response details
        logging.info(f"API Response Content: {response.content}")
        logging.info(f"SMS Status: {status_message}")

        return sms_data  # Return parsed data as needed

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        return {"error": f"HTTP error occurred: {http_err}"}
    except requests.exceptions.RequestException as req_err:
        logging.error(f"Request error occurred: {req_err}")
        return {"error": f"Request error occurred: {req_err}"}
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        return {"error": f"Error occurred: {e}"}

    
    
@app.route('/')
def index():
    return render_template('index.html')

# Route to collect parcel data
@app.route('/collect', methods=['POST'])
def collect_parcel():
   if request.method == "POST":
    parcel_id = request.form["parcel_id"]  # Access by name
    phone_number = request.form["phone_number"]

    key = generate_key()
    encrypted_data = encrypt(parcel_id, key)

    # Log the encrypted message for debugging (optional)
    # logging.debug(f"Encrypted data: {encrypted_data}")

    # Send SMS to the user
    message = f"Your parcel collection data has been secured. Use this key to decrypt: {key}"
    sms_response = send_sms(phone_number, message)

    # Log the SMS response for debugging (optional)
    # logging.debug(f"SMS response: {sms_response}")

    # Store the key and encrypted data for verification (consider using a database for persistence)
    session['des3_key'] = key
    session['encrypted_data'] = encrypted_data

    flash('Parcel details successfully sent. Please check your SMS!', 'success')
    return redirect(url_for('decrypt_form'))

@app.route('/decrypt')
def decrypt_form():
    return render_template('decrypt.html', get_flashed_messages=get_flashed_messages)

# Route to handle decryption request
@app.route('/decrypt', methods=['POST'])
def decrypt_parcel():
    encrypted_data = session.get('encrypted_data')
    des3_key = session.get('des3_key')
    user_key = request.form['key']

    if not encrypted_data or not des3_key:
        flash('No encrypted data found!', 'danger')
        return redirect(url_for('decrypt_form'))

    if des3_key != user_key:
        flash('Invalid key!', 'danger')
        return redirect(url_for('decrypt_form'))

    try:
        decrypted_data = decrypt(encrypted_data, des3_key)
        flash(f'Success! The Decrypted Parcel ID is: {decrypted_data}', 'success')
    except Exception as e:
        flash(f'Error during decryption: {str(e)}', 'danger')

    # Clear session data after successful decryption (optional for security)
    session.pop('des3_key', None)
    session.pop('encrypted_data', None)

    return redirect(url_for('decrypt_form'))

if __name__ == '__main__':
    app.run(debug=True)
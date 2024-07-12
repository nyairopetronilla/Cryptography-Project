# Parcel Collection Service

This is a simple parcel collection service web application built using Flask and Python. The application encrypts parcel details using DES3 encryption and sends the encrypted details via SMS using Africa's Talking API.

## Project Structure

- `app.py`: Main application logic for handling encryption, decryption, and SMS sending.
- `templates`: HTML form sfor user interaction.
- `test.py`: Basic testing script for encryption and decryption functions.
- `requirements.txt`: Python dependencies for the project.
- `README.md`: Project documentation.

## Getting Started

1. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

2. Replace the placeholder API credentials in `app.py` with your Africa's Talking API credentials.

3. Run the application:
    ```bash
    python app.py
    ```

4. Access the application in your web browser at `http://127.0.0.1:5000/`.

## Testing

To run the basic encryption and decryption test:

```bash
python test.py

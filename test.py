from app import encrypt_message, decrypt_message, generate_key

def test_encryption_decryption():
    key = generate_key()
    original_message = 'Test Parcel Details'
    encrypted_message = encrypt_message(original_message, key)
    decrypted_message = decrypt_message(encrypted_message, key)
    assert original_message == decrypted_message, f'Failed: {original_message} != {decrypted_message}'
    print('Encryption and Decryption test passed!')

if __name__ == '__main__':
    test_encryption_decryption()

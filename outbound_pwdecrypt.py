#outbound_pwdecrypt.py

from base64 import b64decode

from Crypto.Cipher import DES3

  

# --- Inputs ---

# The 24-byte DES-EDE3 key. This key is crucial for decryption.

key = b'rcmail-!24ByteDESkey*Str'

  

# Encrypted values (base64 encoded) to be decrypted.

data = {

    'password': 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/',

    'auth_secret': 'DpYqv6maI9HxDL5GhcCd8JaQQW',

    'request_token': 'TIsOaABA1zHSXZOBpH6up5XFyayNRHaw'

}

  

def decrypt_des3_cbc(value, key):

    """

    Decrypts a base64-encoded, DES3-CBC encrypted string.

  

    Args:

        value (str): The base64-encoded encrypted string.

        key (bytes): The 24-byte DES-EDE3 key.

  

    Returns:

        str: The decrypted string, or an error message if decryption fails.

    """

    try:

        # Base64 decode the input value to get the raw bytes.

        raw = b64decode(value)

        # The first 8 bytes of the raw data are the Initialization Vector (IV).

        iv = raw[:8]

        # The rest of the raw data is the ciphertext.

        cipher_text = raw[8:]

        # Create a new DES3 cipher object in CBC mode with the given key and IV.

        cipher = DES3.new(key, DES3.MODE_CBC, iv)

        # Decrypt the ciphertext.

        decrypted = cipher.decrypt(cipher_text)

        # Strip null bytes (common in PHP's rtrim) and then remove the last padding byte.

        # This mimics PHP's rtrim + substr behavior for padding removal.

        decrypted = decrypted.rstrip(b'\x00')[:-1]

        # Decode the bytes to a string, replacing any characters that cannot be decoded.

        return decrypted.decode(errors='replace')

    except Exception as e:

        # Catch any exceptions during the process and return an error message.

        return f"[ERROR] {e}"

  

# Decrypt all values in the 'data' dictionary and print them.

print("--- Decryption Results ---")

for k, v in data.items():

    result = decrypt_des3_cbc(v, key)

    print(f"{k}: {result}")

from pickle import dumps, loads
from flask import Flask, render_template, request, jsonify
import base64, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Xác định thư mục gốc dự án (cha của thư mục api/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    static_url_path='/static',
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

# OTP XOR (Vernam)
def otp_xor(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# AES Encrypt password (used as protector)
def aes_encrypt(password: str, secret: bytes) -> bytes:
    cipher = AES.new(secret, AES.MODE_ECB)
    return cipher.encrypt(pad(password.encode("utf-8"), AES.block_size))

def aes_decrypt(enc_password: bytes, secret: bytes) -> str:
    cipher = AES.new(secret, AES.MODE_ECB)
    return unpad(cipher.decrypt(enc_password), AES.block_size).decode("utf-8")

# Root -> render UI
@app.route('/')
def index():
    return render_template('index.html')

# Encrypt endpoint
@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        file_b64 = data['file']
        password = data.get('password', '')
        compress = bool(data.get('compress', False))
        out_ext = data.get('outExt', 'bin')

        file_bytes = base64.b64decode(file_b64)

        # generate OTP key (random integer bytes)
        key = os.urandom(len(file_bytes))

        # OTP encrypt
        cipher_data = otp_xor(file_bytes, key)

        # AES protect the password (stored encrypted inside package)
        SECRET = b'SECRET_16_BYTE__'  # must be 16 bytes
        enc_pass = aes_encrypt(password, SECRET)

        # Optionally compress key
        if compress:
            from huffman import huffman_compress
            comp_key, tree, padbits = huffman_compress(key)
            huffman_info = dumps((tree, padbits))
            key_to_store = comp_key
        else:
            huffman_info = b''
            key_to_store = key

        # Pack layout
        packed = (
            len(enc_pass).to_bytes(2, 'big') + enc_pass +
            len(key_to_store).to_bytes(4, 'big') + key_to_store +
            len(huffman_info).to_bytes(2, 'big') + huffman_info +
            cipher_data
        )

        if out_ext.lower() == 'txt':
            packed_b64 = base64.b64encode(packed).decode()
            encrypted_data = base64.b64encode(packed_b64.encode()).decode()
        else:
            encrypted_data = base64.b64encode(packed).decode()

        return jsonify({
            'encrypted_data': encrypted_data,
            'key_hex': key.hex(),
            'enc_pass_hex': enc_pass.hex(),
            'log': f'Đã mã hóa ({len(file_bytes)} bytes). Key hiển thị để bạn lưu/chia sẻ.'
        })
    except Exception as e:
        return jsonify({'error': f'Lỗi mã hóa: {str(e)}'}), 500

# Decrypt endpoint
@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        file_b64 = data['file']
        password = data.get('password', '')
        user_key_hex = data.get('key_hex', '').strip()
        out_ext = data.get('outExt', 'bin')

        SECRET = b'SECRET_16_BYTE__'

        if out_ext.lower() == 'txt':
            packed_str = base64.b64decode(file_b64).decode()
            raw = base64.b64decode(packed_str.encode())
        else:
            raw = base64.b64decode(file_b64)

        idx = 0
        enc_len = int.from_bytes(raw[idx:idx+2], 'big'); idx += 2
        enc_pass = raw[idx:idx+enc_len]; idx += enc_len

        key_len = int.from_bytes(raw[idx:idx+4], 'big'); idx += 4
        key_bytes = raw[idx:idx+key_len]; idx += key_len

        info_len = int.from_bytes(raw[idx:idx+2], 'big'); idx += 2
        huffman_info = raw[idx:idx+info_len] if info_len > 0 else b''; idx += info_len

        cipher_data = raw[idx:]

        try:
            dec_pass = aes_decrypt(enc_pass, SECRET)
        except Exception as e:
            return jsonify({'error': f'Lỗi AES: {str(e)}', 'enc_pass_hex': enc_pass.hex()}), 500

        if dec_pass != password:
            return jsonify({'error': 'Sai mật khẩu AES (mật khẩu không trùng).'}), 403

        if user_key_hex:
            try:
                key_from_user = bytes.fromhex(user_key_hex)
            except Exception:
                return jsonify({'error': 'Key HEX không hợp lệ.'}), 400
            key = key_from_user
        else:
            if huffman_info:
                from huffman import huffman_decompress
                tree, padbits = loads(huffman_info)
                key = huffman_decompress(key_bytes, tree, padbits)
            else:
                key = key_bytes

        if len(key) < len(cipher_data):
            repeats = (len(cipher_data) + len(key) - 1) // len(key)
            key = (key * repeats)[:len(cipher_data)]

        original = otp_xor(cipher_data, key)

        return jsonify({
            'original_file': base64.b64encode(original).decode(),
            'log': f'Giải mã thành công ({len(original)} bytes).'
        })
    except Exception as e:
        return jsonify({'error': f'Lỗi giải mã: {str(e)}'}), 500

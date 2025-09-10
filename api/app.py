from pickle import dumps, loads
from flask import Flask, render_template, request, jsonify
import base64, os, re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Xác định thư mục gốc dự án
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    static_url_path='/static',
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

# OTP XOR
def otp_xor(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# AES protect password
def aes_encrypt(password: str, secret: bytes) -> bytes:
    cipher = AES.new(secret, AES.MODE_ECB)
    return cipher.encrypt(pad(password.encode("utf-8"), AES.block_size))

def aes_decrypt(enc_password: bytes, secret: bytes) -> str:
    cipher = AES.new(secret, AES.MODE_ECB)
    return unpad(cipher.decrypt(enc_password), AES.block_size).decode("utf-8")

# Check password strength
def validate_password(password: str) -> bool:
    if len(password) < 6: return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[^a-zA-Z0-9]", password): return False
    return True

@app.route('/')
def index():
    return render_template('index.html')

# Encrypt
@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        file_b64 = data['file']
        password = data.get('password', '')
        compress = bool(data.get('compress', False))
        out_ext = data.get('outExt', 'bin')
        original_ext = data.get('originalExt', 'bin')  # thêm đuôi gốc

        if not validate_password(password):
            return jsonify({'error': 'Mật khẩu không hợp lệ (≥6 ký tự, có chữ hoa, chữ thường và ký tự đặc biệt).'}), 400

        file_bytes = base64.b64decode(file_b64)

        # Tạo OTP key
        key = os.urandom(len(file_bytes))

        # OTP encrypt
        cipher_data = otp_xor(file_bytes, key)

        # AES protect password
        SECRET = b'SECRET_16_BYTE__'
        enc_pass = aes_encrypt(password, SECRET)

        log_msg = ""
        if compress:
            from huffman import huffman_compress
            comp_cipher, codes, padbits = huffman_compress(cipher_data)

            if len(comp_cipher) + len(dumps((codes, padbits))) >= len(cipher_data):
                # fallback
                huffman_info = b''
                cipher_to_store = cipher_data
                log_msg += "⚠️ Huffman không hiệu quả → giữ nguyên dữ liệu.\n"
            else:
                huffman_info = dumps((codes, padbits))
                cipher_to_store = comp_cipher
                log_msg += f"✅ Đã nén dữ liệu bằng Huffman (từ {len(cipher_data)} → {len(comp_cipher)} bytes).\n"
        else:
            huffman_info = b''
            cipher_to_store = cipher_data

        # Ghi thêm extension gốc
        ext_bytes = original_ext.encode()
        packed = (
            len(enc_pass).to_bytes(2, 'big') + enc_pass +
            len(key).to_bytes(4, 'big') + key +
            len(huffman_info).to_bytes(4, 'big') + huffman_info +
            len(ext_bytes).to_bytes(2, 'big') + ext_bytes +   # thêm đuôi file gốc
            cipher_to_store
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
            'log': f'{log_msg}Đã mã hóa ({len(file_bytes)} bytes).'
        })
    except Exception as e:
        return jsonify({'error': f'Lỗi mã hóa: {str(e)}'}), 500

# Decrypt
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

        info_len = int.from_bytes(raw[idx:idx+4], 'big'); idx += 4
        huffman_info = raw[idx:idx+info_len] if info_len > 0 else b''; idx += info_len

        ext_len = int.from_bytes(raw[idx:idx+2], 'big'); idx += 2
        original_ext = raw[idx:idx+ext_len].decode() if ext_len > 0 else 'bin'; idx += ext_len

        cipher_stored = raw[idx:]

        # AES check
        try:
            dec_pass = aes_decrypt(enc_pass, SECRET)
        except Exception as e:
            return jsonify({'error': f'Lỗi AES: {str(e)}'}), 500

        if dec_pass != password:
            return jsonify({'error': 'Sai mật khẩu AES (mật khẩu không trùng).'}), 403

        # Key
        if user_key_hex:
            try:
                key = bytes.fromhex(user_key_hex)
            except Exception:
                return jsonify({'error': 'Key HEX không hợp lệ.'}), 400
        else:
            key = key_bytes

        # Huffman decompress if needed
        if huffman_info:
            from huffman import huffman_decompress
            codes, padbits = loads(huffman_info)
            cipher_data = huffman_decompress(cipher_stored, codes, padbits)
        else:
            cipher_data = cipher_stored

        # OTP decrypt
        if len(key) < len(cipher_data):
            repeats = (len(cipher_data) + len(key) - 1) // len(key)
            key = (key * repeats)[:len(cipher_data)]

        original = otp_xor(cipher_data, key)

        return jsonify({
            'original_file': base64.b64encode(original).decode(),
            'original_ext': original_ext,   # trả về đuôi gốc
            'log': f'Giải mã thành công ({len(original)} bytes).'
        })
    except Exception as e:
        return jsonify({'error': f'Lỗi giải mã: {str(e)}'}), 500

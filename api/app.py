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
        original_ext = data.get('originalExt', 'bin')  # 👈 đuôi file gốc

        if not validate_password(password):
            return jsonify({'error': 'Mật khẩu không hợp lệ (≥6 ký tự, có chữ hoa, chữ thường và ký tự đặc biệt).'}), 400

        file_bytes = base64.b64decode(file_b64)

        # OTP key
        key = os.urandom(len(file_bytes))

        # OTP encrypt
        cipher_data = otp_xor(file_bytes, key)

        # AES protect password
        SECRET = b'SECRET_16_BYTE__'
        enc_pass = aes_encrypt(password, SECRET)

        log_msg = ""
        if compress:
            from huffman import huffman_compress
            comp_key, codes, padbits = huffman_compress(key)

            if len(comp_key) + len(dumps((codes, padbits))) >= len(key):
                huffman_info = b''
                key_to_store = key
                log_msg += "⚠️ Huffman không hiệu quả → giữ nguyên key.\n"
            else:
                huffman_info = dumps((codes, padbits))
                key_to_store = comp_key
                log_msg += f"✅ Đã nén key bằng Huffman (từ {len(key)} → {len(comp_key)} bytes).\n"
        else:
            huffman_info = b''
            key_to_store = key

        # Pack layout: [AES pass][OTP key or comp][Huffman info][original_ext][cipher_data]
        packed = (
            len(enc_pass).to_bytes(2, 'big') + enc_pass +
            len(key_to_store).to_bytes(4, 'big') + key_to_store +
            len(huffman_info).to_bytes(4, 'big') + huffman_info +
            len(original_ext).to_bytes(1, 'big') + original_ext.encode() +
            cipher_data
        )

        # Xuất ra file
        if out_ext.lower() == 'txt':
            encrypted_data = base64.b64encode(packed).decode()
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

        # Decode gói dữ liệu
        raw = base64.b64decode(file_b64)

        idx = 0
        enc_len = int.from_bytes(raw[idx:idx+2], 'big'); idx += 2
        enc_pass = raw[idx:idx+enc_len]; idx += enc_len

        key_len = int.from_bytes(raw[idx:idx+4], 'big'); idx += 4
        key_bytes = raw[idx:idx+key_len]; idx += key_len

        info_len = int.from_bytes(raw[idx:idx+4], 'big'); idx += 4
        huffman_info = raw[idx:idx+info_len] if info_len > 0 else b''; idx += info_len

        ext_len = raw[idx]; idx += 1
        original_ext = raw[idx:idx+ext_len].decode(); idx += ext_len

        cipher_data = raw[idx:]

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
            if huffman_info:
                from huffman import huffman_decompress
                codes, padbits = loads(huffman_info)
                key = huffman_decompress(key_bytes, codes, padbits)
            else:
                key = key_bytes

        if len(key) < len(cipher_data):
            repeats = (len(cipher_data) + len(key) - 1) // len(key)
            key = (key * repeats)[:len(cipher_data)]

        # OTP decrypt
        original = otp_xor(cipher_data, key)

        return jsonify({
            'original_file': base64.b64encode(original).decode(),
            'original_ext': original_ext,  # 👈 gửi đuôi gốc để front-end lưu file chuẩn
            'log': f'Giải mã thành công ({len(original)} bytes).'
        })
    except Exception as e:
        return jsonify({'error': f'Lỗi giải mã: {str(e)}'}), 500

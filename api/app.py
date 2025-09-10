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

# Encrypt endpoint
@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        file_b64 = data['file']
        password = data.get('password', '')
        compress = bool(data.get('compress', False))
        out_ext = data.get('outExt', 'bin')

        if not validate_password(password):
            return jsonify({'error': 'Mật khẩu không hợp lệ (≥6 ký tự, có chữ hoa, chữ thường và ký tự đặc biệt).'}), 400

        file_bytes = base64.b64decode(file_b64)
        original_size = len(file_bytes)

        # Nén Huffman nếu chọn
        log_msg = ""
        if compress:
            from huffman import huffman_compress
            comp_data, codes, padbits = huffman_compress(file_bytes)
            if len(comp_data) + len(dumps((codes, padbits))) >= original_size:
                huffman_info = b''
                data_to_encrypt = file_bytes
                log_msg += f"⚠️ Huffman không hiệu quả → giữ nguyên ({original_size} bytes).\n"
            else:
                huffman_info = dumps((codes, padbits))
                data_to_encrypt = comp_data
                log_msg += f"✅ Đã nén dữ liệu từ {original_size} → {len(comp_data)} bytes.\n"
        else:
            huffman_info = b''
            data_to_encrypt = file_bytes
            log_msg += f"📦 Không nén, dữ liệu giữ nguyên {original_size} bytes.\n"

        # OTP key
        key = os.urandom(len(data_to_encrypt))
        cipher_data = otp_xor(data_to_encrypt, key)

        # AES protect password
        SECRET = b'SECRET_16_BYTE__'
        enc_pass = aes_encrypt(password, SECRET)

        # Pack dữ liệu: AES pass + OTP key + Huffman + cipher
        packed = (
            len(enc_pass).to_bytes(2, 'big') + enc_pass +
            len(key).to_bytes(4, 'big') + key +
            len(huffman_info).to_bytes(4, 'big') + huffman_info +
            cipher_data
        )

        # Chuyển sang text nếu txt, else binary
        if out_ext.lower() == 'txt':
            encrypted_data = base64.b64encode(packed).decode()
        else:
            encrypted_data = packed.hex()  # hex là dạng nhị phân biểu diễn text, có thể ghi ra bin

        return jsonify({
            'encrypted_data': encrypted_data,
            'key_hex': key.hex(),
            'enc_pass_hex': enc_pass.hex(),
            'log': log_msg + f"🔒 Đã mã hóa hoàn tất ({len(file_bytes)} bytes)."
        })
    except Exception as e:
        return jsonify({'error': f'Lỗi mã hóa: {str(e)}'}), 500

# Decrypt endpoint
@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        file_text = data['file']
        password = data.get('password', '')
        user_key_hex = data.get('key_hex', '').strip()
        out_ext = data.get('outExt', 'bin')

        SECRET = b'SECRET_16_BYTE__'

        # Chuyển text về nhị phân
        if out_ext.lower() == 'txt':
            raw = base64.b64decode(file_text.encode())
        else:
            raw = bytes.fromhex(file_text)

        idx = 0
        enc_len = int.from_bytes(raw[idx:idx+2], 'big'); idx += 2
        enc_pass = raw[idx:idx+enc_len]; idx += enc_len

        key_len = int.from_bytes(raw[idx:idx+4], 'big'); idx += 4
        key_bytes = raw[idx:idx+key_len]; idx += key_len

        info_len = int.from_bytes(raw[idx:idx+4], 'big'); idx += 4
        huffman_info = raw[idx:idx+info_len] if info_len > 0 else b''; idx += info_len

        cipher_data = raw[idx:]

        # AES password check
        try:
            dec_pass = aes_decrypt(enc_pass, SECRET)
        except Exception:
            return jsonify({'error': 'Dữ liệu AES không hợp lệ.'}), 500
        if dec_pass != password:
            return jsonify({'error': 'Sai mật khẩu AES.'}), 403

        # Dùng OTP key
        if user_key_hex:
            key = bytes.fromhex(user_key_hex)
        else:
            key = key_bytes

        decrypted_data = otp_xor(cipher_data, key)

        # Huffman decompress nếu có
        if huffman_info:
            from huffman import huffman_decompress
            codes, padbits = loads(huffman_info)
            original = huffman_decompress(decrypted_data, codes, padbits)
            log_msg = f"✅ Giải mã + giải nén Huffman thành công ({len(original)} bytes)."
        else:
            original = decrypted_data
            log_msg = f"✅ Giải mã thành công ({len(original)} bytes)."

        return jsonify({
            'original_file': base64.b64encode(original).decode(),
            'log': log_msg
        })
    except Exception as e:
        return jsonify({'error': f'Lỗi giải mã: {str(e)}'}), 500

@app.route('/clear_log', methods=['POST'])
def clear_log():
    return jsonify({"log": ""})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

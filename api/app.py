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
        compress_key = bool(data.get('compress', False))  # Chỉ nén key
        out_ext = data.get('outExt', 'bin')

        if not validate_password(password):
            return jsonify({'error': 'Mật khẩu không hợp lệ (≥6 ký tự, có chữ hoa, chữ thường và ký tự đặc biệt).'}), 400

        file_bytes = base64.b64decode(file_b64)
        original_size = len(file_bytes)

        # 🔑 Tạo OTP key
        key = os.urandom(original_size)
        key_hex = key.hex()
        log_msg = f"🔑 Key HEX gốc: {len(key_hex)} chars.\n"

        # 🔹 Nén khóa OTP dạng hex nếu chọn
        if compress_key:
            from huffman import huffman_compress
            key_bytes_for_compress = key_hex.encode()
            comp_data, codes, padbits = huffman_compress(key_bytes_for_compress)
            if len(comp_data) + len(dumps((codes, padbits))) >= len(key_bytes_for_compress):
                compressed_key_info = b''
                compressed_key_hex = key_hex
                log_msg += f"⚠️ Huffman key không hiệu quả, giữ nguyên ({len(key_hex)} chars).\n"
            else:
                compressed_key_info = dumps((codes, padbits))
                compressed_key_hex = comp_data.hex()
                log_msg += f"✅ Huffman key thành công: {len(key_hex)} → {len(comp_data)} bytes ({100-(len(comp_data)/len(key_bytes_for_compress)*100):.2f}% giảm).\n"
        else:
            compressed_key_info = b''
            compressed_key_hex = key_hex
            log_msg += f"📦 Không nén key, giữ nguyên {len(key_hex)} chars.\n"

        # 🔐 OTP encrypt file (không nén file)
        cipher_data = otp_xor(file_bytes, key)

        # 🔒 AES bảo vệ password
        SECRET = b'SECRET_16_BYTE__'
        enc_pass = aes_encrypt(password, SECRET)
        log_msg += "🔒 Password đã được bảo vệ AES.\n"

        # Pack layout: [AES pass][OTP key][Huffman key info][cipher_data]
        packed = (
            len(enc_pass).to_bytes(2, 'big') + enc_pass +
            len(key).to_bytes(4, 'big') + key +
            len(compressed_key_info).to_bytes(4, 'big') + compressed_key_info +
            cipher_data
        )

        # Với txt: giữ encode utf-8 để dễ hiển thị
        if out_ext.lower() == 'txt':
            encrypted_data = base64.b64encode(packed).decode('utf-8')
        else:
        # Với bin: giữ nguyên base64 bytes
            encrypted_data = base64.b64encode(packed).decode()

        return jsonify({
            'encrypted_data': encrypted_data,
            'key_hex': compressed_key_hex,
            'enc_pass_hex': enc_pass.hex(),
            'log': log_msg + f"✅ Mã hóa hoàn tất ({original_size} bytes dữ liệu)."
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

        # Giải mã base64 1 lần cho tất cả
        raw = base64.b64decode(file_b64)

        idx = 0
        enc_len = int.from_bytes(raw[idx:idx+2], 'big'); idx += 2
        enc_pass = raw[idx:idx+enc_len]; idx += enc_len

        key_len = int.from_bytes(raw[idx:idx+4], 'big'); idx += 4
        key_bytes = raw[idx:idx+key_len]; idx += key_len

        info_len = int.from_bytes(raw[idx:idx+4], 'big'); idx += 4
        compressed_key_info = raw[idx:idx+info_len] if info_len > 0 else b''; idx += info_len

        cipher_data = raw[idx:]

        # Kiểm tra AES password
        try:
            dec_pass = aes_decrypt(enc_pass, SECRET)
        except Exception:
            return jsonify({'error': 'Lỗi AES: dữ liệu AES không hợp lệ.'}), 500

        if dec_pass != password:
            return jsonify({'error': 'Sai mật khẩu AES.'}), 403

        # Dùng key từ người dùng hoặc từ file
        if user_key_hex:
            try:
                key = bytes.fromhex(user_key_hex)
            except Exception:
                return jsonify({'error': 'Key HEX không hợp lệ.'}), 400
        else:
            key = key_bytes

        # Giải mã OTP
        decrypted_data = otp_xor(cipher_data, key)

        # Giải nén key Huffman nếu có
        if compressed_key_info:
            from huffman import huffman_decompress
            codes, padbits = loads(compressed_key_info)
            log_msg = "✅ Key nén Huffman đã giải nén thành công.\n"
        else:
            log_msg = "✅ Key không nén.\n"

        return jsonify({
            'original_file': base64.b64encode(decrypted_data).decode(),
            'log': log_msg + f"✅ Giải mã thành công ({len(decrypted_data)} bytes)."
        })

    except Exception as e:
        return jsonify({'error': f'Lỗi giải mã: {str(e)}'}), 500

@app.route('/clear_log', methods=['POST'])
def clear_log():
    return jsonify({"log": ""})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

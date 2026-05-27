import json
import time
from flask import Flask, jsonify, request, send_from_directory
from cipher import SPECTRALCipher
from config import FLAG, FLAG_OFFSET, MAX_KEYSTREAM_START, MAX_KEYSTREAM_LENGTH, HOST, PORT

app = Flask(__name__, static_folder="static", static_url_path="")

# Generate the cipher key at startup (persists for the lifetime of the server)
cipher = SPECTRALCipher()

# Pre-compute the encrypted flag
# We need to advance the cipher to FLAG_OFFSET, then encrypt the flag
# But we also need a separate cipher for the keystream oracle (from position 0)
# So we create two instances with the same key

oracle_cipher = SPECTRALCipher(cipher.key)  # For keystream oracle (position 0+)

# For the flag, we need to advance to FLAG_OFFSET and encrypt
flag_cipher = SPECTRALCipher(cipher.key)
if FLAG_OFFSET > 0:
    # Advance the cipher by FLAG_OFFSET bytes
    _ = flag_cipher.keystream_bytes(FLAG_OFFSET)

encrypted_flag = flag_cipher.encrypt(FLAG)

print(f"[SPECTRAL] Key generated. Flag offset: {FLAG_OFFSET} bytes")
print(f"[SPECTRAL] Encrypted flag: {encrypted_flag.hex()}")
print(f"[SPECTRAL] Flag length: {len(FLAG)} bytes")


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/info")
def info():
    """Return challenge information (parameters, etc.)."""
    return jsonify({
        "challenge": "SPECTRAL",
        "difficulty": "Hard",
        "description": "Custom stream cipher using 3 LFSRs with a nonlinear combining function",
        "lfsr1": {
            "degree": 19,
            "polynomial": "x^19 + x^18 + x^17 + x^14 + 1"
        },
        "lfsr2": {
            "degree": 23,
            "polynomial": "x^23 + x^22 + x^21 + x^16 + 1"
        },
        "lfsr3": {
            "degree": 29,
            "polynomial": "x^29 + x^28 + x^25 + x^2 + 1"
        },
        "combining_function": "f(x1, x2, x3) = x1 XOR (x2 AND x3)",
        "key_size": 71,
        "flag_offset": FLAG_OFFSET,
        "flag_length": len(FLAG),
        "max_keystream_start": MAX_KEYSTREAM_START,
        "max_keystream_length": MAX_KEYSTREAM_LENGTH,
        "note": "The flag is encrypted at the given offset. You can request keystream from positions 0 to {0}.".format(MAX_KEYSTREAM_START)
    })


@app.route("/api/flag")
def get_flag():
    """Return the encrypted flag (hex-encoded)."""
    return jsonify({
        "encrypted_flag": encrypted_flag.hex(),
        "offset": FLAG_OFFSET,
        "length": len(encrypted_flag)
    })


@app.route("/api/keystream")
def get_keystream():
    """Return keystream bytes from a given position (limited range)."""
    try:
        start = int(request.args.get("start", "0"))
        length = int(request.args.get("length", "100"))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid start or length parameter"}), 400

    if start < 0 or length <= 0:
        return jsonify({"error": "start must be >= 0 and length must be > 0"}), 400

    if start >= MAX_KEYSTREAM_START:
        return jsonify({
            "error": f"start must be < {MAX_KEYSTREAM_START}",
            "hint": "The keystream oracle only covers early positions. You'll need to find another way to reach the flag offset."
        }), 403

    if start + length > MAX_KEYSTREAM_START:
        length = MAX_KEYSTREAM_START - start
        if length <= 0:
            return jsonify({"error": "Requested range exceeds allowed keystream window"}), 403

    if length > MAX_KEYSTREAM_LENGTH:
        return jsonify({"error": f"length must be <= {MAX_KEYSTREAM_LENGTH}"}), 400

    # Generate keystream from the requested position
    # We need to advance a fresh cipher to the start position
    ks_cipher = SPECTRALCipher(cipher.key)
    if start > 0:
        _ = ks_cipher.keystream_bytes(start)
    ks = ks_cipher.keystream_bytes(length)

    return jsonify({
        "keystream": ks.hex(),
        "start": start,
        "length": length,
        "bits_available": length * 8
    })


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    """Encrypt a plaintext (limited to small sizes)."""
    data = request.get_json()
    if not data or "plaintext" not in data:
        return jsonify({"error": "Provide 'plaintext' as hex string"}), 400

    try:
        pt = bytes.fromhex(data["plaintext"])
    except ValueError:
        return jsonify({"error": "Invalid hex string"}), 400

    if len(pt) > 64:
        return jsonify({"error": "Plaintext too long (max 64 bytes)"}), 400

    # Use a fresh cipher from position 0
    enc_cipher = SPECTRALCipher(cipher.key)
    ct = enc_cipher.encrypt(pt)

    return jsonify({
        "ciphertext": ct.hex(),
        "length": len(ct),
        "note": "Encryption uses keystream from position 0"
    })


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)

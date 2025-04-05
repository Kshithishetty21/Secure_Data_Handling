from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        data = request.form["message"]
        action = request.form["action"]

        if action == "storage":
            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted = cipher.encrypt(data.encode())
            decrypted = cipher.decrypt(encrypted).decode()
            result = f"<b>Encrypted:</b> {encrypted.decode()}<br><b>Decrypted:</b> {decrypted}"

        elif action == "transmission":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            encrypted = public_key.encrypt(
                data.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            decrypted = private_key.decrypt(
                encrypted,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode()
            result = f"<b>Encrypted:</b> {base64.b64encode(encrypted).decode()}<br><b>Decrypted:</b> {decrypted}"

        elif action == "signature":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            signature = private_key.sign(
                data.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            try:
                public_key.verify(
                    signature,
                    data.encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                result = "✅ Digital Signature Verified Successfully!"
            except:
                result = "❌ Verification Failed"

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)


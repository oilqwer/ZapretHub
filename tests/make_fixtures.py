"""Генерирует тестовые данные для `ZapretHub.exe --integritytest <папка>`: подписи Ed25519 делает независимая реализация
(Python cryptography), C# должен их принять; поддельные — отклонить. Сеть и GitHub не используются."""
import base64
import hashlib
import json
import os
import sys
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)  # noqa: E731

# 1. случайные тройки (ключ, сообщение, подпись) + RFC 8032 test 1
vectors = []
for n in range(40):
    k = Ed25519PrivateKey.generate()
    msg = os.urandom(n * 7)
    vectors.append({"pub": b64(raw(k)), "msg": b64(msg), "sig": b64(k.sign(msg))})
rfc_sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
vectors.append({"pub": b64(raw(rfc_sk)), "msg": "", "sig": b64(rfc_sk.sign(b"")), "rfc_pub_hex": raw(rfc_sk).hex(),
                "rfc_sig_hex": rfc_sk.sign(b"").hex()})
json.dump(vectors, open(os.path.join(out, "vectors.json"), "w"))

# 2. «движок» для установки: минимальная структура релиза Flowseal
zpath = os.path.join(out, "engine-9.9.9.zip")
with zipfile.ZipFile(zpath, "w") as z:
    z.writestr("zapret-9.9.9/service.bat", '@echo off\r\nset "LOCAL_VERSION=9.9.9"\r\n')
    z.writestr("zapret-9.9.9/general.bat", '@echo off\r\n"%BIN%winws.exe" --wf-tcp=80,443\r\n')
    z.writestr("zapret-9.9.9/bin/winws.exe", b"MZ dummy")
    z.writestr("zapret-9.9.9/lists/list-general.txt", "example.com\n")
sha = hashlib.sha256(open(zpath, "rb").read()).hexdigest()
uri = "file:///" + zpath.replace("\\", "/")

key = Ed25519PrivateKey.generate()
open(os.path.join(out, "test.pub"), "w").write(b64(raw(key)))


def manifest(name, version, sha256, sequence, signer=key, tamper=False):
    data = json.dumps({"components": {"zapret": {"sha256": sha256, "url": uri, "version": version}}, "schema": 1,
                       "sequence": sequence}, indent=2, sort_keys=True).encode() + b"\n"
    sig = b64(signer.sign(data))
    open(os.path.join(out, name), "wb").write(data + (b" " if tamper else b""))  # лишний байт ломает подпись
    open(os.path.join(out, name + ".sig"), "w").write(sig + "\n")


manifest("good.json", "9.9.9", sha, 10)
manifest("badsha.json", "9.9.9", "0" * 64, 10)          # подписан верно, но хэш архива не тот
manifest("tampered.json", "9.9.9", sha, 10, tamper=True)  # изменён после подписи
manifest("foreign.json", "9.9.9", sha, 10, signer=Ed25519PrivateKey.generate())  # подпись чужим ключом
manifest("old.json", "9.9.9", sha, 3)                    # sequence меньше принятого
print("ok", out)

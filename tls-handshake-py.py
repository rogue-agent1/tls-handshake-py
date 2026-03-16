#!/usr/bin/env python3
"""TLS 1.3 handshake simulator (protocol flow, not crypto)."""
import sys,hashlib,os

class TLSRecord:
    def __init__(self,content_type,data):self.content_type=content_type;self.data=data
    def __repr__(self):return f"TLSRecord(type={self.content_type},len={len(self.data)})"

class HandshakeMessage:
    def __init__(self,msg_type,data=None):self.msg_type=msg_type;self.data=data or{}
    def __repr__(self):return f"Handshake({self.msg_type})"

def simulate_tls13():
    """Simulate TLS 1.3 handshake flow."""
    transcript=[]
    # Client Hello
    client_random=hashlib.sha256(b"client_random").digest()
    ch=HandshakeMessage("ClientHello",{
        "version":"TLS 1.3","random":client_random.hex()[:32],
        "cipher_suites":["TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"],
        "extensions":["supported_versions","key_share","signature_algorithms"]
    })
    transcript.append(ch)
    # Server Hello
    server_random=hashlib.sha256(b"server_random").digest()
    sh=HandshakeMessage("ServerHello",{
        "version":"TLS 1.3","random":server_random.hex()[:32],
        "cipher_suite":"TLS_AES_256_GCM_SHA384",
        "extensions":["supported_versions","key_share"]
    })
    transcript.append(sh)
    # Encrypted Extensions
    transcript.append(HandshakeMessage("EncryptedExtensions"))
    # Certificate
    transcript.append(HandshakeMessage("Certificate",{"cert":"<server_cert>"}))
    # Certificate Verify
    transcript.append(HandshakeMessage("CertificateVerify",{"algorithm":"ed25519"}))
    # Server Finished
    transcript.append(HandshakeMessage("Finished",{"verify_data":"<server_hmac>"}))
    # Client Finished
    transcript.append(HandshakeMessage("Finished",{"verify_data":"<client_hmac>"}))
    return transcript

def main():
    if len(sys.argv)>1 and sys.argv[1]=="--test":
        t=simulate_tls13()
        assert len(t)==7
        types=[m.msg_type for m in t]
        assert types==["ClientHello","ServerHello","EncryptedExtensions","Certificate","CertificateVerify","Finished","Finished"]
        assert t[0].data["version"]=="TLS 1.3"
        assert "TLS_AES_256_GCM_SHA384" in t[0].data["cipher_suites"]
        assert t[1].data["cipher_suite"]=="TLS_AES_256_GCM_SHA384"
        assert len(t[0].data["random"])==32
        print("All tests passed!")
    else:
        for msg in simulate_tls13():print(f"  {msg}")
if __name__=="__main__":main()

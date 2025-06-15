#!/usr/bin/env python3
"""
JWT Token Analyzer
Analyze JWT tokens for potential vulnerabilities and attack vectors
"""

import base64
import json
import sys
import hashlib
import time
from urllib.parse import urlparse

def url_safe_b64_decode(data):
    """Decode URL-safe base64"""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    data = data.replace('-', '+').replace('_', '/')
    return base64.b64decode(data)

def analyze_header(header):
    """Analyze JWT header for vulnerabilities"""
    print("=== Header Analysis ===")
    print(json.dumps(header, indent=2))
    print()
    
    vulnerabilities = []
    recommendations = []
    
    # Algorithm analysis
    alg = header.get('alg', 'missing')
    if alg == 'none':
        vulnerabilities.append("🚨 CRITICAL: 'none' algorithm allows unsigned tokens")
    elif alg in ['HS256', 'HS384', 'HS512']:
        vulnerabilities.append("⚠️  HMAC algorithm - vulnerable to key confusion attacks")
        recommendations.append("Try RS256->HS256 confusion attack with public key")
    elif alg in ['RS256', 'RS384', 'RS512']:
        vulnerabilities.append("✅ RSA algorithm - check for algorithm confusion")
        recommendations.append("Try algorithm confusion attack (RS256->HS256)")
    elif alg == 'missing':
        vulnerabilities.append("🚨 CRITICAL: Missing algorithm field")
    
    # Kid analysis
    if 'kid' in header:
        kid = header['kid']
        print(f"Key ID found: {kid}")
        
        # Check for path traversal
        if '../' in kid or '..\\' in kid:
            vulnerabilities.append("🚨 CRITICAL: Kid contains path traversal")
        if kid.startswith('/'):
            vulnerabilities.append("⚠️  Kid looks like absolute path")
        if any(char in kid for char in ['<', '>', '&', '"', "'"]):
            vulnerabilities.append("⚠️  Kid contains special characters - possible injection")
        
        recommendations.extend([
            "Try kid path traversal: ../../../dev/null",
            "Try kid LFI: /etc/passwd",
            "Try kid injection: /dev/null; ls"
        ])
    
    # JKU analysis
    if 'jku' in header:
        jku = header['jku']
        print(f"JWK Set URL found: {jku}")
        
        parsed = urlparse(jku)
        if parsed.scheme not in ['https']:
            vulnerabilities.append("🚨 CRITICAL: JKU uses insecure protocol")
        if parsed.hostname in ['localhost', '127.0.0.1']:
            vulnerabilities.append("⚠️  JKU points to localhost")
        
        recommendations.extend([
            "Try JKU hijacking with attacker-controlled URL",
            "Check if server validates JKU URL"
        ])
    
    # X5U analysis
    if 'x5u' in header:
        x5u = header['x5u']
        print(f"X.509 URL found: {x5u}")
        vulnerabilities.append("⚠️  X.509 URL present - potential for certificate injection")
        recommendations.append("Try X5U hijacking with malicious certificate")
    
    # Type analysis
    typ = header.get('typ', 'missing')
    if typ != 'JWT':
        vulnerabilities.append(f"⚠️  Unusual type field: {typ}")
    
    return vulnerabilities, recommendations

def analyze_payload(payload):
    """Analyze JWT payload for security issues"""
    print("=== Payload Analysis ===")
    print(json.dumps(payload, indent=2))
    print()
    
    vulnerabilities = []
    recommendations = []
    
    # Expiration analysis
    if 'exp' in payload:
        exp = payload['exp']
        current_time = int(time.time())
        
        if exp < current_time:
            vulnerabilities.append("🚨 CRITICAL: Token is expired")
        elif exp > current_time + (365 * 24 * 60 * 60):  # More than 1 year
            vulnerabilities.append("⚠️  Token has very long expiration (>1 year)")
        
        exp_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp))
        print(f"Token expires: {exp_date}")
    else:
        vulnerabilities.append("⚠️  No expiration time set")
        recommendations.append("Try setting far future expiration")
    
    # Issued at analysis
    if 'iat' in payload:
        iat = payload['iat']
        iat_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(iat))
        print(f"Token issued: {iat_date}")
    
    # Not before analysis
    if 'nbf' in payload:
        nbf = payload['nbf']
        current_time = int(time.time())
        if nbf > current_time:
            vulnerabilities.append("⚠️  Token not yet valid (nbf in future)")
    
    # Subject analysis
    if 'sub' in payload:
        sub = payload['sub']
        print(f"Subject: {sub}")
        if sub in ['admin', 'administrator', 'root', 'superuser']:
            print("  ✅ Already privileged user")
        else:
            recommendations.append(f"Try privilege escalation: change sub to 'admin'")
    
    # Role/permission analysis
    role_fields = ['role', 'roles', 'permissions', 'scope', 'scopes', 'authorities']
    for field in role_fields:
        if field in payload:
            value = payload[field]
            print(f"{field.capitalize()}: {value}")
            
            if isinstance(value, str):
                if 'admin' in value.lower():
                    print(f"  ✅ Admin privileges detected in {field}")
                else:
                    recommendations.append(f"Try escalating {field} to admin")
            elif isinstance(value, list):
                if any('admin' in str(item).lower() for item in value):
                    print(f"  ✅ Admin privileges detected in {field}")
                else:
                    recommendations.append(f"Try adding admin to {field} array")
    
    # Admin flags
    admin_fields = ['admin', 'is_admin', 'isAdmin', 'administrator', 'superuser']
    for field in admin_fields:
        if field in payload:
            value = payload[field]
            if value:
                print(f"  ✅ Admin flag {field} is True")
            else:
                recommendations.append(f"Try setting {field} to true")
    
    # Sensitive information
    sensitive_fields = ['password', 'secret', 'key', 'token', 'api_key']
    for field in sensitive_fields:
        if field in payload:
            vulnerabilities.append(f"⚠️  Sensitive field '{field}' in payload")
    
    # JTI (JWT ID) analysis
    if 'jti' in payload:
        jti = payload['jti']
        print(f"JWT ID: {jti}")
        # Check for predictable patterns
        if jti.isdigit():
            vulnerabilities.append("⚠️  JTI is numeric - potentially predictable")
        elif len(jti) < 16:
            vulnerabilities.append("⚠️  JTI is short - potentially guessable")
    
    return vulnerabilities, recommendations

def analyze_signature(signature):
    """Analyze JWT signature"""
    print("=== Signature Analysis ===")
    print(f"Signature: {signature[:50]}{'...' if len(signature) > 50 else ''}")
    print(f"Signature length: {len(signature)} characters")
    print()
    
    vulnerabilities = []
    recommendations = []
    
    if not signature or signature == '':
        vulnerabilities.append("🚨 CRITICAL: Empty signature - token is unsigned")
    elif len(signature) < 20:
        vulnerabilities.append("⚠️  Very short signature - possibly weak")
    
    # Check for common weak signatures
    weak_sigs = ['signature', 'test', '123', 'fake', 'invalid']
    if signature.lower() in weak_sigs:
        vulnerabilities.append(f"🚨 CRITICAL: Weak signature '{signature}'")
    
    recommendations.extend([
        "Try removing signature completely (none algorithm)",
        "Try common weak signatures: 'test', 'fake', '123'",
        "Try brute forcing short signatures"
    ])
    
    return vulnerabilities, recommendations

def generate_attack_payloads(original_payload):
    """Generate various attack payloads"""
    print("=== Attack Payload Suggestions ===")
    
    attacks = {
        "Admin Privilege Escalation": {
            **original_payload,
            "sub": "admin",
            "role": "admin", 
            "admin": True,
            "is_admin": True,
            "exp": 9999999999
        },
        
        "Root User": {
            **original_payload,
            "sub": "root",
            "role": "root",
            "admin": True,
            "superuser": True,
            "exp": 9999999999
        },
        
        "Service Account": {
            **original_payload,
            "sub": "service",
            "role": "service",
            "scope": "all",
            "permissions": ["read", "write", "admin", "delete"],
            "exp": 9999999999
        },
        
        "Extended Expiration": {
            **original_payload,
            "exp": 9999999999,
            "nbf": 0
        }
    }
    
    for attack_name, attack_payload in attacks.items():
        print(f"\n{attack_name}:")
        print(json.dumps(attack_payload, indent=2))
    
    return attacks

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_analyzer.py <JWT_TOKEN>")
        print("Example: python3 jwt_analyzer.py 'eyJ0eXAiOiJKV1Q...'")
        return
    
    token = sys.argv[1].strip()
    
    try:
        # Split token
        parts = token.split('.')
        if len(parts) != 3:
            print("❌ Invalid JWT format (must have 3 parts separated by dots)")
            return
        
        # Decode parts
        header = json.loads(url_safe_b64_decode(parts[0]))
        payload = json.loads(url_safe_b64_decode(parts[1]))
        signature = parts[2]
        
        print("🔍 JWT Security Analysis")
        print("=" * 50)
        print()
        
        # Analyze each part
        header_vulns, header_recs = analyze_header(header)
        payload_vulns, payload_recs = analyze_payload(payload)
        sig_vulns, sig_recs = analyze_signature(signature)
        
        # Summary
        all_vulns = header_vulns + payload_vulns + sig_vulns
        all_recs = header_recs + payload_recs + sig_recs
        
        print("\n=== VULNERABILITY SUMMARY ===")
        if all_vulns:
            for vuln in all_vulns:
                print(vuln)
        else:
            print("✅ No obvious vulnerabilities found")
        
        print("\n=== ATTACK RECOMMENDATIONS ===")
        if all_recs:
            for i, rec in enumerate(all_recs, 1):
                print(f"{i}. {rec}")
        else:
            print("No specific recommendations")
        
        # Generate attack payloads
        print("\n")
        generate_attack_payloads(payload)
        
        print("\n=== NEXT STEPS ===")
        print("1. Use jwt_quick_bypass.py to generate bypass tokens")
        print("2. Use jwt_advanced_bypass.py for automated testing")
        print("3. Try manual payload modifications based on analysis")
        print("4. Test with different JWT libraries/parsers")
        
    except Exception as e:
        print(f"❌ Error analyzing token: {e}")
        print("Make sure the token is properly formatted")

if __name__ == "__main__":
    main()


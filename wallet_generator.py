#!/usr/bin/env python3

import os
import hashlib
import hmac
import secrets
import base64
from typing import List, Tuple
from nacl.signing import SigningKey
from nacl.public import PrivateKey
import ecdsa
from ecdsa.curves import SECP256k1, NIST256p
from ecdsa.keys import SigningKey as ECDSASigningKey
from flask import Flask, render_template_string, jsonify, send_file, request
import json
import time
from datetime import datetime

app = Flask(__name__)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Octra Wallet Generator</title>
    <style>
        :root {
            --background-default-color: #0a0a0a;
            --background-primary-color: #0033ff;
            --text-primary-color: #ffffff;
            --text-inverted-color: #ffffff;
            --border-color: #333333;
        }
        
        body {
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
            print-color-adjust: exact;
            font-family: Tahoma, Arial, sans-serif;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            font-size: 20px;
            line-height: 24px;
            margin: 0;
            padding: 0;
            background-color: var(--background-default-color);
            color: var(--text-inverted-color);
        }
        
        .container {
            max-width: 900px;
            width: 100%;
            padding: 20px;
        }
        
        h1 {
            text-align: center;
            font-size: 22px;
            margin-bottom: 40px;
            letter-spacing: -0.02em;
        }
        
        .button {
            outline: 1px solid var(--background-primary-color);
            background: var(--background-primary-color);
            color: var(--text-primary-color);
            border: none;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 15px;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 4px;
            font-family: Tahoma, Arial, sans-serif;
            transition: opacity 0.2s;
        }
        
        .button:hover {
            opacity: 0.8;
        }
        
        .button:disabled {
            background-color: #333;
            outline-color: #333;
            cursor: not-allowed;
            opacity: 0.5;
        }
        
        .status {
            margin: 40px 0;
            padding: 20px;
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            min-height: 300px;
            white-space: pre-wrap;
            overflow-y: auto;
            max-height: 400px;
            font-size: 14px;
            line-height: 20px;
            font-family: 'Courier New', monospace;
        }
        
        .wallet-info {
            background-color: transparent;
            padding: 20px 0;
            margin-top: 20px;
            display: none;
        }
        
        .wallet-field {
            margin: 20px 0;
            padding: 20px;
            background-color: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            word-break: break-all;
        }
        
        .field-label {
            font-weight: normal;
            color: var(--text-inverted-color);
            margin-bottom: 10px;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .field-value {
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 20px;
        }
        
        .warning {
            background-color: rgba(255, 0, 0, 0.1);
            color: #ff6b6b;
            padding: 20px;
            border: 1px solid rgba(255, 0, 0, 0.3);
            border-radius: 4px;
            margin: 20px 0;
            text-align: center;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .address-info {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        
        select, input[type="number"] {
            background: var(--background-default-color);
            color: var(--text-inverted-color);
            border: 1px solid var(--border-color);
            padding: 5px 10px;
            border-radius: 4px;
            font-family: Tahoma, Arial, sans-serif;
        }
        
        .derive-button {
            padding: 5px 15px;
            font-size: 14px;
            margin-left: 10px;
        }
        
        #derivedAddress {
            margin-top: 15px;
            padding: 10px;
            background-color: rgba(0, 51, 255, 0.1);
            border: 1px solid var(--background-primary-color);
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>OCTRA WALLET GENERATOR</h1>
        
        <div style="text-align: center;">
            <button id="generateBtn" class="button" onclick="generateWallet()">GENERATE NEW WALLET</button>
        </div>
        
        <div class="status" id="status">Ready to generate wallet...</div>
        
        <div class="wallet-info" id="walletInfo">
            <div class="warning">
                WARNING: DO NOT STORE THIS FILE ONLINE OR ON CLOUD SERVICES<br>
                KEEP YOUR PRIVATE KEY SECURE AND NEVER SHARE IT
            </div>
            
            <div class="wallet-field">
                <div class="field-label">MNEMONIC (12 WORDS)</div>
                <div class="field-value" id="mnemonic"></div>
            </div>
            
            <div class="wallet-field">
                <div class="field-label">PRIVATE KEY</div>
                <div class="field-value">
                    Raw: <span id="privateKeyRaw"></span><br>
                    B64: <span id="privateKeyB64"></span>
                </div>
            </div>
            
            <div class="wallet-field">
                <div class="field-label">PUBLIC KEY</div>
                <div class="field-value">
                    Raw: <span id="publicKeyRaw"></span><br>
                    B64: <span id="publicKeyB64"></span>
                </div>
            </div>
            
            <div class="wallet-field">
                <div class="field-label">OCTRA ADDRESS</div>
                <div class="field-value" id="address"></div>
            </div>
            
            <div class="wallet-field">
                <div class="field-label">TECHNICAL INFORMATION</div>
                <div class="field-value">
                    Entropy: <span id="entropy"></span><br>
                    Seed: <span id="seed"></span><br>
                    Master Chain: <span id="masterChain"></span>
                </div>
            </div>
            
            <div class="wallet-field">
                <div class="field-label">SIGNATURE TEST</div>
                <div class="field-value">
                    Message: <span id="testMessage"></span><br>
                    Signature: <span id="testSignature"></span><br>
                    Validation: <span id="signatureValid"></span>
                </div>
            </div>
            
            <div class="wallet-field">
                <div class="field-label">HD DERIVATION</div>
                <div class="field-value">
                    <label>Network Type: 
                        <select id="networkType">
                            <option value="0">MainCoin</option>
                            <option value="1">SubCoin</option>
                            <option value="2">Contract</option>
                            <option value="3">Subnet</option>
                            <option value="4">Account</option>
                        </select>
                    </label>
                    <label style="margin-left: 10px;">Index: 
                        <input type="number" id="derivationIndex" value="0" min="0" max="100" style="width: 60px;">
                    </label>
                    <button class="button derive-button" onclick="derivePath()">DERIVE</button>
                    <div id="derivedAddress" style="display: none;">
                        Derived Address: <span id="derivedAddressValue"></span><br>
                        Path: <span id="derivedPath"></span>
                    </div>
                </div>
            </div>
            
            <div class="wallet-field" id="saveInfo" style="display: none;">
                <div class="field-label">FILE SAVED</div>
                <div class="field-value">
                    Filename: <span id="savedFilename"></span><br>
                    Location: In the same directory as this script
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentWallet = null;
        
        function updateStatus(message) {
            const status = document.getElementById('status');
            status.textContent += message + '\\n';
            status.scrollTop = status.scrollHeight;
        }
        
        async function derivePath() {
            if (!currentWallet) {
                alert('Please generate a wallet first');
                return;
            }
            
            const networkType = parseInt(document.getElementById('networkType').value);
            const index = parseInt(document.getElementById('derivationIndex').value);
            
            try {
                const response = await fetch('/derive', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        seed_hex: currentWallet.seed_hex,
                        network_type: networkType,
                        index: index
                    })
                });
                
                const result = await response.json();
                if (result.success) {
                    document.getElementById('derivedAddressValue').textContent = result.address;
                    document.getElementById('derivedPath').textContent = result.path;
                    document.getElementById('derivedAddress').style.display = 'block';
                } else {
                    alert('Derivation failed: ' + result.error);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
        
        async function generateWallet() {
            const btn = document.getElementById('generateBtn');
            const status = document.getElementById('status');
            const walletInfo = document.getElementById('walletInfo');
            
            btn.disabled = true;
            status.textContent = '';
            walletInfo.style.display = 'none';
            
            updateStatus('Starting wallet generation...');
            
            try {
                const response = await fetch('/generate', {
                    method: 'POST'
                });
                
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\\n');
                    
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const data = JSON.parse(line.substring(6));
                            
                            if (data.status) {
                                updateStatus(data.status);
                            }
                            
                            if (data.wallet) {
                                currentWallet = data.wallet;
                                displayWallet(data.wallet);
                            }
                        }
                    }
                }
            } catch (error) {
                updateStatus('ERROR: ' + error.message);
            } finally {
                btn.disabled = false;
            }
        }
        
        function displayWallet(wallet) {
            document.getElementById('mnemonic').textContent = wallet.mnemonic.join(' ');
            document.getElementById('privateKeyRaw').textContent = wallet.private_key_hex;
            document.getElementById('privateKeyB64').textContent = wallet.private_key_b64;
            document.getElementById('publicKeyRaw').textContent = wallet.public_key_hex;
            document.getElementById('publicKeyB64').textContent = wallet.public_key_b64;
            document.getElementById('address').textContent = wallet.address;
            document.getElementById('entropy').textContent = wallet.entropy_hex;
            document.getElementById('seed').textContent = wallet.seed_hex.substring(0, 64) + '...';
            document.getElementById('masterChain').textContent = wallet.master_chain_hex;
            document.getElementById('testMessage').textContent = wallet.test_message;
            document.getElementById('testSignature').textContent = wallet.test_signature;
            document.getElementById('signatureValid').textContent = wallet.signature_valid ? 'VALID' : 'INVALID';
            
            document.getElementById('walletInfo').style.display = 'block';
            
            // Auto-save wallet
            saveWallet();
        }
        
        async function saveWallet() {
            if (!currentWallet) return;
            
            try {
                const response = await fetch('/save', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(currentWallet)
                });
                
                if (response.ok) {
                    const result = await response.json();
                    
                    updateStatus('Wallet saved to: ' + result.filename);
                    
                    document.getElementById('savedFilename').textContent = result.filename;
                    document.getElementById('saveInfo').style.display = 'block';
                } else {
                    updateStatus('ERROR: Failed to save wallet');
                }
            } catch (error) {
                updateStatus('ERROR: ' + error.message);
            }
        }
    </script>
</body>
</html>
'''

def load_wordlist(filename: str = "english.txt") -> List[str]:
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File {filename} not found!")
    
    with open(filename, 'r', encoding='utf-8') as f:
        words = [line.strip() for line in f if line.strip()]
    
    if len(words) != 2048:
        raise ValueError(f"Wordlist must contain 2048 words, found: {len(words)}")
    
    return words

def generate_entropy(strength: int = 128) -> bytes:
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError("Strength must be 128, 160, 192, 224 or 256 bits")
    return secrets.token_bytes(strength // 8)

def entropy_to_mnemonic(entropy: bytes, wordlist: List[str]) -> List[str]:
    checksum_bits = len(entropy) * 8 // 32
    checksum = hashlib.sha256(entropy).digest()
    checksum_int = int.from_bytes(checksum[:1], 'big') >> (8 - checksum_bits)
    
    entropy_int = int.from_bytes(entropy, 'big')
    combined = (entropy_int << checksum_bits) | checksum_int
    
    mnemonic = []
    bits = len(entropy) * 8 + checksum_bits
    
    for i in range(bits // 11):
        word_index = (combined >> (bits - (i + 1) * 11)) & 0x7FF
        mnemonic.append(wordlist[word_index])
    
    return mnemonic

def mnemonic_to_seed(mnemonic: List[str], passphrase: str = "") -> bytes:
    mnemonic_str = " ".join(mnemonic)
    salt = ("mnemonic" + passphrase).encode('utf-8')
    seed = hashlib.pbkdf2_hmac('sha512', mnemonic_str.encode('utf-8'), salt, 2048)
    return seed

def derive_master_key(seed: bytes) -> Tuple[bytes, bytes]:
    key = b"Octra seed"
    mac = hmac.new(key, seed, hashlib.sha512).digest()
    master_private_key = mac[:32]
    master_chain_code = mac[32:]
    return master_private_key, master_chain_code

def derive_child_key_ed25519(private_key: bytes, chain_code: bytes, index: int) -> Tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = b'\x00' + private_key + index.to_bytes(4, 'big')
    else:
        signing_key = SigningKey(private_key)
        public_key = signing_key.verify_key.encode()
        data = public_key + index.to_bytes(4, 'big')
    
    mac = hmac.new(chain_code, data, hashlib.sha512).digest()
    child_private_key = mac[:32]
    child_chain_code = mac[32:]
    
    return child_private_key, child_chain_code

def derive_path(seed: bytes, path: List[int]) -> Tuple[bytes, bytes]:
    key, chain = derive_master_key(seed)
    for index in path:
        key, chain = derive_child_key_ed25519(key, chain, index)
    return key, chain

def get_network_type_name(network_type: int) -> str:
    if network_type == 0:
        return "MainCoin"
    elif network_type == 1:
        return f"SubCoin {network_type}"
    elif network_type == 2:
        return f"Contract {network_type}"
    elif network_type == 3:
        return f"Subnet {network_type}"
    elif network_type == 4:
        return f"Account {network_type}"
    else:
        return f"Unknown {network_type}"

def derive_for_network(seed: bytes, network_type: int = 0, network: int = 0, 
                      contract: int = 0, account: int = 0, index: int = 0,
                      token: int = 0, subnet: int = 0) -> dict:
    coin_type = 0 if network_type == 0 else network_type
    
    base_path = [
        0x80000000 | 345,
        0x80000000 | coin_type,
        0x80000000 | network,
    ]
    contract_path = [0x80000000 | contract, 0x80000000 | account]
    optional_path = [0x80000000 | token, 0x80000000 | subnet]
    final_path = [index]
    
    full_path = base_path + contract_path + optional_path + final_path
    
    derived_key, derived_chain = derive_path(seed, full_path)
    
    signing_key = SigningKey(derived_key)
    verify_key = signing_key.verify_key
    
    derived_address = create_octra_address(verify_key.encode())
    
    return {
        'private_key': derived_key,
        'chain_code': derived_chain,
        'public_key': verify_key.encode(),
        'address': derived_address,
        'path': full_path,
        'network_type_name': get_network_type_name(network_type),
        'network': network,
        'contract': contract,
        'account': account,
        'index': index
    }

def base58_encode(data: bytes) -> str:
    if not data:
        return ""
    
    num = int.from_bytes(data, 'big')
    encoded = ""
    
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    
    for byte in data:
        if byte == 0:
            encoded = '1' + encoded
        else:
            break
    
    return encoded

def create_octra_address(public_key: bytes) -> str:
    hash_digest = hashlib.sha256(public_key).digest()
    base58_hash = base58_encode(hash_digest)
    address = "oct" + base58_hash
    return address

def verify_address_format(address: str) -> bool:
    if not address.startswith("oct"):
        return False
    if len(address) < 20 or len(address) > 50:
        return False
    base58_part = address[3:]
    for char in base58_part:
        if char not in BASE58_ALPHABET:
            return False
    return True

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/generate', methods=['POST'])
def generate():
    def generate_steps():
        yield f"data: {json.dumps({'status': 'Loading BIP39 wordlist...'})}\n\n"
        time.sleep(0.2)
        
        try:
            wordlist = load_wordlist()
            yield f"data: {json.dumps({'status': 'Wordlist loaded successfully'})}\n\n"
            time.sleep(0.2)
        except FileNotFoundError:
            yield f"data: {json.dumps({'status': 'ERROR: english.txt file not found!'})}\n\n"
            return
        
        yield f"data: {json.dumps({'status': 'Generating entropy...'})}\n\n"
        time.sleep(0.2)
        entropy = generate_entropy(128)
        yield f"data: {json.dumps({'status': 'Entropy generated'})}\n\n"
        time.sleep(0.2)
        
        yield f"data: {json.dumps({'status': 'Creating mnemonic phrase...'})}\n\n"
        time.sleep(0.2)
        mnemonic = entropy_to_mnemonic(entropy, wordlist)
        yield f"data: {json.dumps({'status': 'Mnemonic created'})}\n\n"
        time.sleep(0.2)
        
        yield f"data: {json.dumps({'status': 'Deriving seed from mnemonic...'})}\n\n"
        time.sleep(0.2)
        seed = mnemonic_to_seed(mnemonic)
        yield f"data: {json.dumps({'status': 'Seed derived'})}\n\n"
        time.sleep(0.2)
        
        yield f"data: {json.dumps({'status': 'Deriving master key...'})}\n\n"
        time.sleep(0.2)
        master_private, master_chain = derive_master_key(seed)
        yield f"data: {json.dumps({'status': 'Master key derived'})}\n\n"
        time.sleep(0.2)
        
        yield f"data: {json.dumps({'status': 'Creating Ed25519 keypair...'})}\n\n"
        time.sleep(0.2)
        signing_key = SigningKey(master_private)
        verify_key = signing_key.verify_key
        private_key_raw = signing_key.encode()
        public_key_raw = verify_key.encode()
        yield f"data: {json.dumps({'status': 'Keypair created'})}\n\n"
        time.sleep(0.2)
        
        yield f"data: {json.dumps({'status': 'Generating Octra address...'})}\n\n"
        time.sleep(0.2)
        address = create_octra_address(public_key_raw)
        
        if not verify_address_format(address):
            yield f"data: {json.dumps({'status': 'ERROR: Invalid address format generated'})}\n\n"
            return
            
        yield f"data: {json.dumps({'status': 'Address generated and verified'})}\n\n"
        time.sleep(0.2)
        
        yield f"data: {json.dumps({'status': 'Testing signature functionality...'})}\n\n"
        time.sleep(0.2)
        test_message = '{"from":"test","to":"test","amount":"1000000","nonce":1}'
        signed = signing_key.sign(test_message.encode())
        signature_b64 = base64.b64encode(signed.signature).decode()
        
        try:
            verify_key.verify(test_message.encode(), signed.signature)
            signature_valid = True
            yield f"data: {json.dumps({'status': 'Signature test passed'})}\n\n"
        except:
            signature_valid = False
            yield f"data: {json.dumps({'status': 'Signature test failed'})}\n\n"
        
        time.sleep(0.2)
        
        wallet_data = {
            'mnemonic': mnemonic,
            'seed_hex': seed.hex(),
            'master_chain_hex': master_chain.hex(),
            'private_key_hex': private_key_raw.hex(),
            'public_key_hex': public_key_raw.hex(),
            'private_key_b64': base64.b64encode(private_key_raw).decode(),
            'public_key_b64': base64.b64encode(public_key_raw).decode(),
            'address': address,
            'entropy_hex': entropy.hex(),
            'test_message': test_message,
            'test_signature': signature_b64,
            'signature_valid': signature_valid
        }
        
        yield f"data: {json.dumps({'status': 'Wallet generation complete!', 'wallet': wallet_data})}\n\n"
    
    return app.response_class(generate_steps(), mimetype='text/event-stream')

@app.route('/save', methods=['POST'])
def save_wallet():
    data = request.get_json()
    filename = f"octra_wallet_{data['address'][-8:]}_{int(time.time())}.txt"
    
    content = f"""OCTRA WALLET
{"=" * 50}

SECURITY WARNING: KEEP THIS FILE SECURE AND NEVER SHARE YOUR PRIVATE KEY

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Address Format: oct + Base58(SHA256(pubkey))

Mnemonic: {' '.join(data['mnemonic'])}
Private Key (B64): {data['private_key_b64']}
Public Key (B64): {data['public_key_b64']}
Address: {data['address']}

Technical Details:
Entropy: {data['entropy_hex']}
Signature Algorithm: Ed25519
Derivation: BIP39-compatible (PBKDF2-HMAC-SHA512, 2048 iterations)
"""
    
    with open(filename, 'w') as f:
        f.write(content)
    
    return jsonify({
        'success': True, 
        'filename': filename,
        'content': content
    })

@app.route('/derive', methods=['POST'])
def derive():
    data = request.get_json()
    seed_hex = data.get('seed_hex', '')
    network_type = data.get('network_type', 0)
    index = data.get('index', 0)
    
    try:
        seed = bytes.fromhex(seed_hex)
        derived = derive_for_network(
            seed=seed,
            network_type=network_type,
            network=0,
            contract=0,
            account=0,
            index=index
        )
        
        return jsonify({
            'success': True,
            'address': derived['address'],
            'path': '/'.join(str(i & 0x7FFFFFFF) + ("'" if i & 0x80000000 else '') for i in derived['path']),
            'network_type_name': derived['network_type_name']
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == "__main__":
    print("OCTRA Wallet Generator Web Server")
    print("Starting server on http://localhost:8888")
    app.run(host='0.0.0.0', port=8888, debug=False)

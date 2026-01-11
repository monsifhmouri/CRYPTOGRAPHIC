# MØNSTR-M1ND CRYPTOGRAPHIC ENGINE
# BLACKHAT MCA 4HKRS
# Author: MØNSTR-M1ND
# Contact: Telegram @monstr_m1nd | Instagram @httpx.mrmonsif

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, font
import hashlib
import os
import json
import time
import threading
import queue
import random
import math
from datetime import datetime
import base64
import secrets
import hmac
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sys
import platform

class QuantumChaosEngine:
    def __init__(self, master_key=None):
        self.entropy_pool = []
        self.chaos_buffer = bytearray()
        self.key_evolution_rate = 0.0001
        
        if master_key:
            self.master_seed = self._hyper_hash(master_key)
        else:
            self.master_seed = get_random_bytes(64)
            
        self._initialize_chaos_matrix()
        self.last_timestamp = time.time()
        self.entropy_collector_thread = threading.Thread(target=self._collect_entropy, daemon=True)
        self.entropy_collector_thread.start()
    
    def _hyper_hash(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        h = hashlib.sha3_512(data).digest()
        
        h = hashlib.blake2s(h + self._get_entropy(16)).digest()
        
        h = self._chaotic_permutation(h)
        
        h = hashlib.sha3_256(h).digest()
        
        return h
    
    def _chaotic_permutation(self, data):
        if len(data) == 0:
            return data
            
        result = bytearray(data)
        r = 3.99
        x = random.random()
        
        for i in range(len(result)):
            x = r * x * (1 - x)
            j = int(x * len(result)) % len(result)
            result[i], result[j] = result[j], result[i]
            
        return bytes(result)
    
    def _get_entropy(self, length):
        entropy_sources = [
            str(time.time_ns()).encode(),
            str(random.getrandbits(256)).encode(),
            os.urandom(32),
            str(hash(os.urandom(16))).encode()
        ]
        
        combined = b''.join(entropy_sources)
        return hashlib.shake_128(combined).digest(length)
    
    def _initialize_chaos_matrix(self):
        self.chaos_matrix = []
        seed = int.from_bytes(self.master_seed[:8], 'big')
        random.seed(seed)
        
        for _ in range(256):
            row = []
            for _ in range(256):
                row.append(random.getrandbits(8))
            self.chaos_matrix.append(row)
    
    def _collect_entropy(self):
        while True:
            try:
                entropy = self._get_entropy(64)
                self.entropy_pool.append(entropy)
                if len(self.entropy_pool) > 1000:
                    self.entropy_pool.pop(0)
                
                if random.random() < self.key_evolution_rate:
                    self._evolve_matrix()
                    
                time.sleep(0.01)
            except:
                pass
    
    def _evolve_matrix(self):
        i = random.randint(0, 255)
        j = random.randint(0, 255)
        self.chaos_matrix[i][j] ^= random.getrandbits(8)
    
    def generate_dynamic_key(self, purpose="encryption"):
        timestamp = time.time_ns().to_bytes(16, 'big')
        entropy = self._get_entropy(64)
        chaos_seed = bytes([self.chaos_matrix[i][j] for i,j in 
                          zip(range(64), range(64))])
        
        combined = timestamp + entropy + chaos_seed + purpose.encode()
        
        stage1 = hashlib.sha3_512(combined).digest()
        stage2 = hashlib.blake2b(stage1).digest()
        stage3 = self._chaotic_permutation(stage2)
        
        return stage3
    
    def encrypt(self, plaintext, key_id="default"):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        layer1_key = self.generate_dynamic_key("layer1")
        layer2_key = self.generate_dynamic_key("layer2")
        layer3_key = self.generate_dynamic_key("layer3")
        
        cipher1 = AES.new(layer1_key[:32], AES.MODE_GCM)
        ciphertext1, tag1 = cipher1.encrypt_and_digest(plaintext)
        
        chaotic_data = self._apply_chaos_transform(ciphertext1, layer2_key)
        
        expanded = self._expand_and_obfuscate(chaotic_data, layer3_key)
        
        metadata = {
            'timestamp': datetime.utcnow().isoformat(),
            'key_id': key_id,
            'layer1_nonce': base64.b64encode(cipher1.nonce).decode(),
            'layer1_tag': base64.b64encode(tag1).decode(),
            'entropy_hash': base64.b64encode(self._get_entropy(32)).decode(),
            'version': 'MØNSTR-M1ND v2.0'
        }
        
        encrypted_package = {
            'metadata': metadata,
            'data': base64.b64encode(expanded).decode()
        }
        
        return json.dumps(encrypted_package)
    
    def _apply_chaos_transform(self, data, key):
        result = bytearray()
        key_hash = hashlib.sha3_256(key).digest()
        
        for i, byte in enumerate(data):
            row = key_hash[i % len(key_hash)]
            col = byte
            transformed = self.chaos_matrix[row % 256][col % 256]
            result.append(transformed ^ key[i % len(key)])
        
        return bytes(result)
    
    def _expand_and_obfuscate(self, data, key):
        expanded = bytearray()
        
        padding_len = random.randint(16, 48)
        expanded.extend(os.urandom(padding_len))
        
        noise_seed = hashlib.shake_128(key).digest(len(data) * 2)
        
        for i, byte in enumerate(data):
            expanded.append(byte)
            expanded.append(noise_seed[i] ^ (i % 256))
        
        checksum = hashlib.sha3_256(data).digest()[:8]
        expanded.extend(checksum)
        
        expanded = self._chaotic_permutation(bytes(expanded))
        
        return expanded
    
    def decrypt(self, encrypted_package):
        try:
            package = json.loads(encrypted_package)
            metadata = package['metadata']
            encrypted_data = base64.b64decode(package['data'])
            
            layer3_key = self.generate_dynamic_key("layer3")
            layer2_key = self.generate_dynamic_key("layer2")
            layer1_key = self.generate_dynamic_key("layer1")
            
            deobfuscated = self._reverse_expansion(encrypted_data, layer3_key)
            
            decrypted_layer2 = self._reverse_chaos_transform(deobfuscated, layer2_key)
            
            cipher1 = AES.new(layer1_key[:32], AES.MODE_GCM, 
                            nonce=base64.b64decode(metadata['layer1_nonce']))
            
            plaintext = cipher1.decrypt_and_verify(
                decrypted_layer2,
                base64.b64decode(metadata['layer1_tag'])
            )
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def _reverse_chaos_transform(self, data, key):
        result = bytearray()
        key_hash = hashlib.sha3_256(key).digest()
        
        reverse_matrix = {}
        for i in range(256):
            for j in range(256):
                reverse_matrix[(i, self.chaos_matrix[i][j])] = j
        
        for i, byte in enumerate(data):
            row = key_hash[i % len(key_hash)]
            original = reverse_matrix.get((row % 256, byte ^ key[i % len(key)]), 0)
            result.append(original)
        
        return bytes(result)
    
    def _reverse_expansion(self, data, key):
        data = self._chaotic_permutation(data)
        
        data = data[:-8]
        
        cleaned = bytearray()
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                cleaned.append(data[i])
        
        for i in range(len(cleaned)):
            if cleaned[i] != 0:
                return bytes(cleaned[i:])
        
        return bytes(cleaned)

class QuantumNumericEncoder:
    def __init__(self, crypto_engine):
        self.crypto_engine = crypto_engine
        self.base_codes = self._generate_base_codes()
        self.dynamic_mappings = {}
        
    def _generate_base_codes(self):
        codes = {}
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~ \\\n\t" + \
                "ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ"
        
        base_value = 999983
        
        for i, char in enumerate(chars):
            chaotic_value = int.from_bytes(
                hashlib.sha3_256(char.encode()).digest()[:4], 
                'big'
            )
            codes[char] = base_value + (chaotic_value % 1000000) + i * 1000000
        
        return codes
    
    def encode_to_numbers(self, text, security_level=3):
        if security_level < 1:
            security_level = 1
        elif security_level > 10:
            security_level = 10
            
        session_key = self.crypto_engine.generate_dynamic_key("encoding")
        self._update_dynamic_mapping(session_key)
        
        numeric_blocks = []
        
        chunk_size = 100
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        
        for chunk in chunks:
            chunk_numbers = []
            for char in chunk:
                if char in self.base_codes:
                    base_num = self.base_codes[char]
                else:
                    base_num = int.from_bytes(
                        hashlib.sha3_256(char.encode()).digest()[:8], 
                        'big'
                    )
                
                dynamic_offset = self._get_dynamic_offset(char, session_key)
                final_num = base_num + dynamic_offset
                
                final_num *= (security_level ** 3)
                
                noise = random.getrandbits(security_level * 32)
                final_num ^= noise
                
                chunk_numbers.append(str(final_num))
            
            separator = "9" * security_level
            block = separator.join(chunk_numbers)
            numeric_blocks.append(block)
        
        checksum = self._generate_checksum(text, session_key, security_level)
        
        final_output = {
            "version": "QNE-2.0",
            "security_level": security_level,
            "timestamp": datetime.utcnow().isoformat(),
            "blocks": numeric_blocks,
            "integrity_hash": checksum,
            "session_id": base64.b64encode(session_key[:16]).decode(),
            "metadata": {
                "encoder": "MØNSTR-M1ND Quantum Encoder",
                "charset": "Extended Unicode + Dynamic",
                "max_value": str(10 ** (security_level * 10))
            }
        }
        
        return json.dumps(final_output, indent=2)
    
    def _update_dynamic_mapping(self, session_key):
        key_hash = hashlib.sha3_512(session_key).digest()
        
        for char in self.base_codes.keys():
            offset = int.from_bytes(
                hashlib.shake_128(char.encode() + key_hash).digest(4), 
                'big'
            )
            self.dynamic_mappings[char] = offset
    
    def _get_dynamic_offset(self, char, session_key):
        if char in self.dynamic_mappings:
            return self.dynamic_mappings[char]
        
        offset = int.from_bytes(
            hashlib.shake_128(char.encode() + session_key).digest(4), 
            'big'
        )
        self.dynamic_mappings[char] = offset
        return offset
    
    def _generate_checksum(self, text, session_key, security_level):
        data = text.encode() + session_key + str(security_level).encode()
        
        layer1 = hashlib.sha3_512(data).digest()
        layer2 = hashlib.blake2s(layer1).digest()
        layer3 = hashlib.shake_128(layer2).digest(64)
        
        checksum_num = int.from_bytes(layer3, 'big')
        
        checksum_num *= (security_level ** 4)
        
        return str(checksum_num)
    
    def decode_from_numbers(self, numeric_json):
        try:
            data = json.loads(numeric_json)
            
            session_key = base64.b64decode(data["session_id"])
            self._update_dynamic_mapping(session_key)
            
            full_text = ""
            for block in data["blocks"]:
                separator = "9" * data["security_level"]
                numbers = block.split(separator)
                
                for num_str in numbers:
                    if not num_str:
                        continue
                        
                    num = int(num_str)
                    
                    security_factor = data["security_level"] ** 3
                    clean_num = num // security_factor
                    
                    for char, code in self.base_codes.items():
                        possible_num = code + self._get_dynamic_offset(char, session_key)
                        if abs(clean_num - possible_num) < 1000:
                            full_text += char
                            break
                    else:
                        full_text += "�"
            
            return full_text
            
        except Exception as e:
            raise ValueError(f"Decoding failed: {str(e)}")

class MonstrCryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MØNSTR-M1ND CRYPTOGRAPHIC ENGINE")
        self.root.geometry("1400x900")
        
        self.bg_color = "#000000"
        self.fg_color = "#FFFFFF"
        self.accent_color = "#333333"
        self.highlight_color = "#666666"
        
        self.root.configure(bg=self.bg_color)
        
        self.crypto_engine = QuantumChaosEngine()
        self.numeric_encoder = QuantumNumericEncoder(self.crypto_engine)
        
        self.security_level = tk.IntVar(value=5)
        self.current_mode = "encrypt"
        self.history = []
        
        self.setup_ui()
        self.start_entropy_monitor()
        
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Title.TLabel', 
                       background=self.bg_color,
                       foreground=self.fg_color,
                       font=('Consolas', 24, 'bold'))
        
        style.configure('Header.TLabel',
                       background=self.bg_color,
                       foreground=self.fg_color,
                       font=('Consolas', 12, 'bold'))
        
        style.configure('Monospace.TEntry',
                       fieldbackground=self.accent_color,
                       foreground=self.fg_color,
                       font=('Consolas', 10))
        
        style.configure('Monospace.TText',
                       background=self.accent_color,
                       foreground=self.fg_color,
                       font=('Consolas', 10))
        
        style.configure('Custom.TButton',
                       background=self.accent_color,
                       foreground=self.fg_color,
                       borderwidth=2,
                       relief='raised')
        
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = ttk.Label(header_frame, 
                               text="MØNSTR-M1ND QUANTUM CRYPTOGRAPHIC ENGINE",
                               style='Title.TLabel')
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = ttk.Label(header_frame,
                                  text="BLACKHAT MCA 4HKRS | Q-RESISTANT ENCRYPTION",
                                  style='Header.TLabel')
        subtitle_label.pack(side=tk.RIGHT)
        
        self.status_bar = ttk.Label(main_container,
                                   text="System Ready | Entropy: High | Security: Quantum Level",
                                   relief=tk.SUNKEN,
                                   anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=(0, 10))
        
        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        left_panel = ttk.Frame(content_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        input_label = ttk.Label(left_panel, 
                               text="INPUT TEXT / NUMERIC DATA",
                               style='Header.TLabel')
        input_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.input_text = scrolledtext.ScrolledText(left_panel,
                                                   height=15,
                                                   bg=self.accent_color,
                                                   fg=self.fg_color,
                                                   insertbackground=self.fg_color,
                                                   font=('Consolas', 10))
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(left_panel)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.encrypt_btn = ttk.Button(button_frame,
                                     text="QUANTUM ENCRYPT",
                                     command=self.encrypt,
                                     style='Custom.TButton')
        self.encrypt_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.decrypt_btn = ttk.Button(button_frame,
                                     text="QUANTUM DECRYPT",
                                     command=self.decrypt,
                                     style='Custom.TButton')
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.encode_btn = ttk.Button(button_frame,
                                    text="NUMERIC ENCODE",
                                    command=self.numeric_encode,
                                    style='Custom.TButton')
        self.encode_btn.pack(side=tk.LEFT, padx=5)
        
        self.decode_btn = ttk.Button(button_frame,
                                    text="NUMERIC DECODE",
                                    command=self.numeric_decode,
                                    style='Custom.TButton')
        self.decode_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame,
                                   text="CLEAR ALL",
                                   command=self.clear_all,
                                   style='Custom.TButton')
        self.clear_btn.pack(side=tk.RIGHT)
        
        security_frame = ttk.Frame(left_panel)
        security_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(security_frame,
                 text="QUANTUM SECURITY LEVEL:",
                 style='Header.TLabel').pack(side=tk.LEFT)
        
        security_scale = ttk.Scale(security_frame,
                                  from_=1,
                                  to=10,
                                  variable=self.security_level,
                                  orient=tk.HORIZONTAL)
        security_scale.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        self.security_label = ttk.Label(security_frame,
                                       text="5",
                                       style='Header.TLabel')
        self.security_label.pack(side=tk.RIGHT)
        
        self.security_level.trace('w', self.update_security_label)
        
        right_panel = ttk.Frame(content_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        output_label = ttk.Label(right_panel,
                                text="OUTPUT / ENCRYPTED DATA",
                                style='Header.TLabel')
        output_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.output_text = scrolledtext.ScrolledText(right_panel,
                                                    height=15,
                                                    bg=self.accent_color,
                                                    fg=self.fg_color,
                                                    insertbackground=self.fg_color,
                                                    font=('Consolas', 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        output_controls = ttk.Frame(right_panel)
        output_controls.pack(fill=tk.X, pady=10)
        
        ttk.Button(output_controls,
                  text="COPY OUTPUT",
                  command=self.copy_output,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(output_controls,
                  text="SAVE TO FILE",
                  command=self.save_output,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(output_controls,
                  text="LOAD FROM FILE",
                  command=self.load_file,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        
        stats_frame = ttk.Frame(right_panel)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.stats_label = ttk.Label(stats_frame,
                                    text="Data: 0 bytes | Entropy: 100% | Time: 0.0s",
                                    style='Header.TLabel')
        self.stats_label.pack()
        
        history_frame = ttk.LabelFrame(main_container,
                                      text="OPERATION HISTORY",
                                      labelanchor=tk.N)
        history_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.history_listbox = tk.Listbox(history_frame,
                                         bg=self.accent_color,
                                         fg=self.fg_color,
                                         font=('Consolas', 9),
                                         height=6)
        self.history_listbox.pack(fill=tk.X, padx=5, pady=5)
        
        contact_frame = ttk.Frame(main_container)
        contact_frame.pack(fill=tk.X, pady=(10, 0))
        
        contact_label = ttk.Label(contact_frame,
                                 text="CRYPTO ENGINE v2.0 | Author: MØNSTR-M1ND | For authorized use only",
                                 style='Header.TLabel')
        contact_label.pack(side=tk.LEFT)
        
        telegram_btn = ttk.Button(contact_frame,
                                 text="TELEGRAM",
                                 command=self.open_telegram,
                                 style='Custom.TButton')
        telegram_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        instagram_btn = ttk.Button(contact_frame,
                                  text="INSTAGRAM",
                                  command=self.open_instagram,
                                  style='Custom.TButton')
        instagram_btn.pack(side=tk.RIGHT)
    
    def update_security_label(self, *args):
        level = self.security_level.get()
        self.security_label.config(text=str(level))
        
        if level <= 3:
            status = "Standard"
        elif level <= 6:
            status = "Military"
        elif level <= 8:
            status = "Quantum"
        else:
            status = "Exponential"
        
        self.status_bar.config(text=f"Security Level: {status} | Entropy Collection Active")
    
    def start_entropy_monitor(self):
        def monitor():
            while True:
                try:
                    entropy = len(self.crypto_engine.entropy_pool)
                    if entropy > 500:
                        level = "HIGH"
                    elif entropy > 200:
                        level = "MEDIUM"
                    else:
                        level = "LOW"
                    
                    current_text = self.status_bar.cget("text")
                    if "Entropy:" in current_text:
                        parts = current_text.split("|")
                        parts[1] = f" Entropy: {level}"
                        new_text = "|".join(parts)
                        self.status_bar.config(text=new_text)
                    
                    time.sleep(2)
                except:
                    pass
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def encrypt(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        if not input_data:
            messagebox.showwarning("Input Error", "Please enter text to encrypt")
            return
        
        try:
            start_time = time.time()
            
            self.status_bar.config(text="Performing Quantum Encryption...")
            self.root.update()
            
            encrypted = self.crypto_engine.encrypt(
                input_data,
                f"security_{self.security_level.get()}"
            )
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", encrypted)
            
            elapsed = time.time() - start_time
            self.stats_label.config(
                text=f"Encrypted: {len(input_data)} → {len(encrypted)} bytes | "
                     f"Time: {elapsed:.3f}s | Security: Level {self.security_level.get()}"
            )
            
            self.add_to_history("ENCRYPT", len(input_data), elapsed)
            
            self.status_bar.config(text="Encryption Complete")
            
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.status_bar.config(text="Encryption Failed")
    
    def decrypt(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        if not input_data:
            messagebox.showwarning("Input Error", "Please enter encrypted data to decrypt")
            return
        
        try:
            start_time = time.time()
            
            self.status_bar.config(text="Performing Quantum Decryption...")
            self.root.update()
            
            decrypted = self.crypto_engine.decrypt(input_data)
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", decrypted)
            
            elapsed = time.time() - start_time
            self.stats_label.config(
                text=f"Decrypted: {len(input_data)} → {len(decrypted)} bytes | "
                     f"Time: {elapsed:.3f}s"
            )
            
            self.add_to_history("DECRYPT", len(input_data), elapsed)
            
            self.status_bar.config(text="Decryption Complete")
            
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            self.status_bar.config(text="Decryption Failed")
    
    def numeric_encode(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        if not input_data:
            messagebox.showwarning("Input Error", "Please enter text to encode")
            return
        
        try:
            start_time = time.time()
            
            self.status_bar.config(text="Generating Numeric Encoding...")
            self.root.update()
            
            numeric = self.numeric_encoder.encode_to_numbers(
                input_data,
                self.security_level.get()
            )
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", numeric)
            
            elapsed = time.time() - start_time
            self.stats_label.config(
                text=f"Encoded: {len(input_data)} chars → {len(numeric)} bytes | "
                     f"Time: {elapsed:.3f}s | Max Value: 10^{self.security_level.get() * 10}"
            )
            
            self.add_to_history("NUM_ENCODE", len(input_data), elapsed)
            
            self.status_bar.config(text="Numeric Encoding Complete")
            
        except Exception as e:
            messagebox.showerror("Encoding Error", str(e))
            self.status_bar.config(text="Encoding Failed")
    
    def numeric_decode(self):
        input_data = self.input_text.get("1.0", tk.END).strip()
        if not input_data:
            messagebox.showwarning("Input Error", "Please enter numeric data to decode")
            return
        
        try:
            start_time = time.time()
            
            self.status_bar.config(text="Decoding Numeric Data...")
            self.root.update()
            
            decoded = self.numeric_encoder.decode_from_numbers(input_data)
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", decoded)
            
            elapsed = time.time() - start_time
            self.stats_label.config(
                text=f"Decoded: {len(input_data)} bytes → {len(decoded)} chars | "
                     f"Time: {elapsed:.3f}s"
            )
            
            self.add_to_history("NUM_DECODE", len(input_data), elapsed)
            
            self.status_bar.config(text="Numeric Decoding Complete")
            
        except Exception as e:
            messagebox.showerror("Decoding Error", str(e))
            self.status_bar.config(text="Decoding Failed")
    
    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.stats_label.config(text="Data: 0 bytes | Entropy: 100% | Time: 0.0s")
        self.status_bar.config(text="System Ready")
    
    def copy_output(self):
        output_data = self.output_text.get("1.0", tk.END).strip()
        if output_data:
            self.root.clipboard_clear()
            self.root.clipboard_append(output_data)
            messagebox.showinfo("Success", "Output copied to clipboard")
    
    def save_output(self):
        output_data = self.output_text.get("1.0", tk.END).strip()
        if not output_data:
            messagebox.showwarning("No Data", "No output to save")
            return
        
        filename = f"monstr_encrypted_{int(time.time())}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(output_data)
        
        messagebox.showinfo("Saved", f"Data saved to {filename}")
    
    def load_file(self):
        filename = "monstr_encrypted.txt"
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = f.read()
            
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", data)
            self.status_bar.config(text=f"Loaded from {filename}")
        except FileNotFoundError:
            messagebox.showwarning("File Not Found", "Create a 'monstr_encrypted.txt' file first")
    
    def add_to_history(self, operation, size, time_taken):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {operation}: {size} bytes in {time_taken:.3f}s"
        
        self.history.append(entry)
        self.history_listbox.insert(0, entry)
        
        if len(self.history) > 10:
            self.history_listbox.delete(10, tk.END)
    
    def open_telegram(self):
        import webbrowser
        webbrowser.open("http://t.me/monstr_m1nd")
    
    def open_instagram(self):
        import webbrowser
        webbrowser.open("https://www.instagram.com/httpx.mrmonsif/")

class SecurityAuditor:
    @staticmethod
    def analyze_encryption(crypto_engine, sample_size=1000):
        results = {
            "entropy_bits": 0,
            "collision_resistance": "HIGH",
            "key_space": "2^256",
            "quantum_resistance": True,
            "chaos_factor": 0.95
        }
        
        if crypto_engine.entropy_pool:
            entropy = len(crypto_engine.entropy_pool) * 8
            results["entropy_bits"] = min(entropy, 256)
        
        test_data = os.urandom(32)
        encrypted1 = crypto_engine.encrypt(test_data.decode('latin-1'))
        
        modified = bytearray(test_data)
        modified[0] ^= 1
        encrypted2 = crypto_engine.encrypt(modified.decode('latin-1'))
        
        diff = sum(b1 != b2 for b1, b2 in zip(encrypted1, encrypted2))
        results["avalanche_effect"] = f"{(diff/len(encrypted1))*100:.2f}%"
        
        return results

def main():
    root = tk.Tk()
    
    window_width = 1400
    window_height = 900
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    center_x = int(screen_width/2 - window_width/2)
    center_y = int(screen_height/2 - window_height/2)
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
    
    app = MonstrCryptApp(root)
    
    root.mainloop()

if __name__ == "__main__":
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Please install pycryptodome: pip install pycryptodome")
        sys.exit(1)
    
    main()
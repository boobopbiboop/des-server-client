import socket
import threading
import sys

# Import DES class (pastikan des_lib.py ada di folder yang sama)
from des_lib import DES

# Shared DES Key (8 bytes)
DES_KEY = b'secret12'

class DESChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.des = DES(DES_KEY)
        self.server_socket = None
        self.client_socket = None
        self.running = False
        self.receive_lock = threading.Lock()
        
    def receive_messages(self):
        """Thread untuk menerima pesan dari client"""
        while self.running:
            try:
                # Terima panjang pesan
                length_data = self.client_socket.recv(4)
                if not length_data:
                    break
                    
                msg_length = int.from_bytes(length_data, byteorder='big')
                
                # Terima pesan terenkripsi
                encrypted_data = b''
                while len(encrypted_data) < msg_length:
                    chunk = self.client_socket.recv(msg_length - len(encrypted_data))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                if not encrypted_data:
                    break
                
                # Tampilkan proses dekripsi
                with self.receive_lock:
                    print("\n" + "="*70)
                    print("🔔 NOTIFIKASI: CLIENT MENGIRIM PESAN!")
                    print("="*70)
                    print(f"Ciphertext diterima: {encrypted_data.hex().upper()}")
                    # print(f"Key yang digunakan : {DES_KEY.decode('utf-8')}")
                    
                    # Dekripsi pesan
                    decrypted_msg = self.des.decrypt(encrypted_data).decode('utf-8')
                    print(f"Plaintext (hasil dekripsi): {decrypted_msg}")
                    print("="*70 + "\n")
                
            except Exception as e:
                if self.running:
                    print(f"\n[ERROR] Receiving: {e}")
                break
    
    def show_menu(self):
        """Tampilkan menu"""
        print("\n" + "="*70)
        print("MENU:")
        print("1. Encrypt dan kirim ke Client")
        print("2. Decrypt lokal (testing)")
        print("3. Exit")
        print("="*70)
    
    def encrypt_and_send(self):
        """Menu 1: Encrypt dan kirim pesan"""
        print("\n📤 ENCRYPTION & SEND")
        print("-" * 70)
        
        plaintext = input("Masukkan plaintext (ASCII): ").strip()
        if not plaintext:
            print("❌ Plaintext tidak boleh kosong!")
            return
        
        # Cek apakah plaintext adalah ASCII
        try:
            plaintext.encode('ascii')
        except UnicodeEncodeError:
            print("❌ Plaintext harus berupa karakter ASCII!")
            return
        
        key_input = input("Masukkan key (8 karakter ASCII): ").strip()
        if len(key_input) != 8:
            print("❌ Key harus 8 karakter!")
            return
        
        # Cek apakah key adalah ASCII
        try:
            key_input.encode('ascii')
        except UnicodeEncodeError:
            print("❌ Key harus berupa karakter ASCII!")
            return
        
        try:
            # Buat DES instance dengan key yang diinput
            des_temp = DES(key_input.encode('utf-8'))
            
            # Enkripsi
            encrypted_msg = des_temp.encrypt(plaintext.encode('utf-8'))
            
            print("\n" + "-" * 70)
            print(f"Plaintext  : {plaintext}")
            print(f"Key        : {key_input}")
            print(f"Ciphertext : {encrypted_msg.hex().upper()}")
            print("-" * 70)
            
            # Kirim ke client
            msg_length = len(encrypted_msg).to_bytes(4, byteorder='big')
            self.client_socket.send(msg_length)
            self.client_socket.send(encrypted_msg)
            
            print("✅ Pesan berhasil dikirim ke Client\n")
            
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def decrypt_local(self):
        """Menu 2: Decrypt lokal untuk testing"""
        print("\n🔓 LOCAL DECRYPTION (Testing)")
        print("-" * 70)
        
        ciphertext_hex = input("Masukkan ciphertext (hex): ").strip()
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
        except ValueError:
            print("❌ Format hex tidak valid!")
            return
        
        key_input = input("Masukkan key (8 karakter ASCII): ").strip()
        if len(key_input) != 8:
            print("❌ Key harus 8 karakter!")
            return
        
        # Cek apakah key adalah ASCII
        try:
            key_input.encode('ascii')
        except UnicodeEncodeError:
            print("❌ Key harus berupa karakter ASCII!")
            return
        
        try:
            # Buat DES instance dengan key yang diinput
            des_temp = DES(key_input.encode('utf-8'))
            
            # Dekripsi
            decrypted_msg = des_temp.decrypt(ciphertext).decode('utf-8')
            
            print("\n" + "-" * 70)
            print(f"Ciphertext : {ciphertext_hex.upper()}")
            print(f"Key        : {key_input}")
            print(f"Plaintext  : {decrypted_msg}")
            print("-" * 70 + "\n")
            
        except Exception as e:
            print(f"❌ Error dekripsi: {e}")
    
    def menu_loop(self):
        """Loop menu utama"""
        print("\n[INFO] Chat dimulai! Pilih menu untuk mulai.\n")
        
        while self.running:
            try:
                self.show_menu()
                choice = input("Pilih menu (1/2/3): ").strip()
                
                if choice == '1':
                    self.encrypt_and_send()
                elif choice == '2':
                    self.decrypt_local()
                elif choice == '3':
                    print("\n[INFO] Keluar dari chat...")
                    self.running = False
                    break
                else:
                    print("❌ Pilihan tidak valid!")
                    
            except EOFError:
                # Handle EOF (Ctrl+D)
                print("\n[INFO] Keluar dari chat...")
                self.running = False
                break
            except KeyboardInterrupt:
                print("\n[INFO] Interrupted by user")
                self.running = False
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def start(self):
        """Jalankan server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            print("="*70)
            print("DES ENCRYPTED CHAT - SERVER (Pure Python Implementation)")
            print("="*70)
            print(f"[INFO] Binding to {self.host}:{self.port}...")
            self.server_socket.bind((self.host, self.port))
            
            print(f"[INFO] Listening for connections...")
            self.server_socket.listen(5)
            
            # Tampilkan IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"[INFO] Server IP: {local_ip}")
            print(f"[INFO] Default DES Key: {DES_KEY.decode('utf-8')}")
            print("[INFO] Menunggu client untuk terhubung...")
            
            self.client_socket, client_address = self.server_socket.accept()
            print(f"\n✅ [SUCCESS] Client terhubung dari {client_address}")
            
            self.running = True
            
            # Start receive thread
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
            
            # Menu loop di main thread
            self.menu_loop()
            
        except KeyboardInterrupt:
            print("\n[INFO] Server dihentikan oleh user")
        except Exception as e:
            print(f"[ERROR] Server error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Bersihkan resource"""
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("\n[INFO] Server ditutup.")

if __name__ == "__main__":
    print("\n⚠️  PASTIKAN file 'des_lib.py' ada di folder yang sama!")
    print("    (Copy DES class dari kode di atas)\n")
    
    try:
        server = DESChatServer()
        server.start()
    except ImportError:
        print("\n❌ ERROR: File 'des_lib.py' tidak ditemukan!")
        print("   Silakan save DES class sebagai 'des_lib.py' dulu.\n")

import pgpy
import os
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

class PGPFileProcessor:
    def __init__(self, key_dir):
        self.key_dir = key_dir
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir)

    def generate_keys(self, name, email, passphrase):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        uid = pgpy.PGPUID.new(name, email=email)
        key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                    ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        
        pub_key_path = os.path.join(self.key_dir, f"{email}_pub.asc")
        priv_key_path = os.path.join(self.key_dir, f"{email}_priv.asc")

        with open(pub_key_path, "wb") as f:
            f.write(str(key.pubkey).encode('utf-8'))

        with open(priv_key_path, "wb") as f:
            f.write(str(key).encode('utf-8'))
            
        return pub_key_path, priv_key_path

    def encrypt_files(self, file_paths, recipient_pub_key_path, output_dir):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        pub_key = pgpy.PGPKey.from_file(recipient_pub_key_path)[0]
        
        encrypted_files = []
        for file_path in file_paths:
            with open(file_path, 'rb') as f:
                message = pgpy.PGPMessage.new(f.read(), file=True)
            
            encrypted_message = pub_key.encrypt(message)
            
            encrypted_file_path = os.path.join(output_dir, os.path.basename(file_path) + ".pgp")
            with open(encrypted_file_path, "wb") as f:
                f.write(str(encrypted_message).encode('utf-8'))
            encrypted_files.append(encrypted_file_path)
        return encrypted_files

    def decrypt_files(self, file_paths, owner_priv_key_path, passphrase, output_dir):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        priv_key = pgpy.PGPKey.from_file(owner_priv_key_path)[0]
        
        decrypted_files = []
        for file_path in file_paths:
            with priv_key.unlock(passphrase):
                with open(file_path, 'rb') as f:
                    encrypted_message = pgpy.PGPMessage.from_blob(f.read())
                decrypted_message = priv_key.decrypt(encrypted_message).message
                
                decrypted_file_path = os.path.join(output_dir, os.path.basename(file_path).replace(".pgp", ""))
                with open(decrypted_file_path, "wb") as f:
                    if isinstance(decrypted_message, str):
                        f.write(decrypted_message.encode('utf-8'))
                    else:
                        f.write(decrypted_message)
                decrypted_files.append(decrypted_file_path)
        return decrypted_files

if __name__ == '__main__':
    # Create a PGPFileProcessor instance
    processor = PGPFileProcessor(key_dir="/home/liuxf/working/keys")

    # Generate keys for two users
    alice_pub, alice_priv = processor.generate_keys("Alice", "alice@example.com", "alice_passphrase")
    bob_pub, bob_priv = processor.generate_keys("Bob", "bob@example.com", "bob_passphrase")

    # Create a dummy file to encrypt
    with open("/home/liuxf/working/secret.txt", "w") as f:
        f.write("This is a secret file for Bob.")

    # Alice encrypts a file for Bob
    encrypted_files = processor.encrypt_files(["/home/liuxf/working/secret.txt"], bob_pub, "/home/liuxf/working/encrypted")
    print(f"Encrypted files: {encrypted_files}")

    # Bob decrypts the file
    decrypted_files = processor.decrypt_files(encrypted_files, bob_priv, "bob_passphrase", "/home/liuxf/working/decrypted")
    print(f"Decrypted files: {decrypted_files}")

    # Verify the content of the decrypted file
    with open(decrypted_files[0], 'r') as f:
        print(f"Decrypted content: {f.read()}")

#!/usr/bin/env python3
"""
Home Assistant Backup Decryption Tool
-----------------------------------
This script automatically decrypts Home Assistant backups using the emergency kit.
Place this script in the same directory as:
- Your Home Assistant emergency kit text file
- Your backup .tar file(s)

Requirements:
pip install cryptography

Usage:
1. Place this script in a directory with your backup files
2. Make it executable: chmod +x decrypt_backup.py
3. Run it: ./decrypt_backup.py
"""

import sys
import tarfile
import glob
import os
import shutil
import re
import platform
import argparse
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
import hashlib

def check_requirements():
    """Check if required packages are installed."""
    try:
        import cryptography
    except ImportError:
        print("Error: Required package 'cryptography' is not installed.")
        print("Please install it using: pip install cryptography")
        sys.exit(1)

def sanitize_filename(name):
    """Sanitize filename for Windows compatibility."""
    if platform.system() == 'Windows':
        # Replace characters that are invalid in Windows filenames
        invalid_chars = '<>:"|?*'
        for char in invalid_chars:
            name = name.replace(char, '_')
    return name

def tar_filter(member, dest_path):
    """Filter for tar extraction to handle cross-platform filename issues."""
    member.name = sanitize_filename(member.name)
    return member

def extract_key_from_kit(kit_path):
    """Extract encryption key from emergency kit file."""
    try:
        with open(kit_path, 'r') as f:
            content = f.read()
            # Look for the key pattern: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
            match = re.search(r'\b([A-Z0-9]{4}-){6}[A-Z0-9]{4}\b', content)
            if match:
                return match.group(0)
    except Exception as e:
        print(f"Error reading emergency kit file: {e}")
    return None

def password_to_key(password):
    """Convert password/key to encryption key."""
    password = password.encode()
    for _ in range(100):
        password = hashlib.sha256(password).digest()
    return password[:16]

def generate_iv(key, salt):
    """Generate initialization vector."""
    temp_iv = key + salt
    for _ in range(100):
        temp_iv = hashlib.sha256(temp_iv).digest()
    return temp_iv[:16]

class SecureTarFile:
    """Handle encrypted tar files."""
    def __init__(self, filename, password):
        self._file = None
        self._name = Path(filename)
        self._tar = None
        self._tar_mode = "r|gz"
        self._aes = None
        self._key = password_to_key(password)
        self._decrypt = None

    def __enter__(self):
        self._file = self._name.open("rb")
        cbc_rand = self.read_rand_from_header(self._file)
        self._aes = Cipher(
            algorithms.AES(self._key),
            modes.CBC(generate_iv(self._key, cbc_rand)),
            backend=default_backend(),
        )
        self._decrypt = self._aes.decryptor()
        self._tar = tarfile.open(fileobj=self, mode=self._tar_mode)
        return self._tar

    def __exit__(self, exc_type, exc_value, traceback):
        if self._tar:
            self._tar.close()
        if self._file:
            self._file.close()

    def read_rand_from_header(cls, st_file):
        """Return header bytes."""
        SECURETAR_MAGIC = b"SecureTar\x02\x00\x00\x00\x00\x00\x00"
        BLOCK_SIZE = 16
        IV_SIZE = BLOCK_SIZE
        header = st_file.read(len(SECURETAR_MAGIC))
        if header != SECURETAR_MAGIC:
            cbc_rand = header
        else:
            plaintext_size = int.from_bytes(st_file.read(8), "big")
            st_file.read(8)  # Skip reserved bytes
            cbc_rand = st_file.read(IV_SIZE)
        return cbc_rand


    def read(self, size=0):
        return self._decrypt.update(self._file.read(size))

def extract_tar(filename):
    """Extract regular tar file."""
    _dirname = '.'.join(filename.split('.')[:-1])
    try:
        shutil.rmtree(_dirname)
    except FileNotFoundError:
        pass
    print(f'📦 Extracting {filename}...')
    _tar = tarfile.open(name=filename, mode="r")
    _tar.extractall(path=_dirname, filter=tar_filter)
    return _dirname

def extract_secure_tar(filename, password):
    """Extract encrypted tar file."""
    _dirname = '.'.join(filename.split('.')[:-2])
    print(f'🔓 Decrypting {filename.split("/")[-1]}...')
    try:
        with SecureTarFile(filename, password) as _tar:
            _tar.extractall(path=_dirname, filter=tar_filter)
    except tarfile.ReadError:
        print("❌ Error: Unable to extract SecureTar - possible wrong password or file is not encrypted")
        return None
    except Exception as e:
        print(f"❌ Error during extraction: {str(e)}")
        return None
    return _dirname

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Decrypt Home Assistant backup files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Interactive mode
  %(prog)s --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
  %(prog)s --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX --file backup.tar
  %(prog)s --key XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX --output-dir ./decrypted
        """
    )
    parser.add_argument(
        '--key',
        '-k',
        help='Encryption key (format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX)'
    )
    parser.add_argument(
        '--file',
        '-f',
        help='Specific backup .tar file to decrypt (defaults to all .tar files in current directory)'
    )
    parser.add_argument(
        '--output-dir',
        '-o',
        help='Output directory for decrypted files (defaults to current directory)'
    )
    parser.add_argument(
        '--cleanup',
        '-c',
        action='store_true',
        help='Remove encrypted .tar.gz files after successful decryption (default behavior)'
    )
    parser.add_argument(
        '--keep-encrypted',
        action='store_true',
        help='Keep encrypted .tar.gz files after decryption'
    )
    return parser.parse_args()

def main():
    print("\n🏠 Home Assistant Backup Decryption Tool")
    print("=======================================")

    # Check requirements first
    check_requirements()

    # Change to the directory where the script/executable is located
    # This allows double-clicking the executable to work properly
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller executable
        script_dir = os.path.dirname(sys.executable)
    else:
        # Running as Python script
        script_dir = os.path.dirname(os.path.abspath(__file__))

    if script_dir:
        os.chdir(script_dir)

    # Parse command line arguments
    args = parse_args()

    # Handle key: CLI arg > emergency kit > manual input
    key = args.key

    if not key:
        # Look for emergency kit file
        kit_files = glob.glob('*emergency*kit*.txt')

        # Try to extract key from the kit file first
        if kit_files:
            key = extract_key_from_kit(kit_files[0])
            if key:
                print(f"✅ Found encryption key in {kit_files[0]}")
            else:
                print("⚠️  Could not find encryption key in emergency kit file.")
        else:
            print("⚠️  No emergency kit file found.")

    # If key not found, ask for manual entry
    if not key:
        print("\nPlease enter your encryption key manually.")
        print("It should be in the format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
        while True:
            manual_key = input("Key: ").strip()
            if re.match(r'^([A-Z0-9]{4}-){6}[A-Z0-9]{4}$', manual_key):
                key = manual_key
                print("✅ Key format verified")
                break
            else:
                print("❌ Invalid key format. Please try again.")
    else:
        # Validate key format from CLI
        if not re.match(r'^([A-Z0-9]{4}-){6}[A-Z0-9]{4}$', key):
            print("❌ Error: Invalid key format!")
            print("Key should be in the format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")
            sys.exit(1)
        print("✅ Key format verified")

    # Change to output directory if specified
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        os.chdir(args.output_dir)
        print(f"📂 Output directory: {args.output_dir}")

    # Look for tar files
    if args.file:
        if not os.path.exists(args.file):
            print(f"❌ Error: File '{args.file}' not found!")
            sys.exit(1)
        tar_files = [args.file]
    else:
        tar_files = glob.glob('*.tar')

    if not tar_files:
        print("❌ Error: No .tar files found!")
        print("Please place your backup .tar files in this directory.")
        sys.exit(1)

    print(f"📁 Found {len(tar_files)} backup file(s) to process")

    # Determine cleanup behavior
    should_cleanup = not args.keep_encrypted
    
    success_count = 0
    for tar_file in tar_files:
        try:
            _dirname = extract_tar(tar_file)
            # Look for encrypted tar.gz files in the extracted directory
            secure_tars = glob.glob(f'{_dirname}/*.tar.gz')
            if not secure_tars:
                print(f"ℹ️  No encrypted files found in {tar_file}")
                continue
                
            for secure_tar in secure_tars:
                if extract_secure_tar(secure_tar, key):
                    if should_cleanup:
                        os.remove(secure_tar)  # Remove the encrypted file after successful extraction
                    success_count += 1
        except Exception as e:
            print(f"❌ Error processing {tar_file}: {str(e)}")
    
    if success_count > 0:
        print(f"\n✅ Successfully decrypted {success_count} backup file(s)!")
        print("You can find the decrypted files in the extracted directories.")
    else:
        print("\n⚠️  No files were successfully decrypted.")
        print("Please check that your backup files and emergency kit are correct.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        sys.exit(1)

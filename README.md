# IV_Encrypt  🐧 ❤️  
![License](https://img.shields.io/badge/license-MIT-green) ![Language](https://img.shields.io/badge/language-C-blue) ![Platform](https://img.shields.io/badge/platform-Linux-black)

**Lightweight Linux image viewer · metadata editor · encrypted steganography**  
*With love for the Linux community.*

---

## ⚡ Features
- 🖼️ View images (4K+), fixed 1200×600 UI with a scrollable preview  
- 📝 Read & edit image metadata (written back into the image via `exiftool`)  
- 🔒 Encrypt messages (libsodium) and hide them in image pixels (LSB)  
- 🔍 Extract & decrypt messages with the correct password  
- ⚙️ Non-blocking metadata write (worker thread + progress spinner)

---

## 🧩 Dependencies (minimal)
- `gcc`, `pkg-config`  
- `libgtk-3-dev`, `libgdk-pixbuf2.0-dev`  
- `libsodium-dev`  
- `libexif-dev` *(optional)*  
- `exiftool` (runtime)

**Ubuntu / Debian example**
```bash
sudo apt install build-essential pkg-config \
libgtk-3-dev libgdk-pixbuf2.0-dev libsodium-dev libexif-dev \
libimage-exiftool-perl
```

Built with **GTK3**, **GdkPixbuf**, **libsodium**, and **exiftool**.

---

## Features
- Fixed-size modern GTK interface (1200×600)
- Fast image preview without resizing the app
- Read & edit metadata of images (JPEG, PNG, etc.)
- Metadata is written **directly into the image**
- Strong encryption using libsodium
- Steganography using LSB (Least Significant Bit)
- Only users with the correct password can decrypt hidden messages

---

## Dependencies

### Build dependencies
- gcc
- pkg-config
- libgtk-3-dev
- libgdk-pixbuf2.0-dev
- libsodium-dev
- libexif-dev
- exiftool (runtime)

### Ubuntu / Debian
```bash
sudo apt install build-essential pkg-config \
libgtk-3-dev libgdk-pixbuf2.0-dev \
libsodium-dev libexif-dev \
libimage-exiftool-perl
```
### Fedora
```bash
sudo dnf install gcc pkgconf-pkg-config \
gtk3-devel gdk-pixbuf2-devel \
libsodium-devel perl-Image-ExifTool
```
### Build
```bash
gcc iv_encrypt.c -o iv_encrypt \
`pkg-config --cflags --libs gtk+-3.0 gdk-pixbuf-2.0 libexif` \
-lsodium -lm
```
### Run
```bash
./iv_encrypt
```
Or open an image directly:
```bash
./iv_encrypt image.jpg
```

### How It Works :

 - Metadata is read and written using exiftool

 - Messages are encrypted using libsodium

 - Encrypted data is embedded in image pixels (LSB steganography)

 - The resulting image looks normal but contains hidden data

 - Without the password, the message cannot be decrypted

### Notes

 - Stego images are saved as PNG to avoid data loss

 - If the password is lost, the message is unrecoverable

 - Always keep backups of original images

### License

MIT License

### Credits

 - GTK & GdkPixbuf

 - libsodium

 - exiftool

 - Linux open-source community



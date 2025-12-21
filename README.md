# IV_Encrypt  
*With love for the Linux community ❤️*

IV_Encrypt is a lightweight Linux application written in **C** that allows you to:
- View images (including 4K+)
- Read and modify image metadata directly inside the image
- Encrypt and hide secret messages inside images (steganography)
- Decrypt hidden messages using a password

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

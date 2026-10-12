// ============================================================================
//  STEGANOGRAPHY TOOL  (C++)
//  Hide encrypted text or files inside a 24-bit BMP image using LSB technique.
//
//  Features:
//    1. Capacity calculator (how much data fits in an image)
//    2. Embed text   (encrypted with a password, hidden in the image)
//    3. Embed a file (any file type, encrypted, hidden in the image)
//    4. Extract      (get the hidden text/file back using the password)
//    5. Create a sample image (so you can demo without needing your own)
//
//  No external libraries needed. BMP reading/writing is built in.
//
//  Compile:   g++ -std=c++11 -O2 stego.cpp -o stego
//  Run:       ./stego        (Windows: stego.exe)
//
//  HOW LSB WORKS:
//  Every pixel colour value is a byte (0-255). The LAST bit (least significant
//  bit) changes the colour by only 1 out of 255, which the human eye cannot
//  see. So we replace that last bit with one bit of our secret data.
//  1 byte of secret = 8 image bytes. Every pixel has 3 bytes (B, G, R).
// ============================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <cmath>

using namespace std;

typedef vector<uint8_t> Bytes;

// ----------------------------------------------------------------------------
//  PART 1: BMP IMAGE HANDLING
// ----------------------------------------------------------------------------

struct Bmp {
    Bytes file;        // the entire BMP file in memory
    uint32_t offset;   // where the pixel data starts inside the file
    int width;         // image width in pixels
    int height;        // image height in pixels (always stored positive here)
    int rowSize;       // bytes per row INCLUDING padding (rows are multiple of 4)
};

static uint32_t read32(const Bytes &b, size_t p) {
    return (uint32_t)b[p] | ((uint32_t)b[p + 1] << 8) |
           ((uint32_t)b[p + 2] << 16) | ((uint32_t)b[p + 3] << 24);
}

static void write32(Bytes &b, size_t p, uint32_t v) {
    b[p] = v & 0xFF;
    b[p + 1] = (v >> 8) & 0xFF;
    b[p + 2] = (v >> 16) & 0xFF;
    b[p + 3] = (v >> 24) & 0xFF;
}

static bool readFile(const string &path, Bytes &out) {
    ifstream in(path.c_str(), ios::binary);
    if (!in) return false;
    out.assign((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    return true;
}

static bool writeFile(const string &path, const Bytes &data) {
    ofstream out(path.c_str(), ios::binary);
    if (!out) return false;
    out.write((const char *)data.data(), data.size());
    return (bool)out;
}

// Load and validate a 24-bit uncompressed BMP.
static bool loadBmp(const string &path, Bmp &img) {
    if (!readFile(path, img.file)) {
        cout << "  [Error] Cannot open file: " << path << "\n";
        return false;
    }
    const Bytes &f = img.file;
    if (f.size() < 54 || f[0] != 'B' || f[1] != 'M') {
        cout << "  [Error] This is not a BMP file.\n";
        return false;
    }
    img.offset = read32(f, 10);
    img.width = (int)read32(f, 18);
    int h = (int)read32(f, 22);
    img.height = h < 0 ? -h : h;
    uint16_t bpp = f[28] | (f[29] << 8);
    uint32_t compression = read32(f, 30);

    if (bpp != 24 || compression != 0) {
        cout << "  [Error] Only 24-bit uncompressed BMP images are supported.\n"
             << "          (Tip: in Paint, 'Save as' -> 'BMP picture' -> 24-bit.)\n";
        return false;
    }
    img.rowSize = ((img.width * 3 + 3) / 4) * 4;
    size_t needed = (size_t)img.offset + (size_t)img.rowSize * img.height;
    if (img.width <= 0 || img.height <= 0 || f.size() < needed) {
        cout << "  [Error] The BMP file looks damaged.\n";
        return false;
    }
    return true;
}

// Number of usable colour bytes (padding bytes are skipped).
static size_t usableBytes(const Bmp &img) {
    return (size_t)img.width * 3 * img.height;
}

// Convert "n-th usable colour byte" into its real position in the file.
static size_t bytePos(const Bmp &img, size_t n) {
    size_t perRow = (size_t)img.width * 3;
    size_t row = n / perRow;
    size_t col = n % perRow;
    return img.offset + row * img.rowSize + col;
}

// Create a colourful gradient test image so the tool can be demoed instantly.
static bool createSampleBmp(const string &path, int w, int h) {
    int rowSize = ((w * 3 + 3) / 4) * 4;
    Bytes f(54 + (size_t)rowSize * h, 0);
    f[0] = 'B';
    f[1] = 'M';
    write32(f, 2, (uint32_t)f.size());
    write32(f, 10, 54);
    write32(f, 14, 40);        // DIB header size
    write32(f, 18, (uint32_t)w);
    write32(f, 22, (uint32_t)h);
    f[26] = 1;                 // planes
    f[28] = 24;                // bits per pixel
    write32(f, 34, (uint32_t)(rowSize * h));
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            size_t p = 54 + (size_t)y * rowSize + (size_t)x * 3;
            f[p] = (uint8_t)(255 * y / h);                       // blue
            f[p + 1] = (uint8_t)(255 * x / w);                   // green
            f[p + 2] = (uint8_t)(128 + 127 * sin(x / 40.0));     // red
        }
    }
    return writeFile(path, f);
}

// ----------------------------------------------------------------------------
//  PART 2: OUR OWN ENCRYPTION LAYER
//  A password-based stream cipher: the password is turned into a number
//  (FNV-1a hash), which seeds a pseudo-random generator (xorshift64).
//  Each data byte is XORed with a random byte. Running it twice with the same
//  password gives back the original data.
//  (Good for a course project. Real-world security would use AES.)
// ----------------------------------------------------------------------------

static void cryptBytes(Bytes &data, const string &password) {
    uint64_t state = 14695981039346656037ULL;
    for (size_t i = 0; i < password.size(); i++) {
        state ^= (uint8_t)password[i];
        state *= 1099511628211ULL;
    }
    if (state == 0) state = 88172645463325252ULL;

    for (size_t i = 0; i < data.size(); i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data[i] ^= (uint8_t)((state >> 24) & 0xFF);
    }
}

// Checksum used to detect a wrong password or corrupted data.
static uint32_t checksum(const Bytes &d) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < d.size(); i++) {
        h ^= d[i];
        h *= 16777619u;
    }
    return h;
}

// ----------------------------------------------------------------------------
//  PART 3: LSB EMBEDDING / EXTRACTION
//
//  What gets hidden in the image (the "container"):
//    [ "STG1" magic : 4 bytes ]  -> lets us recognise our own hidden data
//    [ length       : 4 bytes ]  -> size of the encrypted block below
//    [ encrypted block ]         -> encrypt( type + nameLen + name + data
//                                            + checksum )
// ----------------------------------------------------------------------------

static const size_t HEADER_SIZE = 8;     // magic + length
static const size_t EXTRA_SIZE = 1 + 1 + 4;  // type + nameLen + checksum

static void hideBytes(Bmp &img, const Bytes &data) {
    size_t bit = 0;
    for (size_t i = 0; i < data.size(); i++) {
        for (int b = 7; b >= 0; b--) {
            size_t pos = bytePos(img, bit++);
            uint8_t secretBit = (data[i] >> b) & 1;
            img.file[pos] = (img.file[pos] & 0xFE) | secretBit;  // replace LSB
        }
    }
}

static Bytes revealBytes(const Bmp &img, size_t startByte, size_t count) {
    Bytes out(count, 0);
    size_t bit = startByte * 8;
    for (size_t i = 0; i < count; i++) {
        uint8_t v = 0;
        for (int b = 0; b < 8; b++) {
            size_t pos = bytePos(img, bit++);
            v = (uint8_t)((v << 1) | (img.file[pos] & 1));
        }
        out[i] = v;
    }
    return out;
}

// Max number of secret data bytes (file content / text) that fit in the image.
static long maxPayload(const Bmp &img, size_t fileNameLen) {
    long total = (long)(usableBytes(img) / 8);
    long overhead = (long)(HEADER_SIZE + EXTRA_SIZE + fileNameLen);
    return total - overhead;
}

// type: 0 = text, 1 = file
static bool embedData(Bmp &img, uint8_t type, const string &name,
                      const Bytes &data, const string &password) {
    if (name.size() > 255) {
        cout << "  [Error] File name is too long.\n";
        return false;
    }
    long cap = maxPayload(img, name.size());
    if (cap < 0 || (long)data.size() > cap) {
        cout << "  [Error] Not enough space! Your data is " << data.size()
             << " bytes, but this image can only hold " << (cap < 0 ? 0 : cap)
             << " bytes.\n          Use a bigger image or smaller data.\n";
        return false;
    }

    // Build the plain block
    Bytes block;
    block.push_back(type);
    block.push_back((uint8_t)name.size());
    block.insert(block.end(), name.begin(), name.end());
    block.insert(block.end(), data.begin(), data.end());
    uint32_t sum = checksum(block);
    for (int i = 0; i < 4; i++) block.push_back((sum >> (8 * i)) & 0xFF);

    // Encrypt it
    cryptBytes(block, password);

    // Build the container
    Bytes container;
    container.push_back('S');
    container.push_back('T');
    container.push_back('G');
    container.push_back('1');
    uint32_t len = (uint32_t)block.size();
    for (int i = 0; i < 4; i++) container.push_back((len >> (8 * i)) & 0xFF);
    container.insert(container.end(), block.begin(), block.end());

    // Hide it in the pixels
    hideBytes(img, container);
    return true;
}

static bool extractData(const Bmp &img, const string &password, uint8_t &type,
                        string &name, Bytes &data) {
    if (usableBytes(img) / 8 < HEADER_SIZE) {
        cout << "  [Error] Image is too small to contain hidden data.\n";
        return false;
    }
    Bytes head = revealBytes(img, 0, HEADER_SIZE);
    if (head[0] != 'S' || head[1] != 'T' || head[2] != 'G' || head[3] != '1') {
        cout << "  [Error] No hidden data found in this image.\n";
        return false;
    }
    uint32_t len = read32(head, 4);
    if (len < EXTRA_SIZE || len > usableBytes(img) / 8 - HEADER_SIZE) {
        cout << "  [Error] Hidden data is corrupted.\n";
        return false;
    }

    Bytes block = revealBytes(img, HEADER_SIZE, len);
    cryptBytes(block, password);  // decrypt (same operation)

    // Verify checksum
    Bytes body(block.begin(), block.end() - 4);
    uint32_t stored = read32(block, block.size() - 4);
    if (checksum(body) != stored) {
        cout << "  [Error] Wrong password (or the image was modified).\n";
        return false;
    }

    type = body[0];
    size_t nameLen = body[1];
    if (2 + nameLen > body.size()) {
        cout << "  [Error] Hidden data is corrupted.\n";
        return false;
    }
    name.assign(body.begin() + 2, body.begin() + 2 + nameLen);
    data.assign(body.begin() + 2 + nameLen, body.end());
    return true;
}

// ----------------------------------------------------------------------------
//  PART 4: USER INTERFACE (menu)
// ----------------------------------------------------------------------------

static string ask(const string &question) {
    cout << question;
    string s;
    getline(cin, s);
    return s;
}

// Remove any folder part so extracted files can't be written elsewhere.
static string baseName(const string &path) {
    size_t p = path.find_last_of("/\\");
    return p == string::npos ? path : path.substr(p + 1);
}

static string formatSize(long bytes) {
    if (bytes >= 1024 * 1024)
        return to_string(bytes / (1024.0 * 1024.0)).substr(0, 5) + " MB";
    if (bytes >= 1024)
        return to_string(bytes / 1024.0).substr(0, 5) + " KB";
    return to_string(bytes) + " bytes";
}

static void doCapacity() {
    Bmp img;
    if (!loadBmp(ask("  Image path (.bmp): "), img)) return;
    long cap = maxPayload(img, 0);
    cout << "\n  Image size       : " << img.width << " x " << img.height
         << " pixels\n";
    cout << "  Total colour bytes: " << usableBytes(img) << "\n";
    cout << "  Usable capacity  : " << (cap < 0 ? 0 : cap) << " bytes ("
         << formatSize(cap < 0 ? 0 : cap) << ")\n";
    cout << "  That is about    : " << (cap < 0 ? 0 : cap)
         << " text characters\n";
    cout << "  (Uses 1 bit per colour byte, minus " << HEADER_SIZE + EXTRA_SIZE
         << " bytes for the header.)\n";
}

static void doEmbedText() {
    Bmp img;
    if (!loadBmp(ask("  Cover image path (.bmp): "), img)) return;
    cout << "  This image can hold up to " << maxPayload(img, 0)
         << " characters.\n";
    string text = ask("  Secret message : ");
    if (text.empty()) {
        cout << "  [Error] Message is empty.\n";
        return;
    }
    string pass = ask("  Password       : ");
    if (pass.empty()) {
        cout << "  [Error] Password cannot be empty.\n";
        return;
    }
    string outPath = ask("  Save new image as (e.g. secret.bmp): ");

    Bytes data(text.begin(), text.end());
    if (!embedData(img, 0, "", data, pass)) return;
    if (writeFile(outPath, img.file))
        cout << "\n  [OK] Message hidden and encrypted. Saved to: " << outPath
             << "\n";
    else
        cout << "  [Error] Could not save the output image.\n";
}

static void doEmbedFile() {
    Bmp img;
    if (!loadBmp(ask("  Cover image path (.bmp): "), img)) return;
    string secretPath = ask("  File to hide (any type): ");
    Bytes data;
    if (!readFile(secretPath, data)) {
        cout << "  [Error] Cannot open file: " << secretPath << "\n";
        return;
    }
    string pass = ask("  Password       : ");
    if (pass.empty()) {
        cout << "  [Error] Password cannot be empty.\n";
        return;
    }
    string outPath = ask("  Save new image as (e.g. secret.bmp): ");

    if (!embedData(img, 1, baseName(secretPath), data, pass)) return;
    if (writeFile(outPath, img.file))
        cout << "\n  [OK] File hidden and encrypted. Saved to: " << outPath
             << "\n";
    else
        cout << "  [Error] Could not save the output image.\n";
}

static void doExtract() {
    Bmp img;
    if (!loadBmp(ask("  Image with hidden data (.bmp): "), img)) return;
    string pass = ask("  Password: ");

    uint8_t type;
    string name;
    Bytes data;
    if (!extractData(img, pass, type, name, data)) return;

    if (type == 0) {
        cout << "\n  [OK] Hidden message:\n  -----------------------\n  "
             << string(data.begin(), data.end())
             << "\n  -----------------------\n";
    } else {
        string outName = "extracted_" + baseName(name);
        if (writeFile(outName, data))
            cout << "\n  [OK] Hidden file recovered (" << data.size()
                 << " bytes). Saved as: " << outName << "\n";
        else
            cout << "  [Error] Could not save the recovered file.\n";
    }
}

static void doSample() {
    string path = ask("  Save sample image as (e.g. sample.bmp): ");
    if (createSampleBmp(path, 400, 300))
        cout << "  [OK] Created 400x300 sample image: " << path << "\n";
    else
        cout << "  [Error] Could not create the file.\n";
}

int main() {
    while (true) {
        cout << "\n=========================================\n"
             << "        STEGANOGRAPHY TOOL (LSB)\n"
             << "=========================================\n"
             << "  1. Capacity calculator\n"
             << "  2. Hide a text message in an image\n"
             << "  3. Hide a file in an image\n"
             << "  4. Extract hidden data from an image\n"
             << "  5. Create a sample image (for demo)\n"
             << "  0. Exit\n"
             << "-----------------------------------------\n";
        string choice = ask("  Choose an option: ");
        cout << "\n";
        if (choice == "1") doCapacity();
        else if (choice == "2") doEmbedText();
        else if (choice == "3") doEmbedFile();
        else if (choice == "4") doExtract();
        else if (choice == "5") doSample();
        else if (choice == "0") {
            cout << "  Goodbye!\n";
            break;
        } else cout << "  Invalid option, try again.\n";

        if (!cin) break;  // input closed
    }
    return 0;
}

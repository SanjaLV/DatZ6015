#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstdint>
#include <cstring>

#include <string>
#include <vector>
#include <x86intrin.h>

#include <openssl/aes.h>


FILE * open_file(const std::string& filename, char* mode) {
    FILE * f = fopen(filename.c_str(), mode);
    if (f == nullptr) {
        fprintf(stderr, "Cannot open file '%s'\n", filename.c_str());
        exit(1);
    }
    return f;
}

uint8_t char2hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    assert(false);
}

char FILE_READ[] = "r";
char FILE_READ_BINARY[] = "rb";
char FILE_WRITE[] = "w";
char FILE_WRITE_BINARY[] = "wb";

uint8_t * read_key_from_file(const std::string& filename) {
    FILE * f = open_file(filename, FILE_READ);
    static char tmp[256];
    int res = fscanf(f, "%s", tmp);
    assert(res == 1);
    res = strlen(tmp);

    if (res < 2 || tmp[0] != '0' || tmp[1] != 'x') {
        fprintf(stderr, "Key should be in hexdecimal format\n");
        exit(1);
    }

    uint8_t * key = static_cast<uint8_t*> (malloc(16));

    for (int i = 2, j = 0; i < res; i += 2, j++) {
        uint8_t cur = char2hex(tmp[i]) * 16 + char2hex(tmp[i + 1]);
        key[j] = cur;
    }

    return key;
}

void debugHex(uint8_t* ptr, size_t sz) {
    for (size_t i = 0; i < sz; i++) {
        printf("%02x ", ptr[i]);
    }
    printf("\n");
}

void print2hex(FILE* f, uint8_t value) {
    uint8_t bits = value / 16;
    
    if (bits <= 9u) fprintf(f, "%u", bits);
    else fprintf(f, "%c", 'a' + (bits - 10));

    bits = value & 15u;

    if (bits <= 9u) fprintf(f, "%u", bits);
    else fprintf(f, "%c", 'a' + (bits - 10));
}

void encrypt_cbc(const std::string& key_file,
                 const std::string& input_file,
                 const std::string& output_file) {
    uint8_t * key = read_key_from_file(key_file);
    
    AES_KEY keys;

    AES_set_encrypt_key(key, 128, &keys);
    free(key); // Do not leak key


    FILE * fin = open_file(input_file, FILE_READ_BINARY);
    FILE * fout = open_file(output_file, FILE_WRITE_BINARY);

    uint8_t iv[16];
    uint8_t input_buf[16], output_buf[16];

    __builtin_memset(iv, 0, 16); // zero IV

    while (true) {
        int read = fread(input_buf, 1, 16, fin);

        if (read == 0) break;
        if (read < 16) {
            __builtin_memset(input_buf + read, 0, 16 - read); // pad with zeroes
        }

        for (int i = 0; i < 16; i++) input_buf[i] ^= iv[i];

        AES_encrypt(input_buf, output_buf, &keys);

        fwrite(output_buf, 1, 16, fout);
/*
        printf("Input: "); debugHex(input_buf, 16);
        printf("Output: "); debugHex(output_buf, 16);
 */
        __builtin_memcpy(iv, output_buf, 16);
    }

    fclose(fin);
    fclose(fout);
}

void decrypt_cbc(const std::string& key_file,
                 const std::string& input_file,
                 const std::string& output_file) {
    uint8_t * key = read_key_from_file(key_file);
    AES_KEY keys;

    AES_set_decrypt_key(key, 128, &keys);
    free(key); // Do not leak key


    FILE * fin = open_file(input_file, FILE_READ_BINARY);
    FILE * fout = open_file(output_file, FILE_WRITE_BINARY);

    uint8_t iv[16];
    uint8_t input_buf[16], output_buf[16];

    __builtin_memset(iv, 0, 16); // zero IV

    while (true) {
        int read = fread(input_buf, 1, 16, fin);
        if (read == 0) break;
        assert(read == 16);

        AES_decrypt(input_buf, output_buf, &keys);

        for (int i = 0; i < 16; i++) output_buf[i] ^= iv[i];

        fwrite(output_buf, 1, 16, fout);
/*
        printf("Input: "); debugHex(input_buf, 16);
        printf("Output: "); debugHex(output_buf, 16);
*/
        __builtin_memcpy(iv, input_buf, 16);
    }

    fclose(fin);
    fclose(fout);
}

void encrypt_cfb(const std::string& key_file,
                 const std::string& sig_key_file,
                 const std::string& input_file,
                 const std::string& output_file) {

    uint8_t * key = read_key_from_file(key_file);
    AES_KEY keys;
    AES_set_encrypt_key(key, 128, &keys);
    free(key); // Do not leak key

    uint8_t * CMAC_key = read_key_from_file(sig_key_file);
    AES_KEY CMAC_keys;
    AES_set_encrypt_key(CMAC_key, 128, &CMAC_keys);
    free(CMAC_key); // Do not leak sig_key

    FILE * fin = open_file(input_file, FILE_READ_BINARY);
    FILE * fout = open_file(output_file, FILE_WRITE_BINARY);

    uint8_t iv[16];
    uint8_t input_buf[16], output_buf[16];

    uint8_t CMAC_x[16], CMAC_y[16];
    __builtin_memset(CMAC_x, 0, 16);

    { // Initialize IV from /dev/random
        FILE * f = fopen("/dev/random", "rb");
        int res = fread(iv, 1, 16, f);

        fwrite(iv, 1, 16, fout); // write IV

        assert(res == 16);
        fclose(f);
    }

    while (true) {
        int read = fread(input_buf, 1, 16, fin);

        if (read == 0) break;
        if (read < 16) {
            __builtin_memset(input_buf + read, 0, 16 - read); // pad with zeroes
        }

        // CMAC
        for (int i = 0; i < 16; i++) {
            CMAC_y[i] = CMAC_x[i] ^ input_buf[i];
        }
        AES_encrypt(CMAC_y, CMAC_x, &CMAC_keys);

        AES_encrypt(iv, output_buf, &keys);
        
        for (int i = 0; i < 16; i++) output_buf[i] ^= input_buf[i];

        fwrite(output_buf, 1, 16, fout);
/*
        printf("Input : "); debugHex(input_buf, 16);
        printf("Output: "); debugHex(output_buf, 16);
        printf("IV    : "); debugHex(iv, 16);
 */
        __builtin_memcpy(iv, output_buf, 16);
    }


    { // Output CMAC signature
        FILE * f = open_file(output_file + ".sig", FILE_WRITE_BINARY);
        fwrite(CMAC_x, 1, 16, f);
        fclose(f);
    }

    fclose(fin);
    fclose(fout);
}

void decrypt_cfb(const std::string& key_file,
                 const std::string& sig_key_file,
                 const std::string& input_file,
                 const std::string& output_file) {

    uint8_t * key = read_key_from_file(key_file);
    AES_KEY keys;
    AES_set_encrypt_key(key, 128, &keys);
    free(key); // Do not leak key

    uint8_t * CMAC_key = read_key_from_file(sig_key_file);
    AES_KEY CMAC_keys;
    AES_set_encrypt_key(CMAC_key, 128, &CMAC_keys);
    free(CMAC_key); // Do not leak sig_key


    FILE * fin = open_file(input_file, FILE_READ_BINARY);
    FILE * fout = open_file(output_file, FILE_WRITE_BINARY);

    uint8_t iv[16];
    uint8_t input_buf[16], output_buf[16];

    // read IV
    int res = fread(iv, 1, 16, fin);
    assert(res == 16);

    uint8_t CMAC_x[16], CMAC_y[16];
    __builtin_memset(CMAC_x, 0, 16);

    while (true) {
        int read = fread(input_buf, 1, 16, fin);
        if (read == 0) break;
        assert(read == 16);

        AES_encrypt(iv, output_buf, &keys);

        for (int i = 0; i < 16; i++) output_buf[i] ^= input_buf[i];

        fwrite(output_buf, 1, 16, fout);

        // CMAC
        for (int i = 0; i < 16; i++) {
            CMAC_y[i] = CMAC_x[i] ^ output_buf[i];
        }
        AES_encrypt(CMAC_y, CMAC_x, &CMAC_keys);

/*
        printf("Input : "); debugHex(input_buf, 16);
        printf("Output: "); debugHex(output_buf, 16);
        printf("IV    : "); debugHex(iv, 16);
*/
        __builtin_memcpy(iv, input_buf, 16);
    }

    { // Compare CMAC signature
        FILE * f = open_file(input_file + ".sig", FILE_READ_BINARY);
        int tmp = fread(CMAC_y, 1, 16, f);
        assert(tmp == 16);

        if (__builtin_memcmp(CMAC_x, CMAC_y, 16) != 0) {
            printf("CMAC signature verification failed!\n");
            printf("CMAC_x : "); debugHex(CMAC_x, 16);
            printf("CMAC_y : ");debugHex(CMAC_y, 16);
        }
        else {
            printf("CMAC signature verification OK!\n");
        }

        fclose(f);
    }

    fclose(fin);
    fclose(fout);
}

void generate_key(const std::string& file) {
    FILE * f = open_file(file, FILE_WRITE);

    uint8_t key[16];
    {
        FILE * dev_rand = open_file("/dev/random", FILE_READ_BINARY);
        int res = fread(key, 1, 16, dev_rand);
        assert(res == 16);
        fclose(dev_rand);
    }

    fprintf(f, "0x");
    for (int i = 0; i < 16; i++) {
        print2hex(f, key[i]);
    }
    fprintf(f, "\n");
    fclose(f);
}


void help(const std::string& progname) {
    printf("Usage %s --mode [...args]\n", progname.c_str());
    printf("Where mode is one of the following:\n");
    printf("\tencrypt key.txt input_file output_file [mac_key.txt]\n");
    printf("\tdecrypt key.txt input_file output_file [mac_key.txt]\n");
    printf("\tgenerate key.txt\n");
    printf("\t\t[mac_key.txt] changes mode from CBC to CFB\n");
    printf("\thelp - display this message\n"); 
    exit(0);
}

int modern_main(const std::vector<std::string>& args) {

    if (args.size() == 1) help(args[0]);

    if (args[1] == "--encrypt") {
        if (args.size() < 5) help(args[0]);

        if (args.size() == 6) {
            encrypt_cfb(args[2], args[5], args[3], args[4]);
        }
        else {
            encrypt_cbc(args[2], args[3], args[4]);
        }
    }
    else if (args[1] == "--decrypt") {
        if (args.size() == 6) {
            decrypt_cfb(args[2], args[5], args[3], args[4]);
        }
        else {
            decrypt_cbc(args[2], args[3], args[4]);
        }
    }
    else if (args[1] == "--generate") {
        if (args.size() != 3) help(args[0]);

        generate_key(args[2]);
    }
    else {
        help(args[0]);
    }

    return 0;
}

int main(int argc, char* argv[]) {

    std::vector<std::string> args;
    for (int i = 0; i < argc; i++) {
        args.emplace_back(argv[i]);
    }

    return modern_main(args);
}

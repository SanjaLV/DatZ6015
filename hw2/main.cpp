#include <cstdio>
#include <cstdlib>
#include <cassert>

#include <string>
#include <vector>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "../Utils.h"

void set_name_from_certificate_settings_file(X509* x509, const std::string& settings_file) {

    X509_NAME * name = X509_get_subject_name(x509);

    KeyValueStrings settings = parse_file(settings_file);

    ensure_settings(settings, {"C", "O", "CN"});

    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                           (unsigned char *)settings["C"].c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                           (unsigned char *)settings["O"].c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                           (unsigned char *)settings["CN"].c_str(), -1, -1, 0);

    // set name
    X509_set_issuer_name(x509, name);
}

void create_certificate(const std::string& settings_file, const std::string& private_key) {

    RSA* rsa = RSA_generate_key(2048,   // number of bits
                                RSA_F4, // e
                                NULL,
                                NULL);

    if (rsa == nullptr) {
        fprintf(stderr, "Failed to generate rsa key!\n");
        exit(1);
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    X509 * x509 = X509_new();

    // set serial number to 1
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // set certificate life-time
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    // set public key
    X509_set_pubkey(x509, pkey);

    // read certificate settings from file
    set_name_from_certificate_settings_file(x509, settings_file);

    // sign with SHA-3-256
    X509_sign(x509, pkey, EVP_sha3_256());

    // write private key to file
    {
        FILE * f = fopen(private_key.c_str(), "wb");
        PEM_write_PrivateKey(f,
                             pkey,
                             nullptr,
                             nullptr,
                             0u,
                             nullptr,
                             nullptr);
        fclose(f);
    }

    // write certificate to file
    {
        FILE * f = fopen("cert.pem", "wb");
        PEM_write_X509(f, x509);
        fclose(f);
    }

    printf("DONE\n");
}

X509* read_cert_from_file(const std::string& cert) {
    FILE * f = fopen(cert.c_str(), "rb");

    if (f == nullptr) {
        fprintf(stderr, "Cannot open file '%s'\n", cert.c_str());
        exit(1);
    }

    X509 * x509 = X509_new();
    PEM_read_X509(f, &x509, nullptr, nullptr);
    
    fclose(f);

    return x509;
}

void verify_certificate(const std::string& cert) {
    X509* x509 = read_cert_from_file(cert);

    const int BUFFER_SIZE = 256;
    static char buffer[BUFFER_SIZE], buffer2[BUFFER_SIZE];

    X509_NAME_oneline(X509_get_subject_name(x509), buffer, BUFFER_SIZE);
    

    X509_NAME_oneline(X509_get_issuer_name(x509), buffer2, BUFFER_SIZE);

    if (strcmp(buffer, buffer2) != 0) {
        printf("Subject name does not match issuer name!");
        printf("'%s'\n", buffer);
        printf("'%s'\n", buffer2);
        exit(1);
    }

    printf("Name matched!\n");

    EVP_PKEY *pkey=X509_get_pubkey(x509);
    
    int r = X509_verify(x509, pkey);

    if (r == 1) {
        printf("Verified!\n");
    }
    else {
        printf("Checksum does not match!\n");
        exit(1);
    }
}

void encrypt(const std::string& ifile, const std::string& ofile, const std::string& cert_file) {
    X509* x509 = read_cert_from_file(cert_file);
    
    EVP_PKEY *pkey= X509_get_pubkey(x509);
    RSA * rsa = EVP_PKEY_get1_RSA(pkey);

    FILE* fin  = fopen(ifile.c_str(), "rb");
    FILE* fout = fopen(ofile.c_str(), "wb");

    if (fin == nullptr) {
        fprintf(stderr, "Cannot open file '%s'\n", ifile.c_str());
        exit(1);
    }
    if (fout == nullptr) {
        fprintf(stderr, "Cannot create file '%s'\n", ifile.c_str());
        exit(1);
    }

    const int intput_block_size = RSA_size(rsa) - 42;
    const int output_block_size = RSA_size(rsa);

    unsigned char * input_buf  = static_cast<unsigned char *>(malloc(intput_block_size));
    unsigned char * output_buf = static_cast<unsigned char *>(malloc(output_block_size));

    while (true) {
        int read = fread(input_buf, 1, intput_block_size, fin);
        if (read == 0) break;

        int enc_size = RSA_public_encrypt(read,      // input_size
                                          input_buf,
                                          output_buf,
                                          rsa,
                                          RSA_PKCS1_OAEP_PADDING);

        if (enc_size > 0) {
            fwrite(output_buf, 1, enc_size, fout);
        }

    }

    fclose(fin);
    fclose(fout);
}

EVP_PKEY* read_private_key_from_file(const std::string& file) {
    FILE * f = fopen(file.c_str(), "rb");

    if (f == nullptr) {
        fprintf(stderr, "Cannot open file '%s'\n", file.c_str());
        exit(1);
    }

    EVP_PKEY* key = EVP_PKEY_new();
    
    PEM_read_PrivateKey(f, &key, nullptr, nullptr);
    assert(key != nullptr);

    fclose(f);
    
    return key;
}

void decrypt(const std::string& ifile, const std::string& ofile, const std::string& private_key) {

    FILE* fin  = fopen(ifile.c_str(), "rb");
    FILE* fout = fopen(ofile.c_str(), "wb");

    if (fin == nullptr) {
        fprintf(stderr, "Cannot open file '%s'\n", ifile.c_str());
        exit(1);
    }
    if (fout == nullptr) {
        fprintf(stderr, "Cannot create file '%s'\n", ifile.c_str());
        exit(1);
    } 

    EVP_PKEY* pkey = read_private_key_from_file(private_key);
    RSA * rsa = EVP_PKEY_get1_RSA(pkey);

    const int block_size = RSA_size(rsa);
    unsigned char * input_buf  = static_cast<unsigned char *>(malloc(block_size));
    unsigned char * output_buf = static_cast<unsigned char *>(malloc(block_size));

    while (true) {
        int read = fread(input_buf, 1, block_size, fin);
        if (read == 0) break;

        int enc_size = RSA_private_decrypt(read,
                                          input_buf,
                                          output_buf,
                                          rsa,
                                          RSA_PKCS1_OAEP_PADDING);

        if (enc_size > 0) {
            fwrite(output_buf, 1, enc_size, fout);
        }

    }


    fclose(fin);
    fclose(fout);
}

void help(const std::string& progname) {
    printf("Usage %s --mode [...args]\n", progname.c_str());
    printf("Where mode is one of the following:\n");
    printf("\tcreate settings_file key.pem\n");
    printf("\tverify cert.pem\n");
    printf("\tencrypt cert.pem input_file output_file\n");
    printf("\tdecrypt private_key.pem input_file output_file\n");
    printf("\thelp - display this message\n"); 
    exit(0);
}

int modern_main(const std::vector<std::string>& args) {

    if (args.size() == 1) help(args[0]);

    if (args[1] == "--create") {
        if (args.size() != 4) help(args[0]);
        create_certificate(args[2], args[3]);
    }
    else if (args[1] == "--verify") {
        if (args.size() != 3) help(args[0]);
        verify_certificate(args[2]);
    }
    else if (args[1] == "--encrypt") {
        if (args.size() != 5) help(args[0]);

        encrypt(args[3], args[4], args[2]);
    }
    else if (args[1] == "--decrypt") {
        if (args.size() != 5) help(args[0]);

        decrypt(args[3], args[4], args[2]);
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

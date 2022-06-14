#include <stdio.h>
#include <stdlib.h>

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

void verify_certificate(const std::string& cert) {
    FILE * f = fopen(cert.c_str(), "rb");

    if (f == nullptr) {
        fprintf(stderr, "Cannot open file '%s'\n", cert.c_str());
        exit(1);
    }

    X509 * x509 = X509_new();
    PEM_read_X509(f, &x509, nullptr, nullptr);

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

void help(const std::string& progname) {
    printf("Usage %s --mode [...args]\n", progname.c_str());
    printf("Where mode is one of the following:\n");
    printf("\tcreate settings_file key.pem\n");
    printf("\tverify cert.pem\n");
    printf("\tencrypt file key.pem\n");
    printf("\tdecrypt file key.pem\n");
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
    }
    else if (args[1] == "--decrypt") {
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

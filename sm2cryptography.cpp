#include "sm2cryptography.h"

SM2Cryptography::SM2Cryptography()
{
}

EC_KEY* SM2Cryptography::CreateEC(const char* key, int is_public)
{
    EC_KEY *ec_key = NULL;

    BIO *keybio = BIO_new_file(key, "r");     //    BIO *keybio = BIO_new_mem_buf(buf, -1); 传入文件内容
    if(is_public) {
        ec_key = PEM_read_bio_EC_PUBKEY(keybio, NULL, NULL, NULL);
    }
    else {
        ec_key = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
    }

    if(ec_key == NULL) {
        cout << "Failed to Get Key" << endl;
        exit(1);
    }

    return ec_key;
}

string SM2Cryptography::Encrypt(const string& public_key, const string& plain_text)
{
    unsigned char encrypted[1024] = {};

    EC_KEY *ec_key = CreateEC(public_key.c_str(), 1);

    size_t encrypted_length = 1024;
    int ret = SM2_encrypt_with_recommended((unsigned char*)plain_text.c_str(), plain_text.length(),
            (unsigned char*)encrypted,&encrypted_length, ec_key);

    if (ret == 0) {
        cout << "Failed to Encrypt" << endl;
        exit(1);
    }

    string enc_text((char*)encrypted, encrypted_length);
    return enc_text;
}


string SM2Cryptography::Decrypt(const string& private_key, const string& enc_text)
{
    unsigned char decrypted[1024] = {};

    EC_KEY * ec_key = CreateEC(private_key.c_str(), 0);

    size_t decrypted_length = 0;
    int ret = SM2_decrypt_with_recommended((unsigned char*)enc_text.c_str(), enc_text.length(), decrypted, &decrypted_length, ec_key);

    if (ret == 0) {
        cout << "Failed to Decrypt" << endl;
        exit(1);
    }

    string plain_text((char*)decrypted, decrypted_length);
    return plain_text;
}

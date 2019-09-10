#ifndef SM2CRYPTOGRAPHY_H
#define SM2CRYPTOGRAPHY_H

#include <string>
#include <iostream>
#include "openssl/sm2.h"
#include "openssl/pem.h"

using namespace std;

class SM2Cryptography
{
public:
    SM2Cryptography();

    EC_KEY* CreateEC(const char *key, int is_public);

    string Encrypt(const string& public_key, const string& plain_text);

    string Decrypt(const string& private_key, const string& enc_text);
};

#endif // SM2CRYPTOGRAPHY_H

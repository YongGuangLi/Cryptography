/*
 * AesCryptography.h
 *
 *  Created on: Jul 29, 2019
 *      Author: root
 */

#ifndef AESCRYPTOGRAPHY_H_
#define AESCRYPTOGRAPHY_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

#define KEY  "0123456789abcdef"

class AesCryptography {
public:
    AesCryptography();
    virtual ~AesCryptography();

    int AES_Encrypt(const char *plainText, int length, char *&cipherText);

    void AES_Decrypt(const char *cipherText, int length, char *&plainText);
private:
};

#endif /* AESCRYPTOGRAPHY_H_ */

/*
 * AesCryptography.cpp
 *
 *  Created on: Jul 29, 2019
 *      Author: root
 */

#include "aescryptography.h"

AesCryptography::AesCryptography() {

}

AesCryptography::~AesCryptography() {

}

int AesCryptography::AES_Encrypt(const char *plainText, int length, char *&cipherText)
{
	AES_KEY AesKey;
	int SetDataLen = 0;
	unsigned char ivec[AES_BLOCK_SIZE] = {0};		//建议用unsigned char

    unsigned char Key[AES_BLOCK_SIZE+1] = {0};	    //建议用unsigned char

    if ((length % AES_BLOCK_SIZE) == 0)
		SetDataLen = length;
	else
		SetDataLen = ((length / AES_BLOCK_SIZE) +1 ) * AES_BLOCK_SIZE;

	char *InputData = (char *)calloc(SetDataLen + 1, sizeof(char));  //注意要SetDataLen+1
	if(InputData == NULL)
	{
		fprintf(stderr, "Unable to allocate memory for InputData\n");
		return SetDataLen;
	}
	memcpy(InputData, plainText, length);

    cipherText = (char *)calloc(SetDataLen + 1, sizeof(char));  	//注意要SetDataLen+1
	if(cipherText == NULL)
	{
		fprintf(stderr, "Unable to allocate memory for EncryptData\n");
		return SetDataLen;
    }

	memset(&AesKey, 0x00, sizeof(AES_KEY));
    if(AES_set_encrypt_key(Key, 128, &AesKey) < 0)
	{
		//设置加密密钥
		fprintf(stderr, "Unable to set encryption key in AES...\n");
		return SetDataLen;
	}

	//加密
    AES_cbc_encrypt((unsigned char *)InputData, (unsigned char *)cipherText, SetDataLen, &AesKey, ivec, AES_ENCRYPT);

	if(InputData != NULL)
	{
		free(InputData);
		InputData = NULL;
	}

	return SetDataLen;
}


void AesCryptography::AES_Decrypt(const char *cipherText, int length, char *&plainText)
{
	AES_KEY AesKey;

	unsigned char ivec[AES_BLOCK_SIZE] = {0};		//建议用unsigned char

	unsigned char Key[AES_BLOCK_SIZE+1] = {0};	//建议用unsigned char

    plainText = (char *)calloc(length + 1, sizeof(char));
	if(plainText == NULL)	//注意要SetDataLen+1
	{
		fprintf(stderr, "Unable to allocate memory for DecryptData\n");
		exit(-1);
	}

	memset(&AesKey, 0x00, sizeof(AES_KEY));
	if(AES_set_decrypt_key(Key, 128, &AesKey) < 0)
	{
		//设置解密密钥
		fprintf(stderr, "Unable to set encryption key in AES...\n");
		exit(-1);
	}

	//解密
	AES_cbc_encrypt((unsigned char *)cipherText, (unsigned char *)plainText, length, &AesKey, ivec, AES_DECRYPT);
}

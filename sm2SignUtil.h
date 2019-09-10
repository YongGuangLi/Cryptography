#ifndef x509Parse_H
#define x509Parse_H


#include <QDebug>
#include <stdio.h>
#include <string.h>
#include <string>

#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include <openssl/pkcs12.h>

using namespace std;

class X509Parse
{
public:
    X509Parse();
    ~X509Parse();

    /**
    * @date    2019-09-09
    * @param
    * @return
    * @brief   向证书存储区添加证书
    */
    int X509_STORE_add_cert(X509 *cert);

    /**
    * @date     2019-09-09
    * @param
    * @return
    * @brief    向证书存储区添加证书吊销列表
    */
    int X509_STORE_add_crl(X509_CRL *x);


    /**
    * @date     2019-09-09
    * @param
    * @return
    * @brief    验证证书有效性
    */
    int X509_verify_cert(X509 *cert);

    /**
    * @date     2019-09-09
    * @param
    * @return
    * @brief    验证证书有效性
    */
    int X509_verify_cert(string certpath);

public:
    /**
    * @date      2019-09-09
    * @param
    * @return
    * @brief     获取证书数据
    */
    static X509 *read_X509(string x509CertFile);

    static void X509_free(X509 *cert);

    /**
    * @date      2019-09-09
    * @param
    * @return
    * @brief     获取cert证书公钥
    */
    static EVP_PKEY *X509_get_pubkey(X509 *cert);


    static void X509_free_PKEY(EVP_PKEY *key);

    /**
    * @date      2019-09-09
    * @param
    * @return
    * @brief     获取P12证书私钥
    */
    static EVP_PKEY *read_P12(string p12CertFile, string pass);

    /**
    * @date      2019-09-09
    * @param
    * @return
    * @brief     用私钥签名
    */
    static bool digestSign(const char *msg, unsigned char *&sig, size_t * slen, EVP_PKEY *priKey);

    /**
    * @date      2019-09-09
    * @param
    * @return
    * @brief     用公钥验签
    */
    static bool digestVerify(const char *msg, unsigned char *sig, size_t slen, EVP_PKEY *pubKey);

    /**
    * @date      2019-09-10
    * @param
    * @return
    * @brief     移除签名值中的附加数据
    */
    static unsigned char *stripAdditionalVaule(unsigned char *sig);

    /**
    * @date      2019-09-10
    * @param
    * @return
    * @brief     添加签名值中的附加数据
    */
    static unsigned char *addAdditionalValue(unsigned char *sm2SignValua, int &length);
private:
    X509_STORE *ca_store;
};

#endif // x509Parse_H

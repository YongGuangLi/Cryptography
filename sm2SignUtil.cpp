#include "sm2SignUtil.h"

static time_t ASN1_TIME_get(ASN1_TIME* time)
{
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;

    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) /* two digit year */
    {
        t.tm_year = (str[i++] - '0') * 10 + (str[++i] - '0');
        if (t.tm_year < 70)
        t.tm_year += 100;
    }
    else if (time->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
    {
        t.tm_year = (str[i++] - '0') * 1000 + (str[++i] - '0') * 100 + (str[++i] - '0') * 10 + (str[++i] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon = ((str[i++] - '0') * 10 + (str[++i] - '0')) - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i++] - '0') * 10 + (str[++i] - '0');
    t.tm_hour = (str[i++] - '0') * 10 + (str[++i] - '0');
    t.tm_min  = (str[i++] - '0') * 10 + (str[++i] - '0');
    t.tm_sec  = (str[i++] - '0') * 10 + (str[++i] - '0');

    /* Note: we did not adjust the time based on time zone information */
    return mktime(&t);
}


X509Parse::X509Parse()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    ca_store = X509_STORE_new();
}

X509Parse::~X509Parse()
{
    X509_STORE_free(ca_store);
}


int X509Parse::X509_STORE_add_cert(X509 *cert)
{
    return ::X509_STORE_add_cert(ca_store, cert);
}


int X509Parse::X509_STORE_add_crl(X509_CRL *x)
{
    return ::X509_STORE_add_crl(ca_store, x);
}

int X509Parse::X509_verify_cert(X509 *cert)
{
    STACK_OF(X509) *ca_stack = NULL;
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    int ret = ::X509_STORE_CTX_init(ctx, ca_store, cert, ca_stack);
    if ( ret != 1 )
    {
        fprintf(stderr, "X509_STORE_CTX_init fail, ret = %d\n", ret);
    }

    ret = ::X509_verify_cert(ctx);
    if ( ret != 1 )
    {
       fprintf(stderr, "X509_verify_cert fail, ret = %d,  %s\n", ret, X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
    }

    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);

    return ret;
}

int X509Parse::X509_verify_cert(string certpath)
{
    X509 *cert = read_X509(certpath);
    return X509_verify_cert(cert);
}

X509 *X509Parse::read_X509(string x509CertFile)
{
    X509 *cert = NULL;

    BIO *f = BIO_new_file(x509CertFile.c_str(), "r");
    if (f != NULL)
    {
        cert = PEM_read_bio_X509(f, NULL, 0, NULL);    // 获得证书序列号函数
        BIO_free(f);
    }

    return cert;
}

void X509Parse::X509_free(X509 *cert)
{
    ::X509_free(cert);
}

EVP_PKEY *X509Parse::X509_get_pubkey(X509 *cert)
{
    return ::X509_get_pubkey(cert);
}

void X509Parse::X509_free_PKEY(EVP_PKEY *key)
{
    EVP_PKEY_free(key);
}

EVP_PKEY *X509Parse::read_P12(string p12CertFile, string pass)
{
    FILE *fp;
    if ((fp = fopen(p12CertFile.c_str(), "rb")) == NULL)
    {
        fprintf(stderr, "Error opening file %s\n", p12CertFile.c_str());
        exit(1);
    }

    PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12)
    {
        fprintf(stderr, "Error reading PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    STACK_OF(X509) *ca = NULL;
    EVP_PKEY *pkey;
    X509 *cert;
    if (!PKCS12_parse(p12, pass.c_str(), &pkey, &cert, &ca))
    {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    PKCS12_free(p12);

    X509_free(cert);
    X509_free((X509*)ca);

    return pkey;
}


bool X509Parse::digestSign(const char *msg, unsigned char *&sig, size_t *slen, EVP_PKEY *priKey)
{
    EVP_MD_CTX *mdctx = NULL;
    // 创建消息摘要上下文
    if(!(mdctx = EVP_MD_CTX_create()))
        return false;

    // 初始化DigestSign操作 - 在这个例子中，选择EVP_sm3作为消息摘要函数
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sm3(), NULL, priKey))
       return false;

    // 调用更新消息
    if(1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg)))
        return false;

    // 完成DigestSign操作
    //首先调用EVP_DigestSignFinal，采用一个为NULL的sig参数来获得签名的长度。返回的长度保存在slen变量中
    if(1 != EVP_DigestSignFinal(mdctx, NULL, slen))
        return false;

    // 根据slen的大小为签名分配内存
    if(!(sig = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * (*slen))))
       return false;

    // 获得签名
    if(1 != EVP_DigestSignFinal(mdctx, sig, slen))
        return false;

    if(mdctx)
        EVP_MD_CTX_destroy(mdctx);

    return true;
}

bool X509Parse::digestVerify(const char *msg, unsigned char *sig, size_t slen, EVP_PKEY *pubKey)
{
    EVP_MD_CTX *mdctx = NULL;
    //创建消息摘要上下文
    if(!(mdctx = EVP_MD_CTX_create()))
        return false;

    //用公钥初始化`密钥`
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sm3(), NULL, pubKey))
        return false;

    // 用公钥初始化`密钥`
    if(1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg)))
        return false;

    if(1 != EVP_DigestVerifyFinal(mdctx, sig, slen))
    {
        return false;
    }

    if(mdctx)
        EVP_MD_CTX_destroy(mdctx);

    return true;
}

unsigned char *X509Parse::stripAdditionalVaule(unsigned char *sig)
{
    static unsigned char sm2SignValua[64] = {0};

    if(sig[3] == 32)
    {
        memcpy(sm2SignValua, sig + 4, 32);
    }
    else if(sig[3] == 33)
    {
        memcpy(sm2SignValua, sig + 5, 32);
    }

    int index = 4 + sig[3] + 2;

    if(sig[index -1] == 32)
    {
        memcpy(sm2SignValua + 32, sig + index, 32);
    }
    else if(sig[index -1] == 33)
    {
        memcpy(sm2SignValua + 32, sig + index + 1, 32);
    }

    return sm2SignValua;
}

unsigned char *X509Parse::addAdditionalValue(unsigned char *sm2SignValua, int &length)
{
    static unsigned char sig[72] = {0};
    unsigned char additionalValue1[2] = {0x02, 0x20};
    unsigned char additionalValue2[3] = {0x02, 0x21, 0x00};

    length = 70;
    int index = 2;

    if((sm2SignValua[0] & 0x80)  == 0x80)
    {
        memcpy(sig + index, additionalValue2, 3);
        index += 3;
        memcpy(sig + index, sm2SignValua, 32);
        length++;
    }
    else
    {
        memcpy(sig + index, additionalValue1, 2);
        index += 2;
        memcpy(sig + index, sm2SignValua, 32);
    }

    index += 32;
    if((sm2SignValua[32] & 0x80)  == 0x80)
    {
        memcpy(sig + index, additionalValue2, 3);
        index += 3;
        memcpy(sig + index, sm2SignValua + 32, 32);
        length++;
    }
    else
    {
        memcpy(sig + index, additionalValue1, 2);
        index += 2;
        memcpy(sig + index, sm2SignValua + 32, 32);
    }

    if(length == 72)
    {
        unsigned char additionalValue3[2] = {0x30, 0x46};
        memcpy(sig, additionalValue3, 2);
    }
    else if(length == 71)
    {
        unsigned char additionalValue4[2] = {0x30, 0x45};
        memcpy(sig, additionalValue4, 2);
    }
    else if(length == 70)
    {
        unsigned char additionalValue5[2] = {0x30, 0x44};
        memcpy(sig, additionalValue5, 2);
    }

    return sig;
}







#include "dialog.h"
#include "ui_dialog.h"

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);

//    const char *plainText = "hello world";
//    char *cipherText = NULL;
//    RSACryptography rsaCryptography;
//    int length = rsaCryptography.RSA_Encrypt(plainText, cipherText, QString(qApp->applicationDirPath() + QDir::separator() + "Key_pub.pem").toStdString().c_str());

//    qDebug()<<QByteArray(cipherText, length).toHex();


//    char *plain_Text = NULL;
//    length = rsaCryptography.RSA_Decrypt(cipherText, plain_Text, QString(qApp->applicationDirPath() + QDir::separator() + "Key.pem").toStdString().c_str());
//    qDebug()<<plain_Text;
//    qDebug()<<QByteArray(plain_Text, length).toHex();

//    AesCryptography aesCryptography;
//    const char *plainText = "hello world";
//    char *cipherText = NULL;

//    int length = aesCryptography.AES_Encrypt(plainText, strlen(plainText), cipherText);

//    char *plainText1 = NULL;
//    aesCryptography.AES_Decrypt(cipherText, length, plainText1);
//    qDebug()<<plainText1;


//    const char *plainText = "hello world";

//    SM2Cryptography sm2Cryptography;
//    string enc_text = sm2Cryptography.Encrypt(QString(qApp->applicationDirPath() + QDir::separator() + "ekey.pem").toStdString(), plainText);
//    qDebug()<<QByteArray(enc_text.c_str(), enc_text.length()).toHex()<< enc_text.length();

//    string plain_text = sm2Cryptography.Decrypt(QString(qApp->applicationDirPath() + QDir::separator() + "dkey.pem").toStdString(), enc_text);
//    qDebug()<<QString::fromStdString(plain_text);


    EVP_PKEY *priKey = X509Parse::read_P12("/root/Desktop/certs/platform.p12", "test");

    const char *msg = "hello world";
    unsigned char *sig = NULL;
    size_t slen = 0;
    X509Parse::digestSign(msg, sig, &slen, priKey);

    qDebug()<<QByteArray((const char *)sig, slen).toHex();
    unsigned char *sm2SignValua = X509Parse::stripAdditionalVaule(sig);

    int length = 0;
    unsigned char *sig1 =  X509Parse::addAdditionalValue(sm2SignValua, length);
    qDebug()<<QByteArray((const char *)sig1, length).toHex();

    X509 *cert = X509Parse::read_X509("/root/Desktop/certs/platform.cer");
    EVP_PKEY *pubKey = X509Parse::X509_get_pubkey(cert);

    qDebug()<<X509Parse::digestVerify(msg, sig1, length, pubKey);

    if(sig)
        OPENSSL_free(sig);

    X509Parse::X509_free_PKEY(priKey);
    X509Parse::X509_free_PKEY(pubKey);
}

Dialog::~Dialog()
{
    delete ui;
}



//if ((fp = fopen("/root/Desktop/priKey.pem", "w")) == NULL) {
//  fprintf(stderr, "Error opening file %s\n","/root/Desktop/priKey.pem");
//  exit(1);
//}

//if (pkey) {
//  fprintf(fp, "***Private Key***\n");
//  PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
//}

//if (cert) {
//  fprintf(fp, "***User Certificate***\n");
//  PEM_write_X509_AUX(fp, cert);
//}

//if (ca && sk_X509_num(ca)) {
//  fprintf(fp, "***Other Certificates***\n");
//  for (int i = 0; i < sk_X509_num(ca); i++)
//      PEM_write_X509_AUX(fp, sk_X509_value(ca, i));
//}


/*
 *
 *   int ver = X509_get_version(cert);
    qDebug("ver: %d\n", ver);

    // 获得证书序列号函数
    ASN1_INTEGER *X509_get_serialNumber(X509 *x);

    int nNameLen = 512;
    char csCommonName[512] = {0};
    //获得证书颁发者信息函数
    X509_NAME *pCommonName = X509_get_issuer_name(cert);
    nNameLen = X509_NAME_get_text_by_NID(pCommonName, NID_commonName, csCommonName, nNameLen);
    qDebug("csCommonName:%s\n",csCommonName);

    //获得证书拥有者信息函数
    X509_NAME *pSubName = X509_get_subject_name(cert);

    char csBuf[256] = {0};
    memset(csBuf, 0, 256);
    int iLen = X509_NAME_get_text_by_NID(pSubName, NID_countryName, csBuf, 256);
    qDebug("NID_countryName: %s\n", csBuf);

    memset(csBuf, 0, 256);
    iLen = X509_NAME_get_text_by_NID(pSubName, NID_organizationName, csBuf, 256);
    qDebug("NID_organizationName: %s\n", csBuf);

    memset(csBuf, 0, 256);
    iLen = X509_NAME_get_text_by_NID(pSubName, NID_organizationalUnitName, csBuf, 256);
    qDebug("NID_organizationalUnitName: %s\n", csBuf);

    memset(csBuf, 0, 256);
    iLen = X509_NAME_get_text_by_NID(pSubName, NID_commonName, csBuf, 256);
    qDebug("NID_commonName: %s\n", csBuf);

    //获得证书有效期的起始日期函数
    ASN1_TIME *start = X509_get_notBefore(cert);
    time_t ttStart = ASN1_TIME_get(start);

    //获得证书有效期的起始日期函数
    ASN1_TIME *start = X509_get_notBefore(ca);
    time_t ttStart = ASN1_TIME_get(start);

    //获得证书有效期的终止日期函数
    ASN1_TIME *end = X509_get_notAfter(ca);
    time_t ttEnd = ASN1_TIME_get(end);

    struct tm* pStart = gmtime(&ttStart);
    qDebug("starttime: %04d-%02d-%02d %02d:%02d:%02d\n", pStart->tm_year + 1900, pStart->tm_mon+1, pStart->tm_mday, pStart->tm_hour, pStart->tm_min, pStart->tm_sec);

    struct tm* pEnd = gmtime(&ttEnd);
    qDebug("pEndtime: %04d-%02d-%02d %02d:%02d:%02d\n", pEnd->tm_year + 1900, pEnd->tm_mon+1, pEnd->tm_mday, pEnd->tm_hour, pEnd->tm_min, pEnd->tm_sec);



    pkey = X509_get_pubkey(cert);
    */

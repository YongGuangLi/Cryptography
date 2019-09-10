#ifndef PARSECERTIFICATE_H
#define PARSECERTIFICATE_H


#include <QIODevice>
#include <QString>
#include <QByteArray>
#include <QDebug>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define NOCRYPT

#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>


#include <QFile>
#include "e_os.h"

#pragma execution_character_set("utf-8")

class ParseCertificate
{
public:
    ParseCertificate();
    ~ParseCertificate();

public:
    bool ParseFile(QString strFileName);

protected:
    bool ParsePemFile(QString strFileName);
    bool ParseDerFile(QString strFileName);


public:
//    CertificateEntity m_certEntity;

protected:
    int MyPint( const char ** s, int n, int min, int max, int * e);
    time_t ASN1_TIME_get(ASN1_TIME * a, int *err);


};

#endif // PARSECERTIFICATE_H

#include "ParseCertificate.h"

#include <QFileInfo>

ParseCertificate::ParseCertificate()
{

}

ParseCertificate::~ParseCertificate()
{

}

bool ParseCertificate::ParseDerFile(QString strFileName)
{
    qDebug("-------------Parse DER Certificate File-----------------------\n");
    X509 *cert = 0;
    int id,len,ret;
    FILE *fp,*fp2;
    ASN1_BIT_STRING *dd;
    unsigned char buf[50000],*p;
    char buffer[72];
    char out[5000];

    int outl;

    //EVP_ENCODE_CTX ectx;
    //EVP_EncodeInit(&ectx);

    QFile derFile(strFileName);
    if( !derFile.open(QIODevice::ReadOnly) )
        return false;

    QByteArray strCont = derFile.readAll();
    //qDebug() << strCont2.size();
    QString strBaseRes;
    for(int i =0; i < strCont.size(); ++i)
    {
        //printf("%02x ", (unsigned char)strCont.at(i));
        char buf[10];
        memset(buf, 0, 10);
        sprintf(buf, "%02x", (unsigned char)strCont.at(i));
        strBaseRes.append(QString("%1").arg(buf));
    }

//    QString strBase64Content = QByteArray::fromHex(strBaseRes.toLocal8Bit()).toBase64(QByteArray::Base64Encoding);
//    QString strOrgContent = QString("-----BEGIN CERTIFICATE-----\n") + strBase64Content + QString("\n-----END CERTIFICATE-----\n");

    QFileInfo file(strFileName);
    QString fileName = file.fileName();

//    m_certEntity.set_format("DER");
//    m_certEntity.set_name(fileName.toStdString());


//    m_certEntity.set_content(strBaseRes.toLocal8Bit().data());
//    m_certEntity.set_originalcontent(strOrgContent.toStdString());

    fp=fopen(strFileName.toLatin1().data(), "rb");
    if( fp == NULL )
        return false;
    len=fread(buf,1,50000,fp);
    fclose(fp);
    p=buf;

    d2i_X509(&cert,(const unsigned char **)&p,len);
    if (cert == NULL )
    {
        return false;
    }

    int nNameLen = 512;
    char csCommonName[512] = {0};
    X509_NAME *pCommonName = NULL;
    pCommonName = X509_get_issuer_name(cert);
    nNameLen = X509_NAME_get_text_by_NID(pCommonName, NID_commonName, csCommonName, nNameLen);
    qDebug("issue csCommonName: %s\n", csCommonName);
//    m_certEntity.set_issue(csCommonName);

    int iLen = 0;
    int iSubNameLen = 0;
    char csSubName[1024] = {0};
    char csBuf[256] = {0};
    X509_NAME *pSubName = NULL;
    pSubName = X509_get_subject_name(cert);

    memset(csBuf, 0, 256);
    iLen = X509_NAME_get_text_by_NID(pSubName, NID_countryName, csBuf, 256);
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
//    m_certEntity.set_subject(csBuf);

    int err = 0;
    ASN1_TIME *start = NULL;
    ASN1_TIME *end = NULL;
    time_t ttStart = {0};
    time_t ttEnd = {0};
//    LONGLONG nLLStart = 0;
//    LONGLONG nLLEnd = 0;
//    FILETIME ftStart = {0};
//    FILETIME ftEnd = {0};
//    SYSTEMTIME ptmStart;
//    SYSTEMTIME ptmEnd;
    start = X509_get_notBefore(cert);
    end = X509_get_notAfter(cert);
    ttStart = ASN1_TIME_get(start, &err);
    ttEnd = ASN1_TIME_get(end, &err);
    unsigned char *timedata = start->data;
    printf("starttime: %s, flag:%d, long: %d, type: %d \n", timedata, start->flags, start->length, start->type);
    unsigned char *endtimedata = end->data;
    printf("endtime: %s, flag:%d, long: %d, type: %d \n", endtimedata, end->flags, end->length, end->type);

    printf("ttStart: %lld, ttend: %lld\n", ttStart, ttEnd);
    printf("ttStart is %s\n", ctime(&ttStart));
    printf("ttEnd is %s\n", ctime(&ttEnd));

    struct tm* pStart = gmtime(&ttStart);//localtime
    qDebug("starttime: %d-%d-%d %d:%d:%d\n", pStart->tm_year + 1900, pStart->tm_mon+1, pStart->tm_mday, pStart->tm_hour, pStart->tm_min, pStart->tm_sec);
    struct tm* pEnd = gmtime(&ttEnd);
    qDebug("pEndtime: %d-%d-%d %d:%d:%d\n", pEnd->tm_year + 1900, pEnd->tm_mon+1, pEnd->tm_mday, pEnd->tm_hour, pEnd->tm_min, pEnd->tm_sec);

    char strValidTime[100];
    memset(strValidTime, 0 , 100);
    sprintf(strValidTime, "%04d%02d%02d%02d%02d%02d", pEnd->tm_year + 1900, pEnd->tm_mon+1, pEnd->tm_mday, pEnd->tm_hour, pEnd->tm_min, pEnd->tm_sec);

//    m_certEntity.set_validityperiod(strValidTime);

    X509_free(cert);

    return true;
}

bool ParseCertificate::ParsePemFile(QString strFileName)
{
    qDebug("-------------Parse PEM Certificate File-----------------------\n");

    QFile certFile(strFileName);
    if( !certFile.open(QIODevice::ReadOnly | QIODevice::Text) )
        return false;

    QString strOrgContentRm;
    QString strOrgAllContent;
    QTextStream in(&certFile);
    while(!in.atEnd())
    {
        QString strLine = in.readLine();
        strOrgAllContent.append(strLine);
        strOrgAllContent.append("\n");
        if(strLine.contains("-----BEGIN ") )
        {
            continue;
        }

        if(strLine.contains("-----END ") )
        {
            break;
        }

        strOrgContentRm.append(strLine);
    }


    QFileInfo file(strFileName);
    QString fileName = file.fileName();

//    m_certEntity.set_format("PEM");
//    m_certEntity.set_name(fileName.toStdString());

//    QByteArray certHex =QByteArray::fromBase64(strOrgContentRm.toLocal8Bit(), QByteArray::Base64Encoding).toHex();
//    m_certEntity.set_content(certHex.data());
//    m_certEntity.set_originalcontent(strOrgAllContent.toStdString());



    BIO *bio_err;
    const char *p;
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    p = getenv("OPENSSL_DEBUG_MEMORY");
    if (p != NULL && strcmp(p, "on") == 0)
        CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    BIO *f = BIO_new_file(strFileName.toLocal8Bit(), "r");
    if (f == NULL)
    {
        //fprintf(stderr, "%s: Error opening cert file: '%s': %s\n", progname, *argv, strerror(errno));
        return false;
    }

    int count;
    char *name = 0;
    char *header = 0;
    unsigned char *data = 0;
    long len;
    typedef X509 *(*d2i_X509_t)(X509 **, const unsigned char **, long);
    typedef int (*i2d_X509_t)(X509 *, unsigned char **);
    int err = 0;

    for (count = 0; !err && PEM_read_bio(f, &name, &header, &data, &len); ++count)
    {
        int trusted = strcmp(name, PEM_STRING_X509_TRUSTED) == 0;
        d2i_X509_t d2i = trusted ? d2i_X509_AUX : d2i_X509;
        i2d_X509_t i2d = trusted ? i2d_X509_AUX : i2d_X509;
        X509 *cert = NULL;
        const unsigned char* p = data;
        unsigned char *buf = NULL;
        unsigned char *bufp;
        long enclen;

        if (!trusted && strcmp(name, PEM_STRING_X509) != 0 && strcmp(name, PEM_STRING_X509_OLD) != 0)
        {
            fprintf(stderr, "unexpected PEM object: %s\n", name);
            err = 1;
            goto next;
        }

        cert = d2i(NULL, &p, len);
        if (cert == NULL || (p - data) != len)
        {
            fprintf(stderr, "error parsing input %s\n", name);
            err = 1;
            goto next;
        }

        //lc add
        int ver = X509_get_version(cert);
        printf("ver: %d\n", ver);
        int nNameLen = 512;
        char csCommonName[512] = {0};
        X509_NAME *pCommonName = NULL;
        pCommonName = X509_get_issuer_name(cert);
        nNameLen = X509_NAME_get_text_by_NID(pCommonName, NID_commonName, csCommonName, nNameLen);
        qDebug("issue csCommonName: %s\n", csCommonName);
//        m_certEntity.set_issue(csCommonName);

        int iLen = 0;
        int iSubNameLen = 0;
        char csSubName[1024] = {0};
        char csBuf[256] = {0};
        X509_NAME *pSubName = NULL;
        pSubName = X509_get_subject_name(cert);

        memset(csBuf, 0, 256);
        iLen = X509_NAME_get_text_by_NID(pSubName, NID_countryName, csBuf, 256);
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
        m_certEntity.set_subject(csBuf);

        int err = 0;
        ASN1_TIME *start = NULL;
        ASN1_TIME *end = NULL;
        time_t ttStart = {0};
        time_t ttEnd = {0};
        LONGLONG nLLStart = 0;
        LONGLONG nLLEnd = 0;
        FILETIME ftStart = {0};
        FILETIME ftEnd = {0};
        SYSTEMTIME ptmStart;
        SYSTEMTIME ptmEnd;
        start = X509_get_notBefore(cert);
        end = X509_get_notAfter(cert);
        ttStart = ASN1_TIME_get(start, &err);
        ttEnd = ASN1_TIME_get(end, &err);
        unsigned char *timedata = start->data;
        printf("starttime: %s, flag:%d, long: %d, type: %d \n", timedata, start->flags, start->length, start->type);
        unsigned char *endtimedata = end->data;
        printf("endtime: %s, flag:%d, long: %d, type: %d \n", endtimedata, end->flags, end->length, end->type);

        printf("ttStart: %lld, ttend: %lld\n", ttStart, ttEnd);
        printf("ttStart is %s\n", ctime(&ttStart));
        printf("ttEnd is %s\n", ctime(&ttEnd));

        struct tm* pStart = gmtime(&ttStart);//localtime
        qDebug("starttime: %d-%d-%d %d:%d:%d\n", pStart->tm_year + 1900, pStart->tm_mon+1, pStart->tm_mday, pStart->tm_hour, pStart->tm_min, pStart->tm_sec);
        struct tm* pEnd = gmtime(&ttEnd);
        qDebug("pEndtime: %d-%d-%d %d:%d:%d\n", pEnd->tm_year + 1900, pEnd->tm_mon+1, pEnd->tm_mday, pEnd->tm_hour, pEnd->tm_min, pEnd->tm_sec);

        char strValidTime[100];
        memset(strValidTime, 0 , 100);
        sprintf(strValidTime, "%04d%02d%02d%02d%02d%02d", pEnd->tm_year + 1900, pEnd->tm_mon+1, pEnd->tm_mday, pEnd->tm_hour, pEnd->tm_min, pEnd->tm_sec);

//        m_certEntity.set_validityperiod(strValidTime);
        //lc add end

        /* Test traditional 2-pass encoding into caller allocated buffer */
        enclen = i2d(cert, NULL);
        if (len != enclen)
        {
            fprintf(stderr, "encoded length %ld of %s != input length %ld\n", enclen, name, len);
            err = 1;
            goto next;
        }

        if ((buf = bufp = (unsigned char*)OPENSSL_malloc(len)) == NULL)
        {
            perror("malloc");
            err = 1;
            goto next;
        }
        enclen = i2d(cert, &bufp);
        if (len != enclen)
        {
            fprintf(stderr, "encoded length %ld of %s != input length %ld\n", enclen, name, len);
            err = 1;
            goto next;
        }
        enclen = (long) (bufp - buf);
        if (enclen != len)
        {
            fprintf(stderr, "unexpected buffer position after encoding %s\n", name);
            err = 1;
            goto next;
        }

        if (memcmp(buf, data, len) != 0)
        {
            fprintf(stderr, "encoded content of %s does not match input\n", name);
            err = 1;
            goto next;
        }
        OPENSSL_free(buf);
        buf = NULL;

        /* Test 1-pass encoding into library allocated buffer */
        enclen = i2d(cert, &buf);
        if (len != enclen)
        {
            fprintf(stderr, "encoded length %ld of %s != input length %ld\n", enclen, name, len);
            err = 1;
            goto next;
        }

        if (memcmp(buf, data, len) != 0)
        {
            fprintf(stderr, "encoded content of %s does not match input\n", name);
            err = 1;
            goto next;
        }

        if (trusted)
        {
            /* Encode just the cert and compare with initial encoding */
            OPENSSL_free(buf);
            buf = NULL;

            /* Test 1-pass encoding into library allocated buffer */
            enclen = i2d(cert, &buf);
            if (enclen > len)
            {
                fprintf(stderr, "encoded length %ld of %s > input length %ld\n", enclen, name, len);
                err = 1;
                goto next;
            }

            if (memcmp(buf, data, enclen) != 0)
            {
                fprintf(stderr, "encoded cert content does not match input\n");
                err = 1;
                goto next;
            }
        }

    /*
     * If any of these were null, PEM_read() would have failed.
     */
    next:
        X509_free(cert);
        OPENSSL_free(buf);
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }

    if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE)
    {
        /* Reached end of PEM file */
        if (count > 0)
        {
            ERR_clear_error();

            BIO_free(f);
            BIO_free(bio_err);
            return true;
        }
    }

    BIO_free(f);
    BIO_free(bio_err);
    return false;
}

bool ParseCertificate::ParseFile(QString strFileName)
{
    QFile certFile(strFileName);
    if( !certFile.open(QIODevice::ReadOnly | QIODevice::Text) )
        return false;

    QTextStream in(&certFile);
    while (!in.atEnd())
    {
        QString strLine = in.readLine();
        if( strLine.contains("-----BEGIN ") )
        {
            return ParsePemFile(strFileName);
        }
        else
        {
            return ParseDerFile(strFileName);
        }

        break;
    }

    certFile.close();
}

int ParseCertificate::MyPint( const char ** s, int n, int min, int max, int * e)
{
    int retval = 0;
    while (n) {
        if (**s < '0' || **s > '9') { *e = 1; return 0; }
        retval *= 10;
        retval += **s - '0';
        --n; ++(*s);
    }
    if (retval < min || retval > max) *e = 1;
    return retval;
}

time_t ParseCertificate::ASN1_TIME_get(ASN1_TIME * a, int *err)
{
    char days[2][12] ={{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
                { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }};
    int dummy;
    const char *s;
    int generalized;
    struct tm t;
    int i, year, isleap, offset;
    time_t retval;
    if (err == NULL)
        err = &dummy;
    if (a->type == V_ASN1_GENERALIZEDTIME) {
        generalized = 1;
    } else if (a->type == V_ASN1_UTCTIME) {
        generalized = 0;
    } else {
        *err = 1;
        return 0;
    }
    s = (char *)a->data; // Data should be always null terminated
    if (s == NULL || s[a->length] != '\0') {
        *err = 1;
        return 0;
    }
    *err = 0;
    if (generalized) {
        t.tm_year = MyPint(&s, 4, 0, 9999, err) - 1900;
    } else {
        t.tm_year = MyPint(&s, 2, 0, 99, err);
    if (t.tm_year < 50)
        t.tm_year += 100;
    }
    t.tm_mon = MyPint(&s, 2, 1, 12, err) - 1;
    t.tm_mday = MyPint(&s, 2, 1, 31, err);
// NOTE: It's not yet clear, if this implementation is 100% correct
// for GeneralizedTime... but at least misinterpretation is
// impossible --- we just throw an exception
    t.tm_hour = MyPint(&s, 2, 0, 23, err);
    t.tm_min = MyPint(&s, 2, 0, 59, err);
    if (*s >= '0' && *s <= '9') {
        t.tm_sec = MyPint(&s, 2, 0, 59, err);
    } else {
        t.tm_sec = 0;
    }
    if (*err)
        return 0; // Format violation
    if (generalized) {
        // skip fractional seconds if any
        while (*s == '.' || *s == ',' || (*s >= '0' && *s <= '9')) ++s;
        // special treatment for local time
        if (*s == 0) {
            t.tm_isdst = -1;
            retval = mktime(&t); // Local time is easy :)
            if (retval == (time_t)-1) {
                *err = 2;
                retval = 0;
            }
            return retval;
        }
    }
    if (*s == 'Z') {
        offset = 0;
        ++s;
    } else if (*s == '-' || *s == '+') {
        i = (*s++ == '-');
        offset = MyPint(&s, 2, 0, 12, err);
        offset *= 60;
        offset += MyPint(&s, 2, 0, 59, err);
        if (*err) return 0; // Format violation
        if (i) offset = -offset;
        } else {
        *err = 1;
        return 0;
    }
    if (*s) {
        *err = 1;
        return 0;
    }
// And here comes the hard part --- there's no standard function to
// convert struct tm containing UTC time into time_t without
// messing global timezone settings (breaks multithreading and may
// cause other problems) and thus we have to do this "by hand"
//
// NOTE: Overflow check does not detect too big overflows, but is
// sufficient thanks to the fact that year numbers are limited to four
// digit non-negative values.
    retval = t.tm_sec;
    retval += (t.tm_min - offset) * 60;
    retval += t.tm_hour * 3600;
    retval += (t.tm_mday - 1) * 86400;
    year = t.tm_year + 1900;
    if ( sizeof (time_t) == 4) {
        // This is just to avoid too big overflows being undetected, finer
        // overflow detection is done below.
        if (year < 1900 || year > 2040) *err = 2;
    }
// FIXME: Does POSIX really say, that all years divisible by 4 are
// leap years (for consistency)??? Fortunately, this problem does
// not exist for 32-bit time_t and we should'nt be worried about
// this until the year of 2100 :)
    isleap = ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
    for (i = t.tm_mon - 1; i >= 0; --i) retval += days[isleap][i] * 86400;
    retval += (year - 1970) * 31536000;
    if (year < 1970) {
        retval -= ((1970 - year + 2) / 4) * 86400;
        if ( sizeof (time_t) > 4) {
            for (i = 1900; i >= year; i -= 100) {
                if (i % 400 == 0) continue ;
                retval += 86400;
            }
        }
        if (retval >= 0) *err = 2;
    } else {
        retval += ((year - 1970 + 1) / 4) * 86400;
        if ( sizeof (time_t) > 4) {
            for (i = 2100; i < year; i += 100) {
                // The following condition is the reason to
                // start with 2100 instead of 2000
                if (i % 400 == 0) continue ;
                retval -= 86400;
            }
        }
        if (retval < 0) *err = 2;
    }
    if (*err) retval = 0;
    return retval;

}



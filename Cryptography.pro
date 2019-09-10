#-------------------------------------------------
#
# Project created by QtCreator 2019-08-23T15:21:01
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Cryptography
TEMPLATE = app


SOURCES += main.cpp\
        dialog.cpp \
    rsacryptography.cpp \
    sm2cryptography.cpp \
    aescryptography.cpp \
    sm2SignUtil.cpp

HEADERS  += dialog.h \
    rsacryptography.h \
    sm2cryptography.h \
    aescryptography.h \
    sm2SignUtil.h

FORMS    += dialog.ui

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../../../../../data/GmSSL-master/release/ -lssl
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../../../../../data/GmSSL-master/debug/ -lssl
else:unix: LIBS += -L$$PWD/../../../../../data/GmSSL-master/ -lssl

INCLUDEPATH += $$PWD/../../../../../data/GmSSL-master
DEPENDPATH += $$PWD/../../../../../data/GmSSL-master

win32:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../data/GmSSL-master/release/ssl.lib
else:win32:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../../../../../data/GmSSL-master/debug/ssl.lib
else:unix: PRE_TARGETDEPS += $$PWD/../../../../../data/GmSSL-master/libssl.a

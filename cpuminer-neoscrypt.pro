#-------------------------------------------------
#
# Project created by QtCreator 2014-08-10T02:45:29
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = cpuminer-neoscrypt
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    scrypt.c \
    sha2.c \
    util.c \
    cpu-miner.c \
    neoscrypt.c

OTHER_FILES += \
    README \
    nomacro.pl \
    example-cfg.json \
    autogen.sh \
    AUTHORS \
    ChangeLog \
    COPYING \
    cpuminer-neoscrypt.pro.user \
    Dockerfile \
    LICENSE \
    Makefile.am \
    minerd.1 \
    NEWS \
    configure.ac

HEADERS += \
    scrypt-arm.S \
    scrypt-x64.S \
    scrypt-x86.S \
    sha2-arm.S \
    sha2-x64.S \
    sha2-x86.S \
    compat.h \
    elist.h \
    miner.h \
    neoscrypt.h \
    neoscrypt_asm.S

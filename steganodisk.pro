SOURCES  = main.cc secretfile.cc cipher.cc
HEADERS  = secretfile.h cipher.h
TARGET   = steganodisk
QT       = core
CONFIG += qt release warn_on console c++11
CONFIG -= incremental debug_and_release debug_and_release_targets

# Fix the paths to fit your system
INCLUDEPATH += $$(OPENSSL_DIR)/include

# fix the libraries to fit your system
win32 {
LIBS += -L$$(OPENSSL_DIR)/lib
LIBS += -llibeay32
}

!win32 {
LIBS += $$(OPENSSL_DIR)/lib/libcrypto.a $$(OPENSSL_DIR)/lib/libz.a -ldl
}

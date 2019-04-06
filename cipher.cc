#include "cipher.h"

#include <QCryptographicHash>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include <stdexcept>

// Magic numbers in abundance

// AES256 block size = 16, key length = 32, iv length = 16

// arbitrarily chosen initialization vector
static const unsigned char iv[16] = { 77, 60, 8, 0xB8, 48, 0xe,
    0xd0, 40, 8, 42, 50, 9, 77, 19, 20, 15 };

//
void EncryptData( QByteArray &data, QString const &password )
{
    EVP_CIPHER const *cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init( ctx );

    // turn password into 32-bytes key using sha256
    QCryptographicHash sha256( QCryptographicHash::Sha256 );
    QByteArray key = password.toUtf8();
    sha256.addData( key );
    key = sha256.result();

    EVP_EncryptInit_ex( ctx, cipher, NULL,
        reinterpret_cast<unsigned char*>( key.data() ), iv );
    EVP_CIPHER_CTX_set_padding( ctx, 0 ); // disable padding

    // encrypt the buffer
    int cryptlen = data.size() + EVP_MAX_BLOCK_LENGTH;
    int f_len = 0;
    QByteArray out( cryptlen, ' ' );
    cryptlen = 0;
    EVP_EncryptUpdate( ctx, reinterpret_cast<unsigned char*>( out.data() ),
        &cryptlen, reinterpret_cast<const unsigned char*>( data.data() ),
        data.size() );
    EVP_EncryptFinal_ex( ctx,
        reinterpret_cast<unsigned char*>( out.data() ) + cryptlen, &f_len );

    out.resize( cryptlen + f_len );
    EVP_CIPHER_CTX_free( ctx );

    // data size must not change after encryption
    if( out.size() != data.size() )
    {
        throw std::runtime_error( "encryption changed data size" );
    }

    data = out;
}

//
void DecryptData( QByteArray &data, QString const &password )
{
    EVP_CIPHER const *cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init( ctx );

    // turn password into 32-bytes key using sha256
    QCryptographicHash sha256( QCryptographicHash::Sha256 );
    QByteArray key = password.toUtf8();
    sha256.addData( key );
    key = sha256.result();

    EVP_DecryptInit_ex( ctx, cipher, NULL,
        reinterpret_cast<unsigned char*>( key.data() ), iv );
    EVP_CIPHER_CTX_set_padding( ctx, 0 ); // disable padding

    // decrypt the buffer
    int p_len = data.size();
    int f_len = 0;
    QByteArray res( data.size(), ' ' );

    EVP_DecryptUpdate( ctx, reinterpret_cast<unsigned char*>( res.data() ),
        &p_len, reinterpret_cast<unsigned char*>( data.data() ), data.size() );
    EVP_DecryptFinal_ex( ctx,
        reinterpret_cast<unsigned char*>( data.data() ) + p_len, &f_len );

    EVP_CIPHER_CTX_free( ctx );
    res.resize( p_len + f_len );

    // data size must not change after decryption
    if( res.size() != data.size() )
    {
        throw std::runtime_error( "decryption changed data size" );
    }

    data = res;
}

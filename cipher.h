#ifndef CIPHER_H_BF7D3F3518DF5F0CC8ACCEDE86687958
#define CIPHER_H_BF7D3F3518DF5F0CC8ACCEDE86687958

#include <QByteArray>
#include <QString>

//
void EncryptData( QByteArray &data, QString const &password );

//
void DecryptData( QByteArray &data, QString const &password );

#endif /* CIPHER_H_BF7D3F3518DF5F0CC8ACCEDE86687958 */

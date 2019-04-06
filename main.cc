#include <QByteArray>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QStringList>

#include "cipher.h"
#include "secretfile.h"

#include <iostream>
#include <stdexcept>

#ifdef Q_OS_LINUX
#  include <fcntl.h>
#  include <linux/fs.h>
#  include <sys/ioctl.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>

//
static
qint64 GetDeviceSize( QString const &path )
{
    char const *p = path.toLocal8Bit().constData();

    int fd = open( p, O_RDONLY );
    qint64 file_size_in_bytes = 0;
    ioctl( fd, BLKGETSIZE64, &file_size_in_bytes );
    close( fd );
    return file_size_in_bytes;
}

#endif /* Q_OS_LINUX */

//
static
void EncryptToDevice( QString const &device, SecretFile const &sf,
    QString const &password )
{
    QFileInfo fi( device );
    if( !fi.exists() )
    {
        throw std::runtime_error( "output device or file does not exist" );
    }

    qint64 devSize = fi.size();
#ifdef Q_OS_LINUX
    if( devSize < qint64( ClusterSize ) )
    {
        devSize = GetDeviceSize( device );
    }
#endif

    if( devSize < qint64( ClusterSize ) )
    {
        throw std::runtime_error( "output device or file is too small" );
    }

    QFile file( device );
    if( !file.open( QIODevice::WriteOnly ) )
    {
        throw std::runtime_error( "error opening output device or file "
            "for writing" );
    }

    const quint64 numClusters = quint64( devSize / ClusterSize );
    std::cout << "About to write " << numClusters << " clusters to device " <<
        qPrintable( device ) << std::endl;
    const int secFileClusters = sf.numChunks();
    std::cout << "SecretFile is " << secFileClusters << " cluster(s) long, "
        "writing about " << ( numClusters / secFileClusters ) << " copies." <<
        std::endl;
    for( quint64 cluster = 0; cluster < numClusters; ++cluster )
    {
        QByteArray chunk = sf.getChunkForCluster( cluster );
        EncryptData( chunk, password );
        if( file.write( chunk ) != chunk.size() )
        {
            throw std::runtime_error( "write error" );
        }

        if( ( cluster % 100 ) == 0 )
        {
            int percent = int( ( cluster * 100 ) / numClusters );
            std::cout << "\r" << cluster << ' ' << percent << '%';
            std::cout.flush();
        }
    }
    std::cout  << "\r" << numClusters << " 100%" << std::endl;
}

//
static
void DecryptFromDevice( QString const &device, SecretFile &sf,
    QString const &password )
{
    QFileInfo fi( device );
    if( !fi.exists() )
    {
        throw std::runtime_error( "input device or file does not exist" );
    }

    qint64 devSize = fi.size();
#ifdef Q_OS_LINUX
    if( devSize < qint64( ClusterSize ) )
    {
        devSize = GetDeviceSize( device );
    }
#endif

    if( devSize < qint64( ClusterSize ) )
    {
        throw std::runtime_error( "input device or file is too small" );
    }

    QFile file( device );
    if( !file.open( QIODevice::ReadOnly ) )
    {
        throw std::runtime_error( "error opening output device or file "
            "for reading" );
    }

    const quint32 numClusters = quint32( devSize / ClusterSize );
    std::cout << "Device size: " << numClusters << " clusters" << std::endl;
    quint32 totalChunks = 0, goodChunks = 0;
    QByteArray chunk = file.read( qint64( ClusterSize ) );
    while( chunk.size() == ClusterSize )
    {
        DecryptData( chunk, password );
        if( sf.addDataChunk( chunk ) )
        {
            std::cout << ' ' << totalChunks << " - decrypted\n";
            ++goodChunks;
            if( sf.isFileComplete() )
            {
                break;
            }
        }
        else
        {
            if( ( totalChunks % 100 ) == 0 )
            {
                int percent = int( ( totalChunks * 100 ) / numClusters );
                std::cout << "\r" << totalChunks << ' ' << percent << '%';
                std::cout.flush();
            }
        }
        ++totalChunks;
        std::cout.flush();
        chunk = file.read( qint64( ClusterSize ) );
    }
    std::cout << "\nTotal clusters read: " << totalChunks << ", decrypted: " <<
        goodChunks << std::endl;
}


//
static
bool ParseCommandLine( QStringList const &args, bool &encrypt, QString &device,
    QString &password, QString &secretFile )
{
    for( int i = 1; i < args.size(); ++i )
    {
        if( args[i] == "-h" )
        {
            return false;
        }

        if( args[i] == "-s" )
        {
            ++i;
            secretFile = args[i];
            continue;
        }

        if( args[i] == "-p" )
        {
            ++i;
            password = args[i];
            continue;
        }

        if( args[i] == "-e" )
        {
            encrypt = true;
            continue;
        }

        if( device.isEmpty() )
        {
            device = args[i];
        }
        else
        {
            return false;
        }
    }

    return !password.isEmpty() && !device.isEmpty() &&
        ( !secretFile.isEmpty() == encrypt );
}

//
int main( int argc, char *argv[] )
{
    QCoreApplication app( argc, argv );

    QString device, password, secretFile;
    bool encrypt = false;
    if( !ParseCommandLine( app.arguments(), encrypt, device, password,
            secretFile ) )
    {
        std::cout << "Usage:\n" << qPrintable( app.arguments()[0] ) <<
            " [-h] [-e] -p password [-s secretFile] deviceOrImageFile" <<
            std::endl;
        std::cout <<
            "   -h: this help\n"
            "   -e: encrypt secretFile into device using password (default is "
            "to extract an encrypted file from the device)\n"
            "   -p password: the encryption/decryption password\n"
            "   -s secretFile: the file to encrypt onto the device\n"
            "   deviceOrImageFile: where to write the encrypted data (warning: "
            "will overwrite any existing data!)" << std::endl;
        return 1;
    }

    try {
        SecretFile sf;
        if( encrypt )
        {
            sf.loadFrom( secretFile );
            EncryptToDevice( device, sf, password );
        }
        else
        {
            DecryptFromDevice( device, sf, password );
            sf.saveToSecretFile(); // obtained from the data
            std::cout << "Wrote " << sf.filesize() << " bytes to file " <<
                qPrintable( sf.filename() ) << std::endl;
        }
    }
    catch( std::runtime_error const &e )
    {
        std::cout << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    std::cout << "Done." << std::endl;
    return 0;
}

#include "secretfile.h"

#include <QCryptographicHash>
#include <QFileInfo>

#include <stdexcept>

//
void SecretFile::PushInt32( QByteArray &buf, quint32 num )
{
    buf.push_back( char( num & 0xFF ) );
    buf.push_back( char( ( num >> 8 ) & 0xFF ) );
    buf.push_back( char( ( num >> 16 ) & 0xFF ) );
    buf.push_back( char( ( num >> 24 ) & 0xFF ) );
}

//
void SecretFile::PushInt64( QByteArray &buf, quint64 num )
{
    buf.push_back( char( num & 0xFF ) );
    buf.push_back( char( ( num >> 8 ) & 0xFF ) );
    buf.push_back( char( ( num >> 16 ) & 0xFF ) );
    buf.push_back( char( ( num >> 24 ) & 0xFF ) );
    buf.push_back( char( ( num >> 32 ) & 0xFF ) );
    buf.push_back( char( ( num >> 40 ) & 0xFF ) );
    buf.push_back( char( ( num >> 48 ) & 0xFF ) );
    buf.push_back( char( ( num >> 56 ) & 0xFF ) );
}

//
quint32 SecretFile::PopInt32( QByteArray const &buf, int idx )
{
    quint32 res = quint32( (unsigned char)buf[idx] );
    res += quint32( (unsigned char)buf[idx + 1] ) << 8;
    res += quint32( (unsigned char)buf[idx + 2] ) << 16;
    res += quint32( (unsigned char)buf[idx + 3] ) << 24;

    return res;
}

//
quint64 SecretFile::PopInt64( QByteArray const &buf, int idx )
{
    quint64 res = quint64( (unsigned char)buf[idx] );
    res += quint64( (unsigned char)buf[idx + 1] ) << 8;
    res += quint64( (unsigned char)buf[idx + 2] ) << 16;
    res += quint64( (unsigned char)buf[idx + 3] ) << 24;
    res += quint64( (unsigned char)buf[idx + 4] ) << 32;
    res += quint64( (unsigned char)buf[idx + 5] ) << 40;
    res += quint64( (unsigned char)buf[idx + 6] ) << 48;
    res += quint64( (unsigned char)buf[idx + 7] ) << 56;

    return res;
}

//
void SecretFile::loadFrom( QString const &filename )
{
    // safety checks
    QFileInfo fi( filename );
    if( !fi.exists() )
    {
        throw std::runtime_error( "secretFile does not exist" );
    }

    filesize_ = fi.size();
    if( filesize_ == 0 )
    {
        throw std::runtime_error( "secretFile is empty" );
    }
    // 100 Mb is enough for everyone.
    if( filesize_ > MaxSecretFileSize )
    {
        throw std::runtime_error( "secretFile is too long" );
    }

    filename_ = fi.fileName();
    utf8name_ = filename_.toUtf8();
    if( utf8name_.size() > MaxSecretFileNameLength )
    {
        throw std::runtime_error( "secretFile's name is too long, "
            "please rename to something shorter" );
    }

    // add zeros to name
    while( utf8name_.size() < MaxSecretFileNameLength )
    {
        utf8name_.push_back( char( 0 ) );
    }

    // ok, read the file in chunks.
    QFile file( filename );
    if( !file.open( QIODevice::ReadOnly ) )
    {
        throw std::runtime_error( "cannot open secretFile" );
    }

    quint32 curSize = 0;
    quint32 curChunk = 0;
    while( curSize < filesize_ )
    {
        QByteArray buf = file.read( qint64( DataSize ) );
        if( buf.isEmpty() )
        {
            throw std::runtime_error( "read error while loading secretFile" );
        }
        curSize += buf.size();
        // pad with zeros
        while( buf.size() < DataSize )
        {
            buf.push_back( char( 0 ) );
        }

        // push into the map
        chunks_[curChunk++] = buf;
    }
}

//
void SecretFile::saveToSecretFile()
{
    if( !isFileComplete() )
    {
        throw std::runtime_error( "cannot write incomplete secretFile" );
    }

    QByteArray name = utf8name_;
    name.push_back( char( 0 ) );
    filename_ = QString::fromUtf8( name.data() );
    QFile file( filename_ );
    if( !file.open( QIODevice::ReadWrite ) ) // do not truncate
    {
        throw std::runtime_error( "cannot open secretFile" );
    }

    quint32 curChunk = 0;
    quint32 dataLeft = filesize_;
    while( chunks_.contains( curChunk ) )
    {
        if( dataLeft < quint32( DataSize ) )
        {
            file.write( chunks_[curChunk++].left( dataLeft ) );
        }
        else
        {
            file.write( chunks_[curChunk++] );
        }
        dataLeft -= DataSize;
    }
}

//
bool SecretFile::isFileComplete() const
{
    if( ( filesize_ == 0 ) || utf8name_.isEmpty() )
    {
        return false;
    }

    quint32 curSize = 0;
    quint32 curChunk = 0;
    while( chunks_.contains( curChunk ) )
    {
        curSize += DataSize;
        ++curChunk;
    }

    return ( curSize >= filesize_ );
}

//
QByteArray SecretFile::getChunkForCluster( quint64 cluster ) const
{
    QByteArray res;
    PushInt64( res, cluster );
    PushInt32( res, filesize_ );

    const int numChunks = chunks_.size();
    const quint32 chunkNum = quint32( cluster ) % numChunks;

    PushInt32( res, chunkNum );
    res.append( utf8name_ );
    res.append( chunks_[chunkNum] );

    QCryptographicHash sha1( QCryptographicHash::Sha1 );
    sha1.addData( res );
    res.append( sha1.result() );

    return res;
}

//
bool SecretFile::addDataChunk( QByteArray const &chunk )
{
    // check that the chunk is valid
    if( chunk.size() != ClusterSize )
    {
        return false;
    }

    // verify checksum
    const QByteArray shaSum = chunk.right( 20 );
    QCryptographicHash sha1( QCryptographicHash::Sha1 );
    sha1.addData( chunk.left( ClusterSize - 20 ) );
    if( shaSum != sha1.result() )
    {
        return false;
    }

    // extract and verify the data
    const quint32 fileSize = PopInt32( chunk, 8 );
    if( ( fileSize == 0 ) || ( fileSize > MaxSecretFileSize ) )
    {
        return false;
    }

    const quint32 chunkNum = PopInt32( chunk, 12 );
    const quint32 maxChunkNum = quint32( fileSize / DataSize ) + 1;
    if( chunkNum > maxChunkNum )
    {
        return false;
    }

    QByteArray utfname = chunk.mid( 16, MaxSecretFileNameLength );

    // if we already have some data stored, compare to already known
    if( filesize_ > 0 )
    {
        if( ( fileSize != filesize_ ) || ( utfname != utf8name_ ) )
        {
            return false;
        }
    }
    else // remember
    {
        filesize_ = fileSize;
        utf8name_ = utfname;
    }

    // store data if needed
    if( !chunks_.contains( chunkNum ) )
    {
        chunks_[chunkNum] = chunk.mid( 16 + MaxSecretFileNameLength, DataSize );
    }

    return true;
}

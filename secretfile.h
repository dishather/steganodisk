#ifndef SECRETFILE_H_1B1E6AA0912E2418587A24BA35F8E7D9
#define SECRETFILE_H_1B1E6AA0912E2418587A24BA35F8E7D9

#include <QByteArray>
#include <QMap>
#include <QString>

// Constants
const qint64    MaxSecretFileSize = qint64( 100 * 1024 * 1024 );
const int       ClusterSize = 4096;
const int       MaxSecretFileNameLength = 32;
const int       HeaderSize = 8 + 4 + 4 + MaxSecretFileNameLength + 20;
const int       DataSize = ClusterSize - HeaderSize;

// chunk layout:
// - uint64 nonce
// - uint32 secretFileSize
// - uint32 chunkNumber
// - char[32] fileName (Utf8, not necessarily zero-terminated)
// - char[ChunkSize - HeaderSize] data (possibly padded)
// - char[20] SHA1 of the above.

//
class SecretFile {
public:
    SecretFile(): filename_(), utf8name_(), filesize_( 0 ), chunks_()  {}
    ~SecretFile() = default;

    // these throw on error
    void loadFrom( QString const &filename );
    void saveToSecretFile();

    // checks if the data is ok
    bool addDataChunk( QByteArray const &chunk );

    bool isFileComplete() const;

    QByteArray getChunkForCluster( quint64 cluster ) const;

    int numChunks() const { return chunks_.size(); }
    QString const& filename() const { return filename_; }
    quint32 filesize() const { return filesize_; }

private:
    static void PushInt32( QByteArray &buf, quint32 num );
    static void PushInt64( QByteArray &buf, quint64 num );
    static quint32 PopInt32( QByteArray const &buf, int idx );
    static quint64 PopInt64( QByteArray const &buf, int idx );

    QString filename_;
    QByteArray utf8name_;
    quint32 filesize_;
    QMap<quint32, QByteArray> chunks_;
};

#endif /* SECRETFILE_H_1B1E6AA0912E2418587A24BA35F8E7D9 */

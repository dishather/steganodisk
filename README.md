# steganodisk
Tool to hide data in untouched sectors of hard disks and flash drives

## Steganography on a disk

### 1. The Concept

Simply put: physical disks and partitions have areas that are
never overwritten during normal use. Your hard drive, for example,
has areas that have never been written to since its manufacture.

This means that you can write some secret data onto the whole
disk, then partition it, format it, and put it to normal use.
You can even put your favorite operating system on it!
And even after years of use, the secret data could possibly be
recovered from the disk's untouched areas.


### 2. The Tool

Steganodisk is a proof of concept: it takes a file (called "secretFile"),
encrypts it with the given password and writes repetitive copies of it
onto the given device. After that, it can extract the data from the device
(provided that the password is correct and there are enough untouched
sectors on the disk to reassemble the secretFile from pieces.

Currently, only Linux is supported. Run with root privileges. Building under
Windows is possible, but the tool will have limited functionality.

WARNING! This tool will overwrite any and all existing information on the
device or partition you specify! Make backups before you start experimenting!

NOTE: The longer your secret file, the more untouched sectors are required to
recover it back. Thus, longer files have lower probability of being
successfully recovered. Well, this is kind of obvious.


### 3. Technical Details

- Data is written in 4 KiB clusters. This coincides with most commonly used
  sector and cluster sizes.
- AES256 CBC encryption is used; the key is simply SHA256(utf8(password)).
  The IV (initialization vector) is the same for all sectors, so the tool
  can decrypt each cluster independently.
- Each cluster has a header that contains cluster number, secretFile
  size and name, etc. To ensure that the decryption is correct, each cluster
  has a SHA1 checksum in the end. 
- This all means that each encrypted cluster is different from all other ones,
  thus making the cryptanalysis harder. In other words: even if your secretFile
  contains all zeros, the encrypted data will have no repeating patterns.
- Maximum size of the secret file is 100 megabytes.


### 4. Applicability

- The tool works nicely on mechanical HDDs and flash pendrives.
- Keeping secret data on SSDs may be problematic because of their TRIM
  feature.
- Image files (disk images mounted via a loop device on Linux) do not work.
  The reason is simple: formatting such a "disk" creates the file anew,
  with all empty space filled with zeros ("sparse files" feature).
  You may have limited success with image files that have partitions inside.


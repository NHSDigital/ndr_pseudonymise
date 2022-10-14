# ndr_encrypt script

`ndr_encrypt` encrypts images and other files, allowing them to be hosted and
retrieved safely. The files still need to be hosted securely, but public /
private key encryption provides additional protection.

## Overview

We define a simple suite of tools, `ndr_encrypt`, to generate the encrypted
image files, and the data that lets us access them. These work in a similar way
to git object storage, and require minimal software to run in a standard Linux
/ macOS environment. (Related reading:
https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)

With these tools, you can:
1. transform a nested directory tree of files into an encrypted storage
   representation + CSV file suitable for import to a SQL database
2. identify and decrypt an image, using an entry from the CSV file
3. recover the original contents of an unknown encrypted file (but not the
   original filename), and use the CSV file to identify the original file
   [TODO: not yet implemented]
4. rewrite the encrypted files using a new encryption key [TODO: not yet
   implemented]

## Usage

```
usage: ndr_encrypt [-v | --version] [-h | --help]
                   <command> [<args>]

These are common ndr_encrypt commands used in various situations:

start a working area
   init          Create an empty Git ndr_encrypt working copy

work with files
   add           Add file contents to the encrypted store and index

encryption key rotation and repository maintenance

decrypt data
   cat-remote    Retrieve remote file based on git_blobid
   get           Retrieve local file(s) based on path in CSV index

Low-level Commands / Interrogators

Low-level Commands / Manipulators

Additional options:
        --base_url=URL               Remote repository URL
        --key_name=NAME              Key name
        --private_key=NAME           Private key filename
        --pub_key=NAME               Public key filename
        --passin=OPTIONS             Pass in private key passphrase
    -p                               Print downloaded object
```

`ndr_encrypt` requires ruby 2.0 or later to be installed

## Simple Usage Example

``` shell
# Set up an image repository:
ndr_encrypt init images
cd images

# Set up encryption / decryption keys:
# Use a strong passphrase, e.g. by running openssl rand -hex 32
echo Use a strong passphrase, e.g. `openssl rand -hex 32`
keyname=ourkey1
openssl genpkey -algorithm RSA -out ourkey1.pem -aes-256-cbc -pkeyopt rsa_keygen_bits:4096
openssl rsa -in ourkey1.pem -out ourkey1.pub -outform PEM -pubout

# Create a sample .gif file "test/dir/ok.gif"
mkdir -p test/dir
base64 --decode > test/dir/ok.gif <<BASE64
R0lGODlhDAAIAPABAAAAAP///yH5BAAAAAAAIf8LSW1hZ2VNYWdpY2sOZ2Ft
bWE9MC40NTQ1NDUALAAAAAAMAAgAAAITjI8HC9GuTJvozRchVQz6BIZgAQA7
BASE64

# Add the object to the repository
ndr_encrypt add --key_name=ourkey1 --pub_key=ourkey1.pub test/dir/ok.gif

# Move aside the original file, to test recovery
mv test/dir/ok.gif{,.orig}

# Recover file from the repository, prompting for the passphrase
# (This uses the CSV index file ndr_encrypted/index.csv and
#  the encrypted object store in ndr_encrypted/objects)
ndr_encrypt get --key_name=ourkey1 --private_key=ourkey1.pem test/dir/ok.gif

# Ensure the recovered file is identical
diff -s test/dir/ok.gif{.orig,}

# Check index contents (for hashes used in next example)
cat ndr_encrypted/index.csv
```

## Retrieving files hosted on a webserver

To retrieve files from a webserver, we assume that the contents of the index
file `ndr_encrypted/index.csv` has been moved to a table, and the object store
contents of `ndr_encrypted/objects/` have been hosted on a webserver or S3
buckets, e.g. inside `https://example.org/encrypted/storage/`

``` ruby
require 'open3'

key_name = 'ourkey1'
private_key = 'ourkey1.pem'
private_passphrase = begin # Should be read from encrypted credential storage
  require 'io/console'
  IO::console.getpass("Enter decryption passphrase for #{private_key.inspect}: ")
end

base_url = 'https://example.org/encrypted/storage/'
git_blobid = 'f29bddf64c444f663d106568f4a81a22151ed3f97b0ec0c2a5ab25a0e8a02515'

decrypted_data = Open3.capture2(
                  'ndr_encrypt', 'cat-remote', '-p', "--key_name=#{key_name}",
                  "--private_key=#{private_key}", "--base_url=#{base_url}",
                  '--passin=stdin', git_blobid,
                  stdin_data: private_passphrase, binmode: true
                 )[0]
```

## Low-level object manipulation

TODO

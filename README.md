# Entropy Vault (evlt)

Entropy Vault (evlt) is a command-line application designed for securely storing and retrieving data blobs using a vault file. The application leverages cryptographic keys as coordinates, allowing for the recovery of stored data. With evlt, multiple users can independently store data in the same vault without being aware of each other's data. To access a specific data blob, one must know the vault name, three unique keys, and the number of segments used during storage. This makes evlt particularly suitable for storing sensitive information such as cryptographic keys, passwords, automated login scripts containing sensitive credentials, binary files, and even compiled executables. Essentially, any type of data or file can be stored in an entropy vault.

This tool is primarily intended for system administrators who require secure data storage and management on critical systems, often accessed via the console or with root privileges.

This application is currently still in an experimental state. Consider it as such. Do not use it to store production-critical data.

## Features

- Secure data storage using cryptographic keys.
- Multiple independent data blobs in the same vault.
- Storage and retrieval of any data type.
- Command-line interface for easy integration with scripts and automation.
- On top of the 3 coordinate keys, there is also a master key.
- A default master key can be provided and locally cached in an obscured manner.
- A custom master key can be used for extra secret data.

## Use Cases

### Storing a Binary File

The basic syntax to store a file:
```bash
evlt put /myvault/myfile.jpeg < myfile.jpeg
```

And to recover the file you can simply run:
```bash
evlt get /myvault/myfile.jpeg > myfile.jpeg
```

Note that you can use up to 3 "keys" in the form of /vaultname/keystring1/keystring2/keystring3, but that is optional.
The missing keys will be filled in by a generated hash-based string.

You can also use more '/' subcategories (or subdirs if you want to call it that). These will work as extra keys but will just add to the key3 string. So /v/a/b/c/d/e  --> vault=v key1=a key2=b key3=c/d/e

Technically you could consider it as a sort-of directory structure, but you have no way to list its content without knowing the full "path".

### Storing a Password

To store a sensitive password in the vault:

```bash
evlt put /myvault/apl5a7qs89viok9lqsl23mdkzec/passwords/my_password -p
```

### Retrieving a Password

To retrieve the stored password, but output as an invisible string between >>> and <<< characters. (copy/paste)

```bash
evlt get /myvault/apl5a7qs89viok9lqsl23mdkzec/passwords/my_password -p
```

### Storing a Secret Key

To store the content of a file, such as an SSH private key:

```bash
evlt put /myvault/oiq4fho9qis7hf/rsakeys/id_rsa -n 8 < id_rsa
```

### Retrieving a Secret Key

To retrieve the stored key file and output as invisible copy/paste content on the terminal:

```bash
evlt get /myvault/oiq4fho9qis7hf/rsakeys/id_rsa -n 8 -i
```

### Storing a Script

To store a script in the vault:

```bash
evlt put /myvault/sysadmin/scripts/my_script.sh -n 4 < my_script.sh
```

### Retrieve and Execute a Script

To recover and execute the script:

```bash
evlt get /myvault/sysadmin/scripts/my_script.sh -n 4 -c 
```

The -c option executes the content of the script or binary executable data.

### Delete a Data Blob from a Vault

Use the "del" action to remove a data blob and free its space in the vault.

```bash
evlt del /myvault/sysadmin/scripts/my_data 
evlt del /myvault/sysadmin/scripts/my_data2 -n 4
evlt del /password/mypassword -p
```

Technically using /dev/null or an empty file as input technically has the same effect.

### Using Remote Vaults (via SFTP)
Add an RSA private key for a remote connection.
```bash
ssh-keygen -b 2048 -f mykey
evlt put /.secrets/.remotehosts/.privatekey/username@remotehost -n 1 -f mykey
```
The .secrets vault used is always the single-segment version. Make sure "-n 1"

Store an item in a remote vault.
```bash
evlt put /myvault/mydata/item -R username@remotehost -f inputfile
```

Retrieve an item from a remote vault.
```bash
evlt get /myvault/mydata/item -R username@remotehost -f inputfile
```

A remote vault is always completely copied over locally. When altered, the new version will again be uploaded to the remote location.

Optionally, you can also use custom TCP ports with -R username@hostname:PORT.
If you do this, make sure your private key is also stored in /.secrets/.remotehosts/.privatekey/username@remotehost:PORT

You can use remote vaults with any of the above use cases and options.

## Installation

To install evlt, clone the repository and compile the source code:

```bash
git clone https://github.com/oli4vr/evlt.git
cd evlt
make
make install
```
Currently, "make install" copies the executable to ~/bin. Make sure this is in your PATH.

## Syntax

<pre>
evlt             Entropy Vault
                 by Olivier Van Rompuy

 Syntax          evlt put /vaultname/key1/key2/key3/path [-v] [-n NR_SEGMENTS]
                 evlt get /vaultname/key1/key2/key3/path [-v] [-n NR_SEGMENTS]
                 evlt del /vaultname/key1/key2/key3/path [-v] [-n NR_SEGMENTS]

 put/get         Store/Recall a data blob. Uses stdin/stdout by default
 append          Append the input data to the end of an existing data blob
 del             Delete a data blob
 master          Set the default master key
 ls              List data entries in a path

 -v              Verbose mode
 -S              Secret mode -> Do not index entry -> Invisible to ls command
 -n NR           Use NR number of parallel vault file segments between 1 and 32. Default=8
 -b KBsize       Blocksize in KB Default=64KB Allowed=1 2 4 8 16 32 64
 -p              Password content -> Put: enter value using a password prompt
                                  -> Get: Invisible copy/paste output
 -i              Invisible copy/paste output. Good for keys.
 -c              Run content as a script or command
 -d path         Use an alternate dir path for the vault files
 -f file         Use file for input or output instead of stdin or stdout
 -m [masterkey]  Use a custom master key.
                 If not provided you need to enter it manually via a password prompt.
 -m prompt       Prompt for the default masterkey and store/change the value.
 -R [username@]host[:port]
                 Work on a remote vault via ssh. The rsa public key must be in ~/.ssh/authorized_keys on the remote host.
                 You can store RSA private keys in vault location /.secrets/.remotehosts/.privatekey/user@host[:port]

</pre>

### Config file
A config file .evlt.cfg is looked for in the local path or in ~/.evlt
Example config file content :
<pre>
[evlt]
DefaultSegments=4 
DefaultBlocksize=1 
DefaultPath=localvaults
</pre>
The above define practical defaults. For the path you can define both absolute paths and paths relative to the currect directory. The latter can be practical to use the tool on a usb thumb drive. (Place the evlt executable and config file on the thumb drive mount point)

### How it works
Data is written and processed one block at a time. Each block is divided into a specified number of subblocks (`-n`), which are then encrypted. Every subblock is stored in a segment file, accompanied by a SHA512 hash to ensure integrity. Each subblock undergoes encryption three times using distinct keys for enhanced security. When an EOF is hit on the input file stream, a "stop" flag is set on the last blocks of each segment.

All vault data resides within the `~/.evlt` directory. The names of the vault segment files are derived from hashed strings, which serves to obscure their contents and purpose.

To retrieve data from the vault, the segment file blocks must be processed from the beginning until the stop marker. Each block is decrypted, the sha512 is recalculated and compared. If the hashes match then the data is considered to be part of the requested data blob and sent to the output FILE stream.

# Entropy Vault (evlt)

Entropy Vault (evlt) is a command-line application designed for securely storing and retrieving data blobs using a vault file. The application leverages cryptographic keys as coordinates, allowing for the recovery of stored data. With evlt, multiple users can independently store data in the same vault without being aware of each other's data. To access a specific data blob, one must know the vault name, three unique keys, and the number of segments used during storage. This makes evlt particularly suitable for storing sensitive information such as cryptographic keys, passwords, automated login scripts containing sensitive credentials, binary files, and even compiled executables. Essentially, any type of data or file can be stored in an entropy vault.

This tool is primarily intended for system administrators who require secure data storage and management on critical systems, often accessed via the console or with root privileges.

This application is currently still in an experimental state. Use it at your own risk.

## Features

- Secure data storage using cryptographic keys.
- Multiple independent data blobs in the same vault.
- Storage and retrieval of any data type.
- Command-line interface for easy integration with scripts and automation.

## Use Cases

### Storing a binary file

The basic syntax to store a file :
```bash
evlt put /myvault/myfile.jpeg <myfile.jpeg
```

And to recover the file you can simply run :
```bash
evlt get /myvault/myfile.jpeg >myfile.jpeg
```

Note that you use up to 3 "keys" in the form of /vaultname/keystring1/keystring2/keystring3, but that is optional.
The missing keys will be filled in by a generated hash based string.

You can also use more '/' subcategories (or subdirs if you want to call it that). These will work as extra keys but will just add to the key3 string. So /v/a/b/c/d/e  --> vault=v key1=a key2=b key3=c/d/e

Technically you could consider it as a sort-of directory structure, but you have no way to list or it's content without knowing the full "path".

### Storing a Password

To store a sensitive password in the vault:

```bash
printf "MyP@ssw0rd" | evlt put /myvault/apl5a7qs89viok9lqsl23mdkzec/passwords/my_password 
```

This command will store the password "MyP@ssw0rd" in the vault named "myvault" using the keys "key1", "key2", "key3", and 8 segments.

### Retrieving a Password

To retrieve the stored password, but output as an invisible string between >>> and <<< characters. (copy/paste)

```bash
evlt get /myvault/apl5a7qs89viok9lqsl23mdkzec/passwords/my_password -i
```

The -i option chooses "invisible output mode". This could be handy for double-click copy/paste fields in interactive login scripts.

### Storing a File

To store the content of a file, such as an SSH private key:

```bash
evlt put /myvault/oiq4fho9qis7hf/rsakeys/id_rsa -n 8 < id_rsa
```

This command reads the content of the file "id_rsa" and stores it in the vault.

### Retrieving a File

To retrieve the stored binary file:

```bash
evlt get /myvault/oiq4fho9qis7hf/rsakeys/id_rsa -n 8 > id_rsa_recovered
```

This command writes the retrieved content to a new file "id_rsa_recovered".

### Storing a script

To store a script in the vault :

```bash
evlt put /myvault/sysadmin/scipts/my_script.sh -n 4 < my_script.sh
```

### Retrieve and execute a script

To recover and execute the script :

```bash
evlt get /myvault/sysadmin/scipts/my_script.sh -n 4 -c 
```

The -c option executes the content of the script or binary executable data.

## Installation

To install evlt, clone the repository and compile the source code:

```bash
git clone https://github.com/oli4vr/evlt.git
cd evlt
make
make install
```
Currently "make install" copies the executable to ~/bin. Make sure this is in your PATH.

## Syntax

The general syntax for using evlt is as follows:

```bash
evlt [action] /vaultname/key1/key2/key3 [options]
```

- `[action]` is either `put` to store data or `get` to retrieve data.
- `/vaultname/key1/key2/key3` specifies the vault name and the three keys.
- `[options]` can include:
  - `-n NR_SEGMENTS` to specify the number of parallel vault file segments (default is 8).
  - `-v` for verbose mode.
  - `-i` to output an invisible copy/paste string on the console.
  - `-c` to run the retrieved content as a script or command.

Always ensure that the vault name and keys are kept secure and are not exposed to unauthorized users.

### How it works
Data is written and processed one block at a time. Each block is divided into a specified number of subblocks (`-n`), which are then encrypted. Every subblock is stored in a segment file, accompanied by a SHA512 hash to ensure integrity. Each subblock undergoes encryption three times using distinct keys for enhanced security.

All vault data resides within the `~/.evlt` directory. The names of the vault segment files are derived from hashed strings, which serves to obscure their contents and purpose.

To retrieve data from the vault, the entire vault's contents must be decrypted. The hashes of the decrypted blocks are then compared to ensure they match the requested data blob. Only blocks with matching hashes are considered part of the retrieved data set.

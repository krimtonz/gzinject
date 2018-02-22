## About

gzinject is used to extract the contents of a wad and pack it back into a wad with any changes that have been made.
While this will work for *most* WADs, it is designed to work primarily with the Ocarina of Time wad in order to inject
gz (the practice rom). 

## Usage 

```
Usage: gzinject -a,--action=(genkey | extract | pack) [options]
  options:
    -a, --action (genkey | extract | pack)		Defines the action to run
      genkey: generates a common key
      extract: extracts contents of wadfile specified by --wad to --directory
      pack: packs contents --directory  into wad specified by --wad
    -w, --wad wadfile					Defines the wadfile to use Input wad for extracting, output wad for packing
    -d, --directory directory				Defines the output directory for extract operations, or the input directory for pack operations
    -i, --channelid channelid				Changes the channel id during packing (4 characters)
    -t, --channeltitle channeltitle			Changes the channel title during packing (max 20 characters)
    -r, --region [0-3]					Changes the WAD region during packing 0 = JP, 1 = US, 2 = Europe, 3 = FREE
    -k, --key keyfile					Uses the specified common key file
	--cleanup						Cleans up the wad directory before extracting or after packing
    -v, --verbose					Prints verbose information
	-v, --version					Prints version information
    -?, --help						Prints this help message
```

## Thanks/Authors

gzinject was primarily written by me, Thanks to glankk (https://github.com/glankk) for the memory/controller fixes, 
as well as debugging, testing, and providing fixes for various errors
The general workflow of extracting/packing the wad was taken from showmiiwads (https://github.com/dnasdw/showmiiwads/)
AES encryption/decryption was taken from kokke (https://github.com/kokke/tiny-AES-c)
SHA1 taken from clibs (https://github.com/clibs/sha1), MD5 taken from Alexander Peslyak
http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5

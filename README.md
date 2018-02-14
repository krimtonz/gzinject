## About

gzinject is used to extract the contents of a wad and pack it back into a wad with any changes that have been made.
While this will work for *most* WADs, it is designed to work primarily with the Ocarina of Time wad in order to inject
gz (the practice rom). 

## Usage 

gzinject does 3 primary functions 
**gzinject genkey** will generate common-key.bin in the current directory. This key is required for the other functions

**gzinject extract InWad.wad** will extract all the content files to the wadextract as well as extracts the content5.app 
U8 archive to wadextract/content5 so the rom from the wad file will be wadextract/content5/rom

**gzinject pack OutWad.wad [ChannelID] [ChannelName]** pack wadextract/content5 into wadextract/content5.app, apply the memory/controller mappings to content1.app,
change the title id if requested, change the channel name if requested, set the wad to be region free, then pack it all into Outwad.wad

## Thanks/Authors

gzinject was primarily written by me, Thanks to glankk (https://github.com/glankk) for the memory/controller fixes.
The general workflow of extracting/packing the wad was taken from showmiiwads (https://github.com/dnasdw/showmiiwads/)
AES encryption/decryption was taken from kokke (https://github.com/kokke/tiny-AES-c)
SHA1 taken from clibs (https://github.com/clibs/sha1), MD5 taken from Alexander Peslyak
http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5

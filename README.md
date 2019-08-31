## About

gzinject is used to extract the contents of a wad and pack it back into a wad with any changes that have been made.
While this will work for *most* WADs, it is designed to work primarily with the Ocarina of Time wad in order to inject
gz (the practice rom). 

## Executable 

To build your own, run ./configure, then make, and make install. See BUILDING for more instructions

Prebuilt Windows executable is contained under releases (https://github.com/krimtonz/gzinject/releases/latest)

## Usage 

    Usage: gzinject -a,--action=(genkey | extract | pack) [options]
      options:
      -a, --action (genkey | extract | pack)    Defines the action to run
        genkey: generates a common key
        extract: extracts contents of wadfile specified by --wad to --directory
        pack: packs contents --directory  into wad specified by --wad
        inject: does the extract and pack operations in one pass, requires the --rom option for the rom to inject, wad will be created as wadfile-inject.wad
    
	  -w, --wad wadfile                       Defines the wadfile to use Input wad for extracting, output wad for packing
      -d, --directory directory               Defines the output directory for extract operations, or the input directory for pack operations
      -m, --rom rom                           Defines the rom to inject using -a inject 
      -o, --outputwad wad                     Defines the filename to output to when using -a inject
      -i, --channelid channelid               Changes the channel id during packing (4 characters)
      -t, --channeltitle channeltitle         Changes the channel title during packing (max 20 characters)
      -r, --region [0-3]                      Changes the WAD region during packing 0 = JP, 1 = US, 2 = Europe, 3 = FREE
      --raphnet                               Maps Z To L instead of c-stick down, for N64->GC Raphnet Adapters
      
      disable remapping options:
          --disable-controller-remappings         Disables all controller remappings during packing
          --disable-cstick-d-remapping            Disables c-stick down remapping
          --disable-dpad-d-remapping               Disables dpad-down remapping
          --disable-dpad-u-remapping               Disables dpad-up remapping
          --disable-dpad-l-remapping               Disables dpad-right remapping
          --disable-dpad-r-remapping               Disables dpad-left remapping
      
      --enable-stick-fix                      Enables fix for GC to N64 control stick mapping
      --stick-deadzone size                   Sets the deadzone on the control stick to the supplied value (default: 0). --enable-stick-fix is required
      --stick-bounds n[,n[,n,n]]              Sets the maximum control stick values (default: 106). n = all directions the same, n,n = horizontal and vertical separate, n,n,n,n = all directions separate. --enable-stick-fix is required

      -k, --key keyfile                       Uses the specified common key file
      --cleanup                               Cleans up the wad directory before extracting or after packing
      --verbose                               Prints verbose information
      -v, --version                           Prints version information
      -?, --help                              Prints this help message


## Thanks/Authors

gzinject was primarily written by me, Thanks to glankk (https://github.com/glankk) for the memory/controller fixes, 
as well as debugging, testing, and providing fixes for various errors
The general workflow of extracting/packing the wad was taken from showmiiwads (https://github.com/dnasdw/showmiiwads/)
AES encryption/decryption was taken from kokke (https://github.com/kokke/tiny-AES-c)
SHA1 taken from clibs (https://github.com/clibs/sha1), MD5 taken from Alexander Peslyak
http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5

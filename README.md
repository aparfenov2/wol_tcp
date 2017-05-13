# wol_tcp
wakeonlan via tcp syn

Waking up remote computer over NAT with TCP SYN WOL magic packet.
See description at kantengri.blogspot.com.

To build the project first download these dependencies:

1. PcapPlusPlus    https://github.com/seladb/PcapPlusPlus
    [https://github.com/seladb/PcapPlusPlus/releases/latest](https://github.com/seladb/PcapPlusPlus/releases/latest)
2. Winpcap developer's pack - containing the wpcap library PcapPlusPlus is linking with plus relevant h files. You can download it from https://www.winpcap.org/devel.htm
3. pthread-win32 - can be downloaded from here: ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.zip

working solution is in main3.cpp
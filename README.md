# Squirrel3-SHA-256
SHA-256 algorithm for Squirrel3

### Disclaimer
This was written for the Team Fortress 2 implementation of Squirrel 3, which is 32 bit. SHA-256 requires 64 bit integers to run, and thus this does not function the same outside of TF2 as it does inside of TF2. It generates an entirely different set of hashes when used inside a 32 bit game. However, this produces the correct hashes if called in a squirrel runtime on a 64 bit system.

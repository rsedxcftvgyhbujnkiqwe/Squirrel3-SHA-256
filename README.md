# Squirrel3-SHA-256
SHA-256 algorithm for Squirrel3

### Instructions
vsha256.nut should be used on a 32 bit system (such as a valve game).

sha256.nut should be used on a 64 bit system

### Disclaimer
vsha256.nut produces a different hash than regular sha256. This is due to the inherent limitations of running on a 32-bit system, and my inherent laziness in wanting to try and circumvent this. In a sense this makes it a different/new cryptographic algorithm, though I am not a security researcher so I can't tell you if this is compromised or not.

However, in the context of the use case for this (obfuscating stored data inside of a script file) the accuracy of a real sha256 hash to a vsha256 hash is irrelevant since it produces consistent results. Additionally, since you can't make network requests in a vscript, whether or not it is a real sha256 hash is also irrelevant. 

//SHA-256 Library
//Written by: blank
//Hash generation as specified by: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//                                                   //
//      THIS HASH GENERATION IS !!NOT!! THE SAME     //
//      AS REGULAR SHA-256 WHEN CALLED WITHIN TF2    //
//      BECAUSE IT RUNS ON 32 BIT. HOWEVER, IT       //
//      WILL WORK ON A 64 BIT SYSTEM                 //
//                                                   //
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

//4.2.2 SHA-224 and SHA-256 Constants
//"These words represent the first thirty-two bits of the fractional parts
// of the cube roots of the first sixty-four prime numbers."
K <- [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

//2.2.2 Symbols and operations
//All addition is modulo 2^32
const intcap = 4294967296

//6.2 SHA-256
function sha256(message){
    //6.2.1 SHA-256 Preprocessing
    //5.3.3 Initial hash values
    local h0 = 0x6a09e667
    local h1 = 0xbb67ae85
    local h2 = 0x3c6ef372
    local h3 = 0xa54ff53a
    local h5 = 0x9b05688c
    local h4 = 0x510e527f
    local h6 = 0x1f83d9ab
    local h7 = 0x5be0cd19

    //5.1.1 Padding
    local messageBytes = blob()
    foreach(character in message)
        messageBytes.writen(character,'b')
    local messageLength = messageBytes.len()
    local messageBitLength = messageLength * 8

    messageBytes.writen(0x80,'b')
    while(((messageBytes.len()*8 + 64) % 512) != 0) {
        messageBytes.writen(0x00,'b');
    }

    for (local i = 7;i>=0;i--){
        messageBytes.writen((messageBitLength >> (i*8)) & 0xff,'b')
    }

    //5.2.1 SHA-256 Parsing the Message
    local blocks = []
    for (local i=0;i<messageBytes.len();i +=64){
        blocks.append(ReadBlobRange(messageBytes,0,64))
    }

    //6.2.2 SHA-256 Hash Computation
    foreach(M in blocks){
        //1. Prepare message schedule
        local W = []
        for (local t=0;t<64;t++){
            if (t <16){
                W.append(ReadBlobRange(M,t*4,4))
            }
            else{
                local term1 = sigma1(BytesToIntBE(W[t-2]))
                local term2 = BytesToIntBE(W[t-7])
                local term3 = sigma0(BytesToIntBE(W[t-15]))
                local term4 = BytesToIntBE(W[t-16])
                local schedule = IntToBytesBE((term1 + term2 + term3 + term4) % intcap,4)
                W.append(schedule)
            }

        }

        //2. Initialize working variables
        local a = h0
        local b = h1
        local c = h2
        local d = h3
        local e = h4
        local f = h5
        local g = h6
        local h = h7
        local t1 = 0
        local t2 = 0

        //3. Modify working variables
        for (local t=0;t<64;t++){
            t1 = (h + capsigma1(e) + Ch(e,f,g) + K[t] + BytesToIntBE(W[t])) % intcap
            t2 = (capsigma0(a) + Maj(a,b,c)) % intcap
            h = g
            g = f
            f = e
            e = (d + t1) % intcap
            d = c
            c = b
            b = a
            a = (t1 + t2) % intcap
        }

        //4. Compute intermediate hash value
        h0 = (a + h0) % intcap
        h1 = (b + h1) % intcap
        h2 = (c + h2) % intcap
        h3 = (d + h3) % intcap
        h4 = (e + h4) % intcap
        h5 = (f + h5) % intcap
        h6 = (g + h6) % intcap
        h7 = (h + h7) % intcap
    }

    //Resulting message digest
    local hexstring = ""
    foreach(hval in [h0,h1,h2,h3,h4,h5,h6,h7]){
        foreach (byte in IntToBytesBE(hval,4)){
            hexstring = hexstring + format("%02x",byte)
        }
    }
    return hexstring

}

//4.1.2 SHA-224 and SHA-256 Functions
function Ch(x,y,z){
    return (x & y) ^ (~x & z)
}

function Maj(x,y,z){
    return (x & y) ^ (x & z) ^ (y & z)
}

function ROTR(x,n){
    return (x >> n) | (x << 32 - n)
}

function sigma0(x){
    return ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3)
}

function sigma1(x){
    return ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10)
}

function capsigma0(x){
    return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22)
}

function capsigma1(x){
    return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25)
}

//extra functions for dealing with squirrel
function ReadBlobRange(blob,x,y){
    blob.seek(x)
    return blob.readblob(y)
}

function IntToBytesBE(x,bytecount){
    local byteobj = blob()
    for(local i=bytecount;i>0;i--){
        byteobj.writen((x >> (i-1)*8) & 0xff,'b')
    }
    return byteobj
}

function BytesToIntBE(bytes){
    local num = 0;
    foreach(byte in bytes){
        num = num << 8
        num += byte
    }
    return num;
}

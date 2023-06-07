#ifndef BYTEPATTERN_H
#define BYTEPATTERN_H

#include <string>

#define IN_RANGE(x, a, b)        (x >= a && x <= b)
#define GET_BITS(x)            (IN_RANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xA))
#define GET_BYTE(x)            (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))

class CBytePattern {
public:
    CBytePattern(char *pattern) :
            pattern(pattern) {}

    unsigned long search(unsigned char *src, unsigned long srcLength);

private:
    char *pattern;
};

#endif //BYTEPATTERN_H

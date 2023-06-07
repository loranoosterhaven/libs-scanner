#include <iostream>
#include "bytepattern.h"

unsigned long CBytePattern::search(unsigned char *src, unsigned long srcLength) {
    auto curPattern = (unsigned char *) pattern;
    unsigned long firstMatch = 0;

    for (unsigned long i = 0; i < srcLength; i++) {
        if (src[i] == GET_BYTE(curPattern)) {
            if (firstMatch == 0) {
                firstMatch = i;
            }

            if (*(curPattern + 2) == '\0') {
                return firstMatch;
            }

            curPattern += 3;
        } else if (*curPattern == '?') {
            curPattern += 2;
        } else if (firstMatch != 0) {
            i = firstMatch + 1;
            curPattern = (unsigned char *) pattern;
            firstMatch = 0;
        }
    }
    return 0;
}
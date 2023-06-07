#ifndef KOTLINDETECTOR_H
#define KOTLINDETECTOR_H

#include "apk.h"

class CKotlinInspector {
public:
    explicit CKotlinInspector(CAPK *apk)
            : apk(apk) {}

    bool hasKotlin();

private:
    CAPK *apk;
};

#endif //KOTLINDETECTOR_H

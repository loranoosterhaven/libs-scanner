
#include "dex.h"
#include "kotlininspector.h"
#include "bytepattern.h"

bool CKotlinInspector::hasKotlin() {
    CBytePattern kotlinPatterns[]= {
            //UTF-8 string: "Parameter specified as non-null is null: method"
            CBytePattern("50 61 72 61 6d 65 74 65 72 20 73 70 65 63 69 66 69 65 64 20 61 73 20 6e 6f 6e 2d " \
                "6e 75 6c 6c 20 69 73 20 6e 75 6c 6c 3a 20 6d 65 74 68 6f 64"),

            //UTF-8 string: "kotlin-stdlib"
            CBytePattern("6b 6f 74 6c 69 6e 2d 73 74 64 6c 69 62")
    };

    for( int i = 0; i < apk->getNumDex(); i++ ) {
        CDex* targetDex = apk->getDex(i);

        for (auto & kotlinPattern : kotlinPatterns) {
            unsigned long offset = kotlinPattern.search(targetDex->getBuffer(), targetDex->getSize());

            if( offset != 0 ){
                return true;
            }
        }
    }

    return false;
}
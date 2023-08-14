#ifndef KEYINSPECTOR_H
#define KEYINSPECTOR_H

#include <fstream>
#include <string>
#include <iostream>

#include "apk.h"
#include "disassembler.h"
#include "directory.h"

class CKeyInspector {
public:
    explicit CKeyInspector(CAPK *apk) : apk(apk) { disasm = new CDisassembler(); }

    ~CKeyInspector() {
        delete disasm;
    }

    bool leakingPrivateKey() { return foundPrivateKey; }
    bool isAppObfuscated() { return appObfuscated; }

    void scan(CDirectory* directory);

private:
    void printReferencingMethods(CDex* dex, int dexNum, int stringIdx);

private:
    bool foundPrivateKey;
    bool appObfuscated;

    CAPK *apk;
    CDisassembler *disasm;

    std::ofstream out;
};

#endif //KEYINSPECTOR_H

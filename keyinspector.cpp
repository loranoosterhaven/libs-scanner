#include <iostream>

#include "dex.h"
#include "keyinspector.h"
int numberOfLeakedKeys = 0;
void CKeyInspector::scan(CDirectory* directory)
{
    out = std::ofstream(directory->getPath() + "/key_leakage.txt", std::ios::app);

    //add different output log to file.
    foundPrivateKey = false;
    appObfuscated = false;

    for( int i = 0; i < apk->getNumDex(); i++ ) {
        CDex* targetDex = apk->getDex(i);
        for ( int j = 0; j < targetDex->getNumStrings(); j++ ) {
            char* targetStr = targetDex->getString(j);

            if( strstr(targetStr,"BEGIN") != nullptr && strstr(targetStr,"PRIVATE KEY-") != nullptr
                && strlen(targetStr) > 96) {
                foundPrivateKey = true;

                out << "=====" << apk->getName() << ": found private key:" << "=====" << std::endl << std::endl;
                out << targetStr << std::endl << std::endl;
                numberOfLeakedKeys++;
                out << "total keys: " << numberOfLeakedKeys << std::endl;
                printReferencingMethods(targetDex, i, j);
            } else if( strstr(targetStr,"La/") != nullptr || strstr(targetStr,"Lb/") != nullptr || strstr(targetStr,"La0/") != nullptr
                || strstr(targetStr,"/a$a;") != nullptr) {
                appObfuscated = true;
            }
        }
    }

    out << std::endl;

    out.close();
}

void CKeyInspector::printReferencingMethods(CDex* dex, int dexNum, int stringIdx)
{
    out << "Looking for 0x" << std::hex << stringIdx << " in dex " << dexNum << std::endl;
    bool bFoundRef = false;

    for (int j = 0; j < dex->getNumClassDef(); j++) {
        auto *classDefs = dex->getClassDef(j);

        unsigned long totalClassCodeSize = 0;

        auto *classData = new CDexClass;

        if (dex->decodeClassData(j, classData)) {
            for (int k = 0; k < classData->header.virtualMethodsSize; k++) {
                if (!dex->isValidMethod(&classData->virtualMethods[k])) {
                    continue;
                }

                auto *methodId = dex->getMethodId(classData->virtualMethods[k].methodIdx);
                auto *codeHeader = (dexCode *) &dex->getBuffer()[classData->virtualMethods[k].codeOff];

                totalClassCodeSize += dex->getCodeInstructionsSize(codeHeader);

                unsigned long codeInstrOffset =
                        classData->virtualMethods[k].codeOff + sizeof(dexCode);
                unsigned char *bytecode = &dex->getBuffer()[codeInstrOffset];

                unsigned long relativeOffset = 0;
                while (relativeOffset < dex->getCodeInstructionsSize(codeHeader)) {
                    auto instructionLen = disasm->length(&bytecode[relativeOffset]);

                    if (disasm->isStringConst(&bytecode[relativeOffset]) && stringIdx == disasm->getStringConstStringId(&bytecode[relativeOffset])) {
                        out << "\tRef string id: " << disasm->getStringConstStringId(&bytecode[relativeOffset]) << std::endl;
                        out << "\tRef class: " << dex->getTypeDesc(classDefs->classIdx) << std::endl;
                        out << "\tRef method: " << dex->getString(methodId->nameIdx) << std::endl;
                        out << "\tRef string: " << dex->getString(disasm->getStringConstStringId(&bytecode[relativeOffset])) << std::endl;
                        out << "\tRef offset: " << relativeOffset << std::endl;

                        // Derive size of the key.
                        bFoundRef = true;
                    }

                    relativeOffset += instructionLen;
                }
            }

            for (int k = 0; k < classData->header.directMethodsSize; k++) {
                if (!dex->isValidMethod(&classData->directMethods[k])) {
                    continue;
                }

                auto *methodId = dex->getMethodId(classData->directMethods[k].methodIdx);
                auto *codeHeader = (dexCode *) &dex->getBuffer()[classData->directMethods[k].codeOff];

                totalClassCodeSize += dex->getCodeInstructionsSize(codeHeader);

                unsigned long codeInstrOffset =
                        classData->directMethods[k].codeOff + sizeof(dexCode);
                unsigned char *bytecode = &dex->getBuffer()[codeInstrOffset];

                unsigned long relativeOffset = 0;
                while (relativeOffset < dex->getCodeInstructionsSize(codeHeader)) {
                    auto instructionLen = disasm->length(&bytecode[relativeOffset]);

                    if (disasm->isStringConst(&bytecode[relativeOffset]) && stringIdx == disasm->getStringConstStringId(&bytecode[relativeOffset])) {
                        out << "\tRef string id: " << disasm->getStringConstStringId(&bytecode[relativeOffset]) << std::endl;
                        out << "\tRef class: " << dex->getTypeDesc(classDefs->classIdx) << std::endl;
                        out << "\tRef method: " << dex->getString(methodId->nameIdx) << std::endl;
                        out << "\tRef string: " << dex->getString(disasm->getStringConstStringId(&bytecode[relativeOffset])) << std::endl;
                        out << "\tRef offset: " << relativeOffset << std::endl;

                        // Derive size of the key.
                        bFoundRef = true;
                    }

                    relativeOffset += instructionLen;
                }
            }
        }
    }

    if( !bFoundRef ) {
        out << "\tNo ref found to private key"  << std::endl;
    }
}
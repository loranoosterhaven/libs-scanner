
#include <iostream>
#include <set>
#include "dex.h"
#include "kotlinanalyzer.h"
#include "bytepattern.h"
#include "dextypes.h"

CAnalyzerResult CKotlinAnalyzer::analyze(bool hasKotlin) {
    CAnalyzerResult result;
    memset(&result, 0, sizeof(result));

    result.numDex = apk->getNumDex();
    return result;

    if (hasKotlin) {
        computeKotlinPackageName(&result);
    }

    processKotlinStdlib(result.kotlinPackage, &result);

    for (int i = 0; i < apk->getNumDex(); i++) {
        auto *dex = apk->getDex(i);

        for (int j = 0; j < dex->getNumClassDef(); j++) {
            auto *classDefs = dex->getClassDef(j);

            bool isKotlinCallingClass = false;

            bool isLanguageFeatureCallingClass[KLF_MAX];
            memset(isLanguageFeatureCallingClass, 0, sizeof(isLanguageFeatureCallingClass));

            unsigned long totalClassCodeSize = 0;
            char *typeDescription = dex->getTypeDesc(classDefs->classIdx);

            if (isInnerClass(typeDescription)) {
                continue;
            }

            bool projectClass = isProjectClass(apk, typeDescription);
            bool kotlinStdlibClass =
                    result.kotlinPackage[0] != '\0' && strstr(typeDescription, result.kotlinPackage) != nullptr;

            if (!kotlinStdlibClass) {
                auto *classData = new CDexClass;

                if (dex->decodeClassData(j, classData)) {
                    for (int k = 0; k < classData->header.virtualMethodsSize; k++) {
                        if (!isValidMethod(&classData->virtualMethods[k])) {
                            continue;
                        }

                        auto *codeHeader = (dexCode *) &dex->getBuffer()[classData->virtualMethods[k].codeOff];

                        totalClassCodeSize += dex->getCodeInstructionsSize(codeHeader);

                        unsigned long codeInstrOffset = classData->virtualMethods[k].codeOff + sizeof(dexCode);
                        unsigned char *bytecode = &dex->getBuffer()[codeInstrOffset];

                        unsigned long relativeOffset = 0;
                        while (relativeOffset < dex->getCodeInstructionsSize(codeHeader)) {
                            auto instructionLen = disasm->length(&bytecode[relativeOffset]);

                            if (disasm->isInvocation(&bytecode[relativeOffset])) {
                                result.numInvocations++;

                                if (projectClass) {
                                    result.numProjectInvocations++;
                                }

                                unsigned short invocationMethodIndex = disasm->getInvocationMethodId(
                                        &bytecode[relativeOffset]);

                                auto *invocationMethodId = dex->getMethodId(invocationMethodIndex);
                                auto *invocationTypeDescription = dex->getTypeDesc(invocationMethodId->classIdx);

                                if (result.kotlinPackage[0] != '\0' &&
                                    strstr(invocationTypeDescription, result.kotlinPackage) !=
                                    nullptr) {
                                    isKotlinCallingClass = true;

                                    result.numKotlinInvocations++;

                                    if (projectClass) {
                                        result.numKotlinProjectInvocations++;
                                    }

                                    for (int l = 0; l < KLF_MAX; l++) {
                                        if (strstr(invocationTypeDescription,
                                                   result.languageFeatureTypeDescription[l]) !=
                                            nullptr) {
                                            isLanguageFeatureCallingClass[l] = true;

                                            result.numLanguageFeatureInvocations[l]++;

                                            if (projectClass) {
                                                result.numLanguageFeatureProjectInvocations[l]++;
                                            }
                                        }
                                    }
                                }
                            }

                            relativeOffset += instructionLen;
                        }
                    }

                    for (int k = 0; k < classData->header.directMethodsSize; k++) {
                        if (!isValidMethod(&classData->directMethods[k])) {
                            continue;
                        }

                        auto *codeHeader = (dexCode *) &dex->getBuffer()[classData->directMethods[k].codeOff];

                        totalClassCodeSize += dex->getCodeInstructionsSize(codeHeader);

                        unsigned long codeInstrOffset = classData->directMethods[k].codeOff + sizeof(dexCode);
                        unsigned char *bytecode = &dex->getBuffer()[codeInstrOffset];

                        unsigned long relativeOffset = 0;
                        while (relativeOffset < dex->getCodeInstructionsSize(codeHeader)) {
                            auto instructionLen = disasm->length(&bytecode[relativeOffset]);

                            if (disasm->isInvocation(&bytecode[relativeOffset])) {
                                result.numInvocations++;

                                if (projectClass) {
                                    result.numProjectInvocations++;
                                }

                                unsigned short invocationMethodIndex = disasm->getInvocationMethodId(
                                        &bytecode[relativeOffset]);

                                auto *invocationMethodId = dex->getMethodId(invocationMethodIndex);
                                auto *invocationTypeDescription = dex->getTypeDesc(invocationMethodId->classIdx);

                                if (result.kotlinPackage[0] != '\0' &&
                                    strstr(invocationTypeDescription, result.kotlinPackage) !=
                                    nullptr) {
                                    isKotlinCallingClass = true;

                                    result.numKotlinInvocations++;

                                    if (projectClass) {
                                        result.numKotlinProjectInvocations++;
                                    }

                                    for (int l = 0; l < KLF_MAX; l++) {
                                        if (strstr(invocationTypeDescription,
                                                   result.languageFeatureTypeDescription[l]) !=
                                            nullptr) {
                                            isLanguageFeatureCallingClass[l] = true;

                                            result.numLanguageFeatureInvocations[l]++;

                                            if (projectClass) {
                                                result.numLanguageFeatureProjectInvocations[l]++;
                                            }
                                        }
                                    }
                                }
                            }

                            relativeOffset += instructionLen;
                        }
                    }
                }

                delete classData;
            }

            result.numClasses++;
            result.numBytes += totalClassCodeSize;

            if (!kotlinStdlibClass) {
                if (projectClass) {
                    result.numProjectClasses++;
                    result.numProjectBytes += totalClassCodeSize;

                    if (isKotlinCallingClass) {
                        result.numKotlinInvocatingProjectClasses++;
                        result.numKotlinInvocatingProjectBytes += totalClassCodeSize;
                    }
                }

                if (isKotlinCallingClass) {
                    result.numKotlinInvocatingClasses++;
                    result.numKotlinInvocatingBytes += totalClassCodeSize;
                }

                for (int l = 0; l < KLF_MAX; l++) {
                    if (isLanguageFeatureCallingClass[l]) {
                        result.numLanguageFeatureUsingClasses[l]++;

                        if (projectClass) {
                            result.numLanguageFeatureUsingProjectClasses[l]++;
                        }
                    }
                }
            }
        }
    }

    computeRatios(&result);

    return result;
}

unsigned long CKotlinAnalyzer::findNullSafetyMethod(CDex *dex) {
    auto throwParameterIsNullException = CBytePattern(
            "71 00 ? ? ? ? 0c ? 6e 10 ? ? ? ? 0c ? 12 ? 46 ? ? ? 6E 10");

    auto offset = throwParameterIsNullException.search(dex->getBuffer(), dex->getSize());

    if (offset == 0) {
        return 0;
    }

    return offset - sizeof(dexCode);
}

unsigned long CKotlinAnalyzer::findCoroutinesMethod(CDex *dex) {
    CBytePattern patterns[]{
            // CombinedContext::containsAll
            CBytePattern("39 00 04 00 12 ? 0F ? 54 ? ? ? 20 ? ? ? 38 00 05 00 1F"),

            // ContinuationKt::startCoroutine
            CBytePattern("1A ? ? ? 71 20 ? ? ? ? 1A ? ? ? 71 20 ? ? ? ? 71 30 ? ? ? ? 0C ? 71 10 ? ? ? ? 0C ? 62 ? ? ? 62"),
    };

    for (auto & pattern : patterns){
        auto offset = pattern.search(dex->getBuffer(), dex->getSize());

        if( offset != 0 ) {
            return offset - sizeof(dexCode);
        }
    }

    return 0;
}

unsigned long CKotlinAnalyzer::findDelegationMethod(CDex *dex) {
    auto notNullVar = CBytePattern(
            "1A ? ? ? 71 20 ? ? ? 00 54 ? ? ? 38 ? 03 00 11 ? 22 ? ? ? 22 ? ? ? 70");

    auto offset = notNullVar.search(dex->getBuffer(), dex->getSize());

    if (offset == 0) {
        return 0;
    }

    return offset - sizeof(dexCode);
}

unsigned long CKotlinAnalyzer::findIoMethod(CDex *dex) {
    CBytePattern patterns[]{
            // closable
            CBytePattern("39 ? ? ? 28 0F 39 ? ? ? 72 10 ? ? ? ? 28 09 72 10 ? ? ? ? 28 05 0D ? 71 20 ? ? ? ? 0E 00"),

            // closable
            CBytePattern("39 ? ? ? 0E 00 39 ? ? ? 72 10 ? ? ? ? 28 FA 00 00 72 10"),

            // FilesKt__UtilKt::createTempDir
            CBytePattern("1A ? ? ? 71 20 ? ? ? ? 71 30 ? ? ? ? 0C ? 6E 10 ? ? ? ? 6E 10 ? ? ? ? 0A ? 38 ? ? ? 1A ? ? ? 71 20"),
    };

    for (auto & pattern : patterns){
        auto offset = pattern.search(dex->getBuffer(), dex->getSize());

        if( offset != 0 ) {
            return offset - sizeof(dexCode);
        }
    }

    return 0;
}

unsigned long CKotlinAnalyzer::findRangesMethod(CDex *dex) {
    CBytePattern patterns[]{
            // IntRange::hashCode
            CBytePattern("6E 10 ? ? ? ? 0A 00 38 ? 04 ? 12 F0 28 0C 6E 10 ? ? ? ? 0A 00 DA ? ? ? 6E 10 ? ? ? ? 0A"),
    };

    for (auto & pattern : patterns){
        auto offset = pattern.search(dex->getBuffer(), dex->getSize());

        if( offset != 0 ) {
            return offset - sizeof(dexCode);
        }
    }

    return 0;
}

unsigned long CKotlinAnalyzer::findCollectionsMethod(CDex *dex) {
    CBytePattern patterns[]{
            // EmptyList::listIterator
            CBytePattern("39 ? ? ? 62 ? ? ? 11 ? 22 ? ? ? 22 ? ? ? 70 10 ? ? ? ? 1A ? ? ? 6E 20 ? ? ? ? 6E 20 ? ? ? ? 6E 10 ? ? ? ? 0C ? 70 20 ? ? ? ? 27"),
    };

    for (auto & pattern : patterns){
        auto offset = pattern.search(dex->getBuffer(), dex->getSize());

        if( offset != 0 ) {
            return offset - sizeof(dexCode);
        }
    }

    return 0;
}

unsigned long CKotlinAnalyzer::findSequencesMethod(CDex *dex) {
    CBytePattern patterns[]{
            // TakeSequence::take
            CBytePattern("52 ? ? ? 34 ? 04 ? 07 ? 28 08 22 ? ? ? 54 ? ? ? 70 30"),
    };

    for (auto & pattern : patterns){
        auto offset = pattern.search(dex->getBuffer(), dex->getSize());

        if( offset != 0 ) {
            return offset - sizeof(dexCode);
        }
    }

    return 0;
}

unsigned long CKotlinAnalyzer::findConcurrentMethod(CDex *dex) {
    CBytePattern patterns[]{
            // ThreadKt::thread
            CBytePattern("1A ? ? ? 71 20 ? ? ? ? 22 ? ? ? 70 20 ? ? ? ? 38 ? 06 ? 12 ? 6E 20 ? ? ? ? 3D"),
    };

    for (auto & pattern : patterns){
        auto offset = pattern.search(dex->getBuffer(), dex->getSize());

        if( offset != 0 ) {
            return offset - sizeof(dexCode);
        }
    }

    return 0;
}

dexMethod *CKotlinAnalyzer::findMethodByOffset(CDex *dex, unsigned long offset) {
    for (int j = 0; j < dex->getNumClassDef(); j++) {
        auto *classData = new CDexClass;

        if (!dex->decodeClassData(j, classData)) {
            delete classData;
            continue;
        }

        for (int k = 0; k < classData->header.virtualMethodsSize; k++) {
            if (!isValidMethod(&classData->virtualMethods[k])) {
                continue;
            }

            auto *code = dex->getCode(&classData->virtualMethods[k]);

            if (offset >= classData->virtualMethods[k].codeOff &&
                offset < classData->virtualMethods[k].codeOff + dex->getCodeInstructionsSize(code)) {
                auto *result = new dexMethod(classData->virtualMethods[k]);
                delete classData;

                return result;
            }
        }

        for (int k = 0; k < classData->header.directMethodsSize; k++) {
            if (!isValidMethod(&classData->directMethods[k])) {
                continue;
            }

            auto *code = dex->getCode(&classData->directMethods[k]);

            if (offset >= classData->directMethods[k].codeOff &&
                offset < classData->directMethods[k].codeOff + dex->getCodeInstructionsSize(code)) {
                auto *result = new dexMethod(classData->directMethods[k]);
                delete classData;

                return result;
            }
        }

        delete classData;
    }

    return nullptr;
}

void CKotlinAnalyzer::computeKotlinPackageName(CAnalyzerResult *result) {
    strcpy(result->languageFeatureTypeDescription[KLF_NULL_SAFETY], "Lkotlin/jvm/internal/Intrinsics;");
    strcpy(result->languageFeatureTypeDescription[KLF_COROUTINES], "Lkotlin/coroutines/");
    strcpy(result->languageFeatureTypeDescription[KLF_REFLECTION], "Lkotlin/reflect/");
    strcpy(result->languageFeatureTypeDescription[KLF_DELEGATION], "Lkotlin/properties/");
    strcpy(result->languageFeatureTypeDescription[KLF_RANGES], "Lkotlin/ranges/");
    strcpy(result->languageFeatureTypeDescription[KLF_TEXT], "Lkotlin/text/");
    strcpy(result->languageFeatureTypeDescription[KLF_COLLECTIONS], "Lkotlin/collections/");
    strcpy(result->languageFeatureTypeDescription[KLF_COMPARISONS], "Lkotlin/comparisons/");
    strcpy(result->languageFeatureTypeDescription[KLF_CONCURRENT], "Lkotlin/concurrent/");
    strcpy(result->languageFeatureTypeDescription[KLF_IO], "Lkotlin/io/");
    strcpy(result->languageFeatureTypeDescription[KLF_SEQUENCES], "Lkotlin/sequences/");

    result->obfuscated = false;

    for (int i = 0; i < apk->getNumDex(); i++) {
        auto *dex = apk->getDex(i);

        auto throwParameterIsNullExceptionOffset = findNullSafetyMethod(dex);

        if (throwParameterIsNullExceptionOffset != 0 && result->kotlinPackage[0] == '\0') {
            dexMethod *throwParameterIsNullException = findMethodByOffset(dex, throwParameterIsNullExceptionOffset);

            if (throwParameterIsNullException != nullptr) {
                auto *methodId = dex->getMethodId(throwParameterIsNullException->methodIdx);
                char *className = dex->getTypeDesc(methodId->classIdx);

                if (strcmp(className, "Lkotlin/jvm/internal/Intrinsics;") != 0) {
                    result->obfuscated = true;
                }
                strcpy(result->languageFeatureTypeDescription[KLF_NULL_SAFETY], className);
                strcpy(result->kotlinPackage, className);

                for (int j = 0; j < 3; j++) {
                    char *split = strrchr(result->kotlinPackage, '/');

                    if (split != nullptr) {
                        split[0] = '\0';
                    }
                }

                strcat(result->kotlinPackage, "/");

                delete throwParameterIsNullException;
            }
        }

        auto coroutinesMethodOffset = findCoroutinesMethod(dex);

        if (coroutinesMethodOffset != 0) {
            dexMethod *coroutinesMethod = findMethodByOffset(dex, coroutinesMethodOffset);

            if (coroutinesMethod != nullptr) {
                auto *methodId = dex->getMethodId(coroutinesMethod->methodIdx);
                char *className = dex->getTypeDesc(methodId->classIdx);

                strcpy(result->languageFeatureTypeDescription[KLF_COROUTINES], className);

                char *split = strchr(result->languageFeatureTypeDescription[KLF_COROUTINES], '/');

                if (split != nullptr) {
                    split = strchr(split + 1, '/');

                    if (split != nullptr) {
                        split[0] = '\0';
                    }
                }

                strcat(result->languageFeatureTypeDescription[KLF_COROUTINES], "/");

                delete coroutinesMethod;
            }
        }

        auto notNullVarOffset = findDelegationMethod(dex);

        if (notNullVarOffset != 0) {
            dexMethod *notNullVar = findMethodByOffset(dex, notNullVarOffset);

            if (notNullVar != nullptr) {
                auto *methodId = dex->getMethodId(notNullVar->methodIdx);
                char *className = dex->getTypeDesc(methodId->classIdx);

                strcpy(result->languageFeatureTypeDescription[KLF_DELEGATION], className);

                char *split = strchr(result->languageFeatureTypeDescription[KLF_DELEGATION], '/');

                if (split != nullptr) {
                    split = strchr(split + 1, '/');

                    if (split != nullptr) {
                        split[0] = '\0';
                    }
                }

                strcat(result->languageFeatureTypeDescription[KLF_DELEGATION], "/");

                delete notNullVar;
            }
        }

        auto closableOffset = findIoMethod(dex);

        if (closableOffset != 0) {
            dexMethod *closable = findMethodByOffset(dex, closableOffset);

            if (closable != nullptr) {
                auto methodId = dex->getMethodId(closable->methodIdx);

                char *className = dex->getTypeDesc(methodId->classIdx);

                strcpy(result->languageFeatureTypeDescription[KLF_IO], className);

                char *split = strchr(result->languageFeatureTypeDescription[KLF_IO], '/');

                if (split != nullptr) {
                    split = strchr(split + 1, '/');

                    if (split != nullptr) {
                        split[0] = '\0';
                    }
                }


                split = strchr(result->languageFeatureTypeDescription[KLF_IO], ';');

                if (split != nullptr) {
                    split[0] = '\0';
                }

                strcat(result->languageFeatureTypeDescription[KLF_IO], "/");

                delete closable;
            }
        }

        auto rangesMethodOffset = findRangesMethod(dex);

        if (rangesMethodOffset != 0) {
            dexMethod *rangesMethod = findMethodByOffset(dex, rangesMethodOffset);

            if (rangesMethod != nullptr) {
                auto *methodId = dex->getMethodId(rangesMethod->methodIdx);
                char *className = dex->getTypeDesc(methodId->classIdx);

                strcpy(result->languageFeatureTypeDescription[KLF_RANGES], className);

                char *split = strchr(result->languageFeatureTypeDescription[KLF_RANGES], '/');

                if (split != nullptr) {
                    split = strchr(split + 1, '/');

                    if (split != nullptr) {
                        split[0] = '\0';
                    }
                }

                strcat(result->languageFeatureTypeDescription[KLF_RANGES], "/");

                delete rangesMethod;
            }
        }

        auto collectionsMethodOffset = findCollectionsMethod(dex);

        if (collectionsMethodOffset != 0) {
            dexMethod *collectionsMethod = findMethodByOffset(dex, collectionsMethodOffset);

            if (collectionsMethod != nullptr) {
                auto *methodId = dex->getMethodId(collectionsMethod->methodIdx);
                char *className = dex->getTypeDesc(methodId->classIdx);

                strcpy(result->languageFeatureTypeDescription[KLF_COLLECTIONS], className);

                char *split = strchr(result->languageFeatureTypeDescription[KLF_COLLECTIONS], '/');

                if (split != nullptr) {
                    split = strchr(split + 1, '/');

                    if (split != nullptr) {
                        split[0] = '\0';
                    }
                }

                strcat(result->languageFeatureTypeDescription[KLF_COLLECTIONS], "/");

                delete collectionsMethod;
            }
        }

        auto sequencesMethodOffset = findSequencesMethod(dex);

        if (sequencesMethodOffset != 0) {
            dexMethod *sequencesMethod = findMethodByOffset(dex, sequencesMethodOffset);

            if (sequencesMethod != nullptr) {
                auto *methodId = dex->getMethodId(sequencesMethod->methodIdx);
                char *className = dex->getTypeDesc(methodId->classIdx);

                strcpy(result->languageFeatureTypeDescription[KLF_SEQUENCES], className);

                char *split = strchr(result->languageFeatureTypeDescription[KLF_SEQUENCES], '/');

                if (split != nullptr) {
                    split = strchr(split + 1, '/');

                    if (split != nullptr) {
                        split[0] = '\0';
                    }
                }

                strcat(result->languageFeatureTypeDescription[KLF_SEQUENCES], "/");

                delete sequencesMethod;
            }
        }

        auto concurrentMethodOffset = findConcurrentMethod(dex);

        if (concurrentMethodOffset != 0) {
            dexMethod *concurrentMethod = findMethodByOffset(dex, concurrentMethodOffset);

            if (concurrentMethod != nullptr) {
                auto *methodId = dex->getMethodId(concurrentMethod->methodIdx);
                char *className = dex->getTypeDesc(methodId->classIdx);

                strcpy(result->languageFeatureTypeDescription[KLF_CONCURRENT], className);

                char *split = strchr(result->languageFeatureTypeDescription[KLF_CONCURRENT], '/');

                if (split != nullptr) {
                    split = strchr(split + 1, '/');

                    if (split != nullptr) {
                        split[0] = '\0';
                    }
                }

                strcat(result->languageFeatureTypeDescription[KLF_CONCURRENT], "/");

                delete concurrentMethod;
            }
        }
    }
}

void CKotlinAnalyzer::processKotlinStdlib(char *kotlinPackage,
                                          CAnalyzerResult *result) {
    for (int i = 0; i < apk->getNumDex(); i++) {
        auto *dex = apk->getDex(i);

        for (int j = 0; j < dex->getNumClassDef(); j++) {
            auto *classDefs = dex->getClassDef(j);
            auto *classData = new CDexClass;

            if (!dex->decodeClassData(j, classData)) {
                delete classData;
                continue;
            }

            char *typeDescription = dex->getTypeDesc(classDefs->classIdx);

            if (isInnerClass(typeDescription)) {
                delete classData;
                continue;
            }

            result->numMethods +=
                    (int) classData->header.virtualMethodsSize + (int) classData->header.directMethodsSize;
            result->numClasses++;

            if (kotlinPackage[0] != '\0' && strstr(typeDescription, kotlinPackage) != nullptr) {
                result->numKotlinStdlibMethods +=
                        (int) classData->header.virtualMethodsSize + (int) classData->header.directMethodsSize;
                result->numKotlinStdlibClasses++;

                for (int k = 0; k < KLF_MAX; k++) {
                    if (strstr(typeDescription, result->languageFeatureTypeDescription[k]) != nullptr) {
                        break;
                    }
                }
            }

            delete classData;
        }
    }
}

void CKotlinAnalyzer::computeRatios(CAnalyzerResult *result) {
    result->kotlinStdlinMethodRatio =
            result->numMethods != 0 ? (float) result->numKotlinStdlibMethods / (float) result->numMethods : 0.0f;
    result->kotlinStdlibClassRatio =
            result->numClasses != 0 ? (float) result->numKotlinStdlibClasses / (float) result->numClasses : 0.0f;

    result->kotlinBytesRatio =
            result->numBytes != 0 ? (float) result->numKotlinInvocatingBytes / (float) result->numBytes : 0.0f;
    result->kotlinProjectBytesRatio = result->numProjectBytes != 0 ? (float) result->numKotlinInvocatingProjectBytes /
                                                                     (float) result->numProjectBytes : 0.0f;

    result->kotlinInvocatingClassesRatio = result->numClasses != 0 ?
                                           (float) result->numKotlinInvocatingClasses / (float) result->numClasses
                                                                   : 0.0f;

    result->kotlinInvocatingProjectClassesRatio = result->numProjectClasses != 0 ?
                                                  (float) result->numKotlinInvocatingProjectClasses /
                                                  (float) result->numProjectClasses : 0.0f;

    result->kotlinInvocationsRatio = result->numInvocations != 0 ?
                                     (float) result->numKotlinInvocations / (float) result->numInvocations : 0.0f;

    result->kotlinProjectInvocationsRatio = result->numKotlinProjectInvocations != 0 ?
                                            (float) result->numKotlinProjectInvocations /
                                            (float) result->numProjectInvocations : 0.0f;

    for (int l = 0; l < KLF_MAX; l++) {
        result->languageFeatureUsingClassesRatio[l] =
                result->numClasses != 0 ? (float) result->numLanguageFeatureUsingClasses[l] / (float) result->numClasses
                                        : 0.0f;
        result->languageFeatureUsingProjectClassesRatio[l] =
                result->numProjectClasses != 0 ? (float) result->numLanguageFeatureUsingProjectClasses[l] /
                                                 (float) result->numProjectClasses : 0.0f;
    }
}

bool CKotlinAnalyzer::isValidMethod(dexMethod *method) {
    return method->accessFlags & ACC_METHOD_MASK && !(method->accessFlags & ACC_NATIVE) && method->codeOff != 0;
}

bool CKotlinAnalyzer::isInnerClass(char *typeDescription) {
    return strchr(typeDescription, '$') != nullptr;
}

bool CKotlinAnalyzer::isProjectClass(CAPK *apk, char *typeDescription) {
    return strstr(typeDescription, apk->getProjectPackageName().c_str()) != nullptr;
}

int CKotlinAnalyzer::getParentClass(CDex *dex, char *typeDescription) {
    char parentClassDescription[256];
    strcpy(parentClassDescription, typeDescription);

    char *split = strchr(parentClassDescription, '$');

    if (split != nullptr) {
        split[0] = ';';
        split[1] = '\0';

        for (int i = 0; i < dex->getNumClassDef(); i++) {
            auto *classDef = dex->getClassDef(i);

            if (strcmp(dex->getTypeDesc(classDef->classIdx), parentClassDescription) == 0) {
                return classDef->classIdx;
            }
        }
    }

    return -1;
}

void CKotlinAnalyzer::printClassDef(CDex *dex, dexClassDef *classDef) {
    std::cout << "Class " << classDef->classIdx << std::endl;
    std::cout << "\tdescription: " << dex->getTypeDesc(classDef->classIdx) << std::endl;

    if (classDef->sourceFileIdx != 0 && classDef->sourceFileIdx != 0xFFFFFFFF) {
        std::cout << "\tfile: " << dex->getString(classDef->sourceFileIdx) << std::endl;
    } else {
        std::cout << "\tfile: no source file index" << std::endl;
    }

    std::cout << "\tclass data: " << std::hex << classDef->classDataOff << std::dec << std::endl;
    std::cout << "\taccess flags: " << classDef->accessFlags << std::endl;
}

void CKotlinAnalyzer::printClassDataHeader(CDex *dex, dexClassDataHeader *classDataHeader) {
    std::cout << "\tClass header " << std::endl;
    std::cout << "\t\tstatic fields size: " << classDataHeader->staticFieldsSize << std::endl;
    std::cout << "\t\tinstance fields size: " << classDataHeader->instanceFieldsSize << std::endl;
    std::cout << "\t\tdirect methods size: " << classDataHeader->directMethodsSize << std::endl;
    std::cout << "\t\tvirtual methods size: " << classDataHeader->virtualMethodsSize << std::endl;
}

void CKotlinAnalyzer::printClassField(CDex *dex, dexField *classField) {
    std::cout << "\tField" << std::endl;
    std::cout << "\t\tfieldIdx: " << classField->fieldIdx << std::endl;
    std::cout << "\t\taccessFlags: " << classField->accessFlags << std::endl;
}

void CKotlinAnalyzer::printClassMethod(CDex *dex, dexMethod *classMethod) {
    std::cout << "\t";

    auto methodId = dex->getMethodId(classMethod->methodIdx);

    if (methodId != nullptr) {
        printMethodId(dex, methodId);
    } else {
        std::cout << "INVALID METHOD ID" << std::endl;
    }

    std::cout << "\t\tmethodIdx: " << classMethod->methodIdx << std::endl;
    std::cout << "\t\taccessFlags: " << classMethod->accessFlags << std::endl;
    std::cout << "\t\tcodeOff: " << std::hex << classMethod->codeOff << std::dec << std::endl;
}

void CKotlinAnalyzer::printCode(CDex *dex, dexCode *code) {
    std::cout << "\t\tregistersSize: " << code->registersSize << std::endl;
    std::cout << "\t\tinsSize: " << code->insSize << std::endl;
    std::cout << "\t\toutsSize: " << code->outsSize << std::endl;
    std::cout << "\t\ttriesSize: " << code->triesSize << std::endl;
    std::cout << "\t\tdebugInfoOff: " << code->debugInfoOff << std::endl;
    std::cout << "\t\tinsnsSize: " << dex->getCodeInstructionsSize(code) << std::endl;
}

void CKotlinAnalyzer::printMethodId(CDex *dex, dexMethodId *methodId) {
    if (methodId->nameIdx != 0 && methodId->nameIdx != 0xFFFFFFFF) {
        std::cout << dex->getString(methodId->nameIdx) << std::endl;
    }
}
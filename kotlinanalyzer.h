#ifndef KOTLINANALYZER_H
#define KOTLINANALYZER_H

#include <set>
#include "apk.h"
#include "disassembler.h"

enum EKotlinLanguageFeature {
    KLF_NULL_SAFETY,
    KLF_COROUTINES,
    KLF_REFLECTION,
    KLF_DELEGATION,
    KLF_RANGES,
    KLF_TEXT,
    KLF_COLLECTIONS,
    KLF_COMPARISONS,
    KLF_CONCURRENT,
    KLF_IO,
    KLF_SEQUENCES,
    KLF_MAX
};

class CAnalyzerResult {
public:
    CAnalyzerResult() {}

    char kotlinPackage[256];

    int numMethods;

    int numClasses;
    int numProjectClasses;
    int numKotlinInvocatingProjectClasses;

    int numInvocations;
    int numProjectInvocations;
    int numKotlinStdlibMethods;
    int numKotlinStdlibClasses;
    int numKotlinInvocations;
    int numKotlinProjectInvocations;
    int numKotlinInvocatingClasses;

    unsigned long long numBytes;
    unsigned long long numProjectBytes;
    unsigned long long numKotlinInvocatingBytes;
    unsigned long long numKotlinInvocatingProjectBytes;

    float kotlinStdlinMethodRatio;
    float kotlinStdlibClassRatio;
    float kotlinInvocationsRatio;
    float kotlinProjectInvocationsRatio;
    float kotlinInvocatingClassesRatio;
    float kotlinInvocatingProjectClassesRatio;
    float kotlinBytesRatio;
    float kotlinProjectBytesRatio;

    char languageFeatureTypeDescription[KLF_MAX][128];
    char languageFeatureAltTypeDescription[KLF_MAX][128];
    int numLanguageFeatureUsingClasses[KLF_MAX];
    int numLanguageFeatureUsingProjectClasses[KLF_MAX];
    int numLanguageFeatureInvocations[KLF_MAX];
    int numLanguageFeatureProjectInvocations[KLF_MAX];
    float languageFeatureUsingClassesRatio[KLF_MAX];
    float languageFeatureUsingProjectClassesRatio[KLF_MAX];

    bool obfuscated;
    int numDex;
};

class CKotlinAnalyzer {
public:
    explicit CKotlinAnalyzer(CAPK *apk)
            : apk(apk) { disasm = new CDisassembler(); }

    ~CKotlinAnalyzer() {
        delete disasm;
    }

    CAnalyzerResult analyze(bool hasKotlin);

private:
    static unsigned long findNullSafetyMethod(CDex *dex);

    static unsigned long findCoroutinesMethod(CDex *dex);

    static unsigned long findDelegationMethod(CDex *dex);

    static unsigned long findIoMethod(CDex *dex);

    static unsigned long findRangesMethod(CDex *dex);

    static unsigned long findCollectionsMethod(CDex *dex);

    static unsigned long findSequencesMethod(CDex *dex);

    static unsigned long findConcurrentMethod(CDex *dex);

    dexMethod *findMethodByOffset(CDex *dex, unsigned long offset);

    void computeKotlinPackageName(CAnalyzerResult *result);

    void
    processKotlinStdlib(char *kotlinPackage, CAnalyzerResult *result);

    void computeRatios(CAnalyzerResult *result);

    bool isValidMethod(dexMethod *method);

    bool isInnerClass(char *typeDescription);

    bool isProjectClass(CAPK *apk, char *typeDescription);

    int getParentClass(CDex* dex, char *typeDescription);

    void printClassDef(CDex *dex, dexClassDef *classDef);

    void printClassDataHeader(CDex *dex, dexClassDataHeader *classDataHeader);

    void printClassField(CDex *dex, dexField *classField);

    void printClassMethod(CDex *dex, dexMethod *classMethod);

    void printMethodId(CDex *dex, dexMethodId *methodId);

    void printCode(CDex *dex, dexCode *code);

private:
    CAPK *apk;
    CDisassembler *disasm;

};

#endif //KOTLINDETECTOR_H

#ifndef DEX_H
#define DEX_H

#include <cstring>
#include "dextypes.h"

char* getStrBegin(char* str);

class CDexClass {
public:
    CDexClass() {
        memset(&header, 0, sizeof(header));

        staticFields = nullptr;
        instanceFields = nullptr;
        directMethods = nullptr;
        virtualMethods = nullptr;
    }

    ~CDexClass() {
        delete[] staticFields;
        delete[] instanceFields;
        delete[] directMethods;
        delete[] virtualMethods;
    }

public:
    dexClassDataHeader header;
    dexField *staticFields;
    dexField *instanceFields;
    dexMethod *directMethods;
    dexMethod *virtualMethods;
};

class CDex {
public:
    CDex(unsigned char *dexBuffer, unsigned long dexSize)
            : dexBuffer(dexBuffer), dexSize(dexSize) {}

    ~CDex();

    static bool validHeader(unsigned char *dexBuffer);

    unsigned char *getBuffer() { return dexBuffer; }

    unsigned long getSize() { return dexSize; }

    char *getString(int idIndex);

    int getNumStrings();

    dexClassDef *getClassDef(int defIndex);

    int getNumClassDef();

    bool decodeClassData(int defIndex, CDexClass *data);

    dexMethodId *getMethodId(int idIndex);

    int getNumMethodId();

    char *getTypeDesc(int idIndex);

    int getNumTypeDesc();

    dexCode *getCode(dexMethod *method);

    unsigned int getCodeInstructionsSize(dexCode *code);

    bool isValidMethod(dexMethod *method);

private:
    void decodeClassField(u1 **stream, int *lastIndex, dexField *field);

    void decodeClassMethod(u1 **stream, int *lastIndex, dexMethod *method);

    int uleb128(u1 **lebBuffer);

    int leb128(u1 **lebBuffer);

    unsigned long leb128_len(unsigned long n);

private:
    unsigned char *dexBuffer;
    unsigned long dexSize;
};

#endif //DEX_H


#include <iostream>
#include "dex.h"
#include "dextypes.h"

char* getStrBegin(char* str) {
    char* ret = str;

    while(ret[0] != '\0') {
        ret--;
    }

    return ret + 1;
}

CDex::~CDex() {
    delete[] dexBuffer;
}

bool CDex::validHeader(unsigned char *dexBuffer) {
    auto *header = (dexHeader *) dexBuffer;

    return header->magic.dex[0] == 'd' && header->magic.dex[1] == 'e' && header->magic.dex[2] == 'x';
}

char *CDex::getString(int idIndex) {
    auto header = (dexHeader *) dexBuffer;

    auto stringIds = (dexStringId *) &dexBuffer[header->stringIdsOff];
    auto stringId = &stringIds[idIndex];

    u1 *lebBuffer = &dexBuffer[stringId->stringDataOff];

    int lebValue = uleb128(&lebBuffer);
    unsigned int lebValueLen = leb128_len(lebValue);

    return (char *) &dexBuffer[stringId->stringDataOff + lebValueLen];
}

int CDex::getNumStrings() {
    auto header = (dexHeader *) dexBuffer;
    return header->stringIdsSize;
}

dexClassDef *CDex::getClassDef(int defIndex) {
    auto header = (dexHeader *) dexBuffer;
    auto classDefs = (dexClassDef *) &dexBuffer[header->classDefsOff];

    return &classDefs[defIndex];
}

int CDex::getNumClassDef() {
    auto header = (dexHeader *) dexBuffer;
    return header->classDefsSize;
}

bool CDex::decodeClassData(int defIndex, CDexClass *data) {
    auto classDefs = getClassDef(defIndex);

    if( classDefs->classDataOff == 0 /*|| !( classDefs->accessFlags & ACC_CLASS_MASK )*/ ) {
        return false;
    }

    auto encodedHeader = (dexClassDataHeader *) &dexBuffer[classDefs->classDataOff];

    u1 *stream = (u1 *) encodedHeader;

    data->header.staticFieldsSize = uleb128(&stream);
    data->header.instanceFieldsSize = uleb128(&stream);
    data->header.directMethodsSize = uleb128(&stream);
    data->header.virtualMethodsSize = uleb128(&stream);

    if (data->header.staticFieldsSize > 0) {
        data->staticFields = new dexField[data->header.staticFieldsSize];
    }
    if (data->header.instanceFieldsSize > 0) {
        data->instanceFields = new dexField[data->header.instanceFieldsSize];
    }
    if (data->header.directMethodsSize > 0) {
        data->directMethods = new dexMethod[data->header.directMethodsSize];
    }
    if (data->header.virtualMethodsSize > 0) {
        data->virtualMethods = new dexMethod[data->header.virtualMethodsSize];
    }

    int lastIndex = 0;

    for( int i = 0; i < data->header.staticFieldsSize; i++ ) {
        decodeClassField( &stream, &lastIndex, &data->staticFields[i] );
    }

    lastIndex = 0;

    for( int i = 0; i < data->header.instanceFieldsSize; i++ ) {
        decodeClassField( &stream, &lastIndex, &data->instanceFields[i] );
    }

    lastIndex = 0;

    for( int i = 0; i < data->header.directMethodsSize; i++ ) {
        decodeClassMethod( &stream, &lastIndex, &data->directMethods[i] );
    }

    lastIndex = 0;

    for( int i = 0; i < data->header.virtualMethodsSize; i++ ) {
        decodeClassMethod( &stream, &lastIndex, &data->virtualMethods[i] );
    }

    return true;
}

dexMethodId *CDex::getMethodId(int idIndex) {
    auto header = (dexHeader *) dexBuffer;
    auto methodIds = (dexMethodId *) &dexBuffer[header->methodIdsOff];

    if(idIndex >= header->methodIdsSize) {
        return nullptr;
    }

    return &methodIds[idIndex];
}

int CDex::getNumMethodId() {
    auto header = (dexHeader *) dexBuffer;
    return header->methodIdsSize;
}

char *CDex::getTypeDesc(int idIndex) {
    auto header = (dexHeader *) dexBuffer;
    auto typeDescIds = (dexTypeId *) &dexBuffer[header->typeIdsOff];

    return getString(typeDescIds[idIndex].descriptorIdx);
}

int CDex::getNumTypeDesc() {
    auto header = (dexHeader *) dexBuffer;
    return header->typeIdsSize;
}

void CDex::decodeClassField(u1 **stream, int *lastIndex, dexField *field) {
    u4 index = *lastIndex + uleb128(stream);

    field->accessFlags = uleb128(stream);
    field->fieldIdx = index;

    *lastIndex = index;
}

void CDex::decodeClassMethod(u1 **stream, int *lastIndex, dexMethod *method) {
    u4 index = *lastIndex + uleb128(stream);

    method->accessFlags = uleb128(stream);
    method->codeOff = uleb128(stream);
    method->methodIdx = index;

    *lastIndex = index;
}

int CDex::uleb128(u1 **lebBuffer) {
    u1 *ptr = *lebBuffer;
    int result = *(ptr++);

    if (result > 0x7f) {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }
    *lebBuffer = ptr;
    return result;
}

int CDex::leb128(u1 **lebBuffer) {
    u1* ptr = *lebBuffer;
    int result = *(ptr++);
    if (result <= 0x7f) {
        result = (result << 25) >> 25;
    } else {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur <= 0x7f) {
            result = (result << 18) >> 18;
        } else {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur <= 0x7f) {
                result = (result << 11) >> 11;
            } else {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur <= 0x7f) {
                    result = (result << 4) >> 4;
                } else {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }
    *lebBuffer = ptr;
    return result;
}

unsigned long CDex::leb128_len(unsigned long n) {
    static unsigned char b[32];
    unsigned long i;

    i = 0;
    do {
        b[i] = n & 0x7F;
        if (n >>= 7)
            b[i] |= 0x80;
    } while (b[i++] & 0x80);
    return i;
}

dexCode *CDex::getCode(dexMethod *method) {
    return (dexCode *) &dexBuffer[method->codeOff];
}

unsigned int CDex::getCodeInstructionsSize(dexCode *code) {
    return code->insnsSize * 2;
}

bool CDex::isValidMethod(dexMethod *method) {
    return method->accessFlags & ACC_METHOD_MASK && !(method->accessFlags & ACC_NATIVE) && method->codeOff != 0;
}

#ifndef DEXTYPES_H
#define DEXTYPES_H

#include <cstdint>

#define SHA1_LEN 20

typedef uint8_t u1;
typedef uint16_t u2;
typedef uint32_t u4;

typedef enum {
    kDexInvalid = 0,
    kNormalDex = 1,
    kCompactDex = 2
} dexType;

typedef struct __attribute__((packed)) {
    char dex[4];
    char ver[4];
} dexMagic;

typedef struct __attribute__((packed)) {
    dexMagic magic;
    u4 checksum;
    unsigned char signature[SHA1_LEN];
    u4 fileSize;
    u4 headerSize;
    u4 endianTag;
    u4 linkSize;
    u4 linkOff;
    u4 mapOff;
    u4 stringIdsSize;
    u4 stringIdsOff;
    u4 typeIdsSize;
    u4 typeIdsOff;
    u4 protoIdsSize;
    u4 protoIdsOff;
    u4 fieldIdsSize;
    u4 fieldIdsOff;
    u4 methodIdsSize;
    u4 methodIdsOff;
    u4 classDefsSize;
    u4 classDefsOff;
    u4 dataSize;
    u4 dataOff;
} dexHeader;

typedef struct __attribute__((packed)) {
    dexMagic magic;
    u4 checksum;
    unsigned char signature[SHA1_LEN];
    u4 fileSize;
    u4 headerSize;
    u4 endianTag;
    u4 linkSize;
    u4 linkOff;
    u4 mapOff;
    u4 stringIdsSize;
    u4 stringIdsOff;
    u4 typeIdsSize;
    u4 typeIdsOff;
    u4 protoIdsSize;
    u4 protoIdsOff;
    u4 fieldIdsSize;
    u4 fieldIdsOff;
    u4 methodIdsSize;
    u4 methodIdsOff;
    u4 classDefsSize;
    u4 classDefsOff;
    u4 dataSize;
    u4 dataOff;
    u4 featureFlags;
    u4 debugInfoOffsetsPos;
    u4 debugInfoOffsetsTableOffset;
    u4 debugInfoBase;
    u4 ownedDataBegin;
    u4 ownedDataEnd;
} cdexHeader;

typedef struct __attribute__((packed)) {
    u4 stringDataOff;
} dexStringId;

typedef struct __attribute__((packed)) {
    u4 descriptorIdx;
} dexTypeId;

typedef struct __attribute__((packed)) {
    u2 classIdx;
    u2 typeIdx;
    u4 nameIdx;
} dexFieldId;

typedef struct __attribute__((packed)) {
    u2 classIdx;
    u2 protoIdx;
    u4 nameIdx;
} dexMethodId;

typedef struct __attribute__((packed)) {
    u4 shortyIdx;
    u4 returnTypeIdx;
    u4 parametersOff;
} dexProtoId;

typedef struct __attribute__((packed)) {
    u4 classIdx;
    u4 accessFlags;
    u4 superclassOdx;
    u4 interfacesOff;
    u4 sourceFileIdx;
    u4 annotationsOff;
    u4 classDataOff;
    u4 staticValuesOff;
} dexClassDef;

typedef struct __attribute__((packed)) {
    u2 typeIdx;
} dexTypeItem;

typedef struct __attribute__((packed)) {
    u4 size;
    dexTypeItem list[1];
} dexTypeList;

typedef struct __attribute__((packed)) {
    u2 type;
    u2 unused;
    u4 size;
    u4 offset;
} dexMapItem;

typedef struct __attribute__((packed)) {
    u4 size;
    dexMapItem list[1];
} dexMapList;

typedef struct __attribute__((packed, aligned(4))) {
    // the number of registers used by this code (locals + parameters)
    u2 registersSize;
    // the number of words of incoming arguments to the method  that this code is for
    u2 insSize;
    // the number of words of outgoing argument space required by this code for method invocation
    u2 outsSize;
    // the number of try_items for this instance. If non-zero, then these appear as the tries array
    // just after the insns in this instance.
    u2 triesSize;
    //  Holds file offset to debug info stream.
    u4 debugInfoOff;
    // size of the insns array, in 2 byte code units
    u4 insnsSize;
} dexCode;

typedef struct __attribute__((packed, aligned(2))) {
    // Packed code item data, 4 bits each: [registers_size, ins_size, outs_size, tries_size]
    u2 fields;
    // 5 bits for if either of the fields required preheader extension, 11 bits for the number of
    // instruction code units.
    u2 insnsCountAndFlags;
    u2 insns[1];
    // followed by optional u2 padding
    // followed by try_item[triesSize]
    // followed by uleb128 handlersSize
    // followed by catch_handler_item[handlersSize]
} cdexCode;

typedef struct __attribute__((packed)) {
    u4 start_addr_;
    u2 insn_count_;
    u2 handler_off_;
} dexTryItem;

typedef struct __attribute__((packed)) {
    u1 bleargh;
} dexLinkData;

typedef struct __attribute__((packed)) {
    int size;
    int numEntries;
    struct {
        u4 classDescriptorHash;
        int classDescriptorOff;
        int classDefOff;
    } table[1];
} dexClassLookup;

typedef struct __attribute__((packed)) {
    u4 staticFieldsSize;
    u4 instanceFieldsSize;
    u4 directMethodsSize;
    u4 virtualMethodsSize;
} dexClassDataHeader;

typedef struct __attribute__((packed)) {
    u4 methodIdx;
    u4 accessFlags;
    u4 codeOff;
} dexMethod;

typedef struct __attribute__((packed)) {
    u4 fieldIdx;
    u4 accessFlags;
} dexField;

enum {
    ACC_PUBLIC = 0x00000001,       // class, field, method, ic
    ACC_PRIVATE = 0x00000002,       // field, method, ic
    ACC_PROTECTED = 0x00000004,       // field, method, ic
    ACC_STATIC = 0x00000008,       // field, method, ic
    ACC_FINAL = 0x00000010,       // class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
    ACC_VOLATILE = 0x00000040,       // field
    ACC_BRIDGE = 0x00000040,       // method (1.5)
    ACC_TRANSIENT = 0x00000080,       // field
    ACC_VARARGS = 0x00000080,       // method (1.5)
    ACC_NATIVE = 0x00000100,       // method
    ACC_INTERFACE = 0x00000200,       // class, ic
    ACC_ABSTRACT = 0x00000400,       // class, method, ic
    ACC_STRICT = 0x00000800,       // method
    ACC_SYNTHETIC = 0x00001000,       // field, method, ic
    ACC_ANNOTATION = 0x00002000,       // class, ic (1.5)
    ACC_ENUM = 0x00004000,       // class, field, ic (1.5)
    ACC_CONSTRUCTOR = 0x00010000,       // method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED = 0x00020000,       // method (Dalvik only)

    ACC_CLASS_MASK = (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
     | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
    ACC_INNER_CLASS_MASK = (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
    ACC_FIELD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
     | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
    ACC_METHOD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
     | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
     | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
     | ACC_DECLARED_SYNCHRONIZED),
};

#endif //DEXTYPES_H

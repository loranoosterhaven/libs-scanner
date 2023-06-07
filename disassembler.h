#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

class CDisassembler {
public:
    unsigned long length(unsigned char *bytecode);

    bool isPayload(unsigned char *bytecode);

    unsigned short getPayloadSize(unsigned char *bytecode);

    bool isInvocation(unsigned char *bytecode);

    unsigned short getInvocationMethodId(unsigned char *bytecode);
};

#endif //DISASSEMBLER_H

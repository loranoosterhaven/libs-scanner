#ifndef CSVWRITER_H
#define CSVWRITER_H

#include <string>

class CSVWriter {
public:
    CSVWriter(const char *fileName);

    void addField(const char *field);

    void addField(bool field);

    void addField(int field);

    void addField(unsigned long long field);

    void addField(float field);

    void nextRow();

private:
    const char *fileName;
    bool requiresComma;
};

#endif //CSVWRITER_H

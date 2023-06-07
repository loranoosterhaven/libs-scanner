#include <iostream>
#include <fstream>
#include "csvwriter.h"

CSVWriter::CSVWriter(const char *fileName) {
    this->fileName = fileName;
    this->requiresComma = false;

    std::fstream csvFile(fileName, std::fstream::out | std::fstream::trunc);
    csvFile.close();
}

void CSVWriter::addField(const char *field) {
    std::fstream csvFile(fileName, std::fstream::out | std::fstream::app);

    if (csvFile.is_open()) {
        if (requiresComma) {
            csvFile << ",";
        } else {
            requiresComma = true;
        }

        csvFile << field;
        csvFile.close();
    }
}

void CSVWriter::addField(bool field) {
    std::fstream csvFile(fileName, std::fstream::in | std::fstream::out | std::fstream::app);

    if (csvFile.is_open()) {
        if (requiresComma) {
            csvFile << ",";
        } else {
            requiresComma = true;
        }

        csvFile << field;
        csvFile.close();
    }
}

void CSVWriter::addField(int field) {
    std::fstream csvFile(fileName, std::fstream::in | std::fstream::out | std::fstream::app);

    if (csvFile.is_open()) {
        if (requiresComma) {
            csvFile << ",";
        } else {
            requiresComma = true;
        }

        csvFile << field;
        csvFile.close();
    }
}

void CSVWriter::addField(unsigned long long field) {
    std::fstream csvFile(fileName, std::fstream::in | std::fstream::out | std::fstream::app);

    if (csvFile.is_open()) {
        if (requiresComma) {
            csvFile << ",";
        } else {
            requiresComma = true;
        }

        csvFile << field;
        csvFile.close();
    }
}

void CSVWriter::addField(float field) {
    std::fstream csvFile(fileName, std::fstream::in | std::fstream::out | std::fstream::app);

    if (csvFile.is_open()) {
        if (requiresComma) {
            csvFile << ",";
        } else {
            requiresComma = true;
        }

        csvFile << std::fixed << field;
        csvFile.close();
    }
}

void CSVWriter::nextRow() {
    std::fstream csvFile(fileName, std::fstream::in | std::fstream::out | std::fstream::app);

    if (csvFile.is_open()) {
        csvFile << std::endl;
        csvFile.close();
    }

    requiresComma = false;
}

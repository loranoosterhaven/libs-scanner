#ifndef PAYMENTLIBWRITER_H
#define PAYMENTLIBWRITER_H

#include "csvwriter.h"

void writeLibsHeader(CSVWriter *writer);
int processLibs(int argc, char *argv[]);

#endif
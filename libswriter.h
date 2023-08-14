#ifndef PAYMENTLIBWRITER_H
#define PAYMENTLIBWRITER_H

#include "csvwriter.h"
#include "libsinspector.h"
#include "directory.h"

void writeLibsHeader(CSVWriter *writer);
bool isOutdatedVersion( const char* targetVer, const char* srcVer );
int processLibs(int argc, char *argv[]);
void processVersions(CLibsInspector* libsInspector);
void writeOutdatedApps(CDirectory* directory);

#endif
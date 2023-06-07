#ifndef APK_H
#define APK_H

#include <string>
#include <vector>

#include "dex.h"

class CAPK {
public:
    CAPK(std::string targetPath);

    ~CAPK();

    std::string getPath() { return path; }

    std::string getName() {
        std::string fileName = path;

        const size_t last_slash_idx = fileName.find_last_of("\\/");
        if (std::string::npos != last_slash_idx) {
            fileName.erase(0, last_slash_idx + 1);
        }
        return fileName;
    }

    std::string getPackageName() {
        return packageName;
    }

    std::string getProjectPackageName() {
        return projectPackageName;
    }

    CDex *getDex(int dexIndex) { return dexFiles[dexIndex]; }

    int getNumDex() { return dexFiles.size(); }

    unsigned long long getSize() {
        unsigned long long totalSize = 0;
        for (int j = 0; j < getNumDex(); j++) {
            totalSize += getDex(j)->getSize();
        }
        return totalSize;
    }

private:
    void parseManifest(class zip *z);

    std::string path;
    std::string packageName;
    std::string projectPackageName;
    std::vector<CDex *> dexFiles;
};

#endif //APK_H

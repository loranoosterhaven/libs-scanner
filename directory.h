#ifndef DIRECTORY_H
#define DIRECTORY_H

#include <string>
#include <vector>

class CDirectory {
public:
    CDirectory(std::string targetPath);

    int getAPKCount() { return apkPaths.size(); }

    std::string getAPKPath(int apkIndex) { return apkIndex < getAPKCount() ? apkPaths[apkIndex] : nullptr; }
    std::string getPath() { return path; }

private:
    std::string path;
    std::vector<std::string> apkPaths;
};

#endif //DIRECTORY_H

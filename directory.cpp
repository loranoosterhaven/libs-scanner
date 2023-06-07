#include <dirent.h>
#include <iostream>

#include "directory.h"

CDirectory::CDirectory(const std::string targetPath) {
    path = targetPath;

    DIR *dir = opendir(path.c_str());
    dirent *dp;

    while ((dp = readdir(dir)) != nullptr) {
        if (strstr(dp->d_name, ".apk") != nullptr) {
            apkPaths.emplace_back(path + "/" + dp->d_name);
        }
    }

    closedir(dir);
}
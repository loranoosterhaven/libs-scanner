#include <iostream>
#include <chrono>
#include <map>

#include "directory.h"
#include "apk.h"
#include "csvwriter.h"

#include "libsinspector.h"
#include "keyinspector.h"

#include "libswriter.h"

#include <boost/algorithm/string.hpp>

void writeLibsHeader(CSVWriter *writer) {
    writer->addField("app_name");
    writer->addField("package_name");
    writer->addField("project_package_name");

    for (int j = 0; j < LIB_MAX; j++) {
        writer->addField(CLibsInspector::getHeaderName((ESupportedLibs)j));
        writer->addField(CLibsInspector::getVersionHeaderName((ESupportedLibs)j));
    }

    writer->addField("leak_privatekey");
    writer->addField("is_obfuscated");
    writer->addField("num_dex");
    writer->addField("app_size");
    writer->addField("processing_time_microsec");

    writer->nextRow();
}

int processLibs(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Please pass a directory path as argument." << std::endl;
        return 0;
    }

    bool removeDuplicates = true;
    bool renameToPackageName = true;

    auto start = std::chrono::high_resolution_clock::now();

    char *directoryName = argv[1];
    auto directory = new CDirectory(directoryName);

    std::cout << "Target directory is: " << directoryName << std::endl;
    std::cout << "Containing " << directory->getAPKCount() << " APK files" << std::endl;

    std::string outputFile = directory->getPath() + "/libs_output.csv";

    auto writer = new CSVWriter(outputFile.c_str());
    writeLibsHeader(writer);

    std::vector<std::string> processedPackageNames;

    for (int i = 0; i < directory->getAPKCount(); i++) {
        /*if( strstr(directory->getAPKPath(i).c_str(),"kpmoney") == nullptr ){
            continue;
        }*/

        auto apk = new CAPK(directory->getAPKPath(i));

        if (apk->getNumDex() == 0) {
            continue;
        }

        bool alreadyProcessed = false;

        for (auto &processedPackageName : processedPackageNames) {
            if (processedPackageName == apk->getPackageName()) {
                alreadyProcessed = true;
                break;
            }
        }

        if (renameToPackageName) {
            rename(apk->getPath().c_str(), (directory->getPath() + "/" + apk->getPackageName() + ".apk").c_str());
        }

        if (alreadyProcessed && removeDuplicates) {
            remove(directory->getAPKPath(i).c_str());
            std::cout << "Removed " << apk->getName() << " (" << apk->getPackageName() << ") already processed" << std::endl;
            continue;
        }

        std::cout << i << "/" << directory->getAPKCount() << ": Analyzing " << apk->getName() << " (" << apk->getPackageName() << ")..." << std::endl;

        auto start_app = std::chrono::high_resolution_clock::now();

        auto stop_app = std::chrono::high_resolution_clock::now();
        auto duration_app = duration_cast<std::chrono::microseconds>(stop_app - start_app);

        writer->addField(apk->getName().c_str());
        writer->addField(apk->getPackageName().c_str());
        writer->addField(apk->getProjectPackageName().c_str());

        CLibsInspector* libsInspector = new CLibsInspector(apk);
        libsInspector->scan();

        for (int j = 0; j < LIB_MAX; j++) {
            if(libsInspector->hasLib((ESupportedLibs)j) && !libsInspector->hasNonMetaMatch((ESupportedLibs)j)) {
                std::cout << "\tWARNING: found " << libsInspector->getFriendlyName((ESupportedLibs)j) << " solely based on metadata strings" << std::endl;
            }

            writer->addField(libsInspector->hasLib((ESupportedLibs)j));
            writer->addField(libsInspector->getVersion((ESupportedLibs)j));
        }

        processVersions(libsInspector);

        delete libsInspector;

        CKeyInspector* keyInspector = new CKeyInspector(apk);
        keyInspector->scan(directory);

        writer->addField(keyInspector->leakingPrivateKey());
        writer->addField(keyInspector->isAppObfuscated());
        writer->addField(apk->getNumDex());
        writer->addField(apk->getSize());
        writer->addField((int) duration_app.count());
        writer->nextRow();

        processedPackageNames.push_back(apk->getPackageName());

        delete apk;
    }

    delete writer;

    writeOutdatedApps(directory);

    delete directory;

    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = duration_cast<std::chrono::seconds>(stop - start);

    std::cout << "Time taken to execute program: " << duration.count() << std::endl;

    return 0;
}

std::map<std::string, std::string> versionMap[LIB_MAX];
std::string newestVersion[LIB_MAX];

bool isOutdatedVersion( const char* targetVer, const char* srcVer ) {
    std::vector<std::string> va, vb;
    boost::split(va, targetVer, boost::is_any_of("."));
    boost::split(vb, srcVer, boost::is_any_of("."));

    const int depth = std::min(va.size(), vb.size());
    int ia,ib;
    for (int i=0; i<depth; ++i)
    {
        ia = atoi(va[i].c_str());
        ib = atoi(vb[i].c_str());
        if (ia != ib)
            break;
    }

    if (ia > ib)
        return false;
    else if (ia < ib)
        return true;
    else
    {
        if (va.size() > vb.size())
            return false;
        else if (va.size() < vb.size())
            return true;
    }

    return false;
}

void processVersions(CLibsInspector* libsInspector) {
    for (int i = 0; i < LIB_MAX; i++) {
        if( libsInspector->hasLib((ESupportedLibs)i)) {
            char* versionStr = libsInspector->getVersion((ESupportedLibs)i);

            if(versionStr[0] != '\0') {
                std::cout << "\t" << libsInspector->getAPK()->getPackageName() << ": found version \"" << versionStr << "\" of library \"" << libsInspector->getFriendlyName((ESupportedLibs)i) << "\"" << std::endl;

                versionMap[i][libsInspector->getAPK()->getPackageName()] = versionStr;

                std::cout << "\tadded to map.." << std::endl;

                if(!newestVersion[i].empty())
                    std::cout << "\tcurrent newest version: " << newestVersion[i] << std::endl;

                if(newestVersion[i].empty() || isOutdatedVersion(newestVersion[i].c_str(),versionStr)) {
                    std::cout << "\tset as newest version.." << std::endl;
                    newestVersion[i] = versionStr;
                }
                else
                {
                    std::cout << "\tnot set as newest version.." << std::endl;
                }
            }
        }
    }
}

void writeOutdatedApps(CDirectory* directory) {
    std::string outputFile = directory->getPath() + "/libs_version_output.csv";

    auto writer = new CSVWriter(outputFile.c_str());

    writer->addField("package_name");
    writer->addField("lib_name");
    writer->addField("lib_version");
    writer->addField("lib_outdated");

    writer->nextRow();

    for (int i = 0; i < LIB_MAX; i++) {
        for (auto entry : versionMap[i]) {
            writer->addField(entry.first.c_str());
            writer->addField(CLibsInspector::getFriendlyName((ESupportedLibs)i));
            writer->addField(entry.second.c_str());
            writer->addField(isOutdatedVersion(entry.second.c_str(), newestVersion[i].c_str()));

            writer->nextRow();
        }
    }
    delete writer;
}
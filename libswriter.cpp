#include <iostream>
#include <chrono>

#include "directory.h"
#include "apk.h"
#include "csvwriter.h"

#include "libsinspector.h"

void writeLibsHeader(CSVWriter *writer) {
    writer->addField("app_name");
    writer->addField("package_name");
    writer->addField("project_package_name");

    for (int j = 0; j < LIB_MAX; j++) {
        writer->addField(CLibsInspector::getHeaderName((ESupportedLibs)j));
    }

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

        if (alreadyProcessed && removeDuplicates) {
            remove(directory->getAPKPath(i).c_str());
            std::cout << "Removed " << apk->getName() << " (" << apk->getPackageName() << ") already processed" << std::endl;
            continue;
        }

        std::cout << "Analyzing " << apk->getName() << " (" << apk->getPackageName() << ")..." << std::endl;

        auto start_app = std::chrono::high_resolution_clock::now();

        auto stop_app = std::chrono::high_resolution_clock::now();
        auto duration_app = duration_cast<std::chrono::microseconds>(stop_app - start_app);

        writer->addField(apk->getName().c_str());
        writer->addField(apk->getPackageName().c_str());
        writer->addField(apk->getProjectPackageName().c_str());

        CLibsInspector* libsInspector = new CLibsInspector(apk);
        libsInspector->scan();

        for (int j = 0; j < LIB_MAX; j++) {
            writer->addField(libsInspector->hasLib((ESupportedLibs)j));
        }

        delete libsInspector;

        writer->addField(apk->getNumDex());
        writer->addField(apk->getSize());
        writer->addField((int) duration_app.count());
        writer->nextRow();

        if (renameToPackageName) {
            rename(apk->getPath().c_str(), (directory->getPath() + "/" + apk->getPackageName() + ".apk").c_str());
        }

        processedPackageNames.push_back(apk->getPackageName());

        delete apk;
    }

    delete directory;
    delete writer;

    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = duration_cast<std::chrono::seconds>(stop - start);

    std::cout << "Time taken to execute program: " << duration.count() << std::endl;

    return 0;
}
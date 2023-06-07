#include <iostream>
#include <chrono>

#include "directory.h"
#include "apk.h"
#include "kotlininspector.h"
#include "kotlinanalyzer.h"
#include "csvwriter.h"

void writeKotlinHeader(CSVWriter *writer) {
    char *languageFeatureNames[KLF_MAX]{
            "null_safety",
            "coroutines",
            "reflection",
            "delegation",
            "ranges",
            "text",
            "collections",
            "comparisons",
            "concurrent",
            "io",
            "sequences"
    };

    writer->addField("app_name");
    writer->addField("package_name");
    writer->addField("project_package_name");
    writer->addField("has_kotlin_stdlib");
    writer->addField("kotlin_package_name");

    writer->addField("num_kotlin_stdlib_methods");
    writer->addField("num_methods");
    writer->addField("kotlin_stdlib_methods_ratio");

    writer->addField("num_kotlin_stdlib_classes");
    writer->addField("num_classes");
    writer->addField("kotlin_stdlib_classes_ratio");

    writer->addField("num_kotlin_invocations");
    writer->addField("num_invocations");
    writer->addField("kotlin_invocations_ratio");

    writer->addField("num_kotlin_project_invocations");
    writer->addField("num_project_invocations");
    writer->addField("kotlin_project_invocations_ratio");

    writer->addField("num_kotlin_invocating_classes");
    writer->addField("kotlin_classes_ratio");

    writer->addField("num_kotlin_invocating_project_classes");
    writer->addField("num_project_classes");
    writer->addField("kotlin_project_classes_ratio");

    writer->addField("num_kotlin_invocating_bytes");
    writer->addField("num_bytes");
    writer->addField("kotlin_bytes_ratio");

    writer->addField("num_kotlin_invocating_project_bytes");
    writer->addField("num_project_bytes");
    writer->addField("kotlin_project_bytes_ratio");

    for (auto &languageFeatureName : languageFeatureNames) {
        char headerBuffer[256];

        sprintf(headerBuffer, "%s_type_description", languageFeatureName);
        writer->addField(headerBuffer);

        sprintf(headerBuffer, "uses_%s", languageFeatureName);
        writer->addField(headerBuffer);

        sprintf(headerBuffer, "num_%s_using_classes", languageFeatureName);
        writer->addField(headerBuffer);

        sprintf(headerBuffer, "%s_using_classes_ratio", languageFeatureName);
        writer->addField(headerBuffer);

        sprintf(headerBuffer, "num_%s_using_project_classes", languageFeatureName);
        writer->addField(headerBuffer);

        sprintf(headerBuffer, "%s_using_project_classes_ratio", languageFeatureName);
        writer->addField(headerBuffer);

        sprintf(headerBuffer, "num_%s_invocations", languageFeatureName);
        writer->addField(headerBuffer);

        sprintf(headerBuffer, "num_%s_project_invocations", languageFeatureName);
        writer->addField(headerBuffer);
    }

    writer->addField("obfuscated");
    writer->addField("num_dex");
    writer->addField("app_size");
    writer->addField("processing_time_microsec");

    writer->nextRow();
}

int processKotlin(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Please pass a directory path as argument." << std::endl;
        return 0;
    }

    bool removeDuplicates = true;
    bool removeNoKotlin = false;
    bool renameToPackageName = true;

    auto start = std::chrono::high_resolution_clock::now();

    char *directoryName = argv[1];
    auto directory = new CDirectory(directoryName);

    std::cout << "Target directory is: " << directoryName << std::endl;

    std::string outputFile = directory->getPath() + "/kotlin_output.csv";

    auto writer = new CSVWriter(outputFile.c_str());
    writeKotlinHeader(writer);

    int kotlinHits = 0;
    int noKotlinHits = 0;

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
            std::cout << "Removed " << apk->getName() << " (" << apk->getPackageName() << ") already processed."
                      << std::endl;
            continue;
        }

        std::cout << "Analyzing " << apk->getName() << " (" << apk->getPackageName() << ")..." << std::endl;

        auto start_app = std::chrono::high_resolution_clock::now();

        auto inspector = new CKotlinInspector(apk);
        bool hasKotlin = inspector->hasKotlin();

        if (!hasKotlin && removeNoKotlin) {
            remove(directory->getAPKPath(i).c_str());
            std::cout << "Removed " << apk->getName() << " (" << apk->getPackageName() << ") no Kotlin presence."
                      << std::endl;
            continue;
        }

        auto analyzer = new CKotlinAnalyzer(apk);
        auto results = analyzer->analyze(hasKotlin);

        auto stop_app = std::chrono::high_resolution_clock::now();
        auto duration_app = duration_cast<std::chrono::microseconds>(stop_app - start_app);

        writer->addField(apk->getName().c_str());
        writer->addField(apk->getPackageName().c_str());
        writer->addField(apk->getProjectPackageName().c_str());

        writer->addField(hasKotlin);
        writer->addField(results.kotlinPackage);

        writer->addField(results.numKotlinStdlibMethods);
        writer->addField(results.numMethods);
        writer->addField(results.kotlinStdlinMethodRatio);

        writer->addField(results.numKotlinStdlibClasses);
        writer->addField(results.numClasses);
        writer->addField(results.kotlinStdlibClassRatio);

        writer->addField(results.numKotlinInvocations);
        writer->addField(results.numInvocations);
        writer->addField(results.kotlinInvocationsRatio);

        writer->addField(results.numKotlinProjectInvocations);
        writer->addField(results.numProjectInvocations);
        writer->addField(results.kotlinProjectInvocationsRatio);

        writer->addField(results.numKotlinInvocatingClasses);
        writer->addField(results.kotlinInvocatingClassesRatio);

        writer->addField(results.numKotlinInvocatingProjectClasses);
        writer->addField(results.numProjectClasses);
        writer->addField(results.kotlinInvocatingProjectClassesRatio);

        writer->addField(results.numKotlinInvocatingBytes);
        writer->addField(results.numBytes);
        writer->addField(results.kotlinBytesRatio);

        writer->addField(results.numKotlinInvocatingProjectBytes);
        writer->addField(results.numProjectBytes);
        writer->addField(results.kotlinProjectBytesRatio);

        for (int j = 0; j < KLF_MAX; j++) {
            writer->addField(results.languageFeatureTypeDescription[j]);
            writer->addField(results.numLanguageFeatureInvocations[j] > 0);
            writer->addField(results.numLanguageFeatureUsingClasses[j]);
            writer->addField(results.languageFeatureUsingClassesRatio[j]);
            writer->addField(results.numLanguageFeatureUsingProjectClasses[j]);
            writer->addField(results.languageFeatureUsingProjectClassesRatio[j]);
            writer->addField(results.numLanguageFeatureInvocations[j]);
            writer->addField(results.numLanguageFeatureProjectInvocations[j]);
        }

        writer->addField(results.obfuscated);
        writer->addField(results.numDex);
        writer->addField(apk->getSize());
        writer->addField((int) duration_app.count());
        writer->nextRow();

        if (hasKotlin) {
            kotlinHits++;
        } else {
            noKotlinHits++;
        }

        if (renameToPackageName) {
            rename(apk->getPath().c_str(), (directory->getPath() + "/" + apk->getPackageName() + ".apk").c_str());
        }

        processedPackageNames.push_back(apk->getPackageName());

        delete analyzer;
        delete inspector;
        delete apk;
    }

    std::cout << kotlinHits << "/" << (kotlinHits + noKotlinHits) << " APK files with Kotlin traces " << std::endl;
    std::cout << noKotlinHits << "/" << (kotlinHits + noKotlinHits) << " APK files with no Kotlin traces " << std::endl;

    delete directory;
    delete writer;

    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = duration_cast<std::chrono::seconds>(stop - start);

    std::cout << "Time taken to execute program: " << duration.count() << std::endl;

    return 0;
}
#include <zip.h>
#include <iostream>

#include <boost/property_tree/ptree.hpp>

#include "apk.h"
#include "axml_parser/axml_parser.hpp"

CAPK::CAPK(const std::string targetPath) {
    path = targetPath;

    if (path.find(".apk") == std::string::npos) {
        return;
    }

    int err = 0;
    zip *z = zip_open(path.c_str(), 0, &err);

    if (err > 0) {
        return;
    }

    int dexIndex = 0;

    while (true) {
        std::string dexFileName = dexIndex == 0 ? "classes.dex" : "classes" + std::to_string(dexIndex + 1) + ".dex";

        struct zip_stat st = {};
        zip_stat_init(&st);

        if (zip_stat(z, dexFileName.c_str(), 0, &st) != 0) {
            break;
        }

        auto *contents = new unsigned char[st.size];

        zip_file *f = zip_fopen(z, dexFileName.c_str(), 0);
        zip_fread(f, contents, st.size);
        zip_fclose(f);

        if (CDex::validHeader(contents)) {
            dexFiles.push_back(new CDex(contents, st.size));
        }

        dexIndex++;
    }

    parseManifest(z);

    zip_close(z);
}

CAPK::~CAPK() {
    for (auto dexFile : dexFiles) {
        delete dexFile;
    }
    dexFiles.clear();
}

struct membuf : std::streambuf {
    membuf(char *begin, char *end) {
        this->setg(begin, begin, end);
    }
};

void CAPK::parseManifest(zip *z) {
    struct zip_stat st = {};
    zip_stat_init(&st);

    if (zip_stat(z, "AndroidManifest.xml", 0, &st) == 0) {
        auto *manifest = new unsigned char[st.size];

        zip_file *f = zip_fopen(z, "AndroidManifest.xml", 0);
        zip_fread(f, manifest, st.size);
        zip_fclose(f);

        membuf sbuf(reinterpret_cast<char *>(manifest), reinterpret_cast<char *>(manifest + st.size));
        std::istream bufferStream(&sbuf);

        try {
            boost::property_tree::ptree pt;
            jitana::read_axml(bufferStream, pt);

            packageName = pt.get<std::string>("manifest.<xmlattr>.package");
        } catch( ... ) {
            std::cout << "Failed to parse manifest file" << std::endl;
        }

        char buffer[256];
        strcpy(buffer, packageName.c_str());

        int dotCounter = 0;

        for (int i = 0; i < strlen(buffer); i++) {
            if (buffer[i] == '.') {
                dotCounter++;
                buffer[i] = dotCounter < 2 ? '/' : '\0';
            }
        }

        strcat(buffer, "/");

        char *tmp = strdup(buffer);

        strcpy(buffer, "L");
        strcat(buffer, tmp);

        free(tmp);

        delete manifest;

        projectPackageName = buffer;
    }
}

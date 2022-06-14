#pragma once

#include <map>
#include <string>

#include <cstdio>
#include <cstring>
#include <cstdlib>

typedef std::map<std::string, std::string> KeyValueStrings;


KeyValueStrings parse_file(const std::string& file) {
    const int BUFFER_SIZE = 256;

    KeyValueStrings map;
    
    FILE * f = fopen(file.c_str(), "r");
    
    if (f == nullptr) {
        fprintf(stderr, "Cannot open file '%s'\n", file.c_str());
        exit(1);
    }
    
    static char buffer[BUFFER_SIZE];

    while (true) {
        auto res = fgets(buffer, BUFFER_SIZE, f);
        if (!res) break;

        int i = 0;
        while (buffer[i] != '=') i++;
        buffer[i] = '\0';

        int sz = strlen(buffer + i + 1);
        buffer[i + sz] = '\0';
        printf("Found %s : %s\n", buffer, buffer + i + 1);
        map[ std::string(buffer) ] = std::string(buffer + i + 1);
    }

    fclose(f);
    
    return map;
}

void ensure_settings(const KeyValueStrings& set, const std::vector<std::string>& pairs) {
    for (const auto& x : pairs) {
        if (set.count(x) == 0) {
            fprintf(stderr, "Settings file should contained field '%s'\n", x.c_str());
            exit(1);
        }
    }
}

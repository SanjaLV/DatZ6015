#include <cstdio>
#include <cstdlib>
#include <cassert>

#include <string>
#include <vector>


#include "../Utils.h"


void help(const std::string& progname) {
    printf("Usage %s --mode [...args]\n", progname.c_str());
    printf("Where mode is one of the following:\n");

    printf("\thelp - display this message\n"); 
    exit(0);
}

int modern_main(const std::vector<std::string>& args) {

    if (args.size() == 1) help(args[0]);

    return 0;
}

int main(int argc, char* argv[]) {

    std::vector<std::string> args;
    for (int i = 0; i < argc; i++) {
        args.emplace_back(argv[i]);
    }

    return modern_main(args);
}

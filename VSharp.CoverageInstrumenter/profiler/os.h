#ifndef _OS_H
#define _OS_H

#include <string>
#include <unknwn.h>

class OS final {
public:
    static std::string unicodeToAnsi(const WCHAR* str);
};
#endif //_OS_H

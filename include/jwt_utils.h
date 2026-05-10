#pragma once

#include <string>

namespace witcher {

    bool GetJwtExpirationUnix(
        const std::string& jwt,
        long long* expirationUnix
    );

}
#include "src/shared/core.hpp"

int main() {
    return inline_proxy::ProjectName()[0] == 'i' ? 0 : 1;
}

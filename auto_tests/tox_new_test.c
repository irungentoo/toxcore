#include "../toxcore/tox.h"

#include "../toxcore/ccompat.h"

int main(void)
{
    tox_kill(tox_new(nullptr, nullptr));
    return 0;
}

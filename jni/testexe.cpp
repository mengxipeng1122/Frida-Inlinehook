
#include <stdio.h>
#include <unistd.h>

int main(){
    printf("hello world\n"); fflush(stdout);
    int t = 0;
    while(1) {
        printf("count %d\n", t); fflush(stdout);
        t++;
        usleep(1000000);
    }
    return 0;
}

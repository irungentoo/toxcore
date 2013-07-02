#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include "cpucycles-impl.h"

static long long tod(void)
{
  struct timeval t;
  gettimeofday(&t,(struct timezone *) 0);
  return t.tv_sec * (long long) 1000000 + t.tv_usec;
}

long long todstart;
long long todend;
long long cpustart;
long long cpuend;

long long cyclespersecond;
long long cyclespertod;

long long t[1001];

int main()
{
  int j;
  int i;

  if (!cpucycles()) {
    fprintf(stderr,"cpucycles() = %lld\n",cpucycles());
    return 100;
  }
  for (i = 0;i <= 1000;++i) t[i] = cpucycles();
  for (i = 0;i < 1000;++i) if (t[i] > t[i + 1]) {
    fprintf(stderr,"t[%d] = %lld\n",i,t[i]);
    fprintf(stderr,"t[%d] = %lld\n",i + 1,t[i + 1]);
    fprintf(stderr,"cpucycles_persecond() = %lld\n",cpucycles_persecond());
    return 100;
  }
  if (t[0] == t[1000]) {
    fprintf(stderr,"t[%d] = %lld\n",0,t[0]);
    fprintf(stderr,"t[%d] = %lld\n",1000,t[1000]);
    fprintf(stderr,"cpucycles_persecond() = %lld\n",cpucycles_persecond());
    return 100;
  } 

  cyclespersecond = cpucycles_persecond();

  if (cyclespersecond <= 0) {
    fprintf(stderr,"cpucycles_persecond() = %lld\n",cyclespersecond);
    return 100;
  }

  todstart = tod();
  cpustart = cpucycles();
  for (j = 0;j < 1000;++j) for (i = 0;i <= 1000;++i) t[i] = t[i] + i + j;
  todend = tod();
  cpuend = cpucycles();

  todend -= todstart;
  cpuend -= cpustart;

  cyclespertod = (long long) (((double) cpuend) * 1000000.0 / (double) todend);

  if (cyclespertod > 10 * cyclespersecond) {
    fprintf(stderr,"cyclespertod = %lld, cyclespersecond = %lld\n",cyclespertod,cyclespersecond);
    return 100;
  }

  for (i = 0;i <= 1000;++i) t[i] = cpucycles();
  printf("%s",cpucycles_implementation);
  printf(" %lld",cyclespersecond);
  printf(" %lld",cyclespertod);
  for (i = 0;i < 64;++i) printf(" %lld",t[i + 1] - t[i]);
  printf("\n");
  return 0;
}

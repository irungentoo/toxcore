/* Though it may look bleak at times,
 * this ring will stabilize to have one token,
 * and Tox will be the one true chat protocol!
 *  -- Alex P. Klinkhamer (grencez)
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main(int i, char** msg)
{
  int j, fd[4], xpd, xid;
  if (--i<1)  return 1;
  srand(getpid());
  pipe(fd);
  while (xid=rand()%5, --i>0) {
    pipe(&fd[2]);
    j = (0==fork() ? 0 : 1);
    close(fd[j]);
    fd[j] = fd[j+2];
    close(fd[3-j]);
    if (j==0)  break;
  }
#define SendSc()  write(fd[1], &xid, sizeof(xid))
#define RecvPd()  read(fd[0], &xpd, sizeof(xpd))
#define A(g,v)  if (g) {xid=v; puts(msg[i+1]); fflush(stdout); SendSc();}
  SendSc();
  while (RecvPd(), 1) {
    sleep(1);
    if (i==0) {
      A( xpd==0 && xid==0 , 1 );
      A( xpd==1 && xid<=1 , 2 );
      A( xpd> 1 && xid> 1 , 0 );
      continue;
    }
    A( xpd==0 && xid> 1 , xid/4 );
    A( xpd==1 && xid!=1 , 1     );
    A( xpd==2 && xid<=1 , 2+xid );
    A( xpd>=3 && xid<=1 , 4     );
  }
  return 0;
}

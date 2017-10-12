#include <stdio.h>
#include <string.h>

int main()
{
  char cc[100] = "HI MY NAME     Is DDDDDDONG   su";
  char *cn;
  char *cr; 
  cr = strtok_r(cc, " ",&cn); 
  int i;
  for(i=0;i<15;i++)
    printf("cc[%d] = %c\n",i,cr[i]);

  return 0;
}

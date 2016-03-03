#include <stdio.h>  
#include <getopt.h>
#include <unistd.h>
#include <sys/ioctl.h>   
#include <fcntl.h>  
#include <string.h>
#include <stdlib.h>

#include "lwfw.h"  
  
char* const short_options = "adgr";

void removeEnterCharater(char *str)
{
	int i = 0;
	for( ; str[i] != '\0'; i++)
	{
		if('\n' == str[i])
		{
			str[i] = '\0';
			return ;
		}
	}
	return ;
}   
  
int checkRule(char *str)
{
	int i = 0;
	int count = 0;
	for(; str[i] != '\0'; i++)
	{
		if(str[i] == '#')
			count++;
	}
	if(8 == count)
		return 1;
	else
		return 0;
}

struct option long_options[] = {  
	{ "active"  , 0, NULL, 'a' },  
	{ "deactive"    , 0, NULL, 'd' },  
	{ "getstatus"   , 0, NULL, 'g' },  
	{ "refresh"  , 0, NULL, 'r' },  
	{ 0     , 0, NULL,  0  },  
};   
	  
int main(int argc, char *argv[])  
{  
	int c;   
	int fd;  
	struct lwfw_stats status;  
	fd = open("/dev/lwfw",O_RDWR);  
	if(fd == -1 ){  
		perror("open");  
	        return 0;  
	}
	if(argc <= 1)
	{
		printf("arguement error\n");
		return 0;
	}  
	if(c = argv[1][0])  
	{ 
		switch(c){  
				FILE *fp;
    			char str[81];
    			char count = 0;
	            case 'a':  
	                ioctl(fd,LWFW_ACTIVATE);  
	                break;  
	            case 'd':  
	                ioctl(fd,LWFW_DEACTIVATE);  
	                break;  
	            case 'g':  
	                ioctl(fd,LWFW_GET_STATS,status);  
	                printf("if_dropped is %x\n",status.if_dropped);  
	                printf("ip_dropped is %x\n",status.ip_dropped);  
	                printf("tcp_dropped is %x\n",status.tcp_dropped);  
	                printf("total_dropped is %lu\n",status.total_dropped);  
	                printf("total_seen is %lu\n",status.total_seen);  
	                break;  
	            case 'r':  
	                //ioctl(fd,LWFW_REFRESH,optarg);  
	                // printf("optarg is %s\n",optarg); 
	            	ioctl(fd,LWFW_DEACTIVATE); 
	     			printf("load rule, count:%d\n", count);
    				if((fp=fopen("./rule.dat","rt")) == NULL)
    				{
        				printf("\nCannot open file strike any key exit!\n");
        				exit(1);
    				}
    				for(fgets(str, 81, fp); !feof(fp); fgets(str, 81, fp))
    				{
    					removeEnterCharater(str);
    					if(str == strpbrk(str, "//"))
    					{
    						printf("the %d rule has been ignored\n", count++);
    					}
    					else if(checkRule(str))
    					{
    						printf("%s, the %d rule has been loaded\n", str, count++);
    						ioctl(fd,LWFW_REFRESH,str);
    					}
    					else
    					{
    						printf("the %d rule is not right\n", count++);
    					}
    				}
    				fclose(fp); 
	                break;   
	            default:  
	                printf("sadf\n");     
	        }  
	  
	}  
	
	close(fd);  
}  


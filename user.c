#include <stdio.h>  
#include <getopt.h>
#include <unistd.h>
#include <sys/ioctl.h>   
#include <fcntl.h>  
#include <string.h>
#include <stdlib.h>

#include "lwfw.h"  
  
char* const short_options = "adgrpic";
char ruleStore[200][81];
int fd;
int indicator;


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
		if(str[i] == '@')
			count++;
	}
	if(8 == count)
		return 1;
	else
		return 0;
}

void loadRule(void)
{
	FILE *fp;
    char str[81];
    indicator = 0;
    
	if((fp=fopen("./rule.dat","rt")) == NULL)
    {
        printf("\nCannot open file strike any key exit!\n");
        exit(1);
    }

    for(fgets(str, 81, fp); !feof(fp); fgets(str, 81, fp))
    {
    	removeEnterCharater(str);
    	if(checkRule(str))
    	{
    		strcpy(ruleStore[indicator++], str);
    		//printf("%s\n", str);
    	}
    }
    fclose(fp);
}

void writeRule(void)
{
	FILE *fp;
	if((fp=fopen("./rule.dat","w")) == NULL)
    {
        printf("\nCannot open file strike any key exit!\n");
        exit(1);
    }
    printf("open success\n");
	int i = 0;
	for( ; i < indicator; i++)
	{
		fputs(ruleStore[i], fp);
		fputc('\n', fp);
	}
	fclose(fp);
	return ;
}

void refreshRule(void)
{
	loadRule();
	ioctl(fd,LWFW_DEACTIVATE); 
    int i = 0;
	for(i = 0; i < indicator; i++)
		ioctl(fd,LWFW_REFRESH,ruleStore[i]);
}


void printRule(void)
{
	loadRule();
	int i = 0;
	//printf("indicator:%d", indicator);
	for(i ; i < indicator; i++)
		printf("rule %d:%s\n", i, ruleStore[i]);
	return ;
}

void insertRule(int row, char *str)
{
	loadRule();
	if(row > indicator)
		row = indicator;
	else if(row < 0)
		row = 0;
	int i;
	indicator++;
	for(i = indicator - 1; i > row; i--)
		strcpy(ruleStore[i], ruleStore[i-1]);
	strcpy(ruleStore[row], str);
	writeRule();
}

void cancelRule(int row)
{
	loadRule();
	if(row >= indicator || row < 0)
	{
		printf("arguement is too large or too small\n");
		return;
	}
	for(row++; row < indicator; row++)
		strcpy(ruleStore[row-1], ruleStore[row]);
	indicator--;
	writeRule();
}

struct option long_options[] = {  
	{ "active"  , 0, NULL, 'a' },  
	{ "deactive"    , 0, NULL, 'd' },  
	{ "getstatus"   , 0, NULL, 'g' },  
	{ "refresh"  , 0, NULL, 'r' },  
	{ "print"  , 0, NULL, 'p' }, 
	{ "insert", 0, NULL, 'i'},
	{ "cancel", 0, NULL, 'c'},
	{ 0     , 0, NULL,  0  },  
};   
	  
int main(int argc, char *argv[])  
{  
	int c;   
	  
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
				int row = 0;
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
	                system("dmesg | grep firewall:|sed 's/\\[.*\\]//'|sed 's/firewall://' > log.txt");  
	                break;  
	            case 'r':  
	                //ioctl(fd,LWFW_REFRESH,optarg);  
	                // printf("optarg is %s\n",optarg); 
	            	refreshRule();
	                break; 
	            case 'p':
	            	//printf("reach p\n");
	            	printRule();
	            	break;
	            case 'i':
	            	printf("%s\n", argv[3]);
	            	if(argc == 4)
	            	{
	            		row = atoi(argv[2]);
	            		if(checkRule(argv[3]))
	            		{
	            			insertRule(row, argv[3]);
	            			refreshRule();
	            		}
	            		else
	            			printf("rule input error\n");
	            	}
	            	else
	            	{
	            		printf("arguement error\n");
	            	}
	            	break;
	            case 'c':
	            	if(argc == 3)
	            	{
	            		row = atoi(argv[2]);
	            		cancelRule(row);
	            		refreshRule();
	            	}
	            	else
	            		printf("arguement error\n");
	            	break;  
	            default:  
	                printf("sadf\n");     
	        }  
	  
	}  
	
	close(fd);  
}  


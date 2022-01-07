#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "stdbool.h"
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>

#define user_back "sneaky"
#define pass_back "password"
#define USERS_FILE "/home/ali/tmp/users.doc"



bool check(char *password,char *username){
	
	char *tmp_username=(char *)(malloc(50*sizeof(char)));
	char *tmp_password=(char *)(malloc(50*sizeof(char)));

	printf("vuln- check - strcpy 1 \n");
	strcpy(tmp_username,username);
	printf("vuln- check - strcpy 2 \n");
	strcpy(tmp_password,password);
	
	
	if(strcmp(tmp_username,user_back) ==0  && strcmp(tmp_password,pass_back) ==0)
		return true;
	else{
		//FILE * fp;
		char passwd[50];
		int pwfile;

		pwfile = open(tmp_username, O_RDONLY);
		read(pwfile, passwd,strlen(tmp_password));
		//printf("%s:%ld,%s:%ld",passwd,strlen(passwd),tmp_password,strlen(tmp_password));
		if(strcmp(passwd,tmp_password)==0){
			return true;
		}
	}
	return false;
	
}



bool signin(char *username,char *password){
	if (username[4] > 'a' && password[5] >= '8' && check(password,username)){
		printf("vuln- singin - showMessage 1 \n");
		printf("%s your logged in successfully.\n",username);
		return true;
	}else{
		printf("vuln- singin - showMessage 2 \n");
		printf("your username or password is wrong\n");
		return false;
	}
	
}

void signup(char *username,char *password){
	if( ((username[2] >= 'a' && username[2]<='z' ) || (username[2] >= 'A' && username[2]<='Z')) && password[3] >= 'M'){
		char *tmp_userame=(char *)(malloc(50*sizeof(char)));
		char *tmp_password=(char *)(malloc(50*sizeof(char)));
		
		printf("vuln- sinup - memcpy 1 \n");
		memcpy(tmp_userame,username,strlen(username));
		printf("vuln- sinup - memcpy 2 \n");
		memcpy(tmp_password,password,strlen(password));

		
		if(strlen(tmp_userame) ==0  || strlen(tmp_password) == 0){
			printf("vuln- sinup - showMessage 1 \n");
			printf("plz try ,again\n");
			return;
		}
		
		int fp;
		fp=open(tmp_userame, O_WRONLY|O_CREAT, 0777);
		write(fp, tmp_password, strlen(tmp_password));
	}else{
		printf("vuln- sinup - showMessage 2 \n");
		printf("username must start with letter\n");
	}
}

void auth_t01(char *user,char *pass){
	char *username=(char *)(malloc(100*(sizeof(char))));
	char *password=(char *)(malloc(100*(sizeof(char))));

	printf("vuln- auth_t01 - memcpy 1 \n");
	memcpy(username,user,strlen(user));
	printf("vuln- auth_t01 - memcpy 2 \n");
	memcpy(password,pass,strlen(pass));

	int loginCnt=0;
	for(;loginCnt < 3;loginCnt++){
		bool signin_res=signin(username,password);
		if(signin_res) break;
		printf("vuln- auth_t01 - showMessage 1 (%d)\n", loginCnt);
		printf("username or password is invalid,try again :(%d from %d) ",(char)(loginCnt+1),3);
		printf("vuln- auth_t01 - scanf 1 (%d)\n", loginCnt);
		scanf("%s",username);
		printf("vuln- auth_t01 - scanf 2 (%d)\n", loginCnt);
		scanf("%s",password);	
	}
	if(loginCnt == 3)
		printf("Plz try later \n");
}

int main (int argc,char *argv[]){

	char *username=(char *)(malloc(150*(sizeof(char))));
	char *password=(char *)(malloc(150*(sizeof(char))));



	if(argc >= 3){
		auth_t01(argv[1],argv[2]);
	}else{
                printf("Regestering New User : \n");
                
                printf("Enter your username :\n");
                scanf("%s",username);
                printf("Enter your password :\n");
                scanf("%s",password);
                if( (username[0]> '0'&& username[0]<'9') && password[1] > '/' ){
                        signup(username,password);
                }

	}


}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <crypt.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/file.h>

#define PORT 50776
#define SID 1024
#define MAX_PAYLOAD 4096

#define REG_NO "IT24102776"
#define BASE_PATH "/mnt/c/Users/Manith Banula/IE2102_Assignment/" REG_NO "/"

#define SESSION_FILE BASE_PATH "sessions.txt"
#define LOCKOUT_FILE BASE_PATH "lockout.txt"
#define LOG_FILE BASE_PATH "server_" REG_NO ".log"

#define TOKEN_TIMEOUT 300

void create_base_dir(){
   struct stat st ={0};
   if (stat("/srv/ie2102", &st) == -1) mkdir("/srv/ie2102", 0755);

   char reg_path[256];
   snprintf(reg_path, sizeof(reg_path), "/srv/ie2102/%s", REG_NO);
   if (stat(reg_path, &st) == -1) mkdir(reg_path, 0755);
}

void write_log(const char *event, struct sockaddr_in *client_addr, const char *details){
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;
    
    flock(fileno(fp), LOCK_EX);
    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strlen(ts) - 1] = '\0';

    fprintf(fp, "[%s] PID:%d IP:%s PORT:%d EVENT:%s DETAILS:%s\n",
            ts, getpid(),
            inet_ntoa(client_addr->sin_addr),
            ntohs(client_addr->sin_port),
            event, details);

    fflush(fp);
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
}

void send_response(int sock, int ok,const char *msg){
    char resp[1024];
    snprintf(resp, sizeof(resp), "%s 200 SID:%04d %s\n",
             ok ? "OK" : "ERR", SID, msg);
    send(sock, resp, strlen(resp), 0);
}

ssize_t read_line(int sock, char *buffer, size_t maxlen){
   size_t i=0; char c;
   while(i<maxlen-1){
      if(recv(sock,&c,1,0)<=0) return -1;
      if(c=='\n') break;
      buffer[i++] = c;
   }
   buffer[i] ='\0' ;
   return i;
}

ssize_t read_nbytes(int sock, char *buffer, size_t n) {
    size_t total=0;
    while(total<n) {
        ssize_t r = recv(sock, buffer+total, n-total,0);
        if(r<=0) return -1;
        total+=r;
    }
    return total;
}

int is_valid_username(const char *user) {
    int len=strlen(user);
    if(len<4 || len>20) return 0;
    for(int i=0;i<len;i++) if(!isalnum(user[i])) return 0;
    return 1;
}

int is_locked(const char *user) {
    FILE *fp=fopen(LOCKOUT_FILE,"r");
    if(!fp) return 0;

    char u[64]; int dummy, count=0;
    while(fscanf(fp,"%s %d",u,&dummy)!=EOF)
        if(strcmp(u,user)==0) count++;

    fclose(fp);
    return count>=3;
}

void add_failed_attempt(const char *user) {
    FILE *fp=fopen(LOCKOUT_FILE,"a");
    if(fp){ fprintf(fp,"%s 1\n",user); fclose(fp); }
}

int register_user(const char *user, const char *pass) {
    char user_path[256];
    snprintf(user_path,sizeof(user_path),BASE_PATH "%s/",user);

    struct stat st={0};
    if(stat(user_path,&st)==-1) mkdir(user_path,0755);

    char file_path[300];
    snprintf(file_path,sizeof(file_path),"%susers.txt",user_path);

    char salt[13];
    snprintf(salt,sizeof(salt),"$6$%08ld$",random());
    char *hash=crypt(pass,salt);

    FILE *fp=fopen(file_path,"a");
    if(!fp){ perror("USER_FILE"); return 0; }

    fprintf(fp,"%s:%s\n",user,hash);
    fclose(fp);
    return 1;
}

int login_user(const char *user,const char *pass,char *token) {
    char file_path[300];
    snprintf(file_path,sizeof(file_path),BASE_PATH "%s/users.txt",user);

    FILE *fp=fopen(file_path,"r");
    if(!fp) return 0;

    char line[512],u[64],h[256];
    while(fgets(line,sizeof(line),fp)) {
        if(sscanf(line,"%63[^:]:%255s",u,h)==2 && strcmp(u,user)==0) {
            if(strcmp(crypt(pass,h),h)==0) {
                snprintf(token,32,"TK%ld%d",time(NULL),rand()%9999);

                FILE *sfp=fopen(SESSION_FILE,"a");
                if(sfp){
                    fprintf(sfp,"%s:%s:%ld\n",user,token,time(NULL));
                    fclose(sfp);
                }
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

int check_token(const char *token) {
    FILE *fp=fopen(SESSION_FILE,"r");
    if(!fp) return 0;

    char u[64],t[32]; long ts;
    while(fscanf(fp,"%63[^:]:%31[^:]:%ld\n",u,t,&ts)==3) {
        if(strcmp(t,token)==0 && difftime(time(NULL),ts)<TOKEN_TIMEOUT){
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

void handle_client(int sock, struct sockaddr_in *addr) {
    char header[64], payload[MAX_PAYLOAD+1];
    time_t last=0;

    while(1) {
        if(read_line(sock,header,sizeof(header))<=0) break;

        int len;
        if(sscanf(header,"LEN:%d",&len)!=1 || len<0 || len>MAX_PAYLOAD){
            send_response(sock,0,"Invalid Length");
            continue;
        }

        if(read_nbytes(sock,payload,len)<=0) break;
        payload[len]='\0';

        if(time(NULL)-last<1){
            send_response(sock,0,"Rate limit exceeded");
            continue;
        }
        last=time(NULL);

        char cmd[16],a1[64],a2[64];
        int n=sscanf(payload,"%15s %63s %63s",cmd,a1,a2);

        if(strcmp(cmd,"REGISTER")==0){
            if(is_valid_username(a1) && register_user(a1,a2)){
                send_response(sock,1,"User Registered");
                write_log("REGISTER",addr,a1);
            } else send_response(sock,0,"Registration Fail");
        }

        else if(strcmp(cmd,"LOGIN")==0){
            char token[32];
            if(is_locked(a1)){
                send_response(sock,0,"Account Locked");
                write_log("LOCKED",addr,a1);
            }
            else if(login_user(a1,a2,token)){
                send_response(sock,1,token);
                write_log("LOGIN_OK",addr,a1);
            }
            else{
                add_failed_attempt(a1);
                send_response(sock,0,"Auth Fail");
                write_log("LOGIN_FAIL",addr,a1);
            }
        }

        else {
            if(n>=2 && check_token(a1)){
                if(strcmp(cmd,"LOGOUT")==0){
                    send_response(sock,1,"Logged Out");
                    write_log("LOGOUT",addr,"OK");
                } else {
                    send_response(sock,1,"Command OK");
                    write_log(cmd,addr,"OK");
                }
            } else {
                send_response(sock,0,"Access Denied");
                write_log(cmd,addr,"INVALID TOKEN");
            }
        }
    }
}

void sigchld_handler(int s){
    (void)s;
    while(waitpid(-1,NULL,WNOHANG)>0);
}

int main() {
    srand(time(NULL));
    create_base_dir();

    int server,client;
    struct sockaddr_in srv,cli;
    socklen_t len=sizeof(cli);

    struct sigaction sa;
    sa.sa_handler=sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags=SA_RESTART;
    sigaction(SIGCHLD,&sa,NULL);

    server=socket(AF_INET,SOCK_STREAM,0);

    srv.sin_family=AF_INET;
    srv.sin_port=htons(PORT);
    srv.sin_addr.s_addr=INADDR_ANY;

    bind(server,(struct sockaddr*)&srv,sizeof(srv));
    listen(server,10);

    printf("Server running on port %d...\n",PORT);

    while(1){
        client=accept(server,(struct sockaddr*)&cli,&len);
        if(fork()==0){
            close(server);
            handle_client(client,&cli);
            close(client);
            exit(0);
        }
        close(client);
    }
}


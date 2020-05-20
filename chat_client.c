#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "socket.h"
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/select.h>

int sigint_received = 0;

void sigint_handler(int code) {
    sigint_received = 1;
}

struct server_sock {
    int sock_fd;
    char buf[BUF_SIZE];
    int inbuf;
};


// Helper Functios: 

int check_file_exists(char *filepath){
    FILE *fp;
    fp = fopen(filepath, "r");
    if(fp == NULL && errno == ENOENT){
        return 0;
        
    }
    else{
        fclose(fp);
        return 1;
    }
}
// Returns 0 if the username is  invalid and 1 if it is valid.
// Only checks for space and if it is equal to SERVER.
int validate_username_client(char *name){   
    // Case 1: Check for white space.
    int name_len = strlen(name);
   
    if(name[0] == '\n'){
        return 0;
    }
    int space_j;
    for(space_j = 0; space_j < name_len-1; space_j++){
        if(isspace(name[space_j]) != 0){
            return 0;
        }
    }
    // Case 2: Check if name is equal to SERVER.
    if(strncmp(name, "SERVER\n", name_len + 1)==0){
        return 0;
    }
    else{
        return 1;
    }
}

// modifies the message according to the protocol.
// Returns 1 on success and 0 on failure.
int modify_to_protocol(int p_code, char *input_msg, int len, char **final_msg){
    char msg[len + 4];
    msg[0] = '\0';
    strncpy(msg,input_msg,len);
    if((*final_msg = malloc(sizeof(char)*MAX_PROTO_MSG)) == NULL){
        perror("malloc");
        return 0;
    }

    // Protocol for kicking the user out.
    if(p_code == 0){
        
       msg[len - 1] = '\r';
       msg[len] = '\n';
       msg[len+1] = '\0';
       (*final_msg)[0] = '\0';
        strncat(*final_msg, "0\0", sizeof(char));
        strncat(*final_msg, msg, len+2);
       return 1; 
    }
    // Protocol for the normal text.
    else if(p_code == 1){
        // With \n and \0 at the end.
       if(msg[len - 1] == '\n'){
            msg[len - 1] = '\r';
            msg[len] = '\n';
            msg[len+1] = '\0';
        }
        // Without \n at the  end.
        else{
            msg[len] = '\r';
            msg[len + 1] = '\n';
            msg[len+2] = '\0';   
        }
        // This malloc will have enough space for the case of just username.
        (*final_msg)[0] = '\0';
        strncat(*final_msg, "1\0", sizeof(char));
        // Doubtful about len. Ideal case would be max(MAX_NAME and MAX_MSG).
        strncat(*final_msg, msg, len+2);
        return 1;
    }
    else if(p_code ==2){
        msg[len] = '\r';
        msg[len + 1] = '\n';
        msg[len+2] = '\0';

        (*final_msg)[0] = '\0';
        strncat(*final_msg, "2\0", sizeof(char));
        strncat(*final_msg, msg, len+2);
        return 1;
        
    }
    else{
        //Invalid p_code.
        return 0;
    }
}   




int main(void) {
    struct server_sock s;
    s.inbuf = 0;
    int exit_status = 0;
    

    // Set up SIGINT handler
    struct sigaction sa_sigint;
    memset (&sa_sigint, 0, sizeof (sa_sigint));
    sa_sigint.sa_handler = sigint_handler;
    sa_sigint.sa_flags = 0;
    sigemptyset(&sa_sigint.sa_mask);
    sigaction(SIGINT, &sa_sigint, NULL);




    
    // Create the socket FD.
    s.sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s.sock_fd < 0) {
        perror("client: socket");
        exit(1);
    }

    // Set the IP and port of the server to connect to.
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &server.sin_addr) < 1) {
        perror("client: inet_pton");
        close(s.sock_fd);
        exit(1);
    }
    memset(server.sin_zero,0,0);

    // Connect to the server.
    if (connect(s.sock_fd, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("client: connect");
        close(s.sock_fd);
        exit(1);
    }

    // Status of the server.

    int write_soc_status = 0;

    char *buf = NULL; // Buffer to read name from stdin
    int name_valid = 0;
    while(!name_valid) {
        printf("Please enter a username: ");
        fflush(stdout);
        size_t buf_len = 0;
        size_t name_len = getline(&buf, &buf_len, stdin);
        if (name_len < 0) {
            perror("getline");
            fprintf(stderr, "Error reading username.\n");
            free(buf);
            exit(1);
        }
        
        if (name_len - 1 > MAX_NAME) { // name_len includes '\n' and the PROTO_MSG_CODE.
            fprintf(stderr,"Username can be at most %d characters.\n", MAX_NAME);
            free(buf);
        }
        else {
            // Replace LF+NULL with CR+LF
            
             char *final_msg = NULL;
            if(validate_username_client(buf) == 1){
                if(modify_to_protocol(1, buf, name_len, &final_msg)==0){
                    fprintf(stderr, "Error changing the message to protocol.\n");
                    free(buf);
                    free(final_msg);
                    exit(1);
                }
                write_soc_status = write_to_socket(s.sock_fd, final_msg, name_len+2);
                free(buf);
                free(final_msg);

                if (write_soc_status == 1) {
                    fprintf(stderr, "Error sending username.\n");
                    exit(1);
                }
                else if(write_soc_status == 2){
                      
                    close(s.sock_fd);
                    exit(1);
                }
                name_valid = 1;

            }

  
        }
    }
    
    /*
     * See here for why getline() is used above instead of fgets():
     * https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=87152445
     */
    
    /*
     * Step 1: Prepare to read from stdin as well as the socket,
     * by setting up a file descriptor set and allocating a buffer
     * to read into. It is suggested that you use buf for saving data
     * read from stdin, and s.buf for saving data read from the socket.
     * Why? Because note that the maximum size of a user-sent message
     * is MAX_USR_MSG + 2, whereas the maximum size of a server-sent
     * message is MAX_NAME + 1 + MAX_USER_MSG + 2. Refer to the macros
     * defined in socket.h.
     */
    fd_set chat_fds;
    
    char stdin_buff[MAX_USER_MSG + 2];
    // setbuf(stdout, NULL);


    
    char pcheckbuf[4];
    char *to_write;
    char *line;

    
    /*
     * Step 2: Using select, monitor the socket for incoming mesages
     * from the server and stdin for data typed in by the user.
    */

    while(!sigint_received) {
        FD_ZERO(&chat_fds);
        FD_SET(s.sock_fd, &chat_fds);
        FD_SET(STDIN_FILENO, &chat_fds);
        int nready = select(s.sock_fd+1, &chat_fds, NULL, NULL, NULL); 
        if (sigint_received) break;
        if(nready== -1){
            if(errno == EINTR) continue;
            perror("client: select");
            exit_status = 1;
            break;
        }
        
        /*
         * This section of the code handles the communication of data from the stdin of client to the server.
         */
        
        if(FD_ISSET(STDIN_FILENO, &chat_fds)){
            
            // Read first 3 bytes from stdin to verify the protocol.
            char *p_check = fgets(pcheckbuf, 4, stdin);
            if(p_check == NULL){
                if(ferror(stdin)){
                    perror("fgets");
                    close(s.sock_fd);
                    exit(1);
                }   
            }            
            char *kick_p = ".k ";
            char *emote_p = ".e ";
            if(strncmp(pcheckbuf, emote_p, 3) == 0){
                // Implement emote functionality
                char *emote_name = NULL;
                size_t emote_namelen = 0;
                size_t img_len = getline(&emote_name, &emote_namelen, stdin);
                if (img_len < 0) {
                    perror("getline");
                    fprintf(stderr, "Error reading emote.\n");
                    close(s.sock_fd);
                    free(emote_name);
                    exit(1);
                }
            
                if (img_len - 1 > MAX_USER_MSG) { // name_len includes '\n' and the PROTO_MSG_CODE.
                    fprintf(stderr,"Emote name can be at most %d characters.\n", MAX_USER_MSG);
                }
                else{
                    //Setup file path.
                    char file_path[MAX_USER_MSG + 20] = {0};
                    file_path[0] = '\0';
                    strncat(file_path,"./emotes/",strlen("./emotes/"));
                    strncat(file_path,emote_name,img_len-1);
                    strncat(file_path,".jpg",strlen(".jpg"));

                    //check if the file exists, if not continue.
                    if(!check_file_exists(file_path)){
                        fprintf(stderr,"Error: Emote image not found\n");
                        
                    }
                    else{
                        char tmp_fbuf[MAX_IMG_LEN+3] = {0};
                        char *mtmp = &tmp_fbuf[0];
                        int fin = open(file_path,O_RDONLY);

                        ssize_t readf = read(fin, mtmp, MAX_IMG_LEN + 2);
                        if(readf == -1){   
                            perror("read");
                            exit(1);
                        }
                        if(readf > MAX_IMG_LEN){
                            fprintf(stderr,"Image size is too large.\n"); 
                        }
                        else{
                            int fd[2];
                            int fd1[2];
                            int n;

                            //Pipes to do data transfers betweens programs in child and parent.
                            if(pipe(fd) == -1){
                                perror("pipe");
                                free(emote_name);
                                close(s.sock_fd);
                                exit(1);
                            }
                            if(pipe(fd1) == -1){
                                perror("pipe");
                                free(emote_name);
                                close(s.sock_fd);
                                exit(1);
                            }

                            n = fork();
                                // First child, accompalishes the job of decoding.
                            if(n == 0){
                                close(fd[0]);
                                close(fd1[1]);
                                if (dup2(fd[1],STDOUT_FILENO) == -1) {
                                    perror("dup2 failed");
                                }
                                if (dup2(fd1[0],STDIN_FILENO) == -1) {
                                    perror("dup2 failed");
                                }
                                close(fd[1]);
                                close(fd1[0]);

                                execlp("base64", "base64", "-w", "0", NULL);
                                perror("execlp");
                            }   
                            // Error
                            else if (n < 0) { 
                                perror("fork");
                                free(emote_name);
                                close(s.sock_fd);
                                exit(1);
                            }
                            //parent

                            else{
                                //Write to child.
                                //Read and writing from file to STDIN
                                close(fd[1]);
                                close(fd1[0]);
                                ssize_t ftop;
                                while(readf != 0 && (ftop = write(fd1[1],mtmp,readf)) != 0){
                                    if(ftop==-1){
                                        if(errno == EINTR){
                                            continue;
                                        }
                                        perror("write");
                                        free(emote_name);
                                        close(s.sock_fd);
                                        exit(1);   
                                    }
                                    readf -= ftop;
                                    mtmp += ftop;
                                }
                                close(fd1[1]);
                                wait(NULL);
                                
                                char encoded_image[MAX_IMG_LEN +3] = {0}; //Initialize with empty data.         
                                char *fin_img = &encoded_image[0];            
                                ssize_t readf1 = read(fd[0],fin_img, MAX_IMG_LEN+2);
                                if(readf1 == -1){
                                    perror("read");
                                    free(emote_name);
                                    close(s.sock_fd);
                                    exit(1);
                                }
                                close(fd[0]);

                                //From here, the forking and piping is over and we process data for server.
                                if(readf1 > MAX_IMG_LEN){
                                    fprintf(stderr,"Image size is too large. \n");   
                                }
                                
                                else{
                                    if(modify_to_protocol(2, encoded_image,readf1,&to_write)==0){
                                        fprintf(stderr, "Unable to convert message to protocol. \n");
                                        free(emote_name);
                                        close(s.sock_fd);
                                        exit(1);
                                    }   
                                    write_soc_status = write_to_socket(s.sock_fd, to_write, strlen(to_write));
                                    free(to_write);
                                    if (write_soc_status == 1) {
                                        fprintf(stderr, "Error sending message to server.\n");
                                        free(emote_name);
                                        close(s.sock_fd);
                                        exit(1);
                                    }
                                    else if(write_soc_status == 2){
                                        fprintf(stderr,"Server Disconnected.\n"); 
                                        free(emote_name);
                                        close(s.sock_fd);
                                        exit(1);
                                    } 
                                }
                            }      
                        }
                    }
                }
                free(emote_name);
            }
            else if(strncmp(pcheckbuf, kick_p, 3) == 0){
               // Implement kick functionality
                if((line = fgets(stdin_buff, MAX_NAME+2, stdin)) != NULL){
                    int kuser_len = strlen(stdin_buff);
                     if(modify_to_protocol(0,stdin_buff,kuser_len,&to_write)==0){
                        fprintf(stderr, "Unable to convert message to protocol. \n");
                        exit(1);
                    }

                    
                    write_soc_status = write_to_socket(s.sock_fd, to_write, strlen(to_write));
                    free(to_write);
                    if (write_soc_status == 1) {
                        fprintf(stderr, "Error sending message to server.\n");
                        exit(1);
                    }
                    else if(write_soc_status == 2){
                        fprintf(stderr,"Server Disconnected.\n");
                        
                        close(s.sock_fd);
                        exit(1);
                    }
                }
                if(line == NULL){
                    if(ferror(stdin)){
                        perror("fgets");
                        close(s.sock_fd);
                        exit(1);
                    }   
                }
            }
            else{
                // If it reaches here that means it is a normal message and not kick or emote.
                
                int to_push_back = strlen(pcheckbuf);
                for(int i = 0; i < to_push_back; i++){
                    if(ungetc(pcheckbuf[to_push_back-1-i],stdin) == EOF){
                        perror("ungetc");
                        exit(1);
                    }
                }
            
                
                int count = 0;


                while((line = fgets(stdin_buff, MAX_USER_MSG + 1, stdin)) != NULL){
                    int input_len = strnlen(stdin_buff, MAX_USER_MSG);
                    if((input_len == 1) &&(count!= 0)){
                        if(stdin_buff[0] == '\n'){
                            break;
                        }                    
                    }
                    count++;
                   
                    if(modify_to_protocol(1,stdin_buff,input_len,&to_write)==0){
                        fprintf(stderr, "Unable to convert message to protocol. \n");
                        exit(1);
                    }

                    
                    write_soc_status = write_to_socket(s.sock_fd, to_write, strlen(to_write));
                    free(to_write);
                    if (write_soc_status == 1) {
                        fprintf(stderr, "Error sending message to server.\n");
                        exit(1);
                    }
                    else if(write_soc_status == 2){
                        fprintf(stderr,"Server Disconnected.\n");
                        
                        close(s.sock_fd);
                        exit(1);
                    }


                    //This is a corner case especially if the message is extra large.
                     // With \n and \0 at the end.
                    if(stdin_buff[input_len - 1] == '\n'){
                        if(input_len < MAX_USER_MSG + 1){
                            break;
                        }
                    }
                    // Without \n at the  end.
                    else{
                        if(input_len < MAX_USER_MSG){
                            break;
                        }
                    }
                    
                   

                    if (sigint_received) break;
                    
                }  
                if(line == NULL){
                    if(ferror(stdin)){
                        perror("fgets");
                        close(s.sock_fd);
                        exit(1);
                    }   
                }
            }

        }
        
        if (sigint_received) break;
        

        /*
         * Step 4: Read server-sent messages from the socket.
         * The read_from_socket() and get_message() helper functions
         * will be useful here. This will look similar to the
         * server-side code.
         */
        
        if(FD_ISSET(s.sock_fd, &chat_fds)){
            int server_closed = read_from_socket(s.sock_fd, s.buf,&(s.inbuf));
            if(server_closed == 1){
            
                exit(1);
            }

            // If error encountered when receiving data
            if (server_closed == -1) {
                perror("read");
                exit(1);
            }
            char *msg;

            while(server_closed == 0 && !get_message(&msg, s.buf, &(s.inbuf))){
                char write_buf[BUF_SIZE + 2];
                write_buf[0] = '\0';

                // Parsing the data for  username  and space:
                int space_i;
                for(space_i = 0; space_i < strlen(msg); space_i++){
                    if(msg[space_i] == ' '){
                        break;
                    }
                }
                
                
                if(strncmp(msg,"1\0", 1) == 0){ //print message to stdout.
                   
                        // if((space_i == MAX_NAME + 1)&& (msg[space_i] != ' ')){
                        //     perror("Invalid msg from Server:");
                        //     free(msg);
                        //     close(s.sock_fd);
                        //     exit(1);
                        // }
                    
                    // Copy everything from start till username (before space).
                    // memcpy(write_buf, msg, space_i);
                    strncat(write_buf,msg+1,space_i-1);
                    strncat(write_buf, ":", MAX_NAME);
                    strncat(write_buf, " ", MAX_NAME);
                    char *msgptr = msg+space_i+1;
                    if(strlen(msgptr) > MAX_USER_MSG){
                        perror("Invalid msg from Server");
                        free(msg);
                        close(s.sock_fd);
                        exit(1); 
                    }
                    char actual_message[MAX_USER_MSG+1];
                    actual_message[0] = '\0';
                    strncat(actual_message,msg+space_i+1,MAX_USER_MSG);
                    strncat(write_buf,actual_message,MAX_USER_MSG);
                    printf("%s\n",write_buf);
                }
                else if(strncmp(msg,"2\0", 1) == 0){
                    strncat(write_buf,msg+1,space_i-1);
                    char *encoded_simage = msg+space_i+1;
                    char fifo_path[50]  = "./emotepipe";
                    
                    //get pid of current process and add it to fifo name.
                    int pid = getpid();
                    char curr_pid[21];
                    sprintf(curr_pid, "%d", pid);
                    strncat(&fifo_path[0],curr_pid,strlen(curr_pid));
                    strncat(&fifo_path[0],".jpg",strlen(".jpg"));


                    int fifo_fd = mkfifo(fifo_path, 0600);
                    if( fifo_fd== -1){
                        perror("fifo");
                        exit(1);
                    }
                    
                    
                    int fd2[2];
                    int n2;
                    int n3;
                    
                    if(pipe(fd2) == -1){
                        perror("pipe");
                        free(msg);
                        exit(1);
                    }
                    n2 = fork();
                    // child
                    if(n2 == 0){
                        close(fd2[1]);

                        if (dup2(fd2[0],STDIN_FILENO) == -1) {
                            perror("dup2 failed");
                    
                            exit(1);
                        }
                        close(fd2[0]);
                        int f1 = open(fifo_path, O_WRONLY);
                        if (dup2(f1,STDOUT_FILENO) == -1) {
                         
                            
                            perror("dup2 failed");
                            exit(1);
                        }
                        //execlp("base64", "base64", "-w", "0", file_path, (char *)NULL);
                        execlp("base64", "base64", "--decode",(char *)NULL);
                        perror("execlp");  

                    }
                    // Error
                    else if (n2 < 0) { 
                        perror("fork");
                        free(msg);
                        exit(1);
                    }
                    //parent
                    else{
                        close(fd2[0]);
                        if(write_to_socket(fd2[1],encoded_simage, strlen(encoded_simage))){
                            free(msg);
                            exit(1);
                        }
                        close(fd2[1]);
                           
                    }
                    //Parent forking 2nd child to display the image.
                    //Sending up pipe for sending data to stdout of parent from child.
                    int fd3[2];
                    if(pipe(fd3) == -1){
                        perror("pipe");
                        free(msg);
                        exit(1);
                    }
                  

                    n3 = fork();
                    if(n3 == 0){ //Child process.
                        //Reading end.
                        close(fd3[0]);
                        //Map the stdout to write end.
                        if (dup2(fd3[1],STDOUT_FILENO) == -1) {
                                perror("dup2 failed");
                                exit(1);
                        }
                        close(fd3[1]);
                        
                        //replace the filename.
                        execlp("catimg", "catimg", "-w80", fifo_path, (char *)NULL);
                    }
                    else if(n3 <0){
                        perror("fork");
                        free(msg);
                        exit(1);
                    }
                    else{
                        close(fd3[1]);
                        // wait(NULL);
                        ssize_t readimg;
                        char imgtmp[MAX_IMG_LEN] = {0}; 
                        printf("%s sent an emote:\n", write_buf);
                        while((readimg =read(fd3[0], imgtmp, MAX_IMG_LEN)) != 0){
                            if(readimg == -1){
                                if(errno == EINTR){
                                    continue;
                                }
                                free(msg);
                                perror("read");
                                exit(1);
                            }
                            ssize_t writeimg = write(STDOUT_FILENO,imgtmp,MAX_IMG_LEN);
                            if(writeimg == -1 && errno != EINTR){
                                perror("write");
                                free(msg);
                                exit(1);
                            }
                            
                            unlink(fifo_path);
                            
                        }

                    }                      
                }
                free(msg);
                if (sigint_received) break;
            }
            
            
        }
        if (sigint_received) break;
        

    }
    
    close(s.sock_fd);
    exit(exit_status);
}

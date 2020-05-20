#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>     /* inet_ntoa */
#include <netdb.h>         /* gethostname */
#include <netinet/in.h>    /* struct sockaddr_in */

#include "socket.h"

void setup_server_socket(struct listen_sock *s) {
    if(!(s->addr = malloc(sizeof(struct sockaddr_in)))) {
        perror("malloc");
        exit(1);
    }
    // Allow sockets across machines.
    s->addr->sin_family = AF_INET;
    // The port the process will listen on.
    s->addr->sin_port = htons(SERVER_PORT);
    // Clear this field; sin_zero is used for padding for the struct.
    memset(&(s->addr->sin_zero), 0, 8);
    // Listen on all network interfaces.
    s->addr->sin_addr.s_addr = INADDR_ANY;

    s->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock_fd < 0) {
        perror("server socket");
        exit(1);
    }

    // Make sure we can reuse the port immediately after the
    // server terminates. Avoids the "address in use" error
    int on = 1;
    int status = setsockopt(s->sock_fd, SOL_SOCKET, SO_REUSEADDR,
        (const char *) &on, sizeof(on));
    if (status < 0) {
        perror("setsockopt");
        exit(1);
    }

    // Bind the selected port to the socket.
    if (bind(s->sock_fd, (struct sockaddr *)s->addr, sizeof(*(s->addr))) < 0) {
        perror("server: bind");
        close(s->sock_fd);
        exit(1);
    }

    // Announce willingness to accept connections on this socket.
    if (listen(s->sock_fd, MAX_BACKLOG) < 0) {
        perror("server: listen");
        close(s->sock_fd);
        exit(1);
    }
}

/* Insert Tutorial 10 helper functions here. */


/*
 * Search the first n characters of buf for a network newline (\r\n).
 * Return one plus the index of the '\n' of the first network newline,
 * or -1 if no network newline is found.
 * Definitely do not use strchr or other string functions to search here. (Why not?)
 */
int find_network_newline(const char *buf, int inbuf) {
    for(int i = 0; i< inbuf - 1; i++){
        if(buf[i] == '\r' && buf[i+1]== '\n'){
            return i +  2;
        }
    }
    return -1;
}


/* 
 * Reads from socket sock_fd into buffer *buf containing *inbuf bytes
 * of data. Updates *inbuf after reading from socket.
 *
 * Return -1 if read error or maximum message size is exceeded.
 * Return 0 upon receipt of CRLF-terminated message.
 * Return 1 if socket has been closed.
 * Return 2 upon receipt of partial (non-CRLF-terminated) message.
 */
int read_from_socket(int sock_fd, char *buf, int *inbuf) {
   
    char *tmp_buf = &buf[0];
    int result = read(sock_fd, tmp_buf + (*inbuf), BUF_SIZE- (*inbuf));
    // Might wanna read in a loop.
    if(result == -1 || (*inbuf+result)>BUF_SIZE){
        perror("read");
        close(sock_fd);
        return -1;
    }

    else if(result == 0){
        close(sock_fd);
        return 1;
    }
    else{
        // (*inbuf) += result;
        // int termi = find_network_newline(tmp_buf, *inbuf);
        int termi = find_network_newline(buf+(*inbuf), result);
        (*inbuf) += result;
        if(termi == -1){
            return 2;
        }
        else{
            // Check if i wanna close socket here.
            return 0;
        }
    }
    
}


/*
 * Search src for a network newline, and copy complete message
 * into a newly-allocated NULL-terminated string **dst.
 * Remove the complete message from the *src buffer by moving
 * the remaining content of the buffer to the front.
 *
 * Return 0 on success, 1 on error.
 */
int get_message(char **dst, char *src, int *inbuf) {
    // Implement the find_network_newline() function
    // before implementing this function.
    int index = find_network_newline(src, *inbuf);
    
    if(index==-1){
        return 1;
    }
    *dst = malloc(sizeof(char)*index);
    if(*dst == NULL){
        return 1;
    }
   memcpy(*dst, src, index-2);
   //strncpy(*dst, src, index-2);
    (*dst)[index-2] = '\0';
    memmove(src, src+index, (*inbuf)-index);
    
    (*inbuf)-= index;
    return 0;
}


/* Helper function to be completed for Tutorial 11. */

/*
 * Write a string to a socket.
 *
 * Return 0 on success.
 * Return 1 on error.
 * Return 2 on disconnect.
 * 
 * See Robert Love Linux System Programming 2e p. 37 for relevant details
 */
int write_to_socket(int sock_fd, char *buf, int len) {
    // int result = write(sock_fd, buf, len);
    // See if I wanna write a loop here and fix it. Refer to lecture 1.22.00
    char *temp_buf = &buf[0];
    ssize_t ret;
    int temp_len = len;
    while(temp_len != 0 && (ret = write(sock_fd, temp_buf, temp_len))!= 0){
        if(ret==-1){
            if(errno == EINTR){
                continue;
            }
            perror("write");
            return 1;
        }
        temp_len -= ret;
        temp_buf += ret;

    }

    if(ret == -1){
        perror("write");
        return 1;
    }
    else if(ret == 0){
        // Socket closed.
        return 2;
    }
    else if(temp_len == 0){
        // Successful write.
        return 0;
    }
    else{
        perror("write");
        return 1;
    }
}

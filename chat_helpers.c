#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "socket.h"
#include "chat_helpers.h"
#include <ctype.h>



//Extra  Helper Functions only for this file: 


// Returns 0 if the username is  invalid and 1 if it is valid.
// Only checks for space and if it is equal to SERVER and length.
int validate_username_chelper(char *name){
    int is_valid_name = 1;
    
    // Case 1: Check for white space.
    int name_len = strlen(name);
    int space_j;
    for(space_j = 0; space_j < name_len-1; space_j++){
        if(isspace(name[space_j]) != 0){
            is_valid_name = 0;
            break;
        }
    }
    // Case 2: Check if name is equal to SERVER.
    if(strncmp(name, "SERVER", name_len + 1)==0){
        is_valid_name = 0;
    }
    // Case 3: Check if length is more.
    else if(strlen(name) > MAX_NAME){  //Includes the protocol code.
        is_valid_name = 0;
    }
    return is_valid_name;
}





/* 
 * Send a string to a client.
 * 
 * Input buffer must contain a NULL-terminated string. The NULL
 * terminator is replaced with a network-newline (CRLF) before
 * being sent to the client.
 * 
 * On success, return 0.
 * On error, return 1.
 * On client disconnect, return 2.
 */
int write_buf_to_client(struct client_sock *c, char *buf, int len) {
        // Check for side cases
        // int check = 0;
        // for(int i = 0; i < len; i++){
        //     if(buf[i]=='\n'){
        //         buf[i] = '\r';
        //         buf[i+1] = '\n';
        //         check = 1;
        //     }
        // }
        // if(check == 0){
        //     perror("Invalid Buffer");
        //     exit(1);
        // }
        buf[len] = '\r';
        buf[len+1] = '\n';
    return write_to_socket(c->sock_fd, buf, len+2);
}


/* 
 * Remove client from list. Return 0 on success, 1 on failure.
 * Update curr pointer to the new node at the index of the removed node.
 * Update clients pointer if head node was removed.
 */
int remove_client(struct client_sock **curr, struct client_sock **clients) {
    struct client_sock *prev, *present;
    // 1st node has no previous.
    prev = NULL;
    for(present = *clients;present!=NULL; prev = present, present = present->next){
        // Check if they are equal.

        // if((present->sock_fd == (*curr)->sock_fd) && (present->state == (*curr)->state) && (strncmp(present->buf,(*curr)->buf, BUF_SIZE)==0) && (strncmp(present->username,(*curr)->username, BUF_SIZE)==0)){
        if(*curr == present){
            
            // If it is the first node.
            // Check for the case if there are two exact same clients.(that case you can remove return from here and add at end.)
            if(prev == NULL){
                
                *clients = present->next;
                *curr = present->next;

                free(present->username);
                close(present->sock_fd);
            }
            else{
               
                prev->next = present->next;
                *curr = present->next;    
                free(present->username);
                close(present->sock_fd);
            }
            // We need to deallocated the node we deleted.
            free(present);
            return 0;
        }
    }
    return 1; // Couldn't find the client in the list, or empty list
}


/* 
 * Read incoming bytes from client.
 * 
 * Return -1 if read error or maximum message size is exceeded.
 * Return 0 upon receipt of CRLF-terminated message.
 * Return 1 if client socket has been closed.
 * Return 2 upon receipt of partial (non-CRLF-terminated) message.
 */
int read_from_client(struct client_sock *curr){
    // See if I need to error check.
    return read_from_socket(curr->sock_fd, curr->buf, &(curr->inbuf));
}

/* Set a client's user name.
 * Returns 0 on success.
 * Returns 1 on either get_message() failure. or
 * if user name contains invalid character(s).
 */
int set_username(struct client_sock *curr) {
    // To be completed. Hint: Use get_message().
    char *user;
    
    int result = get_message(&user,curr->buf, &(curr->inbuf));
    if(result == 1){
        return 1;
    }
    // If user does not follow protocol.
    
    if(strncmp(user,"1\0", 1) != 0){
        return 1;
    }
    char *actual_user = user +1;
    if(actual_user[0]=='\n'){
        return 1;
    }
  

    if(validate_username_chelper(actual_user) == 0){
        return 1;
    }
   
    else{
        curr->username = malloc(sizeof(char)*(MAX_NAME+1));
        strncpy(curr->username, actual_user, MAX_NAME+1);
        // (curr->username)[MAX_NAME - 1] = '\0';
        free(user);
        return 0;
    }
}


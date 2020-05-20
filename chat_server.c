#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#include "socket.h"
#include "chat_helpers.h"


int sigint_received = 0;

void sigint_handler(int code) {
    sigint_received = 1;
}

//Helper Functions
// Returns 0 if unique user name and 1 if duplicate.
int validate_duplicate_username(struct client_sock *curr,struct client_sock **clients){
    struct client_sock *front = *clients;
    while(front != NULL && front->username != NULL){
        int check_len = strlen(curr->username);
        if((strncmp(front->username, curr->username, check_len+1) == 0)&& curr != front){
            return 1;
        }
        front = front->next;
    }
    return 0;
}
//kicks the requested user.
int kick(struct client_sock *curr,struct client_sock **clients, char *kick_user){
    struct client_sock *front = *clients; 
    struct client_sock *admin = *clients;
    if(curr == admin){
         while(front != NULL){
            int check_len = strlen(kick_user);
            if((strncmp(front->username, kick_user, check_len+1) == 0)){
                
                close(front->sock_fd);
                printf("Client %d disconnected\n", front->sock_fd);
                remove_client(&front,clients);
                return 1;  
            }
            front = front->next;
         }
    }
    return 0;
}

int validate_protocol(char *client_msg){
    if(client_msg[0] != '1' && client_msg[0] != '2' && client_msg[0] != '0'){
        return 0;
    }
    int len = strlen(client_msg); 
    int act_len = find_network_newline(client_msg, len);
    if(act_len == -1){
        return 0;
    }
    char tmp_msg[BUF_SIZE] = {0};
    strncpy(tmp_msg,client_msg+1,act_len-3);

    if(client_msg[0] == '1' ||client_msg[0]=='0'){     
        if(strlen(tmp_msg)>MAX_USER_MSG){
            return 0;
        }
        return 1;
    }
    else if(client_msg[0] == '2'){
        if(strlen(tmp_msg)>MAX_IMG_LEN){
            return 0;
        }
        return 1;
    }
    else{
        return 0;
    }
}




/*
 * Wait for and accept a new connection.
 * Return -1 if the accept call failed.
 */
int accept_connection(int fd, struct client_sock **clients) {
    struct sockaddr_in peer;
    unsigned int peer_len = sizeof(peer);
    peer.sin_family = AF_INET;

    int num_clients = 0;
    struct client_sock *curr = *clients;
    while (curr != NULL && num_clients < MAX_CONNECTIONS && curr->next != NULL) {
        curr = curr->next;
        num_clients++;
    }

    int client_fd = accept(fd, (struct sockaddr *)&peer, &peer_len);
    
    if (client_fd < 0) {
        perror("server: accept");
        close(fd);
        exit(1);
    }

    if (num_clients == MAX_CONNECTIONS) {
        close(client_fd);
        return -1;
    }

    struct client_sock *newclient = malloc(sizeof(struct client_sock));
    newclient->sock_fd = client_fd;
    newclient->inbuf = newclient->state = 0;
    newclient->username = NULL;
    newclient->next = NULL;
    memset(newclient->buf, 0, BUF_SIZE);
    if (*clients == NULL) {
        *clients = newclient;
    }
    else {
        curr->next = newclient;
    }

    return client_fd;
}

/*
 * Close all sockets, free memory, and exit with specified exit status.
 */
void clean_exit(struct listen_sock s, struct client_sock *clients, int exit_status) {
    struct client_sock *tmp;
    while (clients) {
        tmp = clients;
        close(tmp->sock_fd);
        clients = clients->next;
        free(tmp->username);
        free(tmp);
    }
    close(s.sock_fd);
    free(s.addr);
    exit(exit_status);
}

int main(void) {
    // This line causes stdout not to be buffered.
    // Don't change this! Necessary for autotesting.
    setbuf(stdout, NULL);
    
    /*
     * Turn off SIGPIPE: write() to a socket that is closed on the other
     * end will return -1 with errno set to EPIPE, instead of generating
     * a SIGPIPE signal that terminates the process.
     */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        exit(1);
    }

    // Linked list of clients
    struct client_sock *clients = NULL;
    
    struct listen_sock s;
    setup_server_socket(&s);
    
    // Set up SIGINT handler
    struct sigaction sa_sigint;
    memset (&sa_sigint, 0, sizeof (sa_sigint));
    sa_sigint.sa_handler = sigint_handler;
    sa_sigint.sa_flags = 0;
    sigemptyset(&sa_sigint.sa_mask);
    sigaction(SIGINT, &sa_sigint, NULL);
    
    int exit_status = 0;
    
    int max_fd = s.sock_fd;

    fd_set all_fds, listen_fds;
    
    FD_ZERO(&all_fds);
    FD_SET(s.sock_fd, &all_fds);

    do {
        listen_fds = all_fds;
        int nready = select(max_fd + 1, &listen_fds, NULL, NULL, NULL);
        if (sigint_received) break;
        if (nready == -1) {
            if (errno == EINTR) continue;
            perror("server: select");
            exit_status = 1;
            break;
        }

        /* 
         * If a new client is connecting, create new
         * client_sock struct and add to clients linked list.
         */
        if (FD_ISSET(s.sock_fd, &listen_fds)) {
            int client_fd = accept_connection(s.sock_fd, &clients);
            if (client_fd < 0) {
                printf("Failed to accept incoming connection.\n");
                continue;
            }
            if (client_fd > max_fd) {
                max_fd = client_fd;
            }
            FD_SET(client_fd, &all_fds);
            printf("Accepted connection\n");
        }

        if (sigint_received) break;

        /*
         * Accept incoming messages from clients,
         * and send to all other connected clients.
         */
        struct client_sock *curr = clients;
        while (curr) {
            if (!FD_ISSET(curr->sock_fd, &listen_fds)) {
                curr = curr->next;
                continue;
            }
            int client_closed = read_from_client(curr);

            
            // If error encountered when receiving data
            if (client_closed == -1) {
                perror("read");
                client_closed = 1; // Disconnect the client
            }
            
            // If received at least one complete message
            // and client is newly connected: Get username
            //If the username is invalid the client is disconnected.
          
            if (client_closed == 0 && curr->username == NULL) {
                int put_user = set_username(curr);
                if ((put_user == 1) ||(validate_duplicate_username(curr, &clients) == 1)) {
                    printf("Error processing user name from client %d.\n", curr->sock_fd);
                    // Error Message for wrong username.
                    char *error_usrname_msg = "1SERVER Username invalid or already taken.\r\n";
                    int error_msg_len = strlen(error_usrname_msg);
                    // Writing the error message to client.
                    write_to_socket(curr->sock_fd, error_usrname_msg, error_msg_len);
                    client_closed = 1; // Disconnect the client
                }
                else {
                    printf("Client %d user name is %s.\n", curr->sock_fd, curr->username);
               
                }
            }

            if(client_closed == 0 && !validate_protocol(curr->buf) && curr->username != NULL){
                client_closed =1;    
            }            
            
                
            char *msg;
            // Loop through buffer to get complete message(s)
            while (client_closed == 0 && !get_message(&msg, curr->buf, &(curr->inbuf))) {
                char write_buf[BUF_SIZE];
                write_buf[0] = '\0';
                if(strncmp(msg,"1\0", 1) == 0 || strncmp(msg,"2\0", 1) == 0){
                    int data_len;
                    int hard_check =  strlen(msg+1);
                    if(strncmp(msg,"1\0", 1) == 0){ //write message to socket.
                        
                        if(hard_check > MAX_USER_MSG){
                            client_closed = 1;
                            break;
                        }
                        printf("Echoing message from %s.\n", curr->username);
                        strncat(write_buf, "1\0", sizeof(char));
                        strncat(write_buf, curr->username, MAX_NAME);
                        strncat(write_buf, " ", MAX_NAME);
                        strncat(write_buf, msg+1, MAX_USER_MSG);
                        free(msg);
                        data_len = strlen(write_buf);
                    }
                    else{ //Emote Image.
                        if(hard_check > MAX_IMG_LEN){
                            client_closed = 1;
                            break;
                        }
                        printf("Echoing message from %s.\n", curr->username);
                        strncat(write_buf, "2\0", sizeof(char));
                        strncat(write_buf, curr->username, MAX_NAME);
                        strncat(write_buf, " ", MAX_NAME);
                        strncat(write_buf, msg+1, MAX_IMG_LEN);
                        free(msg);
                        data_len = strlen(write_buf);
                    }
                    
                    struct client_sock *dest_c = clients;
                    while (dest_c) {
                        if (dest_c != curr) {
                            int ret = write_buf_to_client(dest_c, write_buf, data_len);
                            if (ret == 0) {
                                printf("Sent message from %s (%d) to %s (%d).\n",
                                    curr->username, curr->sock_fd,
                                    dest_c->username, dest_c->sock_fd);
                            }
                            else {
                                printf("Failed to send message to user %s (%d).\n", dest_c->username, dest_c->sock_fd);
                                if (ret == 2) {
                                    printf("User %s (%d) disconnected.\n", dest_c->username, dest_c->sock_fd);
                                    assert(remove_client(&dest_c, &clients) == 0); // If this fails we have a bug
                                    continue;
                                }
                            }
                        }
                        dest_c = dest_c->next;
                    }
                }
                else if(strncmp(msg,"0\0", 1) == 0){ //kick user.
                    struct client_sock *front = clients; 
                    struct client_sock *admin = clients;
                    if(curr == admin){
                        while(front != NULL){
                            int check_len = strlen(msg+1);
                            if((strncmp(front->username, msg+1, check_len+1) == 0)){
                                FD_CLR(front->sock_fd, &all_fds);
                                close(front->sock_fd);
                                printf("Client %d disconnected\n", front->sock_fd);
                                remove_client(&front,&clients);
                                break; 
                            }          
                            front = front->next;
                        }
                    }

                }
                
            }
            if (client_closed == 1) { // Client disconnected
                // Note: Never reduces max_fd when client disconnects
                FD_CLR(curr->sock_fd, &all_fds);
                close(curr->sock_fd);
                printf("Client %d disconnected\n", curr->sock_fd);
                assert(remove_client(&curr, &clients) == 0); // If this fails we have a bug
            }
            else {
                curr = curr->next;
            }
        }
    } while(!sigint_received);
    
    clean_exit(s, clients, exit_status);
}

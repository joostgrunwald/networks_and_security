#python implementation of exercise 4b

import socket

import sys

#set file to standardout 
stdout_fileno = sys.stdout

# We specified settings
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 55313       # Port to listen on (non-privileged ports are > 1023)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    #Bind to settings and listen for connections S0 Selfoop implementation
    s.bind((HOST, PORT))
    s.listen()

    #Implementation of S0 -> S1, connection found
    #conn is the socket
    conn, addr = s.accept()
    with conn:
        
        # Mode
        # False means we look for a command + delimiter, True means we look for data or the delimiter
        datamode = False

        # Usedcommand
        # This should always be 1 or 2, standing for echo or print
        usedcommand = 0

        # Delimiter
        delimiter = ""
        
        while True:

            #Data is incoming command, given as byte
            data = conn.recv(1024)

            #disconnect if no good input
            if not data: 
                break

            #We decode the byte input to a string
            datastring = data.decode()

            if datamode == False:
                if datastring[0:4].find("ECHO") != -1:

                    #Get the index of the CRLF index
                    CRLF_index = datastring.find("\r\n")

                    if (CRLF_index == -1):
                        conn.send(bytes("ERROR: CRLF token not found.\n", 'utf-8'))
                    else:
                        #Get the delimiter part
                        delimiter = datastring[5:CRLF_index] #index - 1????

                        #Set datamode to true
                        datamode = True
                        usedcommand = 1


                elif datastring[0:5].find("PRINT") != -1:

                    #Get the index of the CRLF index
                    CRLF_index = datastring.find("\r\n")

                    if (CRLF_index == -1):
                        conn.send(bytes("ERROR: CRLF token not found.\n", 'utf-8'))
                    else:
                        #Get the delimiter part
                        delimiter = datastring[6:CRLF_index] #index - 1????

                        #Set datamode to true
                        datamode = True
                        usedcommand = 2

                else:
                    conn.send(bytes("ERROR: ECHO or PRINT expected.\n", 'utf-8'))

                    #unneeded reset??
                    usedcommand = 0
                    datamode = False
            else:
                if usedcommand == 1:
                    if datastring.find(delimiter) != -1:
                        datamode = False
                    else:
                        conn.sendall(data)
                elif usedcommand == 2:
                    if datastring.find(delimiter) != -1:
                        datamode = False
                    else:
                        stdout_fileno.write(datastring)
                        
                #look for data and use command it
                
            """
                TODO: check command validility
                .1: if not valid, just do nothing with data DONE
                .2: if valid, save del, Echo data to client or use stdin)
                .2.1: Also save delimiter given. DONE
                .2.2: Stay in loop waiting for data until given del is put in again
            """


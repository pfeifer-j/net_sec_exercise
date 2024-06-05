import threading


def process_request(ssock_for_browser):
    # Make a connection to the real server
    sock_for_server = socket.create_connection((hostname, 443))
    newsock, fromaddr = sock.accept()
    ssock = context.wrap_socket(newsock, server_side=True)
    request = ssock_for_browser.recv(2048)
    if request:
        # Forward request to server
        ssock_for_server.sendall(request)
        # Get response from server, and forward it to browser

        response = ssock_for_server.recv(2048)
        while response:
            ssock_for_browser.sendall(response) # Forward to browser
            response = ssock_for_server.recv(2048)
    ssock_for_browser.shutdown(socket.SHUT_RDWR)
    ssock_for_browser.close()

# Accept connection from local browser and start thread to forward these to the server
while True:
    sock_for_browser, fromaddr = sock_listen.accept()
    ssock_for_browser = context_srv.wrap_socket(sock_for_browser,server_side=True)
    x = threading.Thread(target=process_request, args=(ssock_for_browser,))
    x.start()

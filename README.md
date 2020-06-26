# TCP-Server example

A remote file downloader server (and client) that reads on a tcp port, receiving links to download.
This is an example of end to end encrypted communication in Perl.
It uses RSA (4096 bits) for authentication and to exchange a secret password that is then used with AES-128.

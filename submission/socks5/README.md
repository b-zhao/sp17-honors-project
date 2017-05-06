# Welcome to SOCKS5 Proxy Server!
Download all the files and "make" it:D

**Server Usage**: Usage: ./socks5_server <proxy_port>  

Friendly reminder: try www.illinois.edu instead of facebook.com or google.com or.. those website doesn't accept the connection from my server.  

Take look of demo idea, so you would know what you can do with my server:P

**Client Usage**: TBD...(due to naughty google, i spend a whole day debug a nonexisted bug, which there is still other bug exist in client code, sorry...;3


## Demo idea
### 1. Basic connection status
use netstat -tlnp before and after running the server and prove there is a new tunnel establied by the proxy

### 2. Hide ip address
Use "checkmyip before and after connecting to the proxy, proving that ip is changed.
Prereq: Need to running proxy on VM, otherwise the ip addr is not affected.

Alter: 
use terminal to find local ip instead of checkmyip

### 3. Authentication
1. Use curl command to request a website with correct password and username and pipe the result into a html file, proving the website get the request successfully by opening it on web browser
2. Use curl cmd with wrong password, and show error msg for SOCKS_ERROR_AUTH

Alter:
1. Use Firefoxy with correct username and password to visit website, and prove it works fine.
2. Use it again with wrong password, and prove it doesn't work
### 4. Block website
Prereq: VM
#### 1. Block website
sudo /etc/hosts 
add two lines:
127.0.0.1 illinois.edu
127.0.0.1 www.illinois.edu
#### 2. Test for successfully block
#### 3. Link to server and test for bypassing firewall

## useful termianl cmd
1. curl --proxy socks5://admin:12345@localhost:1997 www.google.com --> fail authentication
1.2 curl --proxy socks5://admin:123@localhost:1997 www.google.com --> pass authentication

2. netstat -tlnp




## TODO:
1. Error handling
2. Client connect timeout
3. Use getaddrinfo to replace addrin
4. Code clean up

# Overview
pcat is a versatile command-line network utility used for debugging, file transfer, and creating arbitrary connections.

Besides creating arbitrary TCP and UDP connections, pcat has a built-in port scanning feature, allowing you to view open and closed ports on a provided host.

pcat is directly inspired by the netcat utility which fulfills a similar role. The name pcat is a portmanteau of the words "packet" and "concatenate", similarly to ncat which arises from "network" and "concatenate".

# Dependencies
Building the pcat binary requires no more dependencies than the C standard library. The build process will not work for operating systems other than *NIX based ones.
# Installation
Installation requires two steps:
### 1. Installing Build Dependencies
Install the dependencies listed in the previous section.
### 2. Installing pcat
Clone the repository, move into the newly created repository, and run the **make build** command:
```
git clone https://github.com/sewmo/pcat.git
cd pcat
make build
./pcat
```
Executable options can be listed by running the following:
```
./pcat -h
```
# Technical Overview
The executable can be provided with options that are listed via the **./pcat -h** command. TCP and UDP connections can be made to hosts by providing their IP address. Moreover, pcat can also act as a TCP server, allowing connections to be established.

The port scanning feature will list open and closed ports on a given host. Only one type of scan is implemented thus far, the TCP scan. This scan makes use of high-level system calls to determine the state of the port, meaning it isn't the fastest. In the future, I plan to add more scan types, such as UDP and SYN scans.
# Notes
The project is not yet finished.

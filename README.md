# WS + TLS + INET (RDWR)

Clients and servers can be chained together in one command line with a chain operator '--' (check usage in samples) to build any imaginable connection configurations using pipes or sockets.

The tool includes WS client, WS server, TLS client (cert and anon credentials), TLS server (cert and anon credentials), TCP client, TCP server. GnuTLS is used for TLS.


## Build

GnuTLS dev package name may be different for your distro.

```
$ sudo apt-get install libgnutls28-dev
$ make
```

Docker build (deps are baked in Dockerfile):

```
$ docker build -t ws-tls-inet .
```

## Options

### RDWR (simple data bypass loop)

-T -- create a terminal pair instead of pipe for child process


### WS

-b -- force the tool to use binary frames (text by default) 

-h host -- set Host header during handshake

-r -- reverse pipes

-s -- start in server mode

-T -- create a terminal pair instead of pipe for child process

-u uri -- set uri during handshake


### TLS

-c -- use certificate credentials (client only) 

-C certfile -- use a certificate (server only, check -K option)

-h host -- set SNI (Server Name Indication, client only)

-K keyfile -- use a private key related to a certificate file (server only, check -C option)

-n -- don't verify a server certificate, works only in conjunction with -c (client only)

-r -- reverse pipes

-s -- start in server mode

-T -- create a terminal pair instead of pipe for child process

By default (no arguments) TLS uses anon credentials, to use certificate credentials there are -c option for a client and -C and -K options for a server.


### INET

-k -- keep accepting new connections (by default accept only one, server only)

-r -- reverse pipes

-s -- start in server mode

-T -- create a terminal pair instead of pipe for child process


The last two arguments are host and port.


tls and ws tools read/write plain data from/to the left side and their specific protocol data from/to the right side of a chain. The reverse option internally swaps these directions (check examples below).

## Usage

### Client usage

Connect to public wss echo server:

```
$ PATH=$PATH:.
$ ws -h echo.websocket.org -u / -- tls -c -- inet echo.websocket.org 443

```

Why don't use regular pipe mechanism? The short answer is because there are two pipes and the connection is bidirectional. The chain can be written in pipe notation (this is not a real command):

```
$ ws -h echo.websocket.org -u / | tls -c | inet echo.websocket.org 443 | tls -c | ws -h echo.websocket.org -u /
```
inet basically splits the chain into two pipes (forward and backward directions), but left and right ws/tls are the same tools. Left ws and tls wrap stdin data in WS and TLS and pass it via inet to the remote host, the right tls and ws remove TLS and WS and output plain data to stdout.


Kraken API server. Kraken needs to set SNI (tls -h option).

```
$ PATH=$PATH:.
$ ws -h ws.kraken.com -u / -- tls -c -h ws.kraken.com -- inet ws.kraken.com 443
tls: Handshake is completed: (TLS1.2)-(ECDHE-ECDSA-SECP256R1)-(AES-128-GCM)
ws: Handshake is completed
{"connectionID":18418312588500643063,"event":"systemStatus","status":"online","version":"1.6.0"}

```

Send ping event:

```
$ PATH=$PATH:.
$ while :; do printf '{ "event" : "ping" }'; sleep 5; done  | ws -h ws.kraken.com -u / -- tls -c -h ws.kraken.com -- inet ws.kraken.com 443

```

If there is an application that can work with Kraken API you need to reverse chain (-r option for all tools) to pass data to your application, app stdin and stdout descriptors are connected to Kraken and stripped out of WS and TLS. All tools in a chain share stderr so app can log messages to stderr.

```
$ PATH=$PATH:.
$ inet -r ws.kraken.com 443 -- tls -r -c -h ws.kraken.com -- ws -r -h ws.kraken.com -u / -- app

```

### Client and server usage

Pass stdin data through a client and a server to cat then cat returns data back through the server and the client to stdout. There are 2 pipes in forward and backward directions:

```
$ PATH=$PATH:.
$ ws -h test -u / -- ws -r -s -h test -u / -- cat
```

Add TLS client and server to the previous chain:
```
$ PATH=$PATH:.
$ ws -h test -u / -- tls -- tls -r -s -- ws -r -s -h test -u / -- cat
```

TLS client and server with certificate credentials (since cert.pem is self-signed the client use -n option):
```
$ PATH=$PATH:.
$ ws -h test -u / -- tls -c -n -- tls -r -s -C cert.pem -K key.pem -- ws -r -s -h test -u / -- cat
```


Run a WS remote shell server (setsid is important to detach inet from a control terminal), -k option force inet to accept more than one client, for each connection bash is spawned. The chain is reversed to pass data to bash stdin/stdout:

```
$ PATH=$PATH:.
$ setsid inet -r -s -k localhost 1234 -- ws -r -s -h test -u / -- sh -c 'exec bash -i 2>&1' >/dev/null </dev/null 2>&1
```

setsid and /dev/nulled stdin/stdout/stderr basically daemonize inet. Since bash is detached from a terminal it needs to be run interactively (-i).

Connect from another terminals to WS remote shell server:
```
$ PATH=$PATH:.
$ ws -h test -u / -- inet localhost 1234
```

To run bash with own control terminal extend the previous command with -T:
```
$ PATH=$PATH:.
$ setsid inet -r -s -k localhost 1234 -- ws -r -s -h test -u / -T -- setsid sh -c 'exec bash -i 2>&1' >/dev/null </dev/null 2>&1
```

it forces ws to create pseudoterminal devices (master and slave) and to pass data via master, the slave device becomes the input/output for child process. Use another setsid to make bash a session leader to open the control terminal.


## Test and perfomance

Run test.sh:

```
$ ./test.sh 
ReadWrite   1b: PASS
ReadWrite   5b: PASS
ReadWrite  10b: PASS
ReadWrite   1K: PASS
ReadWrite   5K: PASS
ReadWrite  10K: PASS
ReadWrite   1M: PASS
ReadWrite   5M: PASS
ReadWrite  10M: PASS

```

Run tests in docker:

```
$ docker run -it ws-tls-inet
```

Run perf.sh.

CPU: Intel i7-7700i (looks like TLS uses CPU AES HW acceleration):

```
$ GB=6 ./perf.sh 
           RDWR        3.1 GB/s
        WS(txt)        1.3 GB/s
        WS(bin)        2.5 GB/s
            TLS        1.6 GB/s
    WS(txt)+TLS        1.2 GB/s
    WS(bin)+TLS        1.5 GB/s
```
In text mode WS has to check each chunk of data for UTF8 correctness. In binary mode WS is almost transparent for WS(bin)+TLS.


CPU: Core 2 Duo CPU P8700 (this CPU is ancient there is no CPU acceleration):

```
$ ./perf.sh 
           RDWR        672 MB/s
        WS(txt)        359 MB/s
        WS(bin)        510 MB/s
            TLS        127 MB/s
    WS(txt)+TLS        104 MB/s
    WS(bin)+TLS        123 MB/s
```

# node

This is an example application that uses batched murmur to spread messages in a distributed system.

This showcases the use of both drop and batched murmur for real-life applications (though it is very simple)

For simplicity all arguments are provided on the command line. 

``` shell
node 0.1.0
Configuration information for `Murmur`

USAGE:
    node [OPTIONS] --gossip-size <gossip-size> --listen <listener-addr> [peers]...

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --batch-delay <batch-delay>              Default delay before starting to spread a batch in msecs [default: 200]
        --block-size <block-size>                Size of individual blocks inside locally created batches [default: 256]
    -c, --channel-cap <channel-cap>              Channel capacity [default: 64]
        --gossip-size <gossip-size>              Expected size of the gossip set when sampling
    -l, --listen <listener-addr>                 Address to listen on for incoming connections
    -s, --sponge-threshold <sponge-threshold>    Threshold for beginning batch spread in the network [default: 8194]
    -t, --timeout <timeout>                      Timeout duration in seconds [default: 3]

ARGS:
    <peers>...    List of peers to connect to at startup, format is "ip:port-publickey"
```

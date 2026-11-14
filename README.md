# Yggdrasil Relay Chat

A library providing a very basic framework for writing p2p chat apps using the Yggdrasil network.

Notes:
* By default, only multicast is enabled, which means you need to add peers manually after initialization
* The project uses the Ed25519 public keys for communication, no virtual ipv6 is used here
* The project works completely in parallel of the traditional ipv6 traffic, but due to the nature of this project and Yggdrasil, it is not possibe to use this as a tunnel or use the same key pair for a regular Yggdrasil tunnel and this
* Although no ipv6 traffic is supported and Yggdrasil-protocol command support is very limited, the node can still relay traffic like a regular node
* The current implementation is not ideal for MUCs

An example of how to use the library is provided in [`cmd/demo`](./cmd/demo/main.go)

# How it works

Yggdrasil normally uses two different packet types, session *traffic* and *protocol*. The first one is simply the ipv6 network traffic that is relayed through the tun interface. The latter one is used to exchange other data between nodes, like `yggdrasilctl getnodeinfo`. All traffic transits through peers using their public Ed25519 key. The tun interface needing an actual IP, Yggdrasil provides a convenient system to map them to ipv6, with as litte chance of collisions as possible. For the purposes of this project, this ipv6 address is completely irrelevant since Yrc adds a completeley separate packet type.

There is no real 'session' mechanism, but a best effort is made to ensure that as little traffic as possible is wasted sending packets that won't arrive. As such, Yrc has a hello/olleh (ping/pong) mechanism. This is used between peers to ensure they can reach eachother. There are two instances where peers will periodically say hello to eachother, either they are added in the permanent list through `yrc.Transport.AddHello`, in which case, every minute, they will say hello to eachother. A peer is considered to be alive if it has sent a packet to the current node in the last two minutes. As such, a periodical hello makes sure that both of them are alive. The other case where a periodical hello is sent is whenever a message is outbound to the peer. To prevent sending the potentially large message frames, Yrc waits for the peer to be alive before attempting to send them.

Considering Yggdrasil and Ironwood have a MTU limit, which may be smaller than the messages to be sent, messages are split into fragments, as large as can be fit in the MTU. Best effort is made to ensure that these fragments all arrive to their destination. Only a limited amount of fragments are allowed to be in flight at a time to ensure proper transmission and limiting wasted packets. 'In flight' here means that no acknowledgement for the fragment has been received and it hasn't timed out yet. A fragment times out by default a minute after being sent, but whenever any other fragment of the message has been received, this timeout is greatly reduced. The peer responds with either ACK/NAKs (acknowlegements/negative acknowledgements) to indicate to the sender it has received the fragment, if it has accepted it, and if not, why. <br>
Through the ACKs, the peer also sends a session nonce for the message. If the sender notices that between two ACKs, the nonce has changed, it considers the peer to have lost all previous fragments, and thus sets them back into a 'staged' state. There can be a bit of a problem if ACKs come back with mixed nonces, ie in the case of out-of-order packets and network congestion between restarts, leading to a broken state on the sender side. This is quite unlikely, but possible, and currently it can only be recovered by cancelling the message or destroying the `Transport` and sending it back.

Messages are identified using an identifier, which holds unique information about the it, like its hash, base and compressed sizes, flags, and the size of its fragments.

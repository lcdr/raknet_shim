
A program to transparently translate RakNet 3.25 traffic to TCP and UDP.

RakNet's protocol is designed to support sending packets with one of multiple reliability modes. To achieve this, the RakNet protocol is layered on top of UDP, and implements the necessary protocol structures and behaviors for ensuring the various reliability modes.

RakNet offers the modes `Unreliable`, `UnreliableSequenced`, `Reliable`, `ReliableOrdered`, and `ReliableSequenced`. However, in practice (at least for LU specifically), only `UnreliableSequenced` and `ReliableOrdered` are widely used. Unfortunately, the structures and behaviors necessary for the other modes, the complexity required for implementing reliability comparable with TCP on top of UDP, as well as various bugs/artifacts in RakNet's implementation, make the protocol much more complex than necessary.

RakNet's protocol also rolls its own custom combination of cryptography techniques for encryption. RakNet 3.25 is so niche that it's very unlikely that the protocol has been properly audited for cryptographic correctness, and along with the fact that the protocol is now over 10 years old (version 3.25 is from 2008), it can't be reliably said to be secure.

Further issues arise if RakNet is used in a closed-source context (as in LU). In this situation the version of RakNet used can't be updated, even if it turns out there are bugs in its implementation. This is especially problematic when the potential security vulnerabilities mentioned above are taken into account.

To address these issues, this program replaces the RakNet 3.25 protocol with a new protocol, designed to add as little additional complexity as possible. Support for the reliability modes `Reliable` and `ReliableSequenced` are dropped, with `Reliable` converted to `ReliableOrdered`. Instead of basing the protocol on UDP for all reliability modes, UDP is used as a base for `Unreliable` and `UnreliableSequenced` packets, and TCP is used for `ReliableOrdered` packets. This means that the underlying protocols' mechanisms can be fully utilized and the resulting protocol is kept extremely simple.

For encryption, the TCP connection can be configured to use TLS. As TLS needs a reliable base protocol, and LU only uses unreliable packets for player position updates and not for confidential data, the choice was made not to support encrypted UDP.

As the LU client is closed-source, its use of the RakNet protocol cannot be replaced directly, and the translation into TCP/UDP needs to be transparent to the client. To accomplish this, this program hosts a RakNet 3.25 server which the client connects to. Traffic is translated on the fly and relayed to a server using the new protocol. LU Redirect packets are intercepted and new relays are spun up to facilitate dynamic connections to multiple servers.

More information about the new protocol can be found in the documentation for the TcpUdp connection implementation, and info about the translation and interception process can be found in the `Bridge` documentation.

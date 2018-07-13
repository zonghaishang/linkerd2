+++
title = "Proxy fundamentals"
docpage = true
[menu.docs]
  parent = "docs"
+++

As Linkerd's proxy layer is configured automatically by the control plane,
detailed knowledge of the proxy's internals is not necessary to use and
operate it. However, a basic understanding of the high-level level principles
behind the proxy can be valuable for avoiding some pitfalls.

## Protocol Detection

The Linkerd proxy is *protocol-aware* --- when possible, it proxies traffic
at the level of application layer protocols (HTTP/1, HTTP/2, and gRPC), rather
than forwarding raw TCP traffic at the transport layer. This protocol awareness
unlocks functionality such as intelligent load balancing, protocol-level
telemetry, and routing.

There are essentially two ways for a proxy to be made protocol-aware: either it
can be configured with some prior knowledge describing what protocols to expect
from what traffic (the approach used by Linkerd 1), or it can detect the protocol
of incoming connections as they are accepted. Since Linkerd 2 is designed to
require as little as possible configuration by the user, it automatically detects
protocols. The proxy does this by peeking at the data received on an incoming
connection until it finds a pattern of bytes that uniquely identifies a particular
protocol. If no protocol was identified after peeking up to a set number of bytes,
the connection is treated as raw TCP traffic.

### What This Means

...

## Request Routing


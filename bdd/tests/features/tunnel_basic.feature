@serial
@tunnel_basic
Feature: Full-tunnel VPN between strawc and straw
  As an operator
  I want strawc to establish a CONNECT-IP tunnel to a straw proxy, apply
  the assigned address and advertised routes to its kernel, and carry
  real ICMP and TCP traffic to a network behind the proxy — and to undo
  every kernel change again on shutdown.

  Topology: client ─veth─ proxy ─veth─ origin. The proxy NATs tunnel
  traffic out toward the origin, which serves a file over HTTP.

  Scenario: Bring up the topology
    Given a clean test environment
    When I create namespace "client"
    And I create namespace "proxy"
    And I create namespace "origin"
    And I connect namespace "client" interface "veth0" to namespace "proxy" interface "veth0"
    And I connect namespace "proxy" interface "veth1" to namespace "origin" interface "veth0"
    And I assign address "172.31.0.2/24" to interface "veth0" in namespace "client"
    And I assign address "172.31.0.1/24" to interface "veth0" in namespace "proxy"
    And I assign address "10.99.0.1/24" to interface "veth1" in namespace "proxy"
    And I assign address "10.99.0.2/24" to interface "veth0" in namespace "origin"
    And I serve a 1 MiB file over HTTP in namespace "origin" on "10.99.0.2:8080"
    And I start straw in namespace "proxy" with args "--listen 0.0.0.0:4433 --tun --nat-interface veth1"
    And I start strawc in namespace "client" with args "--server-addr 172.31.0.1:4433 --insecure"
    Then interface "strawc0" in namespace "client" should eventually exist

  Scenario: The proxy's assignment and routes land in the client kernel
    Then interface "strawc0" in namespace "client" should eventually have address "10.100.0.2/32"
    # A full-tunnel advertisement is installed as two halves, never as a
    # default route, so the original default survives underneath.
    And route "0.0.0.0/1" via interface "strawc0" should eventually exist in namespace "client"
    And route "128.0.0.0/1" via interface "strawc0" should eventually exist in namespace "client"
    # The proxy itself is pinned to the pre-tunnel path, or QUIC would
    # route into its own tunnel.
    And route "172.31.0.1" via interface "veth0" should eventually exist in namespace "client"

  Scenario: ICMP through the tunnel
    Then ping from "client" to "10.100.0.1" should eventually succeed
    And ping from "client" to "10.99.0.2" should succeed

  Scenario: TCP through the tunnel
    Then downloading "http://10.99.0.2:8080/payload" from namespace "client" should match the file served by "origin"

  Scenario: Shutting down strawc removes what it installed
    When I stop strawc in namespace "client"
    Then interface "strawc0" in namespace "client" should eventually be gone
    And route "0.0.0.0/1" should not exist in namespace "client"
    And route "128.0.0.0/1" should not exist in namespace "client"
    And route "172.31.0.1" should not exist in namespace "client"
    And ping from "client" to "10.99.0.2" should fail

  Scenario: Teardown topology
    # Separate scenario so cleanup still runs when a step above fails
    # (a failed step skips the rest of its own scenario only).
    When I stop strawc in namespace "client"
    And I stop straw in namespace "proxy"
    And I stop python3 in namespace "origin"
    And I delete namespace "client"
    And I delete namespace "proxy"
    And I delete namespace "origin"
    Then the test environment should be clean

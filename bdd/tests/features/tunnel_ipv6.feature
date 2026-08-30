@serial
@tunnel_ipv6
Feature: Dual-stack tunnel with an IPv6 address pool
  As an operator
  I want a proxy started with --ipv6-pool to give its TUN device the v6
  gateway address (which the tun crate cannot do), assign the client a v6
  address, and carry IPv6 traffic to a network behind the proxy.

  Scenario: Bring up the topology
    Given a clean test environment
    When I create namespace "client"
    And I create namespace "proxy"
    And I create namespace "origin"
    And I connect namespace "client" interface "veth0" to namespace "proxy" interface "veth0"
    And I connect namespace "proxy" interface "veth1" to namespace "origin" interface "veth0"
    And I assign address "172.31.1.2/24" to interface "veth0" in namespace "client"
    And I assign address "172.31.1.1/24" to interface "veth0" in namespace "proxy"
    And I assign address "10.98.0.1/24" to interface "veth1" in namespace "proxy"
    And I assign address "10.98.0.2/24" to interface "veth0" in namespace "origin"
    And I assign address "fd00:98::1/64" to interface "veth1" in namespace "proxy"
    And I assign address "fd00:98::2/64" to interface "veth0" in namespace "origin"
    And I start straw in namespace "proxy" with args "--listen 0.0.0.0:4433 --tun --nat-interface veth1 --ipv6-pool fd00:6d61:7371::/64"
    And I start strawc in namespace "client" with args "--server-addr 172.31.1.1:4433 --insecure"
    Then interface "strawc0" in namespace "client" should eventually exist

  Scenario: Both families are assigned and routed
    Then interface "straw0" in namespace "proxy" should eventually have address "fd00:6d61:7371::1/64"
    And interface "strawc0" in namespace "client" should eventually have address "10.100.0.2/32"
    And interface "strawc0" in namespace "client" should eventually have address "fd00:6d61:7371::2/128"
    And route "::/1" via interface "strawc0" should eventually exist in namespace "client"
    And route "8000::/1" via interface "strawc0" should eventually exist in namespace "client"

  Scenario: IPv6 through the tunnel
    Then ping from "client" to "fd00:6d61:7371::1" should eventually succeed
    # Neighbour discovery on the freshly addressed proxy–origin link takes
    # about a second on first contact, which IPv4 (ARP on an already
    # exercised link) never shows; hence "eventually".
    And ping from "client" to "fd00:98::2" should eventually succeed
    And ping from "client" to "10.98.0.2" should succeed

  Scenario: Teardown topology
    When I stop strawc in namespace "client"
    And I stop straw in namespace "proxy"
    And I delete namespace "client"
    And I delete namespace "proxy"
    And I delete namespace "origin"
    Then the test environment should be clean

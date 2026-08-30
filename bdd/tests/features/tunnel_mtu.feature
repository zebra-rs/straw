@serial
@tunnel_mtu
Feature: Tunnel MTU follows the QUIC path MTU
  As an operator
  I want the tunnel MTU to track what a QUIC DATAGRAM can actually carry,
  so that full-size packets are neither blackholed early in a connection
  (when path-MTU discovery has not ramped) nor dropped silently later.

  Scenario: Bring up the topology
    Given a clean test environment
    When I create namespace "client"
    And I create namespace "proxy"
    And I create namespace "origin"
    And I connect namespace "client" interface "veth0" to namespace "proxy" interface "veth0"
    And I connect namespace "proxy" interface "veth1" to namespace "origin" interface "veth0"
    And I assign address "172.31.2.2/24" to interface "veth0" in namespace "client"
    And I assign address "172.31.2.1/24" to interface "veth0" in namespace "proxy"
    And I assign address "10.97.0.1/24" to interface "veth1" in namespace "proxy"
    And I assign address "10.97.0.2/24" to interface "veth0" in namespace "origin"
    And I serve a 4 MiB file over HTTP in namespace "origin" on "10.97.0.2:8080"
    And I start straw in namespace "proxy" with args "--listen 0.0.0.0:4433 --tun --nat-interface veth1"
    And I start strawc in namespace "client" with args "--server-addr 172.31.2.1:4433 --insecure"
    Then interface "strawc0" in namespace "client" should eventually exist

  Scenario: Both ends converge on the path MTU
    # The proxy samples a low capacity at session setup and refreshes it
    # as discovery ramps; the client widens its device the same way.
    Then the straw log in namespace "proxy" should eventually contain "tunnel MTU updated"
    And the strawc log in namespace "client" should eventually contain "tunnel MTU raised"

  Scenario: A packet filling the proxy's TUN device round-trips
    # straw0 carries 1400 by default. This is the regression test for a
    # tunnel MTU frozen at the initial estimate, and for a read buffer
    # that truncated once the device MTU was raised.
    Then ping from "proxy" to "10.100.0.2" should eventually succeed
    And a 1400 byte unfragmentable ping from "proxy" to "10.100.0.2" should succeed

  Scenario: Larger than the device is refused by PMTUD, not blackholed
    Then a 1500 byte unfragmentable ping from "proxy" to "10.100.0.2" should be refused as too long

  Scenario: Bulk TCP after MTU tracking
    Then downloading "http://10.97.0.2:8080/payload" from namespace "client" should match the file served by "origin"

  Scenario: Teardown topology
    When I stop strawc in namespace "client"
    And I stop straw in namespace "proxy"
    And I stop python3 in namespace "origin"
    And I delete namespace "client"
    And I delete namespace "proxy"
    And I delete namespace "origin"
    Then the test environment should be clean

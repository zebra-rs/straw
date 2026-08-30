@serial
@tunnel_hairpin
Feature: Hairpin forwarding without a TUN device
  As a developer
  I want a proxy started without --tun to still forward packets between
  tunnel clients (and back to the sender), so the data plane can be
  exercised with no privileges beyond the QUIC socket.

  Scenario: Bring up the topology
    Given a clean test environment
    When I create namespace "client"
    And I create namespace "proxy"
    And I connect namespace "client" interface "veth0" to namespace "proxy" interface "veth0"
    And I assign address "172.31.3.2/24" to interface "veth0" in namespace "client"
    And I assign address "172.31.3.1/24" to interface "veth0" in namespace "proxy"
    And I start straw in namespace "proxy" with args "--listen 0.0.0.0:4433"

  Scenario: A client's echo request hairpins back to itself
    Then test_client in namespace "client" via proxy "172.31.3.1:4433" should ping "self" successfully

  Scenario: Teardown topology
    When I stop straw in namespace "proxy"
    And I delete namespace "client"
    And I delete namespace "proxy"
    Then the test environment should be clean

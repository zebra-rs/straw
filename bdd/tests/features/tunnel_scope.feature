@serial
@tunnel_scope
Feature: Flow-scoped tunnels ({target} and {ipproto})
  As an operator
  I want a client that requests a tunnel scoped to a target (RFC 9484 §4.6,
  §8.3) to be advertised only that route, to reach only inside it, and to have an unresolvable hostname target
  refused before the tunnel opens.

  The proxy serves the client pool plus one split route, without a TUN
  device, so destinations hairpin or are rejected by policy before routing.
  A prefix target is advertised directly (§4.6 access control is optional),
  so scoping to the pool /24 keeps the client's own address in scope while
  the split route falls outside it.

  Scenario: Bring up the topology
    Given a clean test environment
    When I create namespace "client"
    And I create namespace "proxy"
    And I connect namespace "client" interface "veth0" to namespace "proxy" interface "veth0"
    And I assign address "172.31.5.2/24" to interface "veth0" in namespace "client"
    And I assign address "172.31.5.1/24" to interface "veth0" in namespace "proxy"
    And I start straw in namespace "proxy" with args "--listen 0.0.0.0:4433 --split-routes 192.168.0.0/16"

  Scenario: The advertisement is narrowed to the requested scope
    # Served routes are the pool plus 192.168.0.0/16; scoping to the pool
    # leaves exactly the pool, and the split route is gone.
    Then command "test_client --server-addr 172.31.5.1:4433 --insecure --count 1 --scope-target 10.100.0.0/24 > /tmp/tunnel_scope.out; grep 'route: 10.100.0.0 - 10.100.0.255 proto any' /tmp/tunnel_scope.out" in namespace "client" should succeed
    And command "grep -q 192.168 /tmp/tunnel_scope.out" in namespace "client" should fail

  Scenario: In-scope is reachable, served-but-out-of-scope is prohibited
    # Self-ping (own address is always in the pool) hairpins and succeeds.
    Then command "test_client --server-addr 172.31.5.1:4433 --insecure --count 2 --scope-target 10.100.0.0/24" in namespace "client" should succeed
    # 192.168.1.1 is served by the proxy but outside this tunnel's scope, so
    # the proxy answers administratively prohibited rather than forwarding.
    And command "test_client --server-addr 172.31.5.1:4433 --insecure --count 2 --scope-target 10.100.0.0/24 --target 192.168.1.1" in namespace "client" should fail
    And the straw log in namespace "proxy" should eventually contain "tunnel established"

  Scenario: A hostname target that does not resolve is refused
    # The proxy resolves the target before replying (RFC 9484 §4.1); a
    # failure is a 502 rather than an accepted-but-dead tunnel.
    Then command "test_client --server-addr 172.31.5.1:4433 --insecure --count 1 --scope-target nonexistent.invalid" in namespace "client" should fail
    And command "test_client --server-addr 172.31.5.1:4433 --insecure --count 1 --scope-target nonexistent.invalid > /tmp/tunnel_scope.out 2>&1; grep 502 /tmp/tunnel_scope.out" in namespace "client" should succeed

  Scenario: Teardown topology
    When I stop straw in namespace "proxy"
    And I delete namespace "client"
    And I delete namespace "proxy"
    Then the test environment should be clean

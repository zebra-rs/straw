@serial
@tunnel_auth
Feature: Bearer-token authentication
  As an operator
  I want a proxy started with --auth-mode bearer to refuse tunnels that
  present no token or the wrong one, and accept the configured token.

  Scenario: Bring up the topology
    Given a clean test environment
    When I create namespace "client"
    And I create namespace "proxy"
    And I connect namespace "client" interface "veth0" to namespace "proxy" interface "veth0"
    And I assign address "172.31.4.2/24" to interface "veth0" in namespace "client"
    And I assign address "172.31.4.1/24" to interface "veth0" in namespace "proxy"
    And I start straw in namespace "proxy" with args "--listen 0.0.0.0:4433 --auth-mode bearer --auth-token s3cret"

  Scenario: Missing and wrong tokens are refused
    Then command "test_client --server-addr 172.31.4.1:4433 --insecure --count 1" in namespace "client" should fail
    And command "test_client --server-addr 172.31.4.1:4433 --insecure --count 1 --bearer-token wrong" in namespace "client" should fail
    And the straw log in namespace "proxy" should eventually contain "authentication failed"

  Scenario: The configured token is accepted
    Then command "test_client --server-addr 172.31.4.1:4433 --insecure --count 1 --bearer-token s3cret" in namespace "client" should succeed

  Scenario: Teardown topology
    When I stop straw in namespace "proxy"
    And I delete namespace "client"
    And I delete namespace "proxy"
    Then the test environment should be clean

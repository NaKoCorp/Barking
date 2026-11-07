//! A halted test node keeps its port, so that nothing else can take it
//! before the restart.

use std::net::{SocketAddr, UdpSocket};

use barking_node::testing::{NodeSpec, local_socket, start_node};

#[tokio::test]
async fn halted_node_keeps_its_port_until_restart() {
    let (socket, v4) = local_socket();
    let addr = SocketAddr::V4(v4);
    let node = start_node(NodeSpec::new(0, None), vec![socket], addr);
    let stopped = node.halt().await;
    // Another test's socket (a client's ephemeral port, a node's port) can
    // land on a freed port and hold it for as long as that test lasts: the
    // restart would then never get its port back.
    assert!(
        UdpSocket::bind(addr).is_err(),
        "the port was released while the node was halted"
    );
    stopped.restart().await.stop().await;
}

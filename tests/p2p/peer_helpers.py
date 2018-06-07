import asyncio
import os
from typing import List

from eth_hash.auto import keccak

from eth_utils import big_endian_to_int

from evm.chains.mainnet import MAINNET_GENESIS_HEADER
from evm.db.backends.memory import MemoryDB

from p2p import auth
from p2p import constants
from p2p import ecies
from p2p import kademlia
from p2p.cancel_token import CancelToken
from p2p.peer import BasePeer, LESPeer, PeerPool
from p2p.server import decode_auth_message

from integration_test_helpers import FakeAsyncHeaderDB


def get_fresh_mainnet_headerdb():
    headerdb = FakeAsyncHeaderDB(MemoryDB())
    headerdb.persist_header(MAINNET_GENESIS_HEADER)
    return headerdb


async def get_directly_linked_peers_without_handshake(
        peer1_class=LESPeer, peer1_headerdb=None,
        peer2_class=LESPeer, peer2_headerdb=None):
    """See get_directly_linked_peers().

    Neither the P2P handshake nor the sub-protocol handshake will be performed here.
    """
    cancel_token = CancelToken("get_directly_linked_peers_without_handshake")
    if peer1_headerdb is None:
        peer1_headerdb = get_fresh_mainnet_headerdb()
    if peer2_headerdb is None:
        peer2_headerdb = get_fresh_mainnet_headerdb()
    peer1_private_key = ecies.generate_privkey()
    peer2_private_key = ecies.generate_privkey()
    peer1_remote = kademlia.Node(
        peer2_private_key.public_key, kademlia.Address('0.0.0.0', 0, 0))
    peer2_remote = kademlia.Node(
        peer1_private_key.public_key, kademlia.Address('0.0.0.0', 0, 0))
    initiator = auth.HandshakeInitiator(peer1_remote, peer1_private_key, cancel_token)
    peer2_reader = asyncio.StreamReader()
    peer1_reader = asyncio.StreamReader()
    # Link the peer1's writer to the peer2's reader, and the peer2's writer to the
    # peer1's reader.
    peer2_writer = type(
        "mock-streamwriter",
        (object,),
        {"write": peer1_reader.feed_data,
         "drain": mock_drain,
         "close": lambda: None}
    )
    peer1_writer = type(
        "mock-streamwriter",
        (object,),
        {"write": peer2_reader.feed_data,
         "drain": mock_drain,
         "close": lambda: None}
    )

    peer1, peer2 = None, None
    handshake_finished = asyncio.Event()

    async def do_handshake():
        nonlocal peer1
        aes_secret, mac_secret, egress_mac, ingress_mac = await auth._handshake(
            initiator, peer1_reader, peer1_writer, cancel_token)

        peer1 = peer1_class(
            remote=peer1_remote, privkey=peer1_private_key, reader=peer1_reader,
            writer=peer1_writer, aes_secret=aes_secret, mac_secret=mac_secret,
            egress_mac=egress_mac, ingress_mac=ingress_mac, headerdb=peer1_headerdb,
            network_id=1)

        handshake_finished.set()

    asyncio.ensure_future(do_handshake())

    responder = auth.HandshakeResponder(peer2_remote, peer2_private_key, cancel_token)
    auth_msg_size = await peer2_reader.read(2)
    auth_msg = await peer2_reader.read(big_endian_to_int(auth_msg_size))

    initiator_ephemeral_pubkey, initiator_nonce, _ = decode_auth_message(
        auth_msg, auth_msg_size, peer2_private_key)
    responder_nonce = keccak(os.urandom(constants.HASH_LEN))
    auth_ack_msg = responder.create_auth_ack_message(responder_nonce)
    auth_ack_ciphertext = responder.encrypt_auth_ack_message(auth_ack_msg)
    peer2_writer.write(auth_ack_ciphertext)

    await handshake_finished.wait()

    aes_secret, mac_secret, egress_mac, ingress_mac = responder.derive_secrets(
        initiator_nonce, responder_nonce, initiator_ephemeral_pubkey,
        auth_msg_size + auth_msg, auth_ack_ciphertext)
    assert egress_mac.digest() == peer1.ingress_mac.digest()
    assert ingress_mac.digest() == peer1.egress_mac.digest()
    peer2 = peer2_class(
        remote=peer2_remote, privkey=peer2_private_key, reader=peer2_reader,
        writer=peer2_writer, aes_secret=aes_secret, mac_secret=mac_secret,
        egress_mac=egress_mac, ingress_mac=ingress_mac, headerdb=peer2_headerdb,
        network_id=1)

    return peer1, peer2


async def get_directly_linked_peers(
        request, event_loop,
        peer1_class=LESPeer, peer1_headerdb=None,
        peer2_class=LESPeer, peer2_headerdb=None):
    """Create two peers with their readers/writers connected directly.

    The first peer's reader will write directly to the second's writer, and vice-versa.
    """
    peer1, peer2 = await get_directly_linked_peers_without_handshake(
        peer1_class, peer1_headerdb,
        peer2_class, peer2_headerdb)
    # Perform the base protocol (P2P) handshake.
    await asyncio.gather(peer1.do_p2p_handshake(), peer2.do_p2p_handshake())

    assert peer1.sub_proto.name == peer2.sub_proto.name
    assert peer1.sub_proto.version == peer2.sub_proto.version
    assert peer1.sub_proto.cmd_id_offset == peer2.sub_proto.cmd_id_offset

    # Perform the handshake for the enabled sub-protocol.
    await asyncio.gather(peer1.do_sub_proto_handshake(), peer2.do_sub_proto_handshake())

    asyncio.ensure_future(peer1.run())
    asyncio.ensure_future(peer2.run())

    def finalizer():
        event_loop.run_until_complete(asyncio.gather(peer1.cancel(), peer2.cancel()))
    request.addfinalizer(finalizer)

    return peer1, peer2


async def mock_drain():
    pass


class MockPeerPoolWithConnectedPeers(PeerPool):

    def __init__(self, peers: List[BasePeer]) -> None:
        super().__init__(
            peer_class=None, headerdb=None, network_id=None, privkey=None, discovery=None)
        for peer in peers:
            self.connected_nodes[peer.remote] = peer

    async def _run(self) -> None:
        raise NotImplementedError("This is a mock PeerPool implementation, you must not _run() it")

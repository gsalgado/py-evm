import asyncio
import logging
import os
import random
import struct
from typing import Tuple

import sha3

import rlp
from rlp import sedes

from eth_keys import (
    datatypes,
    keys,
)

from eth_hash.auto import keccak

from eth_utils import big_endian_to_int

from p2p import ecies
from p2p import kademlia
from p2p.cancel_token import CancelToken, wait_with_token
from p2p.constants import REPLY_TIMEOUT
from p2p.utils import (
    sxor,
)

from .constants import (
    ENCRYPT_OVERHEAD_LENGTH,
    HASH_LEN,
    SUPPORTED_RLPX_VERSION,
)


async def handshake(
        remote: kademlia.Node,
        privkey: datatypes.PrivateKey,
        token: CancelToken) -> Tuple[bytes, bytes, sha3.keccak_256, sha3.keccak_256, asyncio.StreamReader, asyncio.StreamWriter]:  # noqa: E501
    """
    Perform the auth handshake with given remote.

    Returns the established secrets and the StreamReader/StreamWriter pair already connected to
    the remote.
    """
    initiator = HandshakeInitiator(remote, privkey, token)
    reader, writer = await initiator.connect()
    aes_secret, mac_secret, egress_mac, ingress_mac = await _handshake(
        initiator, reader, writer, token)
    return aes_secret, mac_secret, egress_mac, ingress_mac, reader, writer


async def _handshake(initiator: 'HandshakeInitiator', reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter, token: CancelToken,
                     ) -> Tuple[bytes, bytes, sha3.keccak_256, sha3.keccak_256]:
    """See the handshake() function above.

    This code was factored out into this helper so that we can create Peers with directly
    connected readers/writers for our tests.
    """
    initiator_nonce = keccak(os.urandom(HASH_LEN))
    auth_msg = initiator.create_auth_message(initiator_nonce)
    auth_init = initiator.encrypt_auth_message(auth_msg)
    writer.write(auth_init)
    await writer.drain()

    # The first two bytes of the auth-ack msg contain its size.
    ack_size = await wait_with_token(
        reader.read(2),
        token=token,
        timeout=REPLY_TIMEOUT)
    auth_ack = await wait_with_token(
        reader.read(big_endian_to_int(ack_size)),
        token=token,
        timeout=REPLY_TIMEOUT)

    ephemeral_pubkey, responder_nonce = initiator.decode_auth_ack_message(
        auth_ack, shared_mac_data=ack_size)
    aes_secret, mac_secret, egress_mac, ingress_mac = initiator.derive_secrets(
        initiator_nonce,
        responder_nonce,
        ephemeral_pubkey,
        auth_init,
        ack_size + auth_ack
    )

    return aes_secret, mac_secret, egress_mac, ingress_mac


class HandshakeBase:
    logger = logging.getLogger("p2p.peer.Handshake")
    _is_initiator = False

    def __init__(
            self, remote: kademlia.Node, privkey: datatypes.PrivateKey,
            token: CancelToken) -> None:
        self.remote = remote
        self.privkey = privkey
        self.ephemeral_privkey = ecies.generate_privkey()
        self.cancel_token = token

    @property
    def ephemeral_pubkey(self) -> datatypes.PublicKey:
        return self.ephemeral_privkey.public_key

    @property
    def pubkey(self) -> datatypes.PublicKey:
        return self.privkey.public_key

    async def connect(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await wait_with_token(
            asyncio.open_connection(host=self.remote.address.ip, port=self.remote.address.tcp_port),
            token=self.cancel_token,
            timeout=REPLY_TIMEOUT)

    def derive_secrets(self,
                       initiator_nonce: bytes,
                       responder_nonce: bytes,
                       remote_ephemeral_pubkey: datatypes.PublicKey,
                       auth_init_ciphertext: bytes,
                       auth_ack_ciphertext: bytes
                       ) -> Tuple[bytes, bytes, sha3.keccak_256, sha3.keccak_256]:
        """Derive base secrets from ephemeral key agreement."""
        # ecdhe-shared-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        ecdhe_shared_secret = ecies.ecdh_agree(
            self.ephemeral_privkey, remote_ephemeral_pubkey)

        # shared-secret = keccak(ecdhe-shared-secret || keccak(nonce || initiator-nonce))
        shared_secret = keccak(
            ecdhe_shared_secret + keccak(responder_nonce + initiator_nonce))

        # aes-secret = keccak(ecdhe-shared-secret || shared-secret)
        aes_secret = keccak(ecdhe_shared_secret + shared_secret)

        # mac-secret = keccak(ecdhe-shared-secret || aes-secret)
        mac_secret = keccak(ecdhe_shared_secret + aes_secret)

        # setup keccak instances for the MACs
        # egress-mac = sha3.keccak_256(mac-secret ^ recipient-nonce || auth-sent-init)
        mac1 = sha3.keccak_256(
            sxor(mac_secret, responder_nonce) + auth_init_ciphertext
        )
        # ingress-mac = sha3.keccak_256(mac-secret ^ initiator-nonce || auth-recvd-ack)
        mac2 = sha3.keccak_256(
            sxor(mac_secret, initiator_nonce) + auth_ack_ciphertext
        )

        if self._is_initiator:
            egress_mac, ingress_mac = mac1, mac2
        else:
            egress_mac, ingress_mac = mac2, mac1

        return aes_secret, mac_secret, egress_mac, ingress_mac


class HandshakeInitiator(HandshakeBase):
    _is_initiator = True

    def encrypt_auth_message(self, auth_message: bytes) -> bytes:
        return encrypt_eip8_msg(auth_message, self.remote.pubkey)

    def create_auth_message(self, nonce: bytes) -> bytes:
        ecdh_shared_secret = ecies.ecdh_agree(self.privkey, self.remote.pubkey)
        secret_xor_nonce = sxor(ecdh_shared_secret, nonce)
        # S(ephemeral-privk, ecdh-shared-secret ^ nonce)
        S = self.ephemeral_privkey.sign_msg_hash(secret_xor_nonce).to_bytes()
        data = rlp.encode(
            [S, self.pubkey.to_bytes(), nonce, SUPPORTED_RLPX_VERSION], sedes=eip8_auth_sedes)
        return data + os.urandom(random.randint(100, 250))

    def decode_auth_ack_message(
            self, auth_ack: bytes, shared_mac_data: bytes) -> Tuple[datatypes.PublicKey, bytes]:
        """Decrypts and decodes a EIP-8 auth ack message.

        Returns the remote's ephemeral pubkey, nonce and protocol version.
        """
        message = ecies.decrypt(auth_ack, self.privkey, shared_mac_data=shared_mac_data)
        values = rlp.decode(message, sedes=eip8_ack_sedes, strict=False)
        pubkey_bytes, nonce = values[:2]
        return keys.PublicKey(pubkey_bytes), nonce


class HandshakeResponder(HandshakeBase):

    def create_auth_ack_message(self, nonce: bytes) -> bytes:
        data = rlp.encode(
            (self.ephemeral_pubkey.to_bytes(), nonce, SUPPORTED_RLPX_VERSION),
            sedes=eip8_ack_sedes)
        # Pad with random amount of data. The amount needs to be at least 100 bytes to make
        # the message distinguishable from pre-EIP-8 handshakes.
        return data + os.urandom(random.randint(100, 250))

    def encrypt_auth_ack_message(self, ack_message: bytes) -> bytes:
        return encrypt_eip8_msg(ack_message, self.remote.pubkey)


eip8_ack_sedes = sedes.List(
    [
        sedes.Binary(min_length=64, max_length=64),  # ephemeral pubkey
        sedes.Binary(min_length=32, max_length=32),  # nonce
        sedes.BigEndianInt()                         # version
    ], strict=False)
eip8_auth_sedes = sedes.List(
    [
        sedes.Binary(min_length=65, max_length=65),  # sig
        sedes.Binary(min_length=64, max_length=64),  # pubkey
        sedes.Binary(min_length=32, max_length=32),  # nonce
        sedes.BigEndianInt()                         # version
    ], strict=False)


def encrypt_eip8_msg(msg: bytes, pubkey: keys.PublicKey) -> bytes:
    prefix = struct.pack('>H', len(msg) + ENCRYPT_OVERHEAD_LENGTH)
    suffix = ecies.encrypt(msg, pubkey, shared_mac_data=prefix)
    return prefix + suffix


def decode_auth_message(
        auth_msg: bytes, shared_mac_data: bytes,
        privkey: datatypes.PrivateKey) -> Tuple[datatypes.PublicKey, bytes, datatypes.PublicKey]:
    """Decrypts and decodes an EIP8 auth message.

    Returns the initiator's ephemeral pubkey, nonce, and pubkey.
    """
    message = ecies.decrypt(auth_msg, privkey, shared_mac_data=shared_mac_data)
    values = rlp.decode(message, sedes=eip8_auth_sedes, strict=False)
    signature_bytes, pubkey_bytes, initiator_nonce = values[:3]
    sig = keys.Signature(signature_bytes=signature_bytes)
    initiator_pubkey = keys.PublicKey(pubkey_bytes)

    # recover initiator ephemeral pubkey from sig
    #   S(ephemeral-privk, ecdh-shared-secret ^ nonce)
    shared_secret = ecies.ecdh_agree(privkey, initiator_pubkey)

    ephem_pubkey = sig.recover_public_key_from_msg_hash(
        sxor(shared_secret, initiator_nonce))

    return ephem_pubkey, initiator_nonce, initiator_pubkey

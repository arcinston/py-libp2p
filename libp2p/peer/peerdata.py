from collections.abc import (
    Sequence,
)
import time
from typing import (
    Any,
)

from multiaddr import (
    Multiaddr,
)

from libp2p.abc import (
    IPeerData,
)
from libp2p.crypto.keys import (
    PrivateKey,
    PublicKey,
)


class PeerData(IPeerData):
    pubkey: PublicKey | None
    privkey: PrivateKey | None
    metadata: dict[Any, Any]
    protocols: list[str]
    addrs: list[Multiaddr]
    last_identified: int
    ttl: int  # Keep ttl=0 by default for always valid

    def __init__(self) -> None:
        self.pubkey = None
        self.privkey = None
        self.metadata = {}
        self.protocols = []
        self.addrs = []
        self.last_identified = int(time.time())
        self.ttl = 0

    def get_protocols(self) -> list[str]:
        """
        :return: all protocols associated with given peer
        """
        return self.protocols

    def add_protocols(self, protocols: Sequence[str]) -> None:
        """
        :param protocols: protocols to add
        """
        self.protocols.extend(list(protocols))

    def set_protocols(self, protocols: Sequence[str]) -> None:
        """
        :param protocols: protocols to set
        """
        self.protocols = list(protocols)

    def add_addrs(self, addrs: Sequence[Multiaddr]) -> None:
        """
        :param addrs: multiaddresses to add
        """
        for addr in addrs:
            if addr not in self.addrs:
                self.addrs.append(addr)

    def get_addrs(self) -> list[Multiaddr]:
        """
        :return: all multiaddresses
        """
        return self.addrs

    def clear_addrs(self) -> None:
        """Clear all addresses."""
        self.addrs = []

    def put_metadata(self, key: str, val: Any) -> None:
        """
        :param key: key in KV pair
        :param val: val to associate with key
        """
        self.metadata[key] = val

    def get_metadata(self, key: str) -> Any:
        """
        :param key: key in KV pair
        :return: val for key
        :raise PeerDataError: key not found
        """
        if key in self.metadata:
            return self.metadata[key]
        raise PeerDataError("key not found")

    def add_pubkey(self, pubkey: PublicKey) -> None:
        """
        :param pubkey:
        """
        self.pubkey = pubkey

    def get_pubkey(self) -> PublicKey:
        """
        :return: public key of the peer
        :raise PeerDataError: if public key not found
        """
        if self.pubkey is None:
            raise PeerDataError("public key not found")
        return self.pubkey

    def add_privkey(self, privkey: PrivateKey) -> None:
        """
        :param privkey:
        """
        self.privkey = privkey

    def get_privkey(self) -> PrivateKey:
        """
        :return: private key of the peer
        :raise PeerDataError: if private key not found
        """
        if self.privkey is None:
            raise PeerDataError("private key not found")
        return self.privkey

    def update_last_identified(self) -> None:
        self.last_identified = int(time.time())

    def get_last_identified(self) -> int:
        """
        :return: last identified timestamp
        """
        return self.last_identified

    def get_ttl(self) -> int:
        """
        :return: ttl for current peer
        """
        return self.ttl

    def set_ttl(self, ttl: int) -> None:
        """
        :param ttl: ttl to set
        """
        self.ttl = ttl

    def is_expired(self) -> bool:
        """
        :return: true, if last_identified+ttl > current_time
        """
        # for ttl = 0; peer_data is always valid
        if self.ttl > 0 and self.last_identified + self.ttl < int(time.time()):
            return True
        return False


class PeerDataError(KeyError):
    """Raised when a key is not found in peer metadata."""

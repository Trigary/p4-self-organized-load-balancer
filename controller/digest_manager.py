import dataclasses
import logging
from typing import List, Dict, Callable, Any

from controller.utils import SwitchBundle


@dataclasses.dataclass(frozen=True)
class DigestParsed:
    """Semi-parsed version of a received digest"""
    switch: SwitchBundle
    name: str
    values: List[bytes]

    def __repr__(self) -> str:
        values = ['0x' + x.hex() for x in self.values]
        return f"DigestParsed(switch={self.switch}, name={self.name}, values={values})"


class DigestManager:
    """Class responsible for receiving digests and calling the correct, previously registered handler."""

    def __init__(self, switches: List[SwitchBundle]):
        self._switches: List[SwitchBundle] = switches
        self._handlers: Dict[str, Callable] = dict()
        self._digest_remaining: List[DigestParsed] = []
        self._switch_remaining: List[SwitchBundle] = []

    def register(self, name: str, handler: Callable[[DigestParsed], Any]) -> None:
        """
        Maps the specified digest to the specified digest handler.
        This function also takes care of enabling the specified digest on the switches.
        """

        for switch in self._switches:
            max_timeout_ns = 0
            max_list_size = 1
            ack_timeout_ns = 0
            success = switch.grpc.digest_enable(name, max_timeout_ns, max_list_size, ack_timeout_ns)
            if success is not True:
                print('Ignore the previous "ALREADY_EXISTS" error, the digest is being configured...')
                switch.grpc.digest_set_conf(name, max_timeout_ns, max_list_size, ack_timeout_ns)
        self._handlers[name] = handler

    def _handle_parsed(self, parsed: DigestParsed) -> Any:
        """Calls the handler of the specified digest, returning the handler's return value."""
        logger = logging.getLogger(__name__)
        handler = self._handlers[parsed.name]
        if handler is None:
            logger.warning(f'Digest received with no handler: {parsed}')
            return None
        else:
            return handler(parsed)

    def _parse_and_store(self, switch: SwitchBundle, digest_list) -> None:
        """Parses all digests received as a parameter and stores the parsed versions for later use."""
        name: str = switch.grpc.context.get_name_from_id(digest_list.digest_id)
        for data in digest_list.data:
            values: List[bytes] = []
            for member in data.struct.members:
                values.append(member.bitstring)
            self._digest_remaining.append(DigestParsed(switch, name, values))

    def handle_one_if_present(self) -> Any:
        """
        If digest(s) have been received, then this function calls the appropriate handler.
        This function does not block. All switches are checked in sequence for available digests.
        """

        if len(self._digest_remaining) > 0:
            return self._handle_parsed(self._digest_remaining.pop(0))
        if len(self._switch_remaining) == 0:
            self._switch_remaining = list(self._switches)
        while len(self._switch_remaining) > 0:
            switch = self._switch_remaining.pop(0)
            digest_list = switch.grpc.get_digest_list(timeout=0)
            if digest_list is None:
                continue
            self._parse_and_store(switch, digest_list)
            return self._handle_parsed(self._digest_remaining.pop(0))
        return None

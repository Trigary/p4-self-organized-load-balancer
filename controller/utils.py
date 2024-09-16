import dataclasses
import re
from typing import Union

import p4utils.utils.sswitch_p4runtime_API
import p4utils.utils.sswitch_thrift_API


@dataclasses.dataclass(frozen=True)
class SwitchBundle:
    """
    Holder of general, main logic-independent information about a specific switch.
    Thrift and P4Runtime API are both used because not everything is possible with the P4Runtime API,
    and the Thrift API (or at least the Python library for it that is being used) also has some limitations.
    The P4Runtime API is used whenever possible; Thrift is only used when something is not possible otherwise.
    """

    name: str
    thrift: p4utils.utils.sswitch_thrift_API.SimpleSwitchThriftAPI
    grpc: p4utils.utils.sswitch_p4runtime_API.SimpleSwitchP4RuntimeAPI

    def __repr__(self) -> str:
        return f"SwitchBundle('{self.name}')"


class MacAddress:
    BROADCAST: 'MacAddress'

    def __init__(self, value: Union[bytes, int, str]):
        if isinstance(value, bytes):
            self._raw = value.rjust(6, b'\x00')
        elif isinstance(value, int):
            self._raw = int.to_bytes(value, 6, 'big')
        elif isinstance(value, str):
            self._raw = bytes()
            if not re.match(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$', value):
                raise Exception(f'Invalid input format: {value}')
            for b in [int(x, base=16).to_bytes(1, 'big') for x in value.split(':')]:
                self._raw += b
        else:
            raise Exception(f'Invalid input: {value}')

    def __int__(self) -> int:
        return int.from_bytes(self._raw, 'big')

    def __repr__(self) -> str:
        bytes_str = self._raw.hex().upper()
        out = ''
        for i in range(0, len(bytes_str), 2):
            out += ':' + str(bytes_str)[i:i + 2]
        return out[1:]

    def __eq__(self, other) -> bool:
        return isinstance(other, MacAddress) and self._raw == other._raw

    def __hash__(self) -> int:
        return hash(self._raw)


MacAddress.BROADCAST = MacAddress('FF:FF:FF:FF:FF:FF')

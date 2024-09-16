import dataclasses
import enum
import logging
import time
from typing import List, Callable, Dict, Union, Optional, Set

from p4utils.utils.topology import NetworkGraph

from controller.digest_manager import DigestParsed, DigestManager
from controller.utils import MacAddress, SwitchBundle

INDEX_TABLE_NAMES: List[str] = [f'MyIngress.index_table_copy{x}' for x in [1, 2, 3, 4, 5, 6]]


@dataclasses.dataclass(frozen=True)
class FlowId:
    """Identifier of a flow."""
    mac_lower: MacAddress
    mac_upper: MacAddress
    specifier: int  # Hash of IP addresses, port numbers, protocols, etc.

    def __repr__(self) -> str:
        return f'[{self.mac_lower} / {self.mac_upper} / {self.specifier}]'


class PathEntryStorageType(enum.Enum):
    INDEX = enum.auto()
    HASH = enum.auto()


@dataclasses.dataclass
class PathEntry:
    """Represents an entry in the path table."""
    flow_id: FlowId
    port_lower: int
    port_upper: int
    strength_building: int
    strength_confirmation: int
    learn_timestamp: int
    storage_type: PathEntryStorageType


@dataclasses.dataclass
class SwitchContext:
    """Holder of information about a single switch."""
    free_indexes: Set[int] = dataclasses.field(default_factory=set)
    next_index: int = dataclasses.field(default=0)
    index_table: Dict[FlowId, int] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Context:
    """Holder of information about the controller."""
    topology: NetworkGraph
    switches: List[SwitchBundle]
    switch_contexts: Dict[str, SwitchContext]


def initialize_multicast_groups_and_clone_sessions(topology: NetworkGraph, switch: SwitchBundle) -> None:
    # We currently use 1 bit for each port to make it easier to implement the clone sessions and multicast groups.
    # Close sessions IDs have a maximum value, therefore this is a bottleneck, but it can be fixed with a bit of work.
    max_port_count = 9

    switch_ports_dict: Dict[str, int] = topology.get_node_intfs(['port'])[switch.name].copy()
    switch_ports_dict.pop('lo', None)  # Exclude loopback port if it exists
    switch_ports: List[int] = list(switch_ports_dict.values())
    if max(switch_ports) > max_port_count or min(switch_ports) < 1:
        raise Exception(f'Switch has invalid port number(s): {switch.name} -> {switch_ports}')

    all_ports = 0
    for i in range(max_port_count):
        all_ports |= 1 << i

    def flip_port(ports: int, port_to_flip: int) -> int:
        return ports ^ (1 << port_to_flip - 1)

    def register(identifier: int, ports: List[int]) -> None:
        switch.grpc.mc_mgrp_create(identifier, ports)
        switch.grpc.cs_create(identifier, ports)

    # broadcast multicast group / clone session
    register(all_ports, [i for i in switch_ports])

    # split horizon multicast groups / clone sessions (forward to all ports except one)
    for port in switch_ports:
        register(flip_port(all_ports, port), [i for i in switch_ports if i != port])

    # groups containing a single egress port
    for port in switch_ports:
        register(flip_port(0, port), [port])


def free_up_table_entry(context: Context, switch: SwitchBundle, flow_id: FlowId) -> None:
    logger = logging.getLogger(__name__)
    switch_context = context.switch_contexts[switch.name]
    index = switch_context.index_table.pop(flow_id)
    logger.info(f'Freeing up table entry of flow {flow_id} (index={index})')
    switch_context.free_indexes.add(index)
    switch.thrift.register_write('path_initialized_register', index, 0)
    for table in INDEX_TABLE_NAMES:
        switch.grpc.table_delete_match(table, [str(flow_id.mac_lower), str(flow_id.mac_upper), str(flow_id.specifier)])


def free_up_unused_table_entries(context: Context, switch: SwitchBundle, timed_out_timestamp: int) -> None:
    logger = logging.getLogger(__name__)
    if timed_out_timestamp == 0:
        logger.warning('timed_out_timestamp is 0, no path entries can be freed up')
        return

    try:
        switch.thrift.register_write('path_deletion_lock_register', 0, timed_out_timestamp)
        free_up_unused_table_entries_impl(context, switch, timed_out_timestamp)
    finally:
        switch.thrift.register_write('path_deletion_lock_register', 0, 0)


def free_up_unused_table_entries_impl(context: Context, switch: SwitchBundle, timed_out_timestamp: int) -> None:
    logger = logging.getLogger(__name__)
    switch_context = context.switch_contexts[switch.name]

    to_free_up: List[FlowId] = []
    oldest_flow_id: Optional[FlowId] = None
    oldest_timestamp: Optional[int] = None

    count_broadcast = 0
    count_uninitialized = 0
    count_used = 0

    for flow_id, index in switch_context.index_table.items():
        if flow_id.mac_upper == MacAddress.BROADCAST:
            count_broadcast += 1
            continue  # Singular entries must not be deleted: that could cause packet loss and loops
        if DataParser.parse_number(switch.thrift.register_read('path_initialized_register', index)) == 0:
            count_uninitialized += 1
            continue  # Entry is yet to be migrated from hash register. Migration will happen sooner or later.

        learn_timestamp = DataParser.parse_number(switch.thrift.register_read('path_learn_timestamp_register', index))
        if learn_timestamp < timed_out_timestamp:
            to_free_up.append(flow_id)  # We can't delete dict entries while iterating over the dict
        else:
            count_used += 1
            if oldest_timestamp is None or learn_timestamp < oldest_timestamp:
                oldest_flow_id = flow_id
                oldest_timestamp = learn_timestamp

    for flow_id in to_free_up:
        free_up_table_entry(context, switch, flow_id)

    logger.info(f'Table entries summary: (total: {len(to_free_up) + len(switch_context.index_table)})')
    logger.info(f'  broadcast (singular): {count_broadcast}')
    logger.info(f'  uninitialized: {count_uninitialized}')
    logger.info(f'  recently used: {count_used}')
    logger.info(f'  freed up: {len(to_free_up)}')

    if len(switch_context.free_indexes) > 0:
        return

    # Future work: delete the oldest path entry if there are no free indexes left, and we need to insert a singular
    # entry. The reasoning is that singular entries are necessary for packet forwarding, while path entries just make
    # the forwarding more efficient.

    if oldest_flow_id is None:
        logger.warning('No removable entries found')
        return


class DataParser:
    @staticmethod
    def parse_number(raw: Union[bytes, int]) -> int:
        return raw if isinstance(raw, int) else int.from_bytes(raw, 'big')

    @staticmethod
    def parse_mac(raw: Union[bytes, int]) -> MacAddress:
        return MacAddress(raw)


def handle_digest(digest: DigestParsed, context: Context,
                  handler: Callable[[DigestParsed, Context], None]) -> DigestParsed:
    """
    Function that should be calling the real digest handling methods.
    This function does some general tasks such as logging digest.
    """

    logger = logging.getLogger(__name__)
    logger.info(f"Handling '{digest.name}' digest from switch '{digest.switch.name}'...")
    handler(digest, context)
    return digest


def handle_digest_index_table_insert(digest: DigestParsed, context: Context) -> None:
    """Handler of the 'insert a new index into the index table for the specified MAC' digest."""
    logger = logging.getLogger(__name__)
    switch_context = context.switch_contexts[digest.switch.name]
    index_table_size = digest.switch.grpc.context.get_table(INDEX_TABLE_NAMES[0]).size

    flow_id = FlowId(DataParser.parse_mac(digest.values[0]), DataParser.parse_mac(digest.values[1]),
                     DataParser.parse_number(digest.values[2]))
    timed_out_timestamp = DataParser.parse_number(digest.values[3])

    current_index = switch_context.index_table.get(flow_id, None)
    if current_index is not None:
        logger.info(f'Insertion failed: flow {flow_id} is already assigned to index {current_index}')
    else:
        if len(switch_context.free_indexes) > 0:
            current_index = switch_context.free_indexes.pop()
            index_source = 'free index'
        elif switch_context.next_index == index_table_size:
            free_up_unused_table_entries(context, digest.switch, timed_out_timestamp)
            if len(switch_context.free_indexes) == 0:
                logger.info('Warning: insertion failed: no free indexes left')
                return
            current_index = switch_context.free_indexes.pop()
            index_source = 'just now freed index'
        else:
            current_index = switch_context.next_index
            switch_context.next_index += 1
            index_source = 'next index'

        switch_context.index_table[flow_id] = current_index
        serialized_flow = [str(flow_id.mac_lower), str(flow_id.mac_upper), str(flow_id.specifier)]
        for table_name in INDEX_TABLE_NAMES:
            digest.switch.grpc.table_add(table_name, 'index_table_row_setter', serialized_flow, [str(current_index)])
        logger.info(f'Insertion successful: flow {flow_id} is now assigned to index {current_index}'
                    f' (source: {index_source})')


def controller_body(topology: NetworkGraph, switches: List[SwitchBundle]) -> None:
    logger = logging.getLogger(__name__)
    context = Context(topology, switches, {s.name: SwitchContext() for s in switches})

    for switch in switches:
        initialize_multicast_groups_and_clone_sessions(topology, switch)

    digest_manager = DigestManager(switches)
    for x in [1, 2]:
        digest_manager.register(f'digest_index_table_insert{x}_t',
                                lambda digest: handle_digest(digest, context, handle_digest_index_table_insert))

    logger.info('Initialization complete, entering main logic loop...\n\n')
    while True:
        if digest_manager.handle_one_if_present() is None:
            time.sleep(0.001)

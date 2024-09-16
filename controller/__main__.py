import json
import logging
import sys
from argparse import ArgumentParser, FileType
from pathlib import Path

import networkx
from p4utils.utils.topology import NetworkGraph
import p4utils.utils.sswitch_p4runtime_API
import p4utils.utils.sswitch_thrift_API

from controller.logic import controller_body
from controller.utils import SwitchBundle


def main() -> None:
    parser = ArgumentParser()
    parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
    parser.add_argument('--topology-path', type=FileType(), required=True)
    parser.add_argument('--compiler-out-path', type=Path, required=True)
    parser.add_argument('--switch-queue-depth', type=int, default=417)
    parser.add_argument('--switch-queue-rate-pps', type=int, default=25)
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper(),
                        format='[%(asctime)s] %(levelname)s [%(name)s] %(message)s',
                        stream=sys.stdout)
    logger = logging.getLogger(__name__)

    # We don't use p4utils.utils.helper.load_topo because it imports mininet logging, which screws up the logging module
    with args.topology_path as f:
        topology = NetworkGraph(networkx.node_link_graph(json.load(f)))

    logger.info('Loading switches...')
    switches = [
        SwitchBundle(
            name=name,
            thrift=p4utils.utils.sswitch_thrift_API.SimpleSwitchThriftAPI(topology.get_thrift_port(name)),
            grpc=p4utils.utils.sswitch_p4runtime_API.SimpleSwitchP4RuntimeAPI(
                topology.get_p4switch_id(name),
                topology.get_grpc_port(name),
                p4rt_path=args.compiler_out_path / 'switch_p4rt.txt',
                json_path=args.compiler_out_path / 'switch.json'
            )
        ) for name in sorted(topology.get_switches().keys())
    ]

    logger.info('Configuring switch packet queues...')
    queue_depth, queue_rate = args.switch_queue_depth, args.switch_queue_rate_pps
    logger.info(f'Switch queue config: depth = {queue_depth} packets, rate = {queue_rate} pps')
    for switch in switches:
        if queue_depth >= 0:
            switch.thrift.set_queue_depth(queue_depth)
        if queue_rate >= 0:
            switch.thrift.set_queue_rate(queue_rate)

    logger.info('Starting controller logic...')
    try:
        controller_body(topology, switches)
    except (KeyboardInterrupt, EOFError):
        logger.info("Keyboard interrupt detected; shutting down...")

    for switch in switches:
        switch.grpc.teardown()


if __name__ == '__main__':
    main()

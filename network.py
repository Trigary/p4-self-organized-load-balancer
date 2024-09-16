#!/usr/bin/env python3
import os
from argparse import ArgumentParser

from p4utils.mininetlib.network_API import NetworkAPI

# Parse arguments
parser = ArgumentParser()
parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
parser.add_argument('--save-pcap', action='store_true')
args = parser.parse_args()

net = NetworkAPI()
net.setLogLevel(args.log_level)

# 3-tier topology definition
pod_count = 2  # A pod is a 2x2 switch topology
core_count = 2  # Connects pods together
host_per_pod_leaf = 2  # Twice this many hosts will be created for each pod

# Topology creation
next_switch_id = 1
next_host_id = 1
core_switches, next_switch_id = [f"s{next_switch_id + i}" for i in range(core_count)], next_switch_id + core_count
for s in core_switches:
    net.addP4RuntimeSwitch(s)
for pod in range(pod_count):
    pod_switches = [f"s{next_switch_id + i}" for i in range(4)]
    next_switch_id += len(pod_switches)
    for s in pod_switches:
        net.addP4RuntimeSwitch(s)
    for s in pod_switches[:2]:
        for c in core_switches:
            net.addLink(s, c)
    for s in pod_switches[2:]:
        for p in pod_switches[:2]:
            net.addLink(s, p)
        for h in range(host_per_pod_leaf):
            net.addHost(f"h{next_host_id}")
            net.addLink(f"h{next_host_id}", s)
            next_host_id += 1

# Host configuration
net.l2()  # Place all hosts in the same subnet; they will need to use ARP to learn each other's MAC addresses

# Switch configuration
compiler_out_dir = 'work/switch'
net.setCompiler(outdir=compiler_out_dir, p4rt=True)
net.setP4SourceAll('switch/switch.p4')

# Start local controller on network startup
net.setTopologyFile(f'work/topology.json')
os.makedirs(os.path.dirname(net.topoFile), exist_ok=True)
# The topology file will be created on network startup, before the controller is executed
controller_out_file = 'work/log/controller.log'
net.execScript(f'python3 -m controller --log-level {args.log_level} --topology-path {net.topoFile}'
               f' --compiler-out-path {compiler_out_dir}', out_file=controller_out_file)
os.makedirs(os.path.dirname(controller_out_file), exist_ok=True)

# Logging, capturing configuration
net.setLogLevel(args.log_level)
net.enableLogAll(log_dir='work/log')
if args.save_pcap:
    net.enablePcapDumpAll(pcap_dir='work/pcap')
else:
    net.disablePcapDumpAll()

# Execution
net.startNetwork()

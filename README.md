# A load balancing algorithm for self-organized networks

This repository holds a reference implementation of the load balancing algorithm presented in the following paper:

Load Balancing and Alternative Path Selection in Self-Organized Networks: A Data Plane Approach  
_TODO The paper is currently under review. Insert a proper citation here if the paper gets accepted._

We hope this repository aids in the reproduction of the results.

## Requirements, installation

This project depends on [p4-utils](https://github.com/Trigary/p4-utils/tree/digest-non-blocking).
Please follow the instructions in the [README](https://github.com/Trigary/p4-utils/blob/digest-non-blocking/README.md) to install the library and its dependencies.

Please make sure to use the linked fork branch of `p4-utils` until its changes are merged into the main repository (see https://github.com/nsg-ethz/p4-utils/pull/76).

## Usage

A Mininet simulation can be started via `sudo python3 network.py`, which will:

- Compile the P4 source code
- Start a Mininet simulation
  - A 3-level fat tree topology with 2 pods and 2 core switches is used
- Start a controller that simulates local controllers for each switch
  - Local controllers are necessary to set up clone sessions and multicast groups and to allow switches to modify their
    own table entries
- Start a CLI for the user to interact with the simulation

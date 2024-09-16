#ifndef SWITCH_INGRESS_P4
#define SWITCH_INGRESS_P4

#include <core.p4>
#include <v1model.p4>
#include "switch_typedefs.p4"
#include "switch_globals.p4"
#include "switch_headers.p4"
#include "switch_structs.p4"

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    //Fields related to the initialization of the switch (code that only runs once and sets some values).
    register<bit<1>>(1) initialized_status_register;
    register<timestamp_t>(1) initialized_timestamp_register;
    timestamp_t initialized_timestamp;

    //Fields related to determining if the switch is a leaf switch for a specific port:
    // whether there are any more switches on the other side of a specific port or not.
    register<port_status_container_t>(1) port_status_container_register;
    port_status_container_t port_status_container;
    #define IS_PORT_LEAF(PORT) \
            (standard_metadata.ingress_global_timestamp - initialized_timestamp > MILLIS_TO_MICROS(200) \
            && (port_status_container & ((port_status_container_t) 1 << (shift_port_id_t) (PORT - 1)) == 0))

    //Registers responsible for storing path entries while their index is being inserted into the index table.
    //Separate registers exist because structs cannot be stored in registers and the max size of a register is 64 bits.
    register<bit<1>>(PATH_HASH_REGISTER_SIZE) path_hash_initialized_register;
    register<macAddr_t>(PATH_HASH_REGISTER_SIZE * 2) path_hash_mac_register;
    register<flow_specifier_t>(PATH_HASH_REGISTER_SIZE) path_hash_flow_specifier_register;
    register<portId_t>(PATH_HASH_REGISTER_SIZE * 2) path_hash_port_register;
    register<path_strength_t>(PATH_HASH_REGISTER_SIZE * 2) path_hash_strength_register;
    register<timestamp_t>(PATH_HASH_REGISTER_SIZE) path_hash_learn_timestamp_register;

    //Register for locking register path entries while they are being deleted by the control plane. The stored value
    //  is either 0 (unlocked) or a timestamp. Path entries last used before this timestamp are allowed to be deleted.
    register<timestamp_t>(1) path_deletion_lock_register;
    #define TIMED_OUT_TIMESTAMP ((standard_metadata.ingress_global_timestamp < LEARN_TIMESTAMP_GRACE_PERIODS_MAX \
            + PATH_ENTRY_TIMEOUT_MICROS) ? 0 : standard_metadata.ingress_global_timestamp \
            - LEARN_TIMESTAMP_GRACE_PERIODS_MAX - PATH_ENTRY_TIMEOUT_MICROS)

    //Table that maps path keys to register indexes.
    //The row field is used as input/output for the table's apply() method.
    //The table has multiple copies, all with the same contents. Reason: apply() can only be called once per table.
    //The actions that are marked as "could be extern calls" are responsible for modifying the table's contents.
    index_table_row_t index_table_row;
    action index_table_row_setter(path_index_t index) { index_table_row.index = index; }
    #define INDEX_TABLE_CONSTRUCTOR(NAME) table NAME { \
        key = { \
            index_table_row.flow_id.mac_lower: exact; \
            index_table_row.flow_id.mac_upper: exact; \
            index_table_row.flow_id.specifier: exact; \
        } \
        actions = { index_table_row_setter; } \
        default_action = index_table_row_setter(~((bit<PATH_INDEX_T_WIDTH>) 0)); /* value easy to spot in logs */ \
        size = PATH_REGISTER_SIZE; \
    }
    INDEX_TABLE_CONSTRUCTOR(index_table_copy1)
    INDEX_TABLE_CONSTRUCTOR(index_table_copy2)
    INDEX_TABLE_CONSTRUCTOR(index_table_copy3)
    INDEX_TABLE_CONSTRUCTOR(index_table_copy4)
    INDEX_TABLE_CONSTRUCTOR(index_table_copy5)
    INDEX_TABLE_CONSTRUCTOR(index_table_copy6)
    //These below could be extern calls instead
    action index_table_insert(flow_id_t flow_id) {
        log_msg("  sending digest: requesting index table insert for flow: {} / {} / {}", {FLOW_ID_FIELDS(flow_id)});
        // We send a timestamp. Path entries older than this timestamp are allowed to be deleted.
        digest_index_table_insert1_t data = {FLOW_ID_FIELDS(flow_id), TIMED_OUT_TIMESTAMP};
        digest(0, data);
    }
    action index_table_insert_second(flow_id_t flow_id) {
        log_msg("  sending digest: requesting index table insert for flow: {} / {} / {}", {FLOW_ID_FIELDS(flow_id)});
        digest_index_table_insert2_t data = {FLOW_ID_FIELDS(flow_id), TIMED_OUT_TIMESTAMP};
        digest(0, data);
    }
    //These above could be extern calls instead

    //Registers responsible for storing path entries which have an index associated with them in the index table.
    register<bit<1>>(PATH_REGISTER_SIZE) path_initialized_register;
    register<portId_t>(PATH_REGISTER_SIZE * 2) path_port_register;
    register<path_strength_t>(PATH_REGISTER_SIZE * 2) path_strength_register;
    register<timestamp_t>(PATH_REGISTER_SIZE) path_learn_timestamp_register;

    //Helper functions for path entry persistence.
    #define PATH_ENTRY_READ_INITIALIZED(E, REGISTER) \
            REGISTER.read(E.initialized, E.index);
    #define PATH_ENTRY_WRITE_INITIALIZED(E, REGISTER) \
            REGISTER.write(E.index, E.initialized);
    #define PATH_ENTRY_READ_FLOW_ID(E, MAC_REGISTER, SPECIFIER_REGISTER) \
            MAC_REGISTER.read(E.flow_id.mac_lower, E.index * 2); \
            MAC_REGISTER.read(E.flow_id.mac_upper, E.index * 2 + 1); \
            SPECIFIER_REGISTER.read(E.flow_id.specifier, E.index);
    #define PATH_ENTRY_WRITE_FLOW_ID(E, MAC_REGISTER, SPECIFIER_REGISTER) \
            MAC_REGISTER.write(E.index * 2, E.flow_id.mac_lower); \
            MAC_REGISTER.write(E.index * 2 + 1, E.flow_id.mac_upper); \
            SPECIFIER_REGISTER.write(E.index, E.flow_id.specifier);
    #define PATH_ENTRY_READ_REST(E, PORT_REGISTER, STRENGTH_REGISTER, LEARN_TIMESTAMP_REGISTER) \
            PORT_REGISTER.read(E.port_lower, E.index * 2); \
            PORT_REGISTER.read(E.port_upper, E.index * 2 + 1); \
            STRENGTH_REGISTER.read(E.strength_building, E.index * 2); \
            STRENGTH_REGISTER.read(E.strength_confirmation, E.index * 2 + 1); \
            LEARN_TIMESTAMP_REGISTER.read(E.learn_timestamp, E.index);
    #define PATH_ENTRY_WRITE_REST(E, PORT_REGISTER, STRENGTH_REGISTER, LEARN_TIMESTAMP_REGISTER) \
            PORT_REGISTER.write(E.index * 2, E.port_lower); \
            PORT_REGISTER.write(E.index * 2 + 1, E.port_upper); \
            STRENGTH_REGISTER.write(E.index * 2, E.strength_building); \
            STRENGTH_REGISTER.write(E.index * 2 + 1, E.strength_confirmation); \
            LEARN_TIMESTAMP_REGISTER.write(E.index, E.learn_timestamp);
    #define PATH_ENTRY_SET_DEFAULTS(E) \
            E.initialized = 0; \
            E.port_lower = PATH_ENTRY_PORT_UNINITIALIZED; \
            E.port_upper = PATH_ENTRY_PORT_UNINITIALIZED; \
            E.strength_building = PATH_STRENGTH_UNINITIALIZED; \
            E.strength_confirmation = PATH_STRENGTH_UNINITIALIZED; \
            /* Don't let entry get instantly timed out (its storage space freed up) */ \
            E.learn_timestamp = standard_metadata.ingress_global_timestamp - LEARN_TIMESTAMP_GRACE_PERIODS_MAX - 1;

    //Save the path entry fields. The entry must be persisted (have its storage and index fields set).
    #define PATH_ENTRY_SAVE(IN_ENTRY) /* Only called for persisted entries */ \
        if (IN_ENTRY.storage == PATH_ENTRY_STORAGE_INDEX) { \
            log_msg("  saving path entry to index register; index={}", {IN_ENTRY.index}); \
            log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(IN_ENTRY.flow_id)}); \
            PATH_ENTRY_WRITE_INITIALIZED(IN_ENTRY, path_initialized_register); \
            PATH_ENTRY_WRITE_REST(IN_ENTRY, path_port_register, path_strength_register, \
                    path_learn_timestamp_register); \
        } else if (IN_ENTRY.storage == PATH_ENTRY_STORAGE_HASH) { \
            log_msg("  saving path entry to hash register; hash={}", {IN_ENTRY.index}); \
            log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(IN_ENTRY.flow_id)}); \
            PATH_ENTRY_WRITE_INITIALIZED(IN_ENTRY, path_hash_initialized_register); \
            PATH_ENTRY_WRITE_FLOW_ID(IN_ENTRY, path_hash_mac_register, path_hash_flow_specifier_register); \
            PATH_ENTRY_WRITE_REST(IN_ENTRY, path_hash_port_register, path_hash_strength_register, \
                    path_hash_learn_timestamp_register); \
        } else { \
            log_msg("ERROR: invalid storage type in PATH_ENTRY_SAVE: {}", {IN_ENTRY.storage}); \
            assert(false); \
        }

    //Retrieve the path entry associated with the specified MAC address, if such a persisted entry exists.
    //This operations returns "failure" even if the entry could be inserted (but wasn't).
    #define PATH_ENTRY_READ(IN_FLOW_ID, IN_INDEX_TABLE_COPY, OUT_ENTRY) \
        if (true) { /* start a new scope to be able to safely declare new variables */ \
        if (!IS_MAC_UNICAST(IN_FLOW_ID.mac_upper) && IN_FLOW_ID.mac_upper != MAC_BROADCAST) { \
            log_msg("ERROR: upper MAC is neither unicast nor broadcast in flow: {} / {} / {}", \
                    {FLOW_ID_FIELDS(IN_FLOW_ID)}); \
            assert(false); \
        } \
        OUT_ENTRY.flow_id = IN_FLOW_ID; \
        index_table_row.flow_id = IN_FLOW_ID; \
        path_index_t hash_index; \
        hash(hash_index, HashAlgorithm.crc32, (bit<1>) 0, {FLOW_ID_FIELDS(IN_FLOW_ID)}, \
                (bit<32>) PATH_HASH_REGISTER_SIZE); \
        if (IN_INDEX_TABLE_COPY.apply().hit) { /* read index register */ \
            OUT_ENTRY.index = index_table_row.index; \
            PATH_ENTRY_READ_INITIALIZED(OUT_ENTRY, path_initialized_register); \
            if (OUT_ENTRY.initialized != 0) { /* data already in the index register */ \
                log_msg("  reading path entry from index register; index={}", {OUT_ENTRY.index}); \
                log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(IN_FLOW_ID)}); \
                OUT_ENTRY.storage = PATH_ENTRY_STORAGE_INDEX; \
                PATH_ENTRY_READ_REST(OUT_ENTRY, path_port_register, path_strength_register, \
                        path_learn_timestamp_register); \
            } else { /* data might need to be migrated from the hash register */ \
                OUT_ENTRY.index = hash_index; \
                PATH_ENTRY_READ_INITIALIZED(OUT_ENTRY, path_hash_initialized_register); \
                PATH_ENTRY_READ_FLOW_ID(OUT_ENTRY, path_hash_mac_register, path_hash_flow_specifier_register); \
                if (OUT_ENTRY.initialized != 0 && IN_FLOW_ID == OUT_ENTRY.flow_id) { /* migrate data */ \
                    log_msg("  reading path entry: migrating from hash register to index register; hash={}; index={}", \
                            {hash_index, index_table_row.index}); \
                    log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(IN_FLOW_ID)}); \
                    PATH_ENTRY_READ_REST(OUT_ENTRY, path_hash_port_register, path_hash_strength_register, \
                            path_hash_learn_timestamp_register); \
                    OUT_ENTRY.storage = PATH_ENTRY_STORAGE_INDEX; \
                    OUT_ENTRY.index = index_table_row.index; \
                    PATH_ENTRY_SAVE(OUT_ENTRY); /* save the data migration */ \
                    path_hash_initialized_register.write(hash_index, 0); /* Mark the hash register slot as empty */ \
                } else { /* no data to migrate, so treat the entry as a new, not persisted entry */ \
                    /* This happens when persistence was not possible until now due to a hash collision. */ \
                    log_msg("  reading path entry failed: no match in index/hash registers; hash={}; index={}", \
                            {hash_index, index_table_row.index}); \
                    log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(IN_FLOW_ID)}); \
                    OUT_ENTRY.storage = PATH_ENTRY_STORAGE_MISS_AND_INDEX_FREE; \
                    OUT_ENTRY.index = index_table_row.index; \
                    OUT_ENTRY.flow_id = IN_FLOW_ID; \
                    /* write dummy values to avoid incorrect compiler warnings */ \
                    PATH_ENTRY_SET_DEFAULTS(OUT_ENTRY); \
                } \
            } \
        } else { \
            OUT_ENTRY.index = hash_index; \
            PATH_ENTRY_READ_INITIALIZED(OUT_ENTRY, path_hash_initialized_register); \
            PATH_ENTRY_READ_FLOW_ID(OUT_ENTRY, path_hash_mac_register, path_hash_flow_specifier_register); \
            if (OUT_ENTRY.initialized != 0 && IN_FLOW_ID == OUT_ENTRY.flow_id) { /* read hash data */ \
                log_msg("  reading path entry from hash register; hash={}", {hash_index}); \
                log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(IN_FLOW_ID)}); \
                OUT_ENTRY.storage = PATH_ENTRY_STORAGE_HASH; \
                PATH_ENTRY_READ_REST(OUT_ENTRY, path_hash_port_register, path_hash_strength_register, \
                        path_hash_learn_timestamp_register); \
                /* Try to request an index register index again. Necessary, because only 1 digest can be sent */ \
                /*   at once, so if multiple path entries are inserted at once, some won't get indexes. */ \
                /* The call below ensures that after some (up to infinite) attempts, an index will be provided. */ \
                index_table_insert(IN_FLOW_ID); \
            } else { /* read is not possible: entry was not persisted */ \
                log_msg("  reading path entry failed: no matching data in hash register; hash={}", {hash_index}); \
                log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(IN_FLOW_ID)}); \
                OUT_ENTRY.storage = PATH_ENTRY_STORAGE_MISS_AND_INDEX_MISSING; \
                OUT_ENTRY.flow_id = IN_FLOW_ID; \
                /* write dummy values to avoid incorrect compiler warnings */ \
                PATH_ENTRY_SET_DEFAULTS(OUT_ENTRY); \
            } \
        } }

    //Attempt to save a path entry that was not persisted before. This persistence attempt can be unsuccessful.
    #define PATH_ENTRY_INSERT(INOUT_ENTRY, IN_INDEX_TABLE_COPY) \
        if (INOUT_ENTRY.storage == PATH_ENTRY_STORAGE_MISS_AND_INDEX_FREE) { \
            log_msg("  inserting path entry to index register; index={}", {INOUT_ENTRY.index}); \
            log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(INOUT_ENTRY.flow_id)}); \
            INOUT_ENTRY.storage = PATH_ENTRY_STORAGE_INDEX; \
            /* INOUT_ENTRY.index is already set to the correct value, no need for another table lookup */ \
            INOUT_ENTRY.initialized = 1; \
            PATH_ENTRY_SAVE(INOUT_ENTRY); \
        } else if (INOUT_ENTRY.storage == PATH_ENTRY_STORAGE_MISS_AND_INDEX_MISSING) { \
            index_table_insert(INOUT_ENTRY.flow_id); \
            /* INOUT_ENTRY.index already contains the hash, no need to recompute it */ \
            path_entry_t hash_entry; \
            hash_entry.index = INOUT_ENTRY.index; \
            PATH_ENTRY_READ_INITIALIZED(hash_entry, path_hash_initialized_register); \
            PATH_ENTRY_READ_FLOW_ID(hash_entry, path_hash_mac_register, path_hash_flow_specifier_register); \
            index_table_row.flow_id = hash_entry.flow_id; \
            if (hash_entry.initialized == 0) { /* hash register slot is free */ \
                log_msg("  inserting path entry to hash register; hash={}", {INOUT_ENTRY.index}); \
                log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(INOUT_ENTRY.flow_id)}); \
                INOUT_ENTRY.storage = PATH_ENTRY_STORAGE_HASH; \
                INOUT_ENTRY.initialized = 1; \
                PATH_ENTRY_SAVE(INOUT_ENTRY); \
            } else if (IN_INDEX_TABLE_COPY.apply().hit) { /* hash register slot can be freed up: migrate the data */ \
                log_msg("  inserting path entry to hash register after migration; hash={}", {INOUT_ENTRY.index}); \
                log_msg("    to-insert flow: {} / {} / {}", {FLOW_ID_FIELDS(INOUT_ENTRY.flow_id)}); \
                log_msg("    migrated  flow: {} / {} / {}", {FLOW_ID_FIELDS(hash_entry.flow_id)}); \
                /* migrate the current hash entry into the index registers */ \
                PATH_ENTRY_READ_REST(hash_entry, path_hash_port_register, path_hash_strength_register, \
                        path_hash_learn_timestamp_register); \
                hash_entry.storage = PATH_ENTRY_STORAGE_INDEX; \
                hash_entry.index = index_table_row.index; \
                PATH_ENTRY_SAVE(hash_entry); \
                /* persist the new entry */ \
                INOUT_ENTRY.storage = PATH_ENTRY_STORAGE_HASH; \
                INOUT_ENTRY.initialized = 1; \
                PATH_ENTRY_SAVE(INOUT_ENTRY); \
            } else { /* hash collision, we cannot persist this entry */ \
                index_table_insert_second(hash_entry.flow_id); \
                /* Try to request an index register index again. This way we can free up the has register even */ \
                /*   if its flow is not being used. See the comment in PATH_ENTRY_READ for more information. */ \
                log_msg("  WARNING: inserting failed for path entry: hash collision; hash={}", {INOUT_ENTRY.index}); \
                log_msg("    to-insert flow: {} / {} / {}", {FLOW_ID_FIELDS(INOUT_ENTRY.flow_id)}); \
                log_msg("    persisted flow: {} / {} / {}", {FLOW_ID_FIELDS(hash_entry.flow_id)}); \
                INOUT_ENTRY.storage = PATH_ENTRY_STORAGE_MISS_AND_INDEX_MISSING; /* redundant write for clarity */ \
            } \
        } else { \
            log_msg("ERROR: invalid storage type in PATH_ENTRY_INSERT: {}", {INOUT_ENTRY.storage}); \
            assert(false); \
        }

    //Sent register: ingress timestamp when the path change request PNP packet was last sent.
    register<timestamp_t>(1) pnp_request_sent_register;

    apply {
        log_msg(">>> BEGIN ingress");
        //Reset whether a clone has been requested (in case this is a resubmit and the field is preserved by mistake)
        meta.clone_subtype = PNP_SUBTYPE_NONE;

        //Initialize the switch if necessary
        bit<1> initialized_status;
        initialized_status_register.read(initialized_status, 0);
        if (initialized_status == 0) {
            log_msg("Initializing switch");
            initialized_status = 1;
            initialized_status_register.write(0, initialized_status);
            initialized_timestamp = standard_metadata.ingress_global_timestamp;
            initialized_timestamp_register.write(0, initialized_timestamp);

            log_msg("  broadcasting PNP test packets");
            meta.clone_subtype = PNP_SUBTYPE_TEST;
            clone_preserving_field_list(CloneType.I2E, CLONE_SESSION_BROADCAST, CLONE_INDEX_PNP_TEST);
        }

        //Drop invalid packets, log valid packets' most important fields
        if (standard_metadata.parser_error != error.NoError) {
            log_msg("Parser error, dropping");
            mark_to_drop(standard_metadata);
            exit;
        } else if (standard_metadata.checksum_error != 0) {
            log_msg("Checksum error, dropping");
            mark_to_drop(standard_metadata);
            exit;
        } else if (hdr.ethernet.etherType == ETHER_TYPE_PNP) {
            log_msg("Received PNP");
            if (hdr.pnp_test.isValid()) {
                log_msg("  subtype=test; reply={}", {hdr.pnp_test.reply});
            } else if (hdr.pnp_request.isValid()) {
                log_msg("  subtype=request; flow: {} / {} / {}", {FLOW_ID_FIELDS(hdr.pnp_request.flow_id)});
            } else if (hdr.pnp_learn.isValid()) {
                log_msg("  subtype=learn; strength={}; confirmation={}; singular_learn={}",
                        {hdr.pnp_learn.strength, hdr.pnp_learn.confirmation, hdr.pnp_learn.singular_learn});
                log_msg("    flow: {} / {} / {}", {FLOW_ID_FIELDS(hdr.pnp_learn.flow_id)});
            } else {
                log_msg("  unknown subtype, dropping");
                mark_to_drop(standard_metadata);
                exit;
            }
        } else if (hdr.arp.isValid()) {
            log_msg("Received ARP; op={}; srcMAC={}; srcIP={}.{}.{}.{}; dstMAC={}; dstIP={}.{}.{}.{}",
                    {hdr.arp.opcode, hdr.arp.hwSrcAddr, SLICE_IPV4_ADDRESS(hdr.arp.protoSrcAddr),
                    hdr.arp.hwDstAddr, SLICE_IPV4_ADDRESS(hdr.arp.protoDstAddr)});
        } else if (hdr.ipv4.isValid()) {
            log_msg("Received IPv4: ttl={}; protocol={}; {}.{}.{}.{} -> {}.{}.{}.{}",
                    {hdr.ipv4.ttl, hdr.ipv4.protocol,
                    SLICE_IPV4_ADDRESS(hdr.ipv4.srcAddr), SLICE_IPV4_ADDRESS(hdr.ipv4.dstAddr)});
        } else if (hdr.ethernet.etherType == 34525) {
            //For some reason I keep receiving IPv6 packets.
            //I drop them silently so that they don't clutter up the logs.
            mark_to_drop(standard_metadata);
            exit;
        } else {
            log_msg("Received unknown ether type {}", {hdr.ethernet.etherType});
        }

        log_msg("  ingress-port={}, ethernet-src={}, ethernet-dst={}",
                {standard_metadata.ingress_port, hdr.ethernet.srcAddr, hdr.ethernet.dstAddr});

        //Initialize basic variables
        initialized_timestamp_register.read(initialized_timestamp, 0);
        port_status_container_register.read(port_status_container, 0);

        //Handle the PNP packet subtype
        if (hdr.pnp_test.isValid()) {
            log_msg("PNP handling: test");
            shift_port_id_t index = (shift_port_id_t) (standard_metadata.ingress_port - 1);
            if ((port_status_container & ((port_status_container_t) 1 << index)) == 0) {
                log_msg("  marking port as non-leaf");
                port_status_container = port_status_container | ((port_status_container_t) 1 << index);
                port_status_container_register.write(0, port_status_container);
            } else {
                log_msg("  port already marked as non-leaf");
            }
            if (hdr.pnp_test.reply == 0) {
                log_msg("  sending reply");
                hdr.pnp_test.reply = 1;
                standard_metadata.egress_spec = standard_metadata.ingress_port;
            } else {
                log_msg("  dropping");
                mark_to_drop(standard_metadata);
            }
            exit;
        }

        //Determine the flow entry (either of the current flow or the one specified in the PNP packet)
        flow_id_t entry_flow_id;
        if (hdr.pnp_request.isValid()) {
            entry_flow_id = hdr.pnp_request.flow_id;
        } else if (hdr.pnp_learn.isValid()) {
            entry_flow_id = hdr.pnp_learn.flow_id;
        } else if (IS_MAC_UNICAST(hdr.ethernet.dstAddr)) {
            entry_flow_id.mac_lower = MIN(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr);
            entry_flow_id.mac_upper = MAX(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr);
            flow_specifier_pre_hash_t to_hash;
            to_hash.ether_type = hdr.ethernet.etherType;
            if (hdr.ipv4.isValid()) {
                to_hash.ipv4_src = entry_flow_id.mac_lower == hdr.ethernet.srcAddr
                        ? hdr.ipv4.srcAddr : hdr.ipv4.dstAddr;
                to_hash.ipv4_dst = entry_flow_id.mac_lower == hdr.ethernet.srcAddr
                        ? hdr.ipv4.dstAddr : hdr.ipv4.srcAddr;
                to_hash.protocol = hdr.ipv4.protocol;
            } else {
                to_hash.ipv4_src = 0;
                to_hash.ipv4_dst = 0;
                to_hash.protocol = 0;
            }
            if (hdr.tcp.isValid()) {
                to_hash.port_src = entry_flow_id.mac_lower == hdr.ethernet.srcAddr ? hdr.tcp.srcPort : hdr.tcp.dstPort;
                to_hash.port_dst = entry_flow_id.mac_lower == hdr.ethernet.srcAddr ? hdr.tcp.dstPort : hdr.tcp.srcPort;
            } else if (hdr.udp.isValid()) {
                to_hash.port_src = entry_flow_id.mac_lower == hdr.ethernet.srcAddr ? hdr.udp.srcPort : hdr.udp.dstPort;
                to_hash.port_dst = entry_flow_id.mac_lower == hdr.ethernet.srcAddr ? hdr.udp.dstPort : hdr.udp.srcPort;
            } else {
                to_hash.port_src = 0;
                to_hash.port_dst = 0;
            }
            hash(entry_flow_id.specifier, HashAlgorithm.crc32, (bit<1>) 0, to_hash,
                    (bit<33>) (1 << FLOW_SPECIFIER_T_WIDTH));
        } else {
            entry_flow_id = PATH_ENTRY_GET_SINGULAR_FLOW_ID(hdr.ethernet.srcAddr);
        }
        meta.flow_id = entry_flow_id;

        //Read the flow path entry
        path_entry_t path_entry_flow;
        if (!PATH_ENTRY_IS_SINGULAR_FLOW_ID(entry_flow_id)) {
            log_msg("Attempting to read path entry of flow: {} / {} / {}", {FLOW_ID_FIELDS(entry_flow_id)});
            PATH_ENTRY_READ(entry_flow_id, index_table_copy1, path_entry_flow);

            //Determine whether this path entry is being deleted by the control plane
            if (path_entry_flow.storage == PATH_ENTRY_STORAGE_INDEX) {
                timestamp_t path_deletion_lock;
                path_deletion_lock_register.read(path_deletion_lock, 0);
                if (path_deletion_lock != 0 && path_entry_flow.learn_timestamp < path_deletion_lock) {
                    log_msg("  path entry is being deleted -> pretending it's not persisted");
                    path_entry_flow.storage = PATH_ENTRY_BEING_DELETED;
                    //In theory we might be able to use the hash entry, but let's not overcomplicate this edge case
                }
            }

            //Try to persist the path entry if it is not yet persisted
            if (path_entry_flow.storage != PATH_ENTRY_BEING_DELETED && !PATH_ENTRY_IS_PERSISTED(path_entry_flow)) {
                PATH_ENTRY_INSERT(path_entry_flow, index_table_copy2);
                if (hdr.pnp_base.isValid() && !PATH_ENTRY_IS_PERSISTED(path_entry_flow)) {
                    //If we can't persist data, we can't do any PNP-related operations
                    //This isn't exactly true: we might still be able to learn singular entries from learn and
                    //  confirmation packets and forward these packets so other switches can also learn from them.
                    //  But let's not overcomplicate this.
                    log_msg("  PNP path entry insertion failed -> dropping PNP packet");
                    mark_to_drop(standard_metadata);
                    exit;
                }
            }
        } else { //Result is actually unused in this case (but we need to do this it to avoid compiler warnings)
            path_entry_flow = {0, 0, 0, entry_flow_id, 0, 0, 0, 0, 0};
        }

        //Read the lower singular path entry
        path_entry_t path_entry_lower;
        flow_id_t path_entry_lower_flow_id = PATH_ENTRY_GET_SINGULAR_FLOW_ID(entry_flow_id.mac_lower);
        log_msg("Attempting to read singular path entry of source MAC {}", {path_entry_lower_flow_id.mac_lower});
        PATH_ENTRY_READ(path_entry_lower_flow_id, index_table_copy3, path_entry_lower);
        //We assume we are not the leaf if no packets were received from the host.
        //  Issue: if persistence fails and we don't receive any more packets, then we assume we aren't a leaf.
        //The singular entry is not yet updated by the current packet, so we check the ingress port separately.
        bool leaf_lower = (PATH_ENTRY_IS_PERSISTED(path_entry_lower)
                && IS_PORT_LEAF(path_entry_lower.port_lower))
                || (path_entry_lower.flow_id.mac_lower == hdr.ethernet.srcAddr
                && IS_PORT_LEAF(standard_metadata.ingress_port));

        //Read the upper singular path entry
        path_entry_t path_entry_upper;
        bool leaf_upper;
        if (!PATH_ENTRY_IS_SINGULAR_FLOW_ID(entry_flow_id)) {
            flow_id_t path_entry_upper_flow_id = PATH_ENTRY_GET_SINGULAR_FLOW_ID(entry_flow_id.mac_upper);
            log_msg("Attempting to read singular path entry of destination MAC {}",
                    {path_entry_upper_flow_id.mac_lower});
            PATH_ENTRY_READ(path_entry_upper_flow_id, index_table_copy4, path_entry_upper);
            leaf_upper = (PATH_ENTRY_IS_PERSISTED(path_entry_upper)
                    && IS_PORT_LEAF(path_entry_upper.port_lower))
                    || (path_entry_upper.flow_id.mac_lower == hdr.ethernet.srcAddr
                    && IS_PORT_LEAF(standard_metadata.ingress_port));
        } else { //Result is actually unused in this case (but we need to do this it to avoid compiler warnings)
            path_entry_upper = {0, 0, 0, entry_flow_id, 0, 0, 0, 0, 0};
            leaf_upper = false;
        }

        //Handle the PNP packet subtype
        if (hdr.pnp_request.isValid()) {
            log_msg("PNP handling: request");

            //If we don't know the lower MAC port, then we have an incomplete flow entry and will send a request packet
            // at some point, so we can safely drop this packet. If we were to do a split horizon instead, we would
            // either risk a flood or have to utilize a grace period here too. But dropping is simple and works fine.
            if (path_entry_flow.port_lower == PATH_ENTRY_PORT_UNINITIALIZED) {
                log_msg("  lower MAC port uninitialized -> dropping");
                mark_to_drop(standard_metadata);
                exit;
            }

            if (!leaf_lower) {
                log_msg("  not leaf for lower MAC -> forwarding towards lower MAC leaf");
                //  PS: the switch port_lower points to might have had its path entry removed, but in that case it'll
                //  just send a request packet itself, so there is no problem.
                standard_metadata.egress_spec = path_entry_flow.port_lower;
            } else if (standard_metadata.ingress_global_timestamp - path_entry_flow.learn_timestamp
                    <= LEARN_SEND_GRACE_PERIOD) {
                log_msg("  leaf for lower MAC & active grace period -> ignoring");
                mark_to_drop(standard_metadata);
            } else if (!PATH_ENTRY_IS_PERSISTED(path_entry_lower)) {
                //We want to ensure that all switches through which a flow passes know both the lower and the upper MAC
                //  ports via singular entries. This way we can safely delete path entries without causing traffic loss.
                //  But to able to achieve this singular entry learning even in case of one-directional traffic, we must
                //  be able to learn from learn packets. But to learn from learn packets, we must only send them if
                //  we have successfully learned the lower MAC port via a singular entry. Otherwise loops could form.
                log_msg("  leaf for lower MAC & singular entry incomplete -> ignoring");
                mark_to_drop(standard_metadata);
            } else {
                log_msg("  leaf for lower MAC & no grace period & singular entry filled -> broadcasting learn packet");

                //Save that a learn packet was sent and act as if that learn packet had just been received
                path_entry_flow.strength_building = PATH_STRENGTH_MAX;
                path_entry_flow.strength_confirmation = PATH_STRENGTH_UNINITIALIZED;
                path_entry_flow.learn_timestamp = standard_metadata.ingress_global_timestamp;
                PATH_ENTRY_SAVE(path_entry_flow);

                //Send the learn packet
                meta.can_decrease_strength = false;
                hdr.pnp_base.subtype = PNP_SUBTYPE_LEARN;
                hdr.pnp_learn.setValid();
                hdr.pnp_learn.flow_id = hdr.pnp_request.flow_id;
                hdr.pnp_learn.strength = PATH_STRENGTH_MAX;
                hdr.pnp_learn.confirmation = 0;
                hdr.pnp_learn.singular_learn = 1;
                hdr.pnp_request.setInvalid();
                standard_metadata.mcast_grp = MULTICAST_GROUP_ALL_EXCEPT(path_entry_flow.port_lower);
            }
            exit;
        }

        //Handle the PNP packet subtype
        if (hdr.pnp_learn.isValid()) {
            log_msg("PNP handling: learn");

            //Learn the singular entry if necessary and possible
            if (hdr.pnp_learn.confirmation == 0
                    ? PATH_ENTRY_IS_PERSISTED(path_entry_lower)
                    : PATH_ENTRY_IS_PERSISTED(path_entry_upper)) {
                //log_msg("  singular entry already filled");
            } else if (hdr.pnp_learn.singular_learn == 0) {
                log_msg("  singular entry learning not possible from packet");
            } else {
                //We can only use index_table_copy6 once, meaning we can only call PATH_ENTRY_INSERT once.
                //  Alternative solution: make yet another copy of the index table.
                path_entry_t temp;
                if (hdr.pnp_learn.confirmation == 0) {
                    log_msg("  learning lower singular entry");
                    path_entry_lower.port_lower = standard_metadata.ingress_port;
                    temp = path_entry_lower;
                } else {
                    log_msg("  learning upper singular entry");
                    path_entry_upper.port_lower = standard_metadata.ingress_port;
                    temp = path_entry_upper;
                }
                PATH_ENTRY_INSERT(temp, index_table_copy6);
                if (hdr.pnp_learn.confirmation == 0) {
                    path_entry_lower = temp;
                } else {
                    path_entry_upper = temp;
                }
                if (!PATH_ENTRY_IS_PERSISTED(temp)) {
                    log_msg("  singular entry insertion failed -> singular learning disallowed");
                    hdr.pnp_learn.singular_learn = 0;
                }
            }

            //Determine whether we are a leaf and if we are, which port the MAC is connected to.
            //  We only consider ourselves a leaf is the singular entry is persisted.
            bool leaf = false;
            portId_t port_singular_out = PATH_ENTRY_PORT_UNINITIALIZED;
            if (hdr.pnp_learn.confirmation == 0 && PATH_ENTRY_IS_PERSISTED(path_entry_upper)) {
                leaf = leaf_upper;
                port_singular_out = path_entry_upper.port_lower;
            } else if (hdr.pnp_learn.confirmation != 0 && PATH_ENTRY_IS_PERSISTED(path_entry_lower)) {
                leaf = leaf_lower;
                port_singular_out = path_entry_lower.port_lower;
            }

            //Determine whether to learn the (possibly new) path
            if ((hdr.pnp_learn.confirmation == 0
                    && path_entry_flow.port_lower == PATH_ENTRY_PORT_UNINITIALIZED)
                    || (hdr.pnp_learn.confirmation != 0
                    && path_entry_flow.port_upper == PATH_ENTRY_PORT_UNINITIALIZED)) {
                log_msg("  uninitialized flow entry port -> learning");
            } else if ((hdr.pnp_learn.confirmation == 0
                    && hdr.pnp_learn.strength > path_entry_flow.strength_building)
                    || (hdr.pnp_learn.confirmation != 0
                    && hdr.pnp_learn.strength > path_entry_flow.strength_confirmation)) {
                //We check the strength of the confirmation packet, because these packets might arrive out of order.
                //  So if a weaker confirmation packet arrives after a stronger learn packet, we don't want to learn.
                log_msg("  learn packet stronger than entry -> learning");
            } else if (hdr.pnp_learn.confirmation != 0) {
                log_msg("  learn packet too weak & confirmation -> not learning");
                mark_to_drop(standard_metadata);
                exit;
            } else if (standard_metadata.ingress_global_timestamp - path_entry_flow.learn_timestamp
                    <= LEARN_SEND_GRACE_PERIOD) {
                log_msg("  learn packet too weak & not confirmation & active grace period -> not learning");
                mark_to_drop(standard_metadata);
                exit;
            } else {
                //In the past we have learnt a path that had some strength. What if all paths currently have a lower
                //  strength than that, and the currently active path is overloaded? We must allow the learning of a
                //  weaker path. If a path as strong as the previously learnt path is found, then that will be learnt.
                log_msg("  learn packet too weak & not confirmation & no grace period -> learning");
            }

            //Learn the (possibly new) path
            if (hdr.pnp_learn.confirmation == 0) {
                path_entry_flow.port_lower = standard_metadata.ingress_port;
                if (leaf) {
                    //This is the only way to learn the upper leaf port (if we are not the lower leaf switch)
                    path_entry_flow.port_upper = port_singular_out;
                }
                path_entry_flow.strength_building = hdr.pnp_learn.strength;
                path_entry_flow.strength_confirmation = PATH_STRENGTH_UNINITIALIZED;
                path_entry_flow.learn_timestamp = standard_metadata.ingress_global_timestamp;
                PATH_ENTRY_SAVE(path_entry_flow);
            } else {
                path_entry_flow.port_upper = standard_metadata.ingress_port;
                path_entry_flow.strength_confirmation = hdr.pnp_learn.strength;
                PATH_ENTRY_SAVE(path_entry_flow);
            }

            //Update the strength if switch/link is overloaded
            meta.can_decrease_strength = !leaf && hdr.pnp_learn.confirmation == 0;

            //Propagate the packet if necessary
            if (leaf) {
                if (hdr.pnp_learn.confirmation != 0) {
                    log_msg("  leaf & confirmation -> learning ended, dropping");
                    mark_to_drop(standard_metadata);
                } else {
                    log_msg("  leaf & not confirmation -> confirmation reply");
                    hdr.pnp_learn.confirmation = 1;
                    hdr.pnp_learn.singular_learn = 1;
                    standard_metadata.egress_spec = standard_metadata.ingress_port;
                }
            } else if (hdr.pnp_learn.confirmation != 0) {
                log_msg("  not leaf & confirmation -> forwarding");
                standard_metadata.egress_spec = path_entry_flow.port_lower;
            } else {
                log_msg("  not leaf & not confirmation -> split horizon");
                standard_metadata.mcast_grp = MULTICAST_GROUP_ALL_EXCEPT(standard_metadata.ingress_port);
            }
            exit;
        }

        //PNP packets have been handled, now handle normal packets
        if (hdr.pnp_base.isValid()) {
            log_msg("ERROR: all PNP packet subtypes should have been fully handled by now");
            assert(false);
        }

        //Create separate source and destination path entry variables
        path_entry_t path_entry_src;
        path_entry_t path_entry_dst;
        bool path_entry_src_is_lower;
        if (IS_MAC_UNICAST(hdr.ethernet.dstAddr)) {
            path_entry_src_is_lower = hdr.ethernet.srcAddr < hdr.ethernet.dstAddr;
            path_entry_src = path_entry_src_is_lower ? path_entry_lower : path_entry_upper;
            path_entry_dst = path_entry_src_is_lower ? path_entry_upper : path_entry_lower;
        } else {
            path_entry_src_is_lower = true;
            path_entry_src = path_entry_lower;
            //Result is actually unused in this case (but we need to do this it to avoid compiler warnings)
            path_entry_dst = {0, 0, 0, entry_flow_id, 0, 0, 0, 0, 0};
        }

        //Learn the source port in the singular path entry if necessary
        if (!PATH_ENTRY_IS_PERSISTED(path_entry_src)) {
            log_msg("Learning source port of MAC: {}", {hdr.ethernet.srcAddr});
            path_entry_src.port_lower = standard_metadata.ingress_port;
            PATH_ENTRY_INSERT(path_entry_src, index_table_copy5);

            //Update the "alias" of the path entry
            if (path_entry_src_is_lower) {
                path_entry_lower = path_entry_src;
            } else {
                path_entry_upper = path_entry_src;
            }
        }

        //Try to start/request a learning process if...
        //  a) the flow entry is incomplete (e.g. a new flow has just appeared)
        //  b) an asymmetric path is detected (asymmetric paths can form due to packet loss)
        //  c) singular entry/entries are incomplete (they are needed for path entry deletion to work without issues)
        bool request_because_incomplete = IS_MAC_UNICAST(hdr.ethernet.dstAddr)
                && PATH_ENTRY_IS_PERSISTED(path_entry_flow)
                && !PATH_ENTRY_IS_COMPLETE(path_entry_flow);
        bool request_because_asymmetric = IS_MAC_UNICAST(hdr.ethernet.dstAddr)
                && PATH_ENTRY_IS_COMPLETE(path_entry_flow)
                && standard_metadata.ingress_port != PATH_ENTRY_GET_PORT(path_entry_flow, hdr.ethernet.srcAddr);
        bool request_because_singular = IS_MAC_UNICAST(hdr.ethernet.dstAddr)
                && (!PATH_ENTRY_IS_PERSISTED(path_entry_lower) || !PATH_ENTRY_IS_PERSISTED(path_entry_upper));
        if ((request_because_incomplete || request_because_asymmetric || request_because_singular)
                && standard_metadata.ingress_global_timestamp - path_entry_flow.learn_timestamp
                > LEARN_REQUEST_GRACE_PERIOD) {
            log_msg("Attempting to start/request learning; entry incomplete={}; asymmetry={}; singular incomplete={}",
                    {request_because_incomplete, request_because_asymmetric, request_because_singular});

            if (meta.clone_subtype != PNP_SUBTYPE_NONE) {
                log_msg("  cloning for something else was requested -> skipping");
            } else if (leaf_lower) {
                if (standard_metadata.ingress_global_timestamp - path_entry_flow.learn_timestamp
                        <= LEARN_SEND_GRACE_PERIOD) {
                    log_msg("  cloning possible & leaf for lower MAC & active grace period -> skipping");
                } else if (!PATH_ENTRY_IS_PERSISTED(path_entry_lower)) {
                    log_msg("  cloning possible & leaf for lower MAC & singular entry not persisted -> skipping");
                } else {
                    log_msg("  cloning possible & leaf for lower MAC & no grace period -> broadcasting learn packet");

                    //Save that a learn packet was sent and act as if that learn packet had just been received
                    path_entry_flow.port_lower = path_entry_lower.port_lower;
                    if (leaf_upper) {
                        //If the path only contains a single switch, then this is the only way to learn the upper port
                        path_entry_flow.port_upper = path_entry_upper.port_lower;
                    }
                    path_entry_flow.strength_building = PATH_STRENGTH_MAX;
                    path_entry_flow.strength_confirmation = PATH_STRENGTH_UNINITIALIZED;
                    path_entry_flow.learn_timestamp = standard_metadata.ingress_global_timestamp;
                    PATH_ENTRY_SAVE(path_entry_flow);

                    //Send the learn packet
                    meta.clone_subtype = PNP_SUBTYPE_LEARN;
                    meta.clone_flow_id = path_entry_flow.flow_id;
                    clone_preserving_field_list(CloneType.I2E,
                            CLONE_SESSION_ALL_EXCEPT(path_entry_flow.port_lower),
                            CLONE_INDEX_PNP_LEARN);
                }
            } else { // Not the leaf switch
                timestamp_t pnp_request_sent;
                pnp_request_sent_register.read(pnp_request_sent, 0);
                if (standard_metadata.ingress_global_timestamp - pnp_request_sent <= REQUEST_SEND_GRACE_PERIOD) {
                    log_msg("  cloning possible & not lower leaf & active grace period -> skipping");
                } else {
                    log_msg("  cloning possible & not lower leaf & no grace period -> sending request packet");
                    pnp_request_sent = standard_metadata.ingress_global_timestamp;
                    pnp_request_sent_register.write(0, pnp_request_sent);

                    //Send the request packet
                    meta.clone_subtype = PNP_SUBTYPE_REQUEST;
                    meta.clone_flow_id = path_entry_flow.flow_id;
                    //Sending a request packet with an incomplete path entry is tricky, but not impossible.
                    //We must try to send the request packet to a switch that can forward it. If we have learnt the
                    //  flow's lower port, then the switch on the other side of that port is definitely a good choice.
                    //  Using a singular path entry does not guarantee that. Using the ingress port works, even in case
                    //  of one-way traffic from the lower MAC to the higher MAC, because the switch that sent us this
                    //  packet either has a complete path entry or themselves have sent or will send a request packet
                    //  just like the one we need to send. The last remaining option is to do a split horizon: if the
                    //  traffic is one-way from the higher MAC to the lower MAC, then the switches never learn where
                    //  the lower MAC is. So the only way to send a request packet is to do a split horizon and it will
                    //  reach the lower leaf switch (among other switches).
                    if (hdr.ethernet.srcAddr == path_entry_flow.flow_id.mac_lower) {
                        log_msg("  src is lower MAC -> cloning to ingress port");
                        clone_preserving_field_list(CloneType.I2E,
                                CLONE_SESSION_EXACTLY_ONE(standard_metadata.ingress_port),
                                CLONE_INDEX_PNP_REQUEST);
                    } else if (path_entry_flow.port_lower != PATH_ENTRY_PORT_UNINITIALIZED) {
                        log_msg("  flow entry lower MAC port is initialized -> cloning to lower MAC port");
                        //  PS: the switch port_lower points to might have had its path entry removed,
                        //  but in that case it'll just send a request packet itself, so there is no problem.
                        clone_preserving_field_list(CloneType.I2E,
                                CLONE_SESSION_EXACTLY_ONE(path_entry_flow.port_lower),
                                CLONE_INDEX_PNP_REQUEST);
                    } else {
                        log_msg("  lower MAC port is unknown -> split horizon");
                        //Split horizon won't cause a flood because the PNP request handling code will
                        //  drop the packet (instead of doing a split horizon) if the lower MAC port is unknown.
                        clone_preserving_field_list(CloneType.I2E,
                                CLONE_SESSION_ALL_EXCEPT(standard_metadata.ingress_port),
                                CLONE_INDEX_PNP_REQUEST);
                    }
                }
            }
        }

        //Update the path entry's timestamp to show that the entry is still being used (and shouldn't be timed out)
        if (PATH_ENTRY_IS_PERSISTED(path_entry_flow) && standard_metadata.ingress_global_timestamp
                - path_entry_flow.learn_timestamp > LEARN_TIMESTAMP_GRACE_PERIODS_MAX) {
            path_entry_flow.learn_timestamp = standard_metadata.ingress_global_timestamp
                    - LEARN_TIMESTAMP_GRACE_PERIODS_MAX - 1;
            PATH_ENTRY_SAVE(path_entry_flow);
        }

        //Forward the packet if possible
        //We must only forward a packet when the singular src port could be persisted, even if we aren't forwarding via
        //  split horizon. The reason: we learn from these packets and the learnt ports should only point to switches
        //  that have already learnt the singular src port. This way loops can't form. If we didn't do this, then due
        //  to already existing dst singular entries, a switch between two other switches that hasn't learnt the src
        //  port and a path learnt in the opposite direction could cause a loop.
        if (PATH_ENTRY_IS_PERSISTED(path_entry_src) && IS_MAC_UNICAST(hdr.ethernet.dstAddr)) {
            log_msg("Path handling: unicast");
            if (PATH_ENTRY_IS_COMPLETE(path_entry_flow)) {
                //We just filled the source port, so if destination port is filled, then the flow is complete.
                log_msg("  complete flow entry -> forwarding");
                standard_metadata.egress_spec = PATH_ENTRY_GET_PORT(path_entry_flow, hdr.ethernet.dstAddr);
            } else if (PATH_ENTRY_IS_COMPLETE(path_entry_dst)) {
                log_msg("  incomplete flow entry & known destination -> forwarding");
                standard_metadata.egress_spec = path_entry_dst.port_lower;
            } else if (path_entry_src.port_lower == standard_metadata.ingress_port) {
                log_msg("  incomplete flow entry & unknown destination & correct source port -> split horizon");
                standard_metadata.mcast_grp = MULTICAST_GROUP_ALL_EXCEPT(standard_metadata.ingress_port);
            } else {
                log_msg("  incomplete flow entry & unknown destination & incorrect source port -> dropping");
                mark_to_drop(standard_metadata);
                exit;
            }
        } else if (PATH_ENTRY_IS_PERSISTED(path_entry_src)) {
            log_msg("Path handling: broadcast/multicast");
            if (path_entry_src.port_lower == standard_metadata.ingress_port) {
                log_msg("  correct source port -> split horizon");
                standard_metadata.mcast_grp = MULTICAST_GROUP_ALL_EXCEPT(standard_metadata.ingress_port);
            } else {
                log_msg("  incorrect source port -> dropping");
                mark_to_drop(standard_metadata);
                exit;
            }
        } else {
            log_msg("Path handling: singular src port not persisted -> dropping");
            mark_to_drop(standard_metadata);
            exit;
        }

        //Determine whether we are allowed to send a PNP request check.
        if (!IS_MAC_UNICAST(hdr.ethernet.dstAddr)) {
            //In this case the flow entry does not exist, there is nothing to reroute.
            log_msg("not unicast destination -> sending pnp request disallowed");
            meta.can_send_request = false;
        } else if (!PATH_ENTRY_IS_COMPLETE(path_entry_flow)) {
            //In this case a request packet is sent because of the incomplete flow entry
            log_msg("incomplete flow entry -> sending pnp request disallowed");
            meta.can_send_request = false;
        } else if (standard_metadata.ingress_global_timestamp - path_entry_flow.learn_timestamp
                <= LEARN_REQUEST_GRACE_PERIOD) {
            log_msg("current path was recently learned -> sending pnp request disallowed");
            meta.can_send_request = false;
        } else if (leaf_lower && leaf_upper) {
            //Neither of the two links have alternative paths, so we can't reroute traffic.
            log_msg("lower and upper leaf switch -> sending pnp request disallowed");
            meta.can_send_request = false;
        } else if (IS_PORT_LEAF(standard_metadata.egress_spec)) {
            //unicast && path entry complete && we haven't "returned" yet -> egress_spec is set to a real port
            log_msg("packet going to leaf switch -> sending pnp request disallowed");
            meta.can_send_request = false;
        } else {
            log_msg("complete&late learned flow entry & not disallowed leaf  -> sending pnp request allowed");
            meta.can_send_request = true;

            if (!leaf_lower) {
                //The path entry is complete, so the lower port is known. If it is known, then it points to a switch
                //  that can forward our request. If the path entry is not complete, then we send a request packet
                //  for another reason and sooner or later get a complete flow entry.
                //  PS: the switch port_lower points to might have had its path entry removed, but in that case it'll
                //  just send a request packet itself, so there is no problem.
                meta.request_clone_session = CLONE_SESSION_EXACTLY_ONE(path_entry_flow.port_lower);
            } else {
                //We are the lower leaf, we need to be the one receiving the request packet. The easiest way to
                //  implement that is to send a request packet to another switch, which will send it back to us.
                meta.request_clone_session = CLONE_SESSION_EXACTLY_ONE(path_entry_flow.port_upper);
            }
        }
    }
}

#endif //SWITCH_INGRESS_P4

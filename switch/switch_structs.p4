#ifndef SWITCH_STRUCTS_P4
#define SWITCH_STRUCTS_P4

#include <core.p4>
#include <v1model.p4>
#include "switch_typedefs.p4"
#include "switch_globals.p4"

/*********************/
/** FLOW IDENTIFIER **/
/*********************/

//The flow specifier is calculated by hashing an instance of the following struct.
// The source and destination fields are interpreted from the lower MAC's point of view.
struct flow_specifier_pre_hash_t {
    etherType_t ether_type;
    ip4Addr_t ipv4_src;
    ip4Addr_t ipv4_dst;
    protocol_t protocol;
    protocol_port_t port_src;
    protocol_port_t port_dst;
}

//Field declarations for the flow identifier. This digest(s) can also have the same fields.
//Why this is necessary: because digests can't contain other structs.
#define FLOW_ID_BODY \
        macAddr_t mac_lower; \
        macAddr_t mac_upper; \
        flow_specifier_t specifier;

struct flow_id_t { FLOW_ID_BODY }

//Extracts the fields of the specified flow identifier. Useful for new instance initialization or debug logging.
#define FLOW_ID_FIELDS(ID) ID.mac_lower, ID.mac_upper, ID.specifier

/****************/
/** PATH ENTRY **/
/****************/

struct path_entry_t {
    path_storage_t storage; //how or whether this entry is persisted
    path_index_t index; //index for hash register or index register
    bit<1> initialized; //whether the path entry register slot contains real data or is empty
    flow_id_t flow_id;
    portId_t port_lower; //port that leads towards the lower MAC in the flow id
    portId_t port_upper; //port that leads towards the upper MAC in the flow id
    path_strength_t strength_building; //strength of the path's "non-confirmation" direction (from lower to upper MAC)
    path_strength_t strength_confirmation; //strength of the path's "confirmation" direction (from upper to lower MAC)
    timestamp_t learn_timestamp; //when the last learn packet was sent or non-confirmation learn packet was received
}

const path_storage_t PATH_ENTRY_STORAGE_INVALID = 0; //path entry is uninitialized or invalid for some other reason
const path_storage_t PATH_ENTRY_STORAGE_INDEX = 1; //index register contains entry
const path_storage_t PATH_ENTRY_STORAGE_HASH = 2; //hash register contains entry
const path_storage_t PATH_ENTRY_STORAGE_MISS_AND_INDEX_FREE = 3; //no persisted data, index table contains MAC
const path_storage_t PATH_ENTRY_STORAGE_MISS_AND_INDEX_MISSING = 4; //no persisted data, index table doesn't contain MAC
const path_storage_t PATH_ENTRY_BEING_DELETED = 5; //control plane is freeing this entry up, don't use it

//Is the path entry persisted? Can it be saved, or do we need to try to insert it first?
#define PATH_ENTRY_IS_PERSISTED(E) (E.storage == PATH_ENTRY_STORAGE_HASH || E.storage == PATH_ENTRY_STORAGE_INDEX)

//Special port value indicating that a direction in a path entry is unknown.
//The value '0' is used because it is the default value for values in registers.
const portId_t PATH_ENTRY_PORT_UNINITIALIZED = 0;

//Gets the flow id of the pseudo-entry responsible for storing in which direction a MAC can be found.
#define PATH_ENTRY_GET_SINGULAR_FLOW_ID(MAC) {MAC, MAC_BROADCAST, 0}

//Whether the path entry is about a real flow (between two unicast addresses),
// or if the path entry is just a pseudo-entry storing in which direction a MAC can be found.
#define PATH_ENTRY_IS_SINGULAR_FLOW_ID(ID) (ID.mac_upper == MAC_BROADCAST)
#define PATH_ENTRY_IS_SINGULAR(E) PATH_ENTRY_IS_SINGULAR_FLOW_ID(E.flow_id)

//Returns true if both ports are known (or if the path entry is singular and the only port is known).
#define PATH_ENTRY_IS_COMPLETE(E) (E.port_lower != PATH_ENTRY_PORT_UNINITIALIZED \
        && (E.port_upper != PATH_ENTRY_PORT_UNINITIALIZED || PATH_ENTRY_IS_SINGULAR(E)))

//Returns the port associated with the specified MAC address.
//The specified MAC address must be either the lower or the upper MAC address of the flow identifier.
#define PATH_ENTRY_GET_PORT(E, MAC) (MAC == E.flow_id.mac_lower ? E.port_lower : E.port_upper)

/*****************/
/** INDEX TABLE **/
/*****************/

struct index_table_row_t {
    flow_id_t flow_id;
    path_index_t index;
}

struct digest_index_table_insert1_t {
    FLOW_ID_BODY
    timestamp_t current_time; //Thanks to this field the control plane can detect timed out path entries.
    //  Without this field, the control plane doesn't know the current time and the best it can do is take
    //  the maximum of the timestamp it knows about, which is sub-ideal.
}

// A digest can only be sent once per control invocation. If we want to send the same digest multiple times,
// we either duplicate the digest's fields or duplicate the digest (the struct) itself.
struct digest_index_table_insert2_t {
    FLOW_ID_BODY
    timestamp_t current_time;
}

/*************/
/** V1MODEL **/
/*************/

//Clone session indexes used by the @field_list annotation.
const int CLONE_INDEX_PNP_TEST = 1;
const int CLONE_INDEX_PNP_LEARN = 2;
const int CLONE_INDEX_PNP_REQUEST = 3;

//Container of information associated with a packet, valid across controls.
struct metadata {
    @field_list(CLONE_INDEX_PNP_TEST, CLONE_INDEX_PNP_LEARN, CLONE_INDEX_PNP_REQUEST)
    pnp_subtype_t clone_subtype;
    @field_list(CLONE_INDEX_PNP_LEARN, CLONE_INDEX_PNP_REQUEST)
    flow_id_t clone_flow_id;

    flow_id_t flow_id; //Flow id of the (PNP/normal) packet, if it exists. Otherwise a singular flow id.

    bool can_decrease_strength; //Can the learn packet strength be decreased if the switch/link is overloaded?
    bool can_send_request; //Can a PNP request packet be sent if the switch/link is overloaded?
    clone_session_t request_clone_session; //Set if 'can_send_request'. Clone session to use for PNP request packets.
}

#endif //SWITCH_STRUCTS_P4

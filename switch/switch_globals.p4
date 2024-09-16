#ifndef SWITCH_GLOBALS_P4
#define SWITCH_GLOBALS_P4

#include <core.p4>
#include <v1model.p4>
#include "switch_typedefs.p4"

/*******************/
/** MAC ADDRESSES **/
/*******************/

const macAddr_t MAC_BROADCAST = 0xFFFFFFFFFFFF;

//Returns whether the specified MAC address is a multicast address.
#define IS_MAC_UNICAST(MAC) (MAC[40:40] == 0)

/********************/
/** MATH FUNCTIONS **/
/********************/

//Convert seconds/milliseconds to microseconds.
#define SEC_TO_MICROS(MILLI) (MILLI * 1000000)
#define MILLIS_TO_MICROS(MILLI) (MILLI * 1000)

//The smaller/greater of two values.
#define MIN(A, B) ((A) < (B) ? (A) : (B))
#define MAX(A, B) ((A) > (B) ? (A) : (B))

/*******************/
/** CONTROL PLANE **/
/*******************/

//Mathematical helper methods that the control plane also uses.
#define CP_PORT_ALL (~((bit<MAX_PORT_COUNT>) 0))
#define CP_PORT_FLIP(PORTS, FLIP) (PORTS ^ ((bit<MAX_PORT_COUNT>) 1 << (shift_port_id_t) FLIP - 1))

//Multicast group that sends to all ports except the specified one (split horizon).
#define MULTICAST_GROUP_ALL_EXCEPT(P) ((mcast_grp_t) CP_PORT_FLIP(CP_PORT_ALL, P))

//Clone session that sends the clone to all ports.
const clone_session_t CLONE_SESSION_BROADCAST = (clone_session_t) CP_PORT_ALL;

//Clone session that sends the clone just to the specified port.
#define CLONE_SESSION_EXACTLY_ONE(P) ((clone_session_t) CP_PORT_FLIP(0, P))

//Clone session that sends the clone just to all ports except the specified one (split horizon).
#define CLONE_SESSION_ALL_EXCEPT(P) ((clone_session_t) CP_PORT_FLIP(CP_PORT_ALL, P))

/*************/
/** LOGGING **/
/*************/

//Extracts the 4 8-bit IPv4 components, separated by commas. Useful for logging.
#define SLICE_IPV4_ADDRESS(ADDRESS) (ADDRESS)[31:24], (ADDRESS)[23:16], (ADDRESS)[15:8], (ADDRESS)[7:0]

/***********************/
/** V1MODEL EXTENSION **/
/***********************/

//https://github.com/p4lang/behavioral-model/blob/adff022fc8679f5436d07e7af73c3300431df785/targets/simple_switch/simple_switch.h#L146-L154
const bit<32> INSTANCE_TYPE_NORMAL = 0;
const bit<32> INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> INSTANCE_TYPE_EGRESS_CLONE = 2;
const bit<32> INSTANCE_TYPE_COALESCED = 3;
const bit<32> INSTANCE_TYPE_RECIRC = 4;
const bit<32> INSTANCE_TYPE_REPLICATION = 5;
const bit<32> INSTANCE_TYPE_RESUBMIT = 6;

/***********/
/** OTHER **/
/***********/

//Different path strength values. Packets contain values between min and max.
//The uninitialized value means that no learn packet has been received or the strength has been cleared.
const path_strength_t PATH_STRENGTH_UNINITIALIZED = 0; //it is 0 because that is the default value for registers values
const path_strength_t PATH_STRENGTH_MIN = 1;
const path_strength_t PATH_STRENGTH_MAX = (1 << PATH_STRENGTH_T_WIDTH) - 1;

/*******************/
/** CONFIGURATION **/
/*******************/

//Storage size configuration. How many full entries can be stored in the different storage mechanisms.
const int PATH_HASH_REGISTER_SIZE = 256;
const int PATH_REGISTER_SIZE = 1024;

//Path learning configuration.
//Learn send grace period: a new learning process should not be started before the previous one has finished.
//  (Each flow has its own countdown.)
//Learn request grace period: how long should switches be disallowed from requesting a path change after the path has
//  just been learnt? (Each flow has its own countdown.) This grace periods protects paths from incorrectly being
//  labelled as asymmetric, and it also reduces the amount of "useless" request packets that are sent.
//Request send grace period: how long the switch should wait between sending path change request packets?
//  (A single countdown is shared by all flows.)
//Overloaded duration: how long the switch should be considered overloaded when an "excess" packet is received.
//  A packet is "excess" if the switch has already received the allowed number of packets within a time period.
//Path entry timeout: path entries that are unused for at least this long are allowed to be freed up (removed) by the
//  control plane. This only applies to the path register, not the path hash register.
const int LEARN_SEND_GRACE_PERIOD = SEC_TO_MICROS(1);
const int LEARN_REQUEST_GRACE_PERIOD = SEC_TO_MICROS(1);
const int LEARN_TIMESTAMP_GRACE_PERIODS_MAX = MAX((bit<32>) LEARN_SEND_GRACE_PERIOD, LEARN_REQUEST_GRACE_PERIOD);
const int REQUEST_SEND_GRACE_PERIOD = MILLIS_TO_MICROS(100);
const int OVERLOADED_DURATION = MILLIS_TO_MICROS(50);
const int PATH_ENTRY_TIMEOUT_MICROS = SEC_TO_MICROS(5);

//The egress queue depth over which the link should be considered overloaded.
const int OVERLOADED_QUEUE_TIMEDELTA = MILLIS_TO_MICROS(35);

#endif //SWITCH_GLOBALS_P4

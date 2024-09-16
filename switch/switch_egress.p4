#ifndef SWITCH_EGRESS_P4
#define SWITCH_EGRESS_P4

#include <core.p4>
#include <v1model.p4>
#include "switch_typedefs.p4"
#include "switch_globals.p4"
#include "switch_headers.p4"
#include "switch_structs.p4"

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    //Status (register): egress timestamp when the Nth port was last detected as overloaded.
    register<timestamp_t>(1 << PORT_ID_T_WIDTH) egress_overloaded_status_register;
    timestamp_t egress_ingress_overloaded_status;
    timestamp_t egress_egress_overloaded_status;
    #define IS_INGRESS_PORT_OVERLOADED (standard_metadata.egress_global_timestamp \
            - egress_ingress_overloaded_status < OVERLOADED_DURATION \
            && (/* Clone ingress port doesn't matter */ standard_metadata.instance_type == INSTANCE_TYPE_NORMAL \
            || standard_metadata.instance_type == INSTANCE_TYPE_REPLICATION))
    #define IS_EGRESS_PORT_OVERLOADED (standard_metadata.egress_global_timestamp \
            - egress_egress_overloaded_status < OVERLOADED_DURATION)

    //Sent register: egress timestamp when the path change request PNP packet was last sent.
    //  Optimally we would use the same register as in ingress processing, but keeping separate registers for the
    //  separate operations enables greater separation and is not a huge issue. Worst case scenario is that we end
    //  up rerouting two flows, when rerouting a single flow would have been enough.
    register<timestamp_t>(1) egress_pnp_request_sent_register;

    apply {
        log_msg(">>> BEGIN egress (port={})", {standard_metadata.egress_port});

        //Handle cloned packets
        if (standard_metadata.instance_type == INSTANCE_TYPE_INGRESS_CLONE
                || standard_metadata.instance_type == INSTANCE_TYPE_EGRESS_CLONE) {
            //Invalidate all headers except ethernet and set the ethernet headers
            //MACs are set to a custom address so that hosts don't try to handle this packet
            // (and so our own switches don't try to learn the source, if they were to try and learn from this ether type).
            INVALIDATE_ALL_HEADERS(hdr);
            hdr.ethernet.setValid();
            hdr.ethernet.etherType = ETHER_TYPE_PNP;
            hdr.ethernet.srcAddr = MAC_PNP_INTERNAL;
            hdr.ethernet.dstAddr = MAC_PNP_INTERNAL;

            //Set up the PNP packet
            hdr.pnp_base.setValid();
            hdr.pnp_base.subtype = meta.clone_subtype;
            if (meta.clone_subtype == PNP_SUBTYPE_TEST) {
                hdr.pnp_test.setValid();
                hdr.pnp_test.reply = 0;
            } else if (meta.clone_subtype == PNP_SUBTYPE_LEARN) {
                hdr.pnp_learn.setValid();
                hdr.pnp_learn.flow_id = meta.clone_flow_id;
                hdr.pnp_learn.strength = PATH_STRENGTH_MAX;
                hdr.pnp_learn.confirmation = 0;
                hdr.pnp_learn.singular_learn = 1;
            } else if (meta.clone_subtype == PNP_SUBTYPE_REQUEST) {
                hdr.pnp_request.setValid();
                hdr.pnp_request.flow_id = meta.clone_flow_id;
            } else {
                log_msg("ERROR: invalid clone subtype: {}", {meta.clone_subtype});
                assert(false);
            }
            exit;
        } else {
            //In case we want to do cloning during egress processing, save that no cloning has been requested yet.
            meta.clone_subtype = PNP_SUBTYPE_NONE;
        }

        if (standard_metadata.instance_type != INSTANCE_TYPE_NORMAL
                && standard_metadata.instance_type != INSTANCE_TYPE_REPLICATION) {
            log_msg("ERROR: unexpected instance type: {}", {standard_metadata.instance_type});
            assert(false);
        }

        //Determine whether the ingress and egress ports are overloaded
        egress_overloaded_status_register.read(egress_ingress_overloaded_status,
                (bit<32>) standard_metadata.ingress_port);
        if (standard_metadata.deq_timedelta < OVERLOADED_QUEUE_TIMEDELTA) {
            egress_overloaded_status_register.read(egress_egress_overloaded_status,
                    (bit<32>) standard_metadata.egress_port);
        } else {
            log_msg("Overloaded detection: link {} is overloaded", {standard_metadata.egress_port});
            egress_egress_overloaded_status = standard_metadata.egress_global_timestamp;
            egress_overloaded_status_register.write((bit<32>) standard_metadata.egress_port,
                    egress_egress_overloaded_status);
        }

        //Update the learn packet strength if link is overloaded
        if (hdr.pnp_learn.isValid() && meta.can_decrease_strength) {
            //We must check both the ingress and the egress ports: the learn packet only travels the network in
            //  a single direction. If we only checked the egress port and the overloading was happening in the
            //  opposite direction (compared to the learn packet's direction), we would never decrease the strength.
            if (IS_INGRESS_PORT_OVERLOADED && hdr.pnp_learn.strength > PATH_STRENGTH_MIN) {
                log_msg("ingress link overloaded & strength > min -> decreasing packet strength");
                //TODO this should optimally be done during ingress processing, before we use the packet's strength
                //Reason: currently the upper leaf switch ingress port's overloaded status is not taken into account
                hdr.pnp_learn.strength = hdr.pnp_learn.strength - 1;
            } else {
                log_msg("ingress link not overloaded or strength <= min -> keeping packet strength");
            }
            if (IS_EGRESS_PORT_OVERLOADED && hdr.pnp_learn.strength > PATH_STRENGTH_MIN) {
                log_msg("egress link overloaded & strength > min -> decreasing packet strength");
                hdr.pnp_learn.strength = hdr.pnp_learn.strength - 1;
            } else {
                log_msg("egress link not overloaded or strength <= min -> keeping packet strength");
            }
        }

        //PNP packets have been handled, the rest only concerns normal packets
        if (hdr.pnp_base.isValid()) {
            exit;
        }

        //Print some information
        log_msg("Normal packet; port={}; time={}; length={}; deq_timedelta={}",
                {standard_metadata.egress_port, standard_metadata.egress_global_timestamp,
                standard_metadata.packet_length, standard_metadata.deq_timedelta});

        if (meta.can_send_request && IS_EGRESS_PORT_OVERLOADED) {
            log_msg("Overloaded & might be able to send request packet -> checking");
            timestamp_t pnp_request_sent;
            egress_pnp_request_sent_register.read(pnp_request_sent, 0);
            if (meta.clone_subtype != PNP_SUBTYPE_NONE) {
                log_msg("  cloning for something else was requested -> ignoring");
            } else if (standard_metadata.egress_global_timestamp - pnp_request_sent <= REQUEST_SEND_GRACE_PERIOD) {
                log_msg("  active grace period -> ignoring");
            } else {
                log_msg("  cloning possible & no grace period -> go");

                //Save that a request packet was sent
                pnp_request_sent = standard_metadata.egress_global_timestamp;
                egress_pnp_request_sent_register.write(0, pnp_request_sent);

                //Send the request packet
                meta.clone_subtype = PNP_SUBTYPE_REQUEST;
                meta.clone_flow_id = meta.flow_id;
                clone_preserving_field_list(CloneType.E2E, meta.request_clone_session, CLONE_INDEX_PNP_REQUEST);
            }
        }
    }
}

#endif //SWITCH_EGRESS_P4

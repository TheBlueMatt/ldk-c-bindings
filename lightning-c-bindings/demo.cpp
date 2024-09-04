extern "C" {
#include <lightning.h>

#ifdef REAL_NET
#include <ldk_net.h>
#endif
}
#include "include/lightningpp.hpp"

#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <mutex>
#include <vector>
#include <iostream>

const uint8_t valid_node_announcement[] = {
	0x94, 0xe4, 0xf5, 0x61, 0x41, 0x24, 0x7d, 0x90, 0x23, 0xa0, 0xc8, 0x34, 0x8c, 0xc4, 0xca, 0x51,
	0xd8, 0x17, 0x59, 0xff, 0x7d, 0xac, 0x8c, 0x9b, 0x63, 0x29, 0x1c, 0xe6, 0x12, 0x12, 0x93, 0xbd,
	0x66, 0x4d, 0x6b, 0x9c, 0xfb, 0x35, 0xda, 0x16, 0x06, 0x3d, 0xf0, 0x8f, 0x8a, 0x39, 0x99, 0xa2,
	0xf2, 0x5d, 0x12, 0x0f, 0x2b, 0x42, 0x1b, 0x8b, 0x9a, 0xfe, 0x33, 0x0c, 0xeb, 0x33, 0x5e, 0x52,
	0xee, 0x99, 0xa1, 0x07, 0x06, 0xed, 0xf8, 0x48, 0x7a, 0xc6, 0xe5, 0xf5, 0x5e, 0x01, 0x3a, 0x41,
	0x2f, 0x18, 0x94, 0x8a, 0x3b, 0x0a, 0x52, 0x3f, 0xbf, 0x61, 0xa9, 0xc5, 0x4f, 0x70, 0xee, 0xb8,
	0x79, 0x23, 0xbb, 0x1a, 0x44, 0x7d, 0x91, 0xe6, 0x2a, 0xbc, 0xa1, 0x07, 0xbc, 0x65, 0x3b, 0x02,
	0xd9, 0x1d, 0xb2, 0xf2, 0x3a, 0xcb, 0x75, 0x79, 0xc6, 0x66, 0xd8, 0xc1, 0x71, 0x29, 0xdf, 0x04,
	0x60, 0xf4, 0xbf, 0x07, 0x7b, 0xb9, 0xc2, 0x11, 0x94, 0x6a, 0x28, 0xc2, 0xdd, 0xd8, 0x7b, 0x44,
	0x8f, 0x08, 0xe3, 0xc8, 0xd8, 0xf4, 0x81, 0xb0, 0x9f, 0x94, 0xcb, 0xc8, 0xc1, 0x3c, 0xc2, 0x6e,
	0x31, 0x26, 0xfc, 0x33, 0x16, 0x3b, 0xe0, 0xde, 0xa1, 0x16, 0x21, 0x9f, 0x89, 0xdd, 0x97, 0xa4,
	0x41, 0xf2, 0x9f, 0x19, 0xb1, 0xae, 0x82, 0xf7, 0x85, 0x9a, 0xb7, 0x8f, 0xb7, 0x52, 0x7a, 0x72,
	0xf1, 0x5e, 0x89, 0xe1, 0x8a, 0xcd, 0x40, 0xb5, 0x8e, 0xc3, 0xca, 0x42, 0x76, 0xa3, 0x6e, 0x1b,
	0xf4, 0x87, 0x35, 0x30, 0x58, 0x43, 0x04, 0xd9, 0x2c, 0x50, 0x54, 0x55, 0x47, 0x6f, 0x70, 0x9b,
	0x42, 0x1f, 0x91, 0xfc, 0xa1, 0xdb, 0x72, 0x53, 0x96, 0xc8, 0xe5, 0xcd, 0x0e, 0xcb, 0xa0, 0xfe,
	0x6b, 0x08, 0x77, 0x48, 0xb7, 0xad, 0x4a, 0x69, 0x7c, 0xdc, 0xd8, 0x04, 0x28, 0x35, 0x9b, 0x73,
	0x00, 0x00, 0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71, 0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce,
	0xc3, 0xae, 0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad, 0x01, 0xea, 0x33, 0x09, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x5b, 0xe5, 0xe9, 0x47, 0x82,
	0x09, 0x67, 0x4a, 0x96, 0xe6, 0x0f, 0x1f, 0x03, 0x7f, 0x61, 0x76, 0x54, 0x0f, 0xd0, 0x01, 0xfa,
	0x1d, 0x64, 0x69, 0x47, 0x70, 0xc5, 0x6a, 0x77, 0x09, 0xc4, 0x2c, 0x03, 0x5c, 0x4e, 0x0d, 0xec,
	0x72, 0x15, 0xe2, 0x68, 0x33, 0x93, 0x87, 0x30, 0xe5, 0xe5, 0x05, 0xaa, 0x62, 0x50, 0x4d, 0xa8,
	0x5b, 0xa5, 0x71, 0x06, 0xa4, 0x6b, 0x5a, 0x24, 0x04, 0xfc, 0x9d, 0x8e, 0x02, 0xba, 0x72, 0xa6,
	0xe8, 0xba, 0x53, 0xe8, 0xb9, 0x71, 0xad, 0x0c, 0x98, 0x23, 0x96, 0x8a, 0xef, 0x4d, 0x78, 0xce,
	0x8a, 0xf2, 0x55, 0xab, 0x43, 0xdf, 0xf8, 0x30, 0x03, 0xc9, 0x02, 0xfb, 0x8d, 0x02, 0x16, 0x34,
	0x5b, 0xf8, 0x31, 0x16, 0x4a, 0x03, 0x75, 0x8e, 0xae, 0xa5, 0xe8, 0xb6, 0x6f, 0xee, 0x2b, 0xe7,
	0x71, 0x0b, 0x8f, 0x19, 0x0e, 0xe8, 0x80, 0x24, 0x90, 0x32, 0xa2, 0x9e, 0xd6, 0x6e
};

// A simple block containing only one transaction (which is the channel-open transaction for the
// channel we'll create). This was originally created by printing additional data in a simple
// rust-lightning unit test.
//
// Note that the merkle root is incorrect, but it isn't ever checked by LDK, so should be fine.
const uint8_t channel_open_block[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xa2, 0x47, 0xd2, 0xf8, 0xd4, 0xe0, 0x6a, 0x3f, 0xf9, 0x7a, 0x9a, 0x34,
	0xbb, 0xa9, 0x96, 0xde, 0x63, 0x84, 0x5a, 0xce, 0xcf, 0x98, 0xb8, 0xbb, 0x75, 0x4c, 0x4f, 0x7d,
	0xee, 0x4c, 0xa9, 0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, // transaction count
	0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x40, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x20, 0xc5, 0x1c, 0xad, 0x5e,
	0x51, 0x11, 0xb0, 0x11, 0xa1, 0x14, 0xf4, 0xda, 0x02, 0x3d, 0xbc, 0xc1, 0x44, 0x3c, 0x67, 0x31,
	0xec, 0x6f, 0x10, 0x2f, 0x89, 0xc1, 0x05, 0x80, 0xfe, 0xfc, 0xd6, 0xc7, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00
};

// The first transaction in the block is header (80 bytes) + transaction count (1 byte) into the block data.
const uint8_t channel_open_txid[] = {
	0x7a, 0x14, 0x8f, 0xb4, 0x08, 0x49, 0x9b, 0x51, 0x2e, 0xff, 0xf9, 0x46, 0x73, 0xca, 0xc6, 0x48,
	0xfd, 0x95, 0x0e, 0x72, 0xd4, 0xd3, 0xdb, 0x79, 0xc9, 0x20, 0xed, 0x83, 0xb2, 0xde, 0xed, 0x41,
};

// Two blocks built on top of channel_open_block:
const uint8_t block_1[81] = {
	0x01, 0x00, 0x00, 0x00, 0x0c, 0x7a, 0xc2, 0xdc, 0x08, 0xaf, 0x40, 0x7d, 0x58, 0x81, 0x9b, 0x44,
	0xc7, 0xe0, 0x0f, 0x78, 0xc0, 0xd1, 0x01, 0xa2, 0x03, 0x16, 0x4a, 0x8d, 0x92, 0x66, 0x4e, 0xaf,
	0x7f, 0xfc, 0x6e, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, // transaction count
};
const uint8_t block_2[81] = {
	0x01, 0x00, 0x00, 0x00, 0x36, 0x0b, 0xf5, 0x46, 0x4a, 0xc7, 0x26, 0x4c, 0x4b, 0x36, 0xa6, 0x9d,
	0x0e, 0xf0, 0x14, 0xfb, 0x8a, 0xcb, 0x20, 0x84, 0x18, 0xf3, 0xaa, 0x77, 0x32, 0x2d, 0xf7, 0x48,
	0x62, 0x92, 0xb1, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, // transaction count
};

void print_log(const void *this_arg, LDKRecord record_arg) {
	LDK::Record record(std::move(record_arg));
	LDK::Str mod = Record_get_module_path(&record);
	LDK::Str str = Record_get_args(&record);
	printf("%p - %.*s:%d - %.*s\n", this_arg, (int)mod->len, mod->chars, Record_get_line(&record), (int)str->len, str->chars);
}

uint32_t get_fee(const void *this_arg, LDKConfirmationTarget target) {
	if (target == LDKConfirmationTarget_AnchorChannelFee || target == LDKConfirmationTarget_MinAllowedAnchorChannelRemoteFee) {
		return 253;
	} else {
		return 507;
	}
	// Note that we don't call _free() on target, but that's OK, its unitary
}
// We use the same fee estimator globally:
const LDKFeeEstimator fee_est {
	.this_arg = NULL,
	.get_est_sat_per_1000_weight = get_fee,
	.free = NULL,
};

static std::atomic_int num_txs_broadcasted(0);
void broadcast_txn(const void *this_arg, LDKCVec_TransactionZ txn) {
	num_txs_broadcasted += 1;
	CVec_TransactionZ_free(txn);
}

struct NodeMonitors {
	std::mutex mut;
	std::vector<std::pair<LDK::OutPoint, LDK::ChannelMonitor>> mons;
	LDKLogger* logger;

	void ConnectBlock(const uint8_t (*header)[80], uint32_t height, LDKCVec_C2Tuple_usizeTransactionZZ tx_data, LDKBroadcasterInterface broadcast, LDKFeeEstimator fee_est) {
		std::unique_lock<std::mutex> l(mut);
		for (auto& mon : mons) {
			LDK::CVec_TransactionOutputsZ res = ChannelMonitor_block_connected(&mon.second, header, tx_data, height, broadcast, fee_est, logger);
		}
	}
};

LDKCResult_ChannelMonitorUpdateStatusNoneZ add_channel_monitor(const void *this_arg, LDKOutPoint funding_txo_arg, LDKChannelMonitor monitor_arg) {
	// First bind the args to C++ objects so they auto-free
	LDK::ChannelMonitor mon(std::move(monitor_arg));
	LDK::OutPoint funding_txo(std::move(funding_txo_arg));

	NodeMonitors* arg = (NodeMonitors*) this_arg;
	std::unique_lock<std::mutex> l(arg->mut);

	arg->mons.push_back(std::make_pair(std::move(funding_txo), std::move(mon)));
	return CResult_ChannelMonitorUpdateStatusNoneZ_ok(ChannelMonitorUpdateStatus_completed());
}
static std::atomic_int mons_updated(0);
LDKChannelMonitorUpdateStatus update_channel_monitor(const void *this_arg, LDKOutPoint funding_txo_arg, const LDKChannelMonitorUpdate *update) {
	// First bind the args to C++ objects so they auto-free
	LDK::OutPoint funding_txo(std::move(funding_txo_arg));

	NodeMonitors* arg = (NodeMonitors*) this_arg;
	std::unique_lock<std::mutex> l(arg->mut);

	bool updated = false;
	for (auto& mon : arg->mons) {
		if (OutPoint_get_index(&mon.first) == OutPoint_get_index(&funding_txo) &&
				!memcmp(OutPoint_get_txid(&mon.first), OutPoint_get_txid(&funding_txo), 32)) {
			updated = true;
			LDKBroadcasterInterface broadcaster = {
				.broadcast_transactions = broadcast_txn,
			};
			LDK::CResult_NoneNoneZ res = ChannelMonitor_update_monitor(&mon.second, update, &broadcaster, &fee_est, arg->logger);
			assert(res->result_ok);
		}
	}
	assert(updated);

	mons_updated += 1;
	return ChannelMonitorUpdateStatus_completed();
}
LDKCVec_C4Tuple_OutPointChannelIdCVec_MonitorEventZPublicKeyZZ monitors_pending_monitor_events(const void *this_arg) {
	NodeMonitors* arg = (NodeMonitors*) this_arg;
	std::unique_lock<std::mutex> l(arg->mut);

	if (arg->mons.size() == 0) {
		return LDKCVec_C4Tuple_OutPointChannelIdCVec_MonitorEventZPublicKeyZZ {
			.data = NULL,
			.datalen = 0,
		};
	} else {
		// We only ever actually have one channel per node, plus concatenating two
		// Rust Vecs to each other from C++ will require a bit of effort.
		assert(arg->mons.size() == 1);
		LDK::CVec_MonitorEventZ events = ChannelMonitor_get_and_clear_pending_monitor_events(&arg->mons[0].second);
		LDK::C2Tuple_OutPointCVec_u8ZZ funding_info = ChannelMonitor_get_funding_txo(&arg->mons[0].second);
		LDK::OutPoint outpoint = std::move(funding_info->a);
		LDKPublicKey counterparty_node_id = ChannelMonitor_get_counterparty_node_id(&arg->mons[0].second);
		LDKThirtyTwoBytes channel_id;
		memset(&channel_id, 0, sizeof(channel_id));
		LDK::ChannelId chan_id = ChannelId_new(channel_id);
		LDK::C4Tuple_OutPointChannelIdCVec_MonitorEventZPublicKeyZ tuple = C4Tuple_OutPointChannelIdCVec_MonitorEventZPublicKeyZ_new(std::move(outpoint), std::move(chan_id), std::move(events), std::move(counterparty_node_id));
		auto vec = LDKCVec_C4Tuple_OutPointChannelIdCVec_MonitorEventZPublicKeyZZ {
			.data = (LDKC4Tuple_OutPointChannelIdCVec_MonitorEventZPublicKeyZ*)malloc(sizeof(LDKC4Tuple_OutPointChannelIdCVec_MonitorEventZPublicKeyZ)),
			.datalen = 1,
		};
		vec.data[0] = std::move(tuple);
		return vec;
	}
}

struct EventQueue {
	std::vector<LDK::Event> events;
};
LDKCResult_NoneReplayEventZ handle_event(const void *this_arg, LDKEvent event) {
	EventQueue* arg = (EventQueue*) this_arg;
	arg->events.push_back(std::move(event));
	return CResult_NoneReplayEventZ_ok();
}

#ifdef REAL_NET
class PeersConnection {
	void* node1_handler;
	void* node2_handler;

public:
	PeersConnection(LDK::ChannelManager& cm1, LDK::ChannelManager& cm2, LDK::PeerManager& net1, LDK::PeerManager& net2) {
		node1_handler = init_socket_handling(&net1);
		node2_handler = init_socket_handling(&net2);

		struct sockaddr_in listen_addr;
		listen_addr.sin_family = AF_INET;
		listen_addr.sin_addr.s_addr = htonl((127 << 8*3) | 1);
		listen_addr.sin_port = htons(10042);
		assert(!socket_bind(node2_handler, (sockaddr*)&listen_addr, sizeof(listen_addr)));

		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));

		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting initial handshake completion..." << std::endl;
		while (true) {
			// Wait for the initial handshakes to complete...
			LDK::CVec_PeerDetailsZ peers_1 = PeerManager_list_peers(&net1);
			LDK::CVec_PeerDetailsZ peers_2 = PeerManager_list_peers(&net2);
			if (peers_1->datalen == 1 && peers_2->datalen == 1) { break; }
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Initial handshake complete!" << std::endl;

		// Connect twice, which should auto-disconnect, and is a good test of our disconnect pipeline
		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));
		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));

		// Then disconnect the "main" connection, while another connection is being made.
		PeerManager_disconnect_by_node_id(&net1, ChannelManager_get_our_node_id(&cm2));
		PeerManager_disconnect_by_node_id(&net2, ChannelManager_get_our_node_id(&cm1));
		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));

		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting new connection handshake..." << std::endl;
		while (true) {
			// Wait for the new connection handshake...
			LDK::CVec_PeerDetailsZ peers_1 = PeerManager_list_peers(&net1);
			LDK::CVec_PeerDetailsZ peers_2 = PeerManager_list_peers(&net2);
			if (peers_1->datalen == 1 && peers_2->datalen == 1) { break; }
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "New connection handshake complete!" << std::endl;

		// Wait for all our sockets to disconnect (making sure we disconnect any new connections)...
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting peer disconnection..." << std::endl;
		while (true) {
			PeerManager_disconnect_by_node_id(&net1, ChannelManager_get_our_node_id(&cm2));
			// Wait for the peers to disconnect...
			LDK::CVec_PeerDetailsZ peers_1 = PeerManager_list_peers(&net1);
			LDK::CVec_PeerDetailsZ peers_2 = PeerManager_list_peers(&net2);
			if (peers_1->datalen == 0 && peers_2->datalen == 0) { break; }
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Peers disconnected!" << std::endl;
		// Note that the above is somewhat race-y, as node 2 may still think its connected.
		// Thus, make sure any connections are disconnected on its end as well.
		PeerManager_disconnect_by_node_id(&net2, ChannelManager_get_our_node_id(&cm1));

		// Finally make an actual connection and keep it this time
		assert(!socket_connect(node1_handler, ChannelManager_get_our_node_id(&cm2), (sockaddr*)&listen_addr, sizeof(listen_addr)));

		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting initial handshake completion..." << std::endl;
		while (true) {
			// Wait for the initial handshakes to complete...
			LDK::CVec_PeerDetailsZ peers_1 = PeerManager_list_peers(&net1);
			LDK::CVec_PeerDetailsZ peers_2 = PeerManager_list_peers(&net2);
			if (peers_1->datalen == 1 && peers_2->datalen == 1) { break; }
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Initial handshake complete!" << std::endl;
	}
	void stop() {
		interrupt_socket_handling(node1_handler);
		interrupt_socket_handling(node2_handler);
	}
};

#else // REAL_NET

uintptr_t sock_send_data(void *this_arg, LDKu8slice data, bool resume_read) {
	return write((int)((long)this_arg), data.data, data.datalen);
}
void sock_disconnect_socket(void *this_arg) {
	close((int)((long)this_arg));
}
bool sock_eq(const void *this_arg, const LDKSocketDescriptor *other_arg) {
	return this_arg == other_arg->this_arg;
}
uint64_t sock_hash(const void *this_arg) {
	return (uint64_t)this_arg;
}
void sock_read_data_thread(int rdfd, LDKSocketDescriptor *peer_descriptor, LDKPeerManager *pm) {
	unsigned char buf[1024];
	LDKu8slice data;
	data.data = buf;
	ssize_t readlen = 0;
	while ((readlen = read(rdfd, buf, 1024)) > 0) {
		data.datalen = readlen;
		LDK::CResult_boolPeerHandleErrorZ res = PeerManager_read_event(&*pm, peer_descriptor, data);
		if (!res->result_ok) {
			peer_descriptor->disconnect_socket(peer_descriptor->this_arg);
			return;
		}
		PeerManager_process_events(pm);
	}
	PeerManager_socket_disconnected(&*pm, peer_descriptor);
}

class PeersConnection {
	int pipefds_1_to_2[2];
	int pipefds_2_to_1[2];
	std::thread t1, t2;
	LDKSocketDescriptor sock1, sock2;

public:
	PeersConnection(LDK::ChannelManager& cm1, LDK::ChannelManager& cm2, LDK::PeerManager& net1, LDK::PeerManager& net2) {
		assert(!pipe(pipefds_1_to_2));
		assert(!pipe(pipefds_2_to_1));

		sock1 = LDKSocketDescriptor {
			.this_arg = (void*)(long)pipefds_1_to_2[1],
			.send_data = sock_send_data,
			.disconnect_socket = sock_disconnect_socket,
			.eq = sock_eq,
			.hash = sock_hash,
			.cloned = NULL,
			.free = NULL,
		};

		sock2 = LDKSocketDescriptor {
			.this_arg = (void*)(long)pipefds_2_to_1[1],
			.send_data = sock_send_data,
			.disconnect_socket = sock_disconnect_socket,
			.eq = sock_eq,
			.hash = sock_hash,
			.cloned = NULL,
			.free = NULL,
		};

		t1 = std::thread(&sock_read_data_thread, pipefds_2_to_1[0], &sock1, &net1);
		t2 = std::thread(&sock_read_data_thread, pipefds_1_to_2[0], &sock2, &net2);

		// Note that we have to bind the result to a C++ class to make sure it gets free'd
		LDK::CResult_CVec_u8ZPeerHandleErrorZ con_res = PeerManager_new_outbound_connection(&net1, ChannelManager_get_our_node_id(&cm2), sock1, COption_SocketAddressZ_none());
		assert(con_res->result_ok);
		LDK::CResult_NonePeerHandleErrorZ con_res2 = PeerManager_new_inbound_connection(&net2, sock2, COption_SocketAddressZ_none());
		assert(con_res2->result_ok);

		auto writelen = write(pipefds_1_to_2[1], con_res->contents.result->data, con_res->contents.result->datalen);
		assert(writelen > 0 && uint64_t(writelen) == con_res->contents.result->datalen);

		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting initial handshake completion..." << std::endl;
		while (true) {
			// Wait for the initial handshakes to complete...
			LDK::CVec_PeerDetailsZ peers_1 = PeerManager_list_peers(&net1);
			LDK::CVec_PeerDetailsZ peers_2 = PeerManager_list_peers(&net2);
			if (peers_1->datalen == 1 && peers_2->datalen ==1) { break; }
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Initial handshake complete!" << std::endl;
	}

	void stop() {
		close(pipefds_1_to_2[0]);
		close(pipefds_2_to_1[0]);
		close(pipefds_1_to_2[1]);
		close(pipefds_2_to_1[1]);
		t1.join();
		t2.join();
	}
};
#endif // !REAL_NET

struct CustomOnionMsgQueue {
	std::mutex mtx;
	std::vector<LDK::OnionMessageContents> msgs;
};

uint64_t custom_onion_msg_type_id(const void *this_arg) {
	return 8888;
}
LDKCVec_u8Z custom_onion_msg_bytes(const void *this_arg) {
	uint8_t *bytes = (uint8_t *) malloc(1024);
	memset(bytes, 43, 1024);
	return LDKCVec_u8Z {
		.data = bytes, .datalen = 1024
	};
}
LDKStr custom_onion_msg_str(const void *this_arg) {
	return LDKStr {
		.chars = (const uint8_t*)"Custom Onion Message",
		.len = 20, .chars_is_owned = false
	};
}

LDKCOption_C2Tuple_OnionMessageContentsResponseInstructionZZ handle_custom_onion_message(const void* this_arg, struct LDKOnionMessageContents msg, LDKCOption_CVec_u8ZZ context, LDKResponder responder) {
	LDK::Responder resp(std::move(responder));
	LDK::COption_CVec_u8ZZ ctx(std::move(context));
	CustomOnionMsgQueue* arg = (CustomOnionMsgQueue*) this_arg;
	std::unique_lock<std::mutex> lck(arg->mtx);
	arg->msgs.push_back(std::move(msg));
	return COption_C2Tuple_OnionMessageContentsResponseInstructionZZ_none();
}

LDKOnionMessageContents build_custom_onion_message() {
	return LDKOnionMessageContents {
		.this_arg = NULL,
		.tlv_type = custom_onion_msg_type_id,
		.write = custom_onion_msg_bytes,
		.debug_str = custom_onion_msg_str,
		.cloned = NULL,
		.free = NULL,
	};
}

LDKCResult_COption_OnionMessageContentsZDecodeErrorZ read_custom_onion_message(const void* this_arg, uint64_t type, LDKu8slice buf) {
	assert(type == 8888);
	assert(buf.datalen == 1024);
	uint8_t cmp[1024];
	memset(cmp, 43, 1024);
	assert(!memcmp(cmp, buf.data, 1024));
	return CResult_COption_OnionMessageContentsZDecodeErrorZ_ok(COption_OnionMessageContentsZ_some(build_custom_onion_message()));
}

LDKCVec_C2Tuple_OnionMessageContentsMessageSendInstructionsZZ release_no_messages(const void* this_arg) {
	return LDKCVec_C2Tuple_OnionMessageContentsMessageSendInstructionsZZ {
		.data = NULL, .datalen = 0
	};
}

struct CustomMsgQueue {
	std::vector<LDK::Type> msgs;
};

uint16_t custom_msg_type_id(const void *this_arg) {
	return 8888;
}
LDKCVec_u8Z custom_msg_bytes(const void *this_arg) {
	uint8_t *bytes = (uint8_t *) malloc(1024);
	memset(bytes, 42, 1024);
	return LDKCVec_u8Z {
		.data = bytes, .datalen = 1024
	};
}
LDKStr custom_msg_debug(const void *this_arg) {
	return LDKStr {
		.chars = (const unsigned char*) "Custom Message", .len = 14, .chars_is_owned = false
	};
}

LDKCResult_COption_TypeZDecodeErrorZ read_custom_message(const void* this_arg, uint16_t type_id, LDKu8slice buf) {
	assert(type_id == 8888);
	assert(buf.datalen == 1024);
	uint8_t cmp[1024];
	memset(cmp, 42, 1024);
	assert(!memcmp(cmp, buf.data, 1024));
	return CResult_COption_TypeZDecodeErrorZ_ok(COption_TypeZ_some(LDKType {
		.this_arg = NULL,
		.type_id = custom_msg_type_id,
		.debug_str = custom_msg_debug,
		.write = NULL, // This message should never be written
		.free = NULL,
	}));
}

LDKCResult_NoneLightningErrorZ handle_custom_message(const void* this_arg, struct LDKType msg, struct LDKPublicKey _sender_node_id) {
	CustomMsgQueue* arg = (CustomMsgQueue*) this_arg;
	arg->msgs.push_back(std::move(msg));
	return CResult_NoneLightningErrorZ_ok();
}
LDKCVec_C2Tuple_PublicKeyTypeZZ never_send_custom_msgs(const void* this_arg) {
	return LDKCVec_C2Tuple_PublicKeyTypeZZ {
		.data = NULL, .datalen = 0
	};
}
void peer_disconnected(const void* this_arg, struct LDKPublicKey _their_node_id) {}
LDKCResult_NoneNoneZ accept_peer_connected(const void* this_arg, struct LDKPublicKey _their_node_id, const struct LDKInit *msg, bool inbound) {
	return CResult_NoneNoneZ_ok();
}


LDKCVec_C2Tuple_PublicKeyTypeZZ create_custom_msg(const void* this_arg) {
	const LDKPublicKey *counterparty_node_id = (const LDKPublicKey *)this_arg;
	LDKCVec_C2Tuple_PublicKeyTypeZZ ret = {
		.data = ((LDKC2Tuple_PublicKeyTypeZ*)malloc(sizeof(LDKC2Tuple_PublicKeyTypeZ))),
		.datalen = 1
	};
	ret.data[0].a = *counterparty_node_id;
	ret.data[0].b = LDKType {
		.this_arg = NULL,
		.type_id = custom_msg_type_id,
		.debug_str = custom_msg_debug,
		.write = custom_msg_bytes,
		.free = NULL,
	};
	return ret;
}

LDKNodeFeatures custom_node_features(const void *this_arg) {
	return NodeFeatures_empty();
}

LDKInitFeatures custom_init_features(const void *this_arg, struct LDKPublicKey their_node_id) {
	return InitFeatures_empty();
}

uint64_t get_chan_score(const void *this_arg, const LDKCandidateRouteHop *hop, LDKChannelUsage usage_in, const LDKProbabilisticScoringFeeParameters *params) {
	LDK::ChannelUsage usage(std::move(usage_in));
	return 42;
}

struct LDKCResult_RouteLightningErrorZ custom_find_route(const void *this_arg, struct LDKPublicKey payer, const struct LDKRouteParameters *NONNULL_PTR route_params, struct LDKCVec_ChannelDetailsZ *first_hops, const struct LDKInFlightHtlcs in_flights, LDKThirtyTwoBytes payment_id, LDKThirtyTwoBytes payment_hash) {
	const LDK::DefaultRouter *router = (LDK::DefaultRouter *)this_arg;
	assert(first_hops->datalen == 1);
	assert(ChannelDetails_get_is_usable(&first_hops->data[0]));
	const LDK::Router router_impl = DefaultRouter_as_Router(&*router);
	return router_impl->find_route(router_impl->this_arg, payer, route_params, first_hops, in_flights);
}

int main() {
	uint8_t channel_open_header[80];
	uint8_t header_1[80];
	uint8_t header_2[80];
	memcpy(channel_open_header, channel_open_block, 80);
	memcpy(header_1, block_1, 80);
	memcpy(header_2, block_2, 80);

	LDKPublicKey null_pk;
	memset(&null_pk, 0, sizeof(null_pk));

	LDKThirtyTwoBytes random_bytes;
	LDKThirtyTwoBytes chain_tip;
	memset(&chain_tip, 0, sizeof(chain_tip)); // channel_open_header's prev_blockhash is all-0s

	LDKNetwork network = LDKNetwork_Testnet;

	// Trait implementations:
	LDKBroadcasterInterface broadcast {
		.this_arg = NULL,
		.broadcast_transactions = broadcast_txn,
		.free = NULL,
	};

	// Instantiate classes for the nodes that don't get reloaded on a ser-des reload
	LDKLogger logger1 {
		.this_arg = (void*)1,
		.log = print_log,
		.free = NULL,
	};

	NodeMonitors mons1;
	mons1.logger = &logger1;
	LDKWatch mon1 {
		.this_arg = &mons1,
		.watch_channel = add_channel_monitor,
		.update_channel = update_channel_monitor,
		.release_pending_monitor_events = monitors_pending_monitor_events,
		.free = NULL,
	};

	LDK::NetworkGraph net_graph1 = NetworkGraph_new(network, logger1);
	LDK::P2PGossipSync graph_msg_handler1 = P2PGossipSync_new(&net_graph1, COption_UtxoLookupZ_none(), logger1);

	LDKLogger logger2 {
		.this_arg = (void*)2,
		.log = print_log,
		.free = NULL,
	};

	NodeMonitors mons2;
	mons2.logger = &logger2;
	LDKWatch mon2 {
		.this_arg = &mons2,
		.watch_channel = add_channel_monitor,
		.update_channel = update_channel_monitor,
		.release_pending_monitor_events = monitors_pending_monitor_events,
		.free = NULL,
	};

	LDKRouter panic_router = {
		.this_arg = NULL,
		.find_route = NULL, // Segfault if we ever try to find a route
		.find_route_with_id = NULL, // Segfault if we ever try to find a route
		.free = NULL,
	};

	LDK::NetworkGraph net_graph2 = NetworkGraph_new(network, logger2);
	LDK::P2PGossipSync graph_msg_handler2 = P2PGossipSync_new(&net_graph2, COption_UtxoLookupZ_none(), logger2);

	LDK::CVec_u8Z cm1_ser = LDKCVec_u8Z {}; // ChannelManager 1 serialization at the end of the ser-des scope
	LDK::CVec_u8Z cm2_ser = LDKCVec_u8Z {}; // ChannelManager 2 serialization at the end of the ser-des scope

	{ // Scope for the ser-des reload
		// Instantiate classes for node 1:
		uint8_t node_seed[32];
		memset(&node_seed, 0, 32);
		LDK::KeysManager keys1 = KeysManager_new(&node_seed, 0, 0);
		LDK::NodeSigner node_signer1 = KeysManager_as_NodeSigner(&keys1);
		LDK::EntropySource entropy_source1 = KeysManager_as_EntropySource(&keys1);
		LDK::SignerProvider signer_provider1 = KeysManager_as_SignerProvider(&keys1);

		LDK::ChannelManager cm1 = ChannelManager_new(fee_est, mon1, broadcast, panic_router, logger1, KeysManager_as_EntropySource(&keys1), KeysManager_as_NodeSigner(&keys1), KeysManager_as_SignerProvider(&keys1), UserConfig_default(), ChainParameters_new(network, BestBlock_new(chain_tip, 0)), 1689638400);

		LDK::IgnoringMessageHandler ignoring_handler1 = IgnoringMessageHandler_new();
		LDK::CustomMessageHandler custom_msg_handler1 = IgnoringMessageHandler_as_CustomMessageHandler(&ignoring_handler1);
		LDK::CustomOnionMessageHandler custom_onion_msg_handler1 = IgnoringMessageHandler_as_CustomOnionMessageHandler(&ignoring_handler1);
		LDK::AsyncPaymentsMessageHandler async_msg_handler1 = IgnoringMessageHandler_as_AsyncPaymentsMessageHandler(&ignoring_handler1);
		LDK::DefaultMessageRouter mr1 = DefaultMessageRouter_new(&net_graph1, KeysManager_as_EntropySource(&keys1));
		LDK::OnionMessenger om1 = OnionMessenger_new(KeysManager_as_EntropySource(&keys1), KeysManager_as_NodeSigner(&keys1), logger1, ChannelManager_as_NodeIdLookUp(&cm1), DefaultMessageRouter_as_MessageRouter(&mr1), IgnoringMessageHandler_as_OffersMessageHandler(&ignoring_handler1), std::move(async_msg_handler1), std::move(custom_onion_msg_handler1));

		LDK::CVec_ChannelDetailsZ channels = ChannelManager_list_channels(&cm1);
		assert(channels->datalen == 0);

		LDK::MessageHandler msg_handler1 = MessageHandler_new(ChannelManager_as_ChannelMessageHandler(&cm1), P2PGossipSync_as_RoutingMessageHandler(&graph_msg_handler1), OnionMessenger_as_OnionMessageHandler(&om1), std::move(custom_msg_handler1));

		random_bytes = entropy_source1.get_secure_random_bytes();
		LDK::PeerManager net1 = PeerManager_new(std::move(msg_handler1), 0xdeadbeef, &random_bytes.data, logger1, std::move(node_signer1));

		// Demo getting a channel key and check that its returning real pubkeys:
		LDKSixteenBytes user_id_1 { .data = {45, 0, 0, 0, 0, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0} };
		LDKThirtyTwoBytes chan_signer_id1 = signer_provider1.generate_channel_keys_id(false, 42, U128_new(user_id_1));
		LDK::EcdsaChannelSigner chan_signer1 = signer_provider1.derive_channel_signer(42, chan_signer_id1);
		chan_signer1->ChannelSigner.set_pubkeys(&chan_signer1->ChannelSigner); // Make sure pubkeys is defined
		LDKPublicKey payment_point = ChannelPublicKeys_get_payment_point(&chan_signer1->ChannelSigner.pubkeys);
		assert(memcmp(&payment_point, &null_pk, sizeof(null_pk)));

		// Instantiate classes for node 2:
		memset(&node_seed, 1, 32);
		LDK::KeysManager keys2 = KeysManager_new(&node_seed, 0, 0);
		LDK::NodeSigner node_signer2 = KeysManager_as_NodeSigner(&keys2);
		LDK::EntropySource entropy_source2 = KeysManager_as_EntropySource(&keys2);
		LDK::SignerProvider signer_provider2 = KeysManager_as_SignerProvider(&keys2);

		LDK::ChannelHandshakeConfig handshake_config2 = ChannelHandshakeConfig_default();
		ChannelHandshakeConfig_set_minimum_depth(&handshake_config2, 2);
		LDK::UserConfig config2 = UserConfig_default();
		UserConfig_set_channel_handshake_config(&config2, std::move(handshake_config2));

		LDK::ChannelManager cm2 = ChannelManager_new(fee_est, mon2, broadcast, panic_router, logger2, KeysManager_as_EntropySource(&keys2), KeysManager_as_NodeSigner(&keys2), KeysManager_as_SignerProvider(&keys2), std::move(config2), ChainParameters_new(network, BestBlock_new(chain_tip, 0)), 1689638400);

		LDK::IgnoringMessageHandler ignoring_handler2 = IgnoringMessageHandler_new();
		LDK::CustomMessageHandler custom_msg_handler2 = IgnoringMessageHandler_as_CustomMessageHandler(&ignoring_handler2);
		LDK::CustomOnionMessageHandler custom_onion_msg_handler2 = IgnoringMessageHandler_as_CustomOnionMessageHandler(&ignoring_handler2);
		LDK::DefaultMessageRouter mr2 = DefaultMessageRouter_new(&net_graph2, KeysManager_as_EntropySource(&keys2));
		LDK::OnionMessenger om2 = OnionMessenger_new(KeysManager_as_EntropySource(&keys2), KeysManager_as_NodeSigner(&keys2), logger2, ChannelManager_as_NodeIdLookUp(&cm2), DefaultMessageRouter_as_MessageRouter(&mr2), IgnoringMessageHandler_as_OffersMessageHandler(&ignoring_handler2), IgnoringMessageHandler_as_AsyncPaymentsMessageHandler(&ignoring_handler2), std::move(custom_onion_msg_handler2));

		LDK::CVec_ChannelDetailsZ channels2 = ChannelManager_list_channels(&cm2);
		assert(channels2->datalen == 0);

		LDK::RoutingMessageHandler net_msgs2 = P2PGossipSync_as_RoutingMessageHandler(&graph_msg_handler2);
		LDK::CResult_ChannelAnnouncementDecodeErrorZ chan_ann = ChannelAnnouncement_read(LDKu8slice { .data = valid_node_announcement, .datalen = sizeof(valid_node_announcement) });
		assert(chan_ann->result_ok);
		LDK::CResult_boolLightningErrorZ ann_res = net_msgs2->handle_channel_announcement(net_msgs2->this_arg, chan_ann->contents.result);
		assert(ann_res->result_ok);

		LDK::MessageHandler msg_handler2 = MessageHandler_new(ChannelManager_as_ChannelMessageHandler(&cm2), std::move(net_msgs2), OnionMessenger_as_OnionMessageHandler(&om1), std::move(custom_msg_handler2));

		random_bytes = entropy_source2.get_secure_random_bytes();
		LDK::PeerManager net2 = PeerManager_new(std::move(msg_handler2), 0xdeadbeef, &random_bytes.data, logger2, std::move(node_signer2));

		// Open a connection!
		PeersConnection conn(cm1, cm2, net1, net2);

		// Note that we have to bind the result to a C++ class to make sure it gets free'd
		LDK::CResult_ChannelIdAPIErrorZ res = ChannelManager_create_channel(&cm1, ChannelManager_get_our_node_id(&cm2), 40000, 1000, U128_new(user_id_1), LDKChannelId { .inner = NULL, .is_owned = false }, UserConfig_default());
		assert(res->result_ok);
		PeerManager_process_events(&net1);

		LDK::CVec_ChannelDetailsZ new_channels = ChannelManager_list_channels(&cm1);
		assert(new_channels->datalen == 1);
		LDK::ChannelCounterparty new_channels_counterparty = ChannelDetails_get_counterparty(&new_channels->data[0]);
		LDKPublicKey chan_open_pk = ChannelCounterparty_get_node_id(&new_channels_counterparty);
		assert(!memcmp(chan_open_pk.compressed_form, ChannelManager_get_our_node_id(&cm2).compressed_form, 33));

		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting first channel..." << std::endl;
		while (true) {
			LDK::CVec_ChannelDetailsZ new_channels_2 = ChannelManager_list_channels(&cm2);
			if (new_channels_2->datalen == 1) {
				// Sample getting our counterparty's init features (which used to be hard to do without a memory leak):
				LDK::ChannelCounterparty new_channels_2_counterparty = ChannelDetails_get_counterparty(&new_channels_2->data[0]);
				const LDK::InitFeatures init_feats = ChannelCounterparty_get_features(&new_channels_2_counterparty);
				assert(init_feats->inner != NULL);
				break;
			}
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "First channel listed!" << std::endl;

		LDK::EventsProvider ev1 = ChannelManager_as_EventsProvider(&cm1);
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting FundingGenerationReady event..." << std::endl;
		while (true) {
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev1.process_pending_events(handler);
			if (queue.events.size() == 1) {
				assert(queue.events[0]->tag == LDKEvent_FundingGenerationReady);
				LDKSixteenBytes event_id = U128_le_bytes(queue.events[0]->funding_generation_ready.user_channel_id);
				assert(!memcmp(&event_id, &user_id_1, 16));
				assert(queue.events[0]->funding_generation_ready.channel_value_satoshis == 40000);
				assert(queue.events[0]->funding_generation_ready.output_script.datalen == 34);

				assert(!memcmp(queue.events[0]->funding_generation_ready.output_script.data, channel_open_block + 58 + 81, 34));
				LDKTransaction funding_transaction { .data = const_cast<uint8_t*>(channel_open_block + 81), .datalen = sizeof(channel_open_block) - 81, .data_is_owned = false };

				LDK::CResult_NoneAPIErrorZ fund_res = ChannelManager_funding_transaction_generated(&cm1, ChannelId_clone(&queue.events[0]->funding_generation_ready.temporary_channel_id), queue.events[0]->funding_generation_ready.counterparty_node_id, funding_transaction);
				assert(fund_res->result_ok);
				break;
			}
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received FundingGenerationReady event!" << std::endl;

		// We observe when the funding signed messages have been exchanged by
		// waiting for two monitors to be registered.
		assert(num_txs_broadcasted == 0);
		PeerManager_process_events(&net1);
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting transaction broadcast..." << std::endl;
		while (num_txs_broadcasted != 1) {
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Transaction was broadcast!" << std::endl;

		// Note that the channel ID is the same as the channel txid reversed as the output index is 0
		uint8_t expected_chan_id[32];
		for (int i = 0; i < 32; i++) { expected_chan_id[i] = channel_open_txid[31-i]; }

		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting ChannelPending event..." << std::endl;
		while (true) {
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev1.process_pending_events(handler);
			if (queue.events.size() == 1) {
				assert(queue.events[0]->tag == LDKEvent_ChannelPending);
				assert(!memcmp(ChannelId_get_a(&queue.events[0]->channel_pending.channel_id), expected_chan_id, 32));
				break;
			}
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received ChannelPending event!" << std::endl;

		LDK::EventsProvider ev2 = ChannelManager_as_EventsProvider(&cm2);
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting ChannelPending event..." << std::endl;
		while (true) {
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev2.process_pending_events(handler);
			if (queue.events.size() == 1) {
				assert(queue.events[0]->tag == LDKEvent_ChannelPending);
				assert(!memcmp(ChannelId_get_a(&queue.events[0]->channel_pending.channel_id), expected_chan_id, 32));
				break;
			}
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received ChannelPending event!" << std::endl;

		LDK::Listen listener1 = ChannelManager_as_Listen(&cm1);
		listener1->block_connected(listener1->this_arg, LDKu8slice { .data = channel_open_block, .datalen = sizeof(channel_open_block) }, 1);

		LDK::Listen listener2 = ChannelManager_as_Listen(&cm2);
		listener2->block_connected(listener2->this_arg, LDKu8slice { .data = channel_open_block, .datalen = sizeof(channel_open_block) }, 1);

		LDKCVec_C2Tuple_usizeTransactionZZ txdata { .data = (LDKC2Tuple_usizeTransactionZ*)malloc(sizeof(LDKC2Tuple_usizeTransactionZ)), .datalen = 1 };
		*txdata.data = C2Tuple_usizeTransactionZ_new(0, LDKTransaction { .data = (uint8_t*)channel_open_block + 81, .datalen = sizeof(channel_open_block) - 81, .data_is_owned = false });
		mons1.ConnectBlock(&channel_open_header, 1, txdata, broadcast, fee_est);

		txdata = LDKCVec_C2Tuple_usizeTransactionZZ { .data = (LDKC2Tuple_usizeTransactionZ*)malloc(sizeof(LDKC2Tuple_usizeTransactionZ)), .datalen = 1 };
		*txdata.data = C2Tuple_usizeTransactionZ_new(0, LDKTransaction { .data = (uint8_t*)channel_open_block + 81, .datalen = sizeof(channel_open_block) - 81, .data_is_owned = false });
		mons2.ConnectBlock(&channel_open_header, 1, txdata, broadcast, fee_est);

		listener1->block_connected(listener1->this_arg, LDKu8slice { .data = block_1, .datalen = sizeof(block_1) }, 2);
		listener2->block_connected(listener2->this_arg, LDKu8slice { .data = block_1, .datalen = sizeof(block_1) }, 2);
		mons1.ConnectBlock(&header_1, 2, LDKCVec_C2Tuple_usizeTransactionZZ { .data = NULL, .datalen = 0 }, broadcast, fee_est);
		mons2.ConnectBlock(&header_1, 2, LDKCVec_C2Tuple_usizeTransactionZZ { .data = NULL, .datalen = 0 }, broadcast, fee_est);

		listener1->block_connected(listener1->this_arg, LDKu8slice { .data = block_2, .datalen = sizeof(block_1) }, 3);
		listener2->block_connected(listener2->this_arg, LDKu8slice { .data = block_2, .datalen = sizeof(block_1) }, 3);
		mons1.ConnectBlock(&header_2, 3, LDKCVec_C2Tuple_usizeTransactionZZ { .data = NULL, .datalen = 0 }, broadcast, fee_est);
		mons2.ConnectBlock(&header_2, 3, LDKCVec_C2Tuple_usizeTransactionZZ { .data = NULL, .datalen = 0 }, broadcast, fee_est);

		PeerManager_process_events(&net1);
		PeerManager_process_events(&net2);

		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting ChannelReady event..." << std::endl;
		while (true) {
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev2.process_pending_events(handler);
			if (queue.events.size() == 1) {
				assert(queue.events[0]->tag == LDKEvent_ChannelReady);
				assert(!memcmp(ChannelId_get_a(&queue.events[0]->channel_ready.channel_id), expected_chan_id, 32));
				break;
			}
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received ChannelReady event!" << std::endl;

		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting ChannelReady event..." << std::endl;
		while (true) {
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev1.process_pending_events(handler);
			if (queue.events.size() == 1) {
				assert(queue.events[0]->tag == LDKEvent_ChannelReady);
				assert(!memcmp(ChannelId_get_a(&queue.events[0]->channel_ready.channel_id), expected_chan_id, 32));
				break;
			}
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received ChannelReady event!" << std::endl;

		// Now send funds from 1 to 2!
		uint64_t channel_scid;
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting usable channel..." << std::endl;
		while (true) {
			LDK::CVec_ChannelDetailsZ outbound_channels = ChannelManager_list_usable_channels(&cm1);
			if (outbound_channels->datalen == 1) {
				const LDKChannelDetails *channel = &outbound_channels->data[0];
				LDK::ChannelCounterparty counterparty = ChannelDetails_get_counterparty(channel);

				LDK::ChannelId chan_id = ChannelDetails_get_channel_id(channel);
				assert(!memcmp(ChannelId_get_a(&chan_id), expected_chan_id, 32));
				assert(!memcmp(
					ChannelCounterparty_get_node_id(&counterparty).compressed_form,
					ChannelManager_get_our_node_id(&cm2).compressed_form, 33));
				assert(ChannelDetails_get_channel_value_satoshis(channel) == 40000);
				// We opened the channel with 1000 push_msat:
				assert(ChannelDetails_get_outbound_capacity_msat(channel) ==
					40000*1000 - 1000 - 1000 * ChannelCounterparty_get_unspendable_punishment_reserve(&counterparty));
				int64_t inbound_capacity = ((int64_t)1000) - ChannelCounterparty_get_unspendable_punishment_reserve(&counterparty);
				if (inbound_capacity < 0) inbound_capacity = 0;
				assert(ChannelDetails_get_inbound_capacity_msat(channel) == (uint64_t)inbound_capacity);
				assert(ChannelDetails_get_is_usable(channel));
				LDK::COption_u64Z scid_opt = ChannelDetails_get_short_channel_id(channel);
				assert(scid_opt->some);
				channel_scid = scid_opt->some;
				break;
			}
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Listed usable channel!" << std::endl;

		LDKCOption_u64Z min_value = {
			.tag = LDKCOption_u64Z_Some,
			.some = 5000,
		};
		LDK::CResult_Bolt11InvoiceSignOrCreationErrorZ invoice = create_invoice_from_channelmanager(&cm2,
			KeysManager_as_NodeSigner(&keys2), logger2,
			LDKCurrency_Bitcoin, min_value,
			LDKStr {
				.chars = (const uint8_t *)"Invoice Description",
				.len =             strlen("Invoice Description"),
				.chars_is_owned = false
			}, 3600, COption_u16Z_none());
		assert(invoice->result_ok);
		LDKThirtyTwoBytes payment_hash;
		memcpy(payment_hash.data, Bolt11Invoice_payment_hash(invoice->contents.result), 32);

		{
			LDK::CVec_ChannelDetailsZ outbound_channels = ChannelManager_list_usable_channels(&cm1);
			LDK::ScoreLookUp chan_scorer = LDKScoreLookUp {
				.this_arg = NULL, .channel_penalty_msat = get_chan_score, .free = NULL,
			};
			LDK::Payee payee = Payee_clear(ChannelManager_get_our_node_id(&cm2), Bolt11Invoice_route_hints(invoice->contents.result),
				LDKBolt11InvoiceFeatures {
					.inner = NULL, .is_owned = false
				}, Bolt11Invoice_min_final_cltv_expiry_delta(invoice->contents.result));
			LDK::RouteParameters route_params = RouteParameters_from_payment_params_and_value(
				PaymentParameters_new(std::move(payee), COption_u64Z_none(), 0xffffffff, 1, 20, 2,
					LDKCVec_u64Z { .data = NULL, .datalen = 0 }, LDKCVec_u64Z { .data = NULL, .datalen = 0 }),
				5000);
			random_bytes = entropy_source1.get_secure_random_bytes();
			LDK::ProbabilisticScoringFeeParameters params = ProbabilisticScoringFeeParameters_default();

			LDK::CResult_RouteLightningErrorZ route_res = find_route(ChannelManager_get_our_node_id(&cm1), &route_params, &net_graph2, &outbound_channels, logger1, &chan_scorer, &params, &random_bytes.data);

			assert(route_res->result_ok);
			LDK::CVec_PathZ paths = Route_get_paths(route_res->contents.result);
			assert(paths->datalen == 1);
			LDK::CVec_RouteHopZ hops = Path_get_hops(&paths->data[0]);
			assert(hops->datalen == 1);
			assert(!memcmp(RouteHop_get_pubkey(&hops->data[0]).compressed_form,
				ChannelManager_get_our_node_id(&cm2).compressed_form, 33));
			assert(RouteHop_get_short_channel_id(&hops->data[0]) == channel_scid);
			LDKThirtyTwoBytes payment_secret;
			memcpy(payment_secret.data, Bolt11Invoice_payment_secret(invoice->contents.result), 32);
			LDK::Route route(Route_clone(route_res->contents.result));
			LDK::CResult_NonePaymentSendFailureZ send_res = ChannelManager_send_payment_with_route(&cm1,
				std::move(route), payment_hash, RecipientOnionFields_secret_only(payment_secret), payment_hash);
			assert(send_res->result_ok);
		}

		mons_updated = 0;
		PeerManager_process_events(&net1);
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting 4 updated monitors..." << std::endl;
		while (mons_updated != 4) {
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "4 monitors updated!" << std::endl;

		// Check that we received the payment!
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting PendingHTLCsForwardable event..." << std::endl;
		while (true) {
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev2.process_pending_events(handler);
			if (queue.events.size() == 1) {
				assert(queue.events[0]->tag == LDKEvent_PendingHTLCsForwardable);
				break;
			}
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received PendingHTLCsForwardable event!" << std::endl;
		ChannelManager_process_pending_htlc_forwards(&cm2);
		PeerManager_process_events(&net2);

		mons_updated = 0;
		LDKThirtyTwoBytes payment_preimage;
		{
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			ev2.process_pending_events(handler);
			assert(queue.events.size() == 1);
			assert(queue.events[0]->tag == LDKEvent_PaymentClaimable);
			assert(!memcmp(queue.events[0]->payment_claimable.payment_hash.data, payment_hash.data, 32));
			assert(queue.events[0]->payment_claimable.purpose.tag == LDKPaymentPurpose_Bolt11InvoicePayment);
			assert(!memcmp(queue.events[0]->payment_claimable.purpose.bolt11_invoice_payment.payment_secret.data,
					Bolt11Invoice_payment_secret(invoice->contents.result), 32));
			assert(queue.events[0]->payment_claimable.amount_msat == 5000);
			assert(queue.events[0]->payment_claimable.purpose.bolt11_invoice_payment.payment_preimage.tag == LDKCOption_ThirtyTwoBytesZ_Some);
			memcpy(payment_preimage.data, queue.events[0]->payment_claimable.purpose.bolt11_invoice_payment.payment_preimage.some.data, 32);
			ChannelManager_claim_funds(&cm2, payment_preimage);

			queue.events.clear();
			ev2.process_pending_events(handler);
			assert(queue.events.size() == 1);
			assert(queue.events[0]->tag == LDKEvent_PaymentClaimed);
			assert(!memcmp(queue.events[0]->payment_claimed.payment_hash.data, payment_hash.data, 32));
			assert(queue.events[0]->payment_claimed.purpose.tag == LDKPaymentPurpose_Bolt11InvoicePayment);
		}
		PeerManager_process_events(&net2);
		// Wait until we've passed through a full set of monitor updates (ie new preimage + CS/RAA messages)
		{
			EventQueue queue;
			LDKEventHandler handler = { .this_arg = &queue, .handle_event = handle_event, .free = NULL };
			std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting PaymentSent and PaymentPathSuccessful events..." << std::endl;
			while (queue.events.size() < 2) {
				ev1.process_pending_events(handler);
				std::this_thread::yield();
			}
			std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received PaymentSent and PaymentPathSuccessful events (presumably)!" << std::endl;
			assert(queue.events.size() == 2);
			assert(queue.events[0]->tag == LDKEvent_PaymentSent);
			assert(!memcmp(queue.events[0]->payment_sent.payment_preimage.data, payment_preimage.data, 32));
			assert(queue.events[1]->tag == LDKEvent_PaymentPathSuccessful);
			assert(queue.events[1]->payment_path_successful.payment_hash.tag == LDKCOption_ThirtyTwoBytesZ_Some);
			assert(!memcmp(queue.events[1]->payment_path_successful.payment_hash.some.data, payment_hash.data, 32));
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting 5 updated monitors..." << std::endl;
		while (mons_updated != 5) {
			std::this_thread::yield();
		}
		std::cout << __FILE__ << ":" << __LINE__ << " - " << "5 monitors updated!" << std::endl;

		conn.stop();

		cm1_ser = ChannelManager_write(&cm1);
		cm2_ser = ChannelManager_write(&cm2);
	}

	LDK::CVec_ChannelMonitorZ mons_list1 = LDKCVec_ChannelMonitorZ { .data = (LDKChannelMonitor*)malloc(sizeof(LDKChannelMonitor)), .datalen = 1 };
	assert(mons1.mons.size() == 1);
	mons_list1->data[0] = *& std::get<1>(mons1.mons[0]); // Note that we need a reference, thus need a raw clone here, which *& does.
	mons_list1->data[0].is_owned = false; // XXX: God this sucks
	uint8_t node_seed[32];
	memset(&node_seed, 0, 32);
	LDK::KeysManager keys1 = KeysManager_new(&node_seed, 1, 0);
	LDK::NodeSigner node_signer1 = KeysManager_as_NodeSigner(&keys1);
	LDK::EntropySource entropy_source1 = KeysManager_as_EntropySource(&keys1);
	LDK::SignerProvider signer_provider1 = KeysManager_as_SignerProvider(&keys1);

	LDK::ProbabilisticScorer scorer1 = ProbabilisticScorer_new(ProbabilisticScoringDecayParameters_default(), &net_graph1, logger1);
	LDK::Score scorer_trait1 = ProbabilisticScorer_as_Score(&scorer1);
	LDK::MultiThreadedLockableScore scorer_mtx1 = MultiThreadedLockableScore_new(std::move(scorer_trait1));
	LDK::LockableScore scorer_mtx_trait1 = MultiThreadedLockableScore_as_LockableScore(&scorer_mtx1);
	LDK::ProbabilisticScoringFeeParameters params = ProbabilisticScoringFeeParameters_default();
	const LDK::DefaultRouter default_router_1 = DefaultRouter_new(&net_graph1, logger1, KeysManager_as_EntropySource(&keys1), std::move(scorer_mtx_trait1), std::move(params));
	LDKRouter router1 = {
		.this_arg = (void*)&default_router_1,
		.find_route = NULL, // LDK currently doesn't use this, its just a default-impl
		.find_route_with_id = custom_find_route,
		.free = NULL,
	};

	LDK::ChannelManagerReadArgs cm1_args = ChannelManagerReadArgs_new(KeysManager_as_EntropySource(&keys1), KeysManager_as_NodeSigner(&keys1), KeysManager_as_SignerProvider(&keys1), fee_est, mon1, broadcast, router1, logger1, UserConfig_default(), std::move(mons_list1));
	LDK::CResult_C2Tuple_ThirtyTwoBytesChannelManagerZDecodeErrorZ cm1_read =
		C2Tuple_ThirtyTwoBytesChannelManagerZ_read(LDKu8slice { .data = cm1_ser->data, .datalen = cm1_ser -> datalen}, std::move(cm1_args));
	assert(cm1_read->result_ok);
	LDK::ChannelManager cm1(std::move(cm1_read->contents.result->b));

	LDKCustomOnionMessageHandler custom_onion_msg_handler1 = {
		.this_arg = NULL,
		.handle_custom_message = NULL, // We only create custom messages, not handle them
		.read_custom_message = NULL, // We only create custom messages, not handle them
		.release_pending_custom_messages = release_no_messages,
		.free = NULL,
	};
	LDK::DefaultMessageRouter mr1 = DefaultMessageRouter_new(&net_graph1, KeysManager_as_EntropySource(&keys1));
	LDK::IgnoringMessageHandler ignorer_1 = IgnoringMessageHandler_new();
	LDK::OnionMessenger om1 = OnionMessenger_new(KeysManager_as_EntropySource(&keys1), KeysManager_as_NodeSigner(&keys1), logger1, ChannelManager_as_NodeIdLookUp(&cm1), DefaultMessageRouter_as_MessageRouter(&mr1), IgnoringMessageHandler_as_OffersMessageHandler(&ignorer_1), IgnoringMessageHandler_as_AsyncPaymentsMessageHandler(&ignorer_1), std::move(custom_onion_msg_handler1));

	LDK::CVec_ChannelMonitorZ mons_list2 = LDKCVec_ChannelMonitorZ { .data = (LDKChannelMonitor*)malloc(sizeof(LDKChannelMonitor)), .datalen = 1 };
	assert(mons2.mons.size() == 1);
	mons_list2->data[0] = *& std::get<1>(mons2.mons[0]); // Note that we need a reference, thus need a raw clone here, which *& does.
	mons_list2->data[0].is_owned = false; // XXX: God this sucks
	memset(&node_seed, 1, 32);
	LDK::KeysManager keys2 = KeysManager_new(&node_seed, 1, 0);
	LDK::NodeSigner node_signer2 = KeysManager_as_NodeSigner(&keys2);
	LDK::EntropySource entropy_source2 = KeysManager_as_EntropySource(&keys2);
	LDK::SignerProvider signer_provider2 = KeysManager_as_SignerProvider(&keys2);

	LDK::ChannelManagerReadArgs cm2_args = ChannelManagerReadArgs_new(KeysManager_as_EntropySource(&keys2), KeysManager_as_NodeSigner(&keys2), KeysManager_as_SignerProvider(&keys2), fee_est, mon2, broadcast, panic_router, logger2, UserConfig_default(), std::move(mons_list2));
	LDK::CResult_C2Tuple_ThirtyTwoBytesChannelManagerZDecodeErrorZ cm2_read =
		C2Tuple_ThirtyTwoBytesChannelManagerZ_read(LDKu8slice { .data = cm2_ser->data, .datalen = cm2_ser -> datalen}, std::move(cm2_args));
	assert(cm2_read->result_ok);
	LDK::ChannelManager cm2(std::move(cm2_read->contents.result->b));

	CustomOnionMsgQueue peer_2_custom_onion_messages;
	LDKCustomOnionMessageHandler custom_onion_msg_handler2 = {
		.this_arg = &peer_2_custom_onion_messages,
		.handle_custom_message = handle_custom_onion_message,
		.read_custom_message = read_custom_onion_message,
		.release_pending_custom_messages = release_no_messages,
		.free = NULL,
	};
	LDK::DefaultMessageRouter mr2 = DefaultMessageRouter_new(&net_graph2, KeysManager_as_EntropySource(&keys2));
	LDK::IgnoringMessageHandler ignorer_2 = IgnoringMessageHandler_new();
	LDK::OnionMessenger om2 = OnionMessenger_new(KeysManager_as_EntropySource(&keys2), KeysManager_as_NodeSigner(&keys2), logger2, ChannelManager_as_NodeIdLookUp(&cm2), DefaultMessageRouter_as_MessageRouter(&mr2), IgnoringMessageHandler_as_OffersMessageHandler(&ignorer_2), IgnoringMessageHandler_as_AsyncPaymentsMessageHandler(&ignorer_2), custom_onion_msg_handler2);

	// Attempt to close the channel...
	LDKThirtyTwoBytes chan_id_bytes;
	for (int i = 0; i < 32; i++) { chan_id_bytes.data[i] = channel_open_txid[31-i]; }
	LDK::ChannelId chan_id = ChannelId_new(chan_id_bytes);
	LDK::CResult_NoneAPIErrorZ close_res = ChannelManager_close_channel(&cm1, &chan_id, ChannelManager_get_our_node_id(&cm2));
	assert(!close_res->result_ok); // Note that we can't close while disconnected!

	// Open a connection!
	LDKPublicKey chan_2_node_id = ChannelManager_get_our_node_id(&cm2);
	LDKCustomMessageHandler custom_msg_handler1 = {
		.this_arg = &chan_2_node_id,
		.handle_custom_message = NULL, // We only create custom messages, not handle them
		.get_and_clear_pending_msg = create_custom_msg,
		.peer_disconnected = peer_disconnected,
		.peer_connected = accept_peer_connected,
		.provided_node_features = custom_node_features,
		.provided_init_features = custom_init_features,
		.CustomMessageReader = LDKCustomMessageReader {
			.this_arg = NULL,
			.read = read_custom_message,
			.free = NULL,
		},
		.free = NULL,
	};
	LDK::MessageHandler msg_handler1 = MessageHandler_new(ChannelManager_as_ChannelMessageHandler(&cm1), P2PGossipSync_as_RoutingMessageHandler(&graph_msg_handler1), OnionMessenger_as_OnionMessageHandler(&om1), custom_msg_handler1);
	random_bytes = entropy_source1.get_secure_random_bytes();
	LDK::PeerManager net1 = PeerManager_new(std::move(msg_handler1), 0xdeadbeef, &random_bytes.data, logger1, std::move(node_signer1));

	CustomMsgQueue peer_2_custom_messages;
	LDKCustomMessageHandler custom_msg_handler2 = {
		.this_arg = &peer_2_custom_messages,
		.handle_custom_message = handle_custom_message,
		.get_and_clear_pending_msg = never_send_custom_msgs,
		.peer_disconnected = peer_disconnected,
		.peer_connected = accept_peer_connected,
		.provided_node_features = custom_node_features,
		.provided_init_features = custom_init_features,
		.CustomMessageReader = LDKCustomMessageReader {
			.this_arg = NULL,
			.read = read_custom_message,
			.free = NULL,
		},
		.free = NULL,
	};
	LDK::MessageHandler msg_handler2 = MessageHandler_new(ChannelManager_as_ChannelMessageHandler(&cm2), P2PGossipSync_as_RoutingMessageHandler(&graph_msg_handler2), OnionMessenger_as_OnionMessageHandler(&om2), custom_msg_handler2);
	random_bytes = entropy_source1.get_secure_random_bytes();
	LDK::PeerManager net2 = PeerManager_new(std::move(msg_handler2), 0xdeadbeef, &random_bytes.data, logger2, std::move(node_signer2));

	PeersConnection conn(cm1, cm2, net1, net2);

	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting usable channel..." << std::endl;
	while (true) {
		// Wait for the channels to be considered up once the reestablish messages are processed
		LDK::CVec_ChannelDetailsZ outbound_channels = ChannelManager_list_usable_channels(&cm1);
		if (outbound_channels->datalen == 1) {
			break;
		}
		std::this_thread::yield();
	}
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Listed usable channel!" << std::endl;

	// Send another payment, this time via the retires path
	LDK::CResult_Bolt11InvoiceSignOrCreationErrorZ invoice_res2 = create_invoice_from_channelmanager(&cm2,
		KeysManager_as_NodeSigner(&keys2), logger1,
		LDKCurrency_Bitcoin, COption_u64Z_some(10000),
		LDKStr {
			.chars = (const uint8_t *)"Invoice 2 Description",
			.len =             strlen("Invoice 2 Description"),
			.chars_is_owned = false
		}, 3600, COption_u16Z_none());
	assert(invoice_res2->result_ok);
	const LDKBolt11Invoice *invoice2 = invoice_res2->contents.result;
	LDK::CResult_C3Tuple_ThirtyTwoBytesRecipientOnionFieldsRouteParametersZNoneZ pay_params =
		payment_parameters_from_invoice(invoice2);
	LDK::RecipientOnionFields invoice2_recipient(std::move(pay_params->contents.result->b));
	LDK::RouteParameters invoice2_params(std::move(pay_params->contents.result->c));
	assert(pay_params->result_ok);
	LDKThirtyTwoBytes payment_id;
	memset(&payment_id, 0, 32);
	LDK::CResult_NoneRetryableSendFailureZ invoice_pay_res = ChannelManager_send_payment(
		&cm1, std::move(pay_params->contents.result->a), std::move(invoice2_recipient),
		std::move(payment_id), std::move(invoice2_params), Retry_attempts(0)
	);
	assert(invoice_pay_res->result_ok);
	PeerManager_process_events(&net1);

	// Check that we received the payment!
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting PendingHTLCsForwardable event..." << std::endl;
	while (true) {
		EventQueue queue2;
		LDKEventHandler handler2 = { .this_arg = &queue2, .handle_event = handle_event, .free = NULL };
		LDK::EventsProvider ev2 = ChannelManager_as_EventsProvider(&cm2);
		ev2.process_pending_events(handler2);
		if (queue2.events.size() == 1) {
			assert(queue2.events[0]->tag == LDKEvent_PendingHTLCsForwardable);
			break;
		}
		std::this_thread::yield();
	}
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received PendingHTLCsForwardable event!" << std::endl;
	ChannelManager_process_pending_htlc_forwards(&cm2);
	PeerManager_process_events(&net2);

	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting PaymentClaimable/PaymentClaimed event..." << std::endl;
	while (true) {
		EventQueue queue2;
		LDKEventHandler handler2 = { .this_arg = &queue2, .handle_event = handle_event, .free = NULL };
		LDK::EventsProvider ev2 = ChannelManager_as_EventsProvider(&cm2);
		ev2.process_pending_events(handler2);
		if (queue2.events.size() == 1) {
			assert(queue2.events[0]->tag == LDKEvent_PaymentClaimable);
			const struct LDKEvent_LDKPaymentClaimable_Body *event_data = &queue2.events[0]->payment_claimable;
			assert(!memcmp(event_data->payment_hash.data, Bolt11Invoice_payment_hash(invoice2), 32));
			assert(event_data->purpose.tag == LDKPaymentPurpose_Bolt11InvoicePayment);
			assert(!memcmp(event_data->purpose.bolt11_invoice_payment.payment_secret.data,
					Bolt11Invoice_payment_secret(invoice2), 32));
			assert(event_data->amount_msat == 10000);
			assert(event_data->purpose.bolt11_invoice_payment.payment_preimage.tag == LDKCOption_ThirtyTwoBytesZ_Some);
			ChannelManager_claim_funds(&cm2, event_data->purpose.bolt11_invoice_payment.payment_preimage.some);

			queue2.events.clear();
			ev2.process_pending_events(handler2);
			assert(queue2.events.size() == 1);
			assert(queue2.events[0]->tag == LDKEvent_PaymentClaimed);
			assert(!memcmp(queue2.events[0]->payment_claimed.payment_hash.data, Bolt11Invoice_payment_hash(invoice2), 32));
			assert(queue2.events[0]->payment_claimed.purpose.tag == LDKPaymentPurpose_Bolt11InvoicePayment);

			break;
		}
		std::this_thread::yield();
	}
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received PaymentClaimable/PaymentClaimed event!" << std::endl;

	EventQueue queue1;
	LDKEventHandler handler1 = { .this_arg = &queue1, .handle_event = handle_event, .free = NULL };
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting PaymentSent and PaymentPathSuccessful events..." << std::endl;
	while (queue1.events.size() < 2) {
		PeerManager_process_events(&net2);
		PeerManager_process_events(&net1);

		LDK::EventsProvider ev1 = ChannelManager_as_EventsProvider(&cm1);
		ev1.process_pending_events(handler1);
		std::this_thread::yield();
	}
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received PaymentSent and PaymentPathSuccessful events (presumably)!" << std::endl;
	assert(queue1.events.size() == 2);
	assert(queue1.events[0]->tag == LDKEvent_PaymentSent);
	assert(queue1.events[1]->tag == LDKEvent_PaymentPathSuccessful);

	// Actually close the channel
	num_txs_broadcasted = 0;
	close_res = ChannelManager_close_channel(&cm1, &chan_id, ChannelManager_get_our_node_id(&cm2));
	assert(close_res->result_ok);
	PeerManager_process_events(&net1);
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting 2 transaction broadcasts..." << std::endl;
	while (num_txs_broadcasted != 2) {
		std::this_thread::yield();
	}
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Broadcast 2 transactions!" << std::endl;
	LDK::CVec_ChannelDetailsZ chans_after_close1 = ChannelManager_list_channels(&cm1);
	assert(chans_after_close1->datalen == 0);
	LDK::CVec_ChannelDetailsZ chans_after_close2 = ChannelManager_list_channels(&cm2);
	assert(chans_after_close2->datalen == 0);

	LDK::CResult_SendSuccessSendErrorZ om_send_res =
		OnionMessenger_send_onion_message(&om1,
			build_custom_onion_message(),
			MessageSendInstructions_without_reply_path(Destination_node(ChannelManager_get_our_node_id(&cm2))));
	assert(om_send_res->result_ok);
	PeerManager_process_events(&net1);
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Awaiting onion message..." << std::endl;
	while (true) {
		std::this_thread::yield();
		std::unique_lock<std::mutex> lck(peer_2_custom_onion_messages.mtx);
		if (peer_2_custom_onion_messages.msgs.size() != 0) break;
	}
	std::cout << __FILE__ << ":" << __LINE__ << " - " << "Received onion message!" << std::endl;

	conn.stop();

	std::unique_lock<std::mutex> lck(peer_2_custom_onion_messages.mtx);
	assert(peer_2_custom_onion_messages.msgs.size() == 1);
	assert(peer_2_custom_onion_messages.msgs[0].tlv_type() == 8888);
	assert(peer_2_custom_messages.msgs.size() != 0);

	// Few extra random tests:
	LDKSecretKey sk;
	memset(&sk, 42, 32);
	LDKThirtyTwoBytes kdiv_params;
	memset(&kdiv_params, 43, 32);
	LDK::InMemorySigner signer = InMemorySigner_new(sk, sk, sk, sk, sk, random_bytes, 42, kdiv_params, kdiv_params);
}

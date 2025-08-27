/**
 * @file dpdk_init.cc
 * @brief Initialization code for a DPDK port. This is a separate file because
 * it's used by both the eRPC library and the DPDK QP management daemon.
 */

#ifdef ERPC_DPDK

#include "dpdk_externs.h"
#include "dpdk_transport.h"
#include <rte_ethdev.h>
#include <rte_version.h>
#include <rte_thash.h>
#include <rte_flow.h>

namespace erpc {

#if RTE_VERSION < RTE_VERSION_NUM(21, 0, 0, 0)
#define RTE_ETH_MQ_RX_NONE              ETH_MQ_RX_NONE
#define RTE_ETH_MQ_TX_NONE              ETH_MQ_TX_NONE

#define RTE_ETH_TX_OFFLOAD_IPV4_CKSUM   DEV_TX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_TCP_CKSUM    DEV_TX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_TX_OFFLOAD_UDP_CKSUM    DEV_TX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_TX_OFFLOAD_VLAN_INSERT  DEV_TX_OFFLOAD_VLAN_INSERT
#define RTE_ETH_RX_OFFLOAD_VLAN_STRIP   DEV_RX_OFFLOAD_VLAN_STRIP

#define RTE_ETH_RSS_IPV4                ETH_RSS_IPV4
#define RTE_ETH_RSS_FRAG_IPV4           ETH_RSS_FRAG_IPV4
#define RTE_ETH_RSS_IPV6                ETH_RSS_IPV6
#define RTE_ETH_RSS_FRAG_IPV6           ETH_RSS_FRAG_IPV6

#define RTE_ETH_RSS_NONFRAG_IPV4_UDP    ETH_RSS_NONFRAG_IPV4_UDP
#define RTE_ETH_RSS_NONFRAG_IPV6_UDP    ETH_RSS_NONFRAG_IPV6_UDP
#define RTE_ETH_RSS_NONFRAG_IPV4_TCP    ETH_RSS_NONFRAG_IPV4_TCP
#define RTE_ETH_RSS_NONFRAG_IPV6_TCP    ETH_RSS_NONFRAG_IPV6_TCP

#define RTE_ETH_MQ_RX_RSS               ETH_MQ_RX_RSS
#endif
#define RSS_HASH_KEY_LENGTH 40
#define RSS_NONE            0
#define RSS_L3              1
#define RSS_L3L4            2
static uint8_t rss_hash_key_symmetric_be[RSS_HASH_KEY_LENGTH];
static uint8_t rss_hash_key_symmetric[RSS_HASH_KEY_LENGTH] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};
constexpr uint8_t DpdkTransport::kDefaultRssKey[];

#if 0
void DpdkTransport::setup_phy_port(uint16_t phy_port, size_t numa_node,
                                   DpdkProcType proc_type) {
  _unused(proc_type);
  uint16_t num_ports = rte_eth_dev_count_avail();
  if (phy_port > num_ports) {
  //if (phy_port >= num_ports) {
    fprintf(stderr,
            "Error: Port %u (0-based) requested, but only %u DPDK ports "
            "available. Please ensure:\n",
            phy_port, num_ports);
    fprintf(stderr,
            "1. If you have a DPDK-capable port, ensure that (a) the NIC's "
            "NUMA node has huge pages, and (b) this process is not pinned "
            "(e.g., via numactl) to a different NUMA node than the NIC's.\n");

    const char *ld_library_path = getenv("LD_LIBRARY_PATH");
    const char *library_path = getenv("LIBRARY_PATH");

    fprintf(stderr,
            "2. Your LD_LIBRARY_PATH (= %s) and/or LIBRARY_PATH (= %s) "
            "contains the NIC's userspace libraries (e.g., libmlx5.so).\n",
            ld_library_path == nullptr ? "not set" : ld_library_path,
            library_path == nullptr ? "not set" : library_path);
    rt_assert(false);
  }
#if 0
  rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(phy_port, &dev_info);
  fprintf(stderr,"phy port %u, port avail %u ,dev_info.rx_desc_lim.nb_max %d and dev_info.tx_desc_lim.nb_max %d \n",phy_port,num_ports,dev_info.rx_desc_lim.nb_max,dev_info.tx_desc_lim.nb_max);
  rt_assert(dev_info.rx_desc_lim.nb_max >= kNumRxRingEntries,
            "Device RX ring too small");
  rt_assert(dev_info.tx_desc_lim.nb_max >= kNumTxRingDesc,
            "Device TX ring too small");
  ERPC_INFO("Initializing port %u with driver %s\n", phy_port,
            dev_info.driver_name);
#endif
  // Create per-thread RX and TX queues
  rte_eth_conf eth_conf;
  memset(&eth_conf, 0, sizeof(eth_conf));

  if (!kIsWindows) {
#if 0
    eth_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    eth_conf.lpbk_mode = 1;
    eth_conf.rx_adv_conf.rss_conf.rss_key =
        const_cast<uint8_t *>(kDefaultRssKey);
    eth_conf.rx_adv_conf.rss_conf.rss_key_len = 40;
    eth_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_UDP;
#else
    eth_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
#endif
  } else {
    eth_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
  }

  eth_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
  //eth_conf.txmode.offloads = kOffloads;

  int ret = rte_eth_dev_configure(phy_port, kMaxQueuesPerPort,
                                  kMaxQueuesPerPort, &eth_conf);
  rt_assert(ret == 0, "Ethdev configuration error: ", strerror(-1 * ret));

  // Set up all RX and TX queues and start the device. This can't be done later
  // on a per-thread basis since we must start the device to use any queue.
  // Once the device is started, more queues cannot be added without stopping
  // and reconfiguring the device.
  for (size_t i = 0; i < kMaxQueuesPerPort; i++) {
    const std::string pname = get_mempool_name(phy_port, i);
    rte_mempool *mempool =
        rte_pktmbuf_pool_create(pname.c_str(), kNumMbufs, 0 /* cache */,
                                0 /* priv size */, kMbufSize, numa_node);
    rt_assert(mempool != nullptr, "Mempool create failed: " + dpdk_strerror());

    rte_eth_rxconf eth_rx_conf;
    memset(&eth_rx_conf, 0, sizeof(eth_rx_conf));
    eth_rx_conf.rx_thresh.pthresh = 8;

    int ret = rte_eth_rx_queue_setup(phy_port, i, kNumRxRingEntries, numa_node,
                                     &eth_rx_conf, mempool);
    rt_assert(ret == 0, "Failed to setup RX queue: " + std::to_string(i) +
                            ". Error " + strerror(-1 * ret));

    rte_eth_txconf eth_tx_conf;
    memset(&eth_tx_conf, 0, sizeof(eth_tx_conf));
    eth_tx_conf.tx_thresh.pthresh = 32;
    eth_tx_conf.offloads = eth_conf.txmode.offloads;

    ret = rte_eth_tx_queue_setup(phy_port, i, kNumTxRingDesc, numa_node,
                                 &eth_tx_conf);
    rt_assert(ret == 0, "Failed to setup TX queue: " + std::to_string(i));
  }

  rte_eth_dev_start(phy_port);
#if 1
  num_ports = rte_eth_dev_count_avail();
  rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(phy_port, &dev_info);
  fprintf(stderr,"phy port %u, port avail %u ,dev_info.rx_desc_lim.nb_max %d and dev_info.tx_desc_lim.nb_max %d \n",phy_port,num_ports,dev_info.rx_desc_lim.nb_max,dev_info.tx_desc_lim.nb_max);
  rt_assert(dev_info.rx_desc_lim.nb_max >= kNumRxRingEntries,
            "Device RX ring too small");
  rt_assert(dev_info.tx_desc_lim.nb_max >= kNumTxRingDesc,
            "Device TX ring too small");
  ERPC_INFO("Initializing port %u with driver %s\n", phy_port,
            dev_info.driver_name);
#endif
}
#else
static uint64_t rss_get_rss_hf(struct rte_eth_dev_info *dev_info, uint8_t rss, bool ipv6)
{
    uint64_t offloads = 0;
    uint64_t ipv4_flags = 0;
    uint64_t ipv6_flags = 0;

    offloads = dev_info->flow_type_rss_offloads;
    if (rss == RSS_L3) {
        ipv4_flags = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4;
        ipv6_flags = RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_FRAG_IPV6;
    } else if (rss == RSS_L3L4) {
        ipv4_flags = RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV4_TCP;
        ipv6_flags = RTE_ETH_RSS_NONFRAG_IPV6_UDP | RTE_ETH_RSS_NONFRAG_IPV6_TCP;
    }

    if (ipv6) {
        if ((offloads & ipv6_flags) == 0) {
            return 0;
        }
    } else {
        if ((offloads & ipv4_flags) == 0) {
            return 0;
        }
    }

    return (offloads & (ipv4_flags | ipv6_flags));
}
int rss_config_port(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info)
{
    uint64_t rss_hf = 0;
    struct rte_eth_rss_conf *rss_conf = NULL;

    rss_conf = &conf->rx_adv_conf.rss_conf;
#if 0
    if (g_config.rss == RSS_AUTO) {
        if (g_config.mq_rx_rss) {
            conf->rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
            rss_conf->rss_hf = rss_get_rss_hf(dev_info, g_config.rss_auto);
        }
        return 0;
    }
#endif
    rss_hf = rss_get_rss_hf(dev_info, RSS_L3L4,false);
    //rss_hf = rss_get_rss_hf(dev_info, RSS_L3,false);
    if (rss_hf == 0) {
        return -1;
    }

    conf->rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
#if DEBUG_I40E
#else
    rss_conf->rss_key = rss_hash_key_symmetric;
    rss_conf->rss_key_len = RSS_HASH_KEY_LENGTH,
#endif
    rss_conf->rss_hf = rss_hf;

    return 0;
}
void rss_init(void)
{
    rte_convert_rss_key(reinterpret_cast<const uint32_t*>(rss_hash_key_symmetric),
                        reinterpret_cast<uint32_t*>(rss_hash_key_symmetric_be), RSS_HASH_KEY_LENGTH);
}
void DpdkTransport::setup_phy_port(uint16_t phy_port, size_t numa_node,
                                   DpdkProcType proc_type) {
	int ret;
	struct rte_eth_conf port_conf = {
#if RTE_VERSION < RTE_VERSION_NUM(20, 0, 0, 0)
		.rxmode = {
                        .mq_mode = ETH_MQ_RX_NONE,
			.split_hdr_size = 0,
		},
#else
                .rxmode = {
                ///.mq_mode = RTE_ETH_MQ_RX_NONE,
                .max_lro_pkt_size = 1024,
                //.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
                },
#endif
		.txmode = {
			.offloads =
				DEV_TX_OFFLOAD_VLAN_INSERT |
				DEV_TX_OFFLOAD_IPV4_CKSUM  |
				DEV_TX_OFFLOAD_UDP_CKSUM   |
				DEV_TX_OFFLOAD_TCP_CKSUM   |
				DEV_TX_OFFLOAD_SCTP_CKSUM  |
				DEV_TX_OFFLOAD_TCP_TSO,
		},
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;
        struct rte_eth_conf dev_conf;
        printf("phy_port is %u, state : %u, valid : %d \n",phy_port,rte_eth_devices[phy_port].state, rte_eth_dev_is_valid_port(phy_port));
	ret = rte_eth_dev_info_get(phy_port, &dev_info);
	if (ret != 0)
        {
                printf("get phy_port  %u info fail \n",phy_port);
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			phy_port, strerror(-ret));

        }
#if 1
        rss_init();
        rss_config_port(&dev_conf,&dev_info);
#endif
        if(dev_info.flow_type_rss_offloads & RTE_ETH_RSS_IPV4) {
            printf("support RTE_ETH_RSS_IPV4 \n");
        }
        if(dev_info.flow_type_rss_offloads &  RTE_ETH_RSS_FRAG_IPV4) {
            printf("support  RTE_ETH_RSS_FRAG_IPV4\n");
        }
        if(dev_info.flow_type_rss_offloads &  RTE_ETH_RSS_NONFRAG_IPV4_UDP) {
            printf("support  RTE_ETH_RSS_NONFRAG_IPV4_UDP\n");
        }
        if(dev_info.flow_type_rss_offloads &  RTE_ETH_RSS_NONFRAG_IPV4_TCP) {
            printf("support  RTE_ETH_RSS_NONFRAG_IPV4_TCP\n");
        }
	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
        port_conf.rx_adv_conf.rss_conf = dev_conf.rx_adv_conf.rss_conf;
        port_conf.rxmode.mq_mode = dev_conf.rxmode.mq_mode; 
	printf(":: initializing port: %d\n", phy_port);
	ret = rte_eth_dev_configure(phy_port,
				kMaxQueuesPerPort, kMaxQueuesPerPort, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, phy_port);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;
  for (size_t i = 0; i < kMaxQueuesPerPort; i++) {
    const std::string pname = get_mempool_name(phy_port, i);
    rte_mempool *mempool =
        rte_pktmbuf_pool_create(pname.c_str(), kNumMbufs, 0 /* cache */,
                                0 /* priv size */, kMbufSize, numa_node);
    rt_assert(mempool != nullptr, "Mempool create failed: " + dpdk_strerror() +"\n");

    int ret = rte_eth_rx_queue_setup(phy_port, i, kNumRxRingEntries, numa_node,
                                     &rxq_conf, mempool);
    rt_assert(ret == 0, "Failed to setup RX queue: " + std::to_string(i) +
                            ". Error " + strerror(-1 * ret) + "\n");

    ret = rte_eth_tx_queue_setup(phy_port, i, kNumTxRingDesc, numa_node,
                                 &txq_conf);
    rt_assert(ret == 0, "Failed to setup TX queue: " + std::to_string(i) + "\n");
  }
    printf(":: initializing port: %d queue done\n", phy_port);
#if 0
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	for (i = 0; i < nr_queues; i++) {
                //printf("setup %u queue \n",i);
		ret = rte_eth_rx_queue_setup(phy_port, i, NUM_OF_DESC,
				     rte_eth_dev_socket_id(phy_port),
				     &rxq_conf,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, phy_port);
		}
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_tx_queue_setup(phy_port, i, NUM_OF_DESC,
				rte_eth_dev_socket_id(phy_port),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, phy_port);
		}
	}
#endif
	ret = rte_eth_promiscuous_enable(phy_port);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			":: promiscuous mode enable failed: err=%s, port=%u\n",
			rte_strerror(-ret), phy_port);

	ret = rte_eth_dev_start(phy_port);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, phy_port);
	}


	printf(":: initializing port: %d done\n", phy_port);
}
#endif

}  // namespace erpc

#endif

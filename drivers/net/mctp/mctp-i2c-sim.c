// SPDX-License-Identifier: GPL-2.0
/*
 * MCTP I2C Simulator — virtual I2C adapter with loopback MCTP endpoint.
 *
 * Creates a virtual I2C bus. The mctp-i2c driver attaches to it via DTS
 * (compatible = "mctp-i2c-controller"). Outgoing MCTP frames from the kernel
 * are intercepted in master_xfer() and processed as MCTP Control Protocol
 * requests. Responses are injected back via i2c_slave_event() to simulate
 * a remote endpoint replying over I2C.
 *
 * Supports:
 *   - MCTP Control: Get/Set Endpoint ID, Get UUID, Get Message Type Support
 *   - PLDM Discovery (type 0x00): GetTID, GetPLDMVersion, GetPLDMTypes,
 *                                  GetPLDMCommands, GetDeviceIdentifiers
 *   - PLDM Monitoring (type 0x02): GetPDRRepositoryInfo, GetPDR, GetSensorReading
 *   - PLDM FRU (type 0x04): GetFRURecordTableMetadata, GetFRURecordTable
 *   - PLDM FWUP (type 0x05): Phase 1 inventory (QueryDeviceIdentifiers,
 *                               GetFirmwareParameters) + Phase 2 update state
 *                               machine (RequestFirmwareData, TransferComplete,
 *                               VerifyComplete, ApplyComplete)
 *   - Echo (type 0x7e): loopback with multi-fragment reassembly
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <linux/i2c-smbus.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/crc32.h>

#define MCTP_I2C_COMMANDCODE	0x0f
#define MCTP_CTRL_MSG_TYPE	0x00

/* MCTP Control Protocol command codes */
#define MCTP_CTRL_CMD_SET_EID		0x01
#define MCTP_CTRL_CMD_GET_EID		0x02
#define MCTP_CTRL_CMD_GET_UUID		0x03
#define MCTP_CTRL_CMD_GET_MSG_TYPE	0x05

/* PLDM message type (DSP0240) */
#define MCTP_MSG_TYPE_PLDM		0x01

/* Vendor-defined message type used for loopback echo testing (mctp-req default) */
#define MCTP_MSG_TYPE_ECHO		0x7e

/* PLDM types */
#define PLDM_TYPE_DISCOVERY		0x00
#define PLDM_TYPE_MONITORING		0x02
#define PLDM_TYPE_FRU			0x04
#define PLDM_TYPE_FWUP			0x05

/* PLDM FRU commands (DSP0257) */
#define PLDM_CMD_GET_FRU_RECORD_TABLE_METADATA	0x01
#define PLDM_CMD_GET_FRU_RECORD_TABLE		0x02

/* PLDM FWUP commands (DSP0267) */
#define PLDM_CMD_FWUP_QUERY_DEVICE_IDENTIFIERS	0x01
#define PLDM_CMD_FWUP_GET_FIRMWARE_PARAMETERS	0x02
#define PLDM_CMD_FWUP_REQUEST_UPDATE		0x10
#define PLDM_CMD_FWUP_PASS_COMPONENT_TABLE	0x13
#define PLDM_CMD_FWUP_UPDATE_COMPONENT		0x14
#define PLDM_CMD_FWUP_REQUEST_FIRMWARE_DATA	0x15
#define PLDM_CMD_FWUP_TRANSFER_COMPLETE		0x16
#define PLDM_CMD_FWUP_VERIFY_COMPLETE		0x17
#define PLDM_CMD_FWUP_APPLY_COMPLETE		0x18
#define PLDM_CMD_FWUP_ACTIVATE_FIRMWARE		0x1a

/* MCTP Tag Owner bit (bit 3 of flags_seq_tag) */
#define MCTP_HDR_TO	BIT(3)

/* JMicron PCI Vendor ID */
#define SIM_PCI_VENDOR_ID	0x197B

/* FWUP firmware chunk size per RequestFirmwareData */
#define SIM_FWUP_CHUNK_SIZE	64
/* Fixed MCTP tag used for simulator-initiated FWUP requests (TO=1) */
#define SIM_FWUP_TAG		1

/* PLDM Discovery commands */
#define PLDM_CMD_GET_DEVICE_IDENTIFIERS 0x01
#define PLDM_CMD_GET_TID                0x02
#define PLDM_CMD_GET_PLDM_VERSION       0x03
#define PLDM_CMD_GET_PLDM_TYPES         0x04
#define PLDM_CMD_GET_PLDM_COMMANDS      0x05

/* PLDM Completion Codes */
#define PLDM_SUCCESS                    0x00
#define PLDM_ERROR                      0x01
#define PLDM_ERROR_UNSUPPORTED_PLDM_CMD 0x05
#define PLDM_INVALID_RECORD_HANDLE      0x82

/* PLDM Version 1.0.0 encoded as per DSP0240 */
static const u8 pldm_version_100[] = { 0xF1, 0xF0, 0xF0, 0x00 };

/* PLDM Platform Monitoring commands */
#define PLDM_CMD_GET_SENSOR_READING	0x11
#define PLDM_CMD_GET_PDR_REPO_INFO	0x50
#define PLDM_CMD_GET_PDR		0x51

/* Simulated temperature: 45.00 °C = 4500 (unit_modifier = -2, i.e. ×10^-2) */
#define SIM_TEMP_READING		4500

/* DSP0237 baseline MTU: minimum all implementations must support */
#define MCTP_I2C_MINMTU			(64 + 4)	/* 68: 64 payload + 4 MCTP hdr */
/* Default fragment size: use baseline MTU payload (conservative, spec-compliant) */
#define MCTP_I2C_MAX_PAYLOAD		(MCTP_I2C_MINMTU - 4)	/* 64 bytes */

/* MCTP header fields */
#define MCTP_HDR_VER		0x01
#define MCTP_HDR_EOM		BIT(6)
#define MCTP_HDR_SOM		BIT(7)

/* Endpoint simulated EID (assigned by mctpd) */
#define SIM_EID_DEFAULT		0x00     /* before Set EID */

/* Simulated endpoint I2C slave address (7-bit) */
#define SIM_EP_ADDR		0x30

/* UUID for the simulated endpoint (randomly chosen, fixed) */
static const u8 sim_uuid[16] = {
	0xab, 0xcd, 0xef, 0x01,
	0x23, 0x45, 0x67, 0x89,
	0xaa, 0xbb, 0xcc, 0xdd,
	0xee, 0xff, 0x00, 0x11,
};

/* FWUP state machine */
enum sim_fwup_state {
	SIM_FWUP_IDLE,
	SIM_FWUP_READY_XFER,	/* RequestUpdate accepted */
	SIM_FWUP_DOWNLOAD,	/* downloading via RequestFirmwareData */
	SIM_FWUP_VERIFY,	/* TransferComplete sent, waiting ack */
	SIM_FWUP_VERIFY2,	/* VerifyComplete sent, waiting ack */
	SIM_FWUP_APPLY,		/* ApplyComplete sent, waiting ack */
	SIM_FWUP_ACTIVATING,	/* waiting for ActivateFirmware from BMC */
};

struct sim_fwup_ctx {
	enum sim_fwup_state	state;
	u32			total_size;	/* from UpdateComponent */
	u32			offset;		/* bytes downloaded so far */
	u8			inst_id;	/* incrementing PLDM instance id */
	u8			dest_addr;	/* BMC I2C address */
	u8			dest_eid;	/* BMC EID */
};

struct mctp_i2c_sim {
	struct i2c_adapter	adapter;
	struct i2c_client	*slave;		/* registered by mctp-i2c driver */
	struct platform_device	*pdev;
	u8			ep_eid;		/* current EID of simulated endpoint */

	/* echo reassembly state */
	u8			echo_buf[1024];	/* reassembly buffer */
	size_t			echo_len;	/* bytes accumulated so far */
	u8			echo_dest_addr;	/* I2C addr to send response to */
	u8			echo_dest_eid;	/* BMC EID (response destination) */
	u8			echo_mctp_tag;	/* MCTP tag from first fragment */

	/* PLDM reassembly state */
	u8			pldm_buf[256];	/* reassembly buffer */
	size_t			pldm_len;	/* bytes accumulated so far */
	u8			pldm_dest_addr;	/* I2C addr to send response to */
	u8			pldm_dest_eid;	/* BMC EID (response destination) */
	u8			pldm_mctp_tag;	/* MCTP tag from first fragment */

	/* FWUP Phase 2 state machine */
	struct sim_fwup_ctx	fwup;
	spinlock_t		fwup_lock;
	struct delayed_work	fwup_work;

	/* FWUP firmware version tracking */
	char			fw_active_version[32];	/* current active version */
	char			fw_pending_version[32];	/* version from UpdateComponent */

	/* deferred work to set net device MTU after mctp-i2c probes */
	struct delayed_work	mtu_work;
};

/* DSP0237 wire frame layout (excluding PEC) */
struct mctp_i2c_hdr {
	u8 dest_slave;		/* dest addr << 1 */
	u8 command;		/* 0x0f */
	u8 byte_count;		/* count of bytes after this field, excl PEC */
	u8 source_slave;	/* src addr << 1 | 1 */
};

struct mctp_hdr {
	u8 ver;
	u8 dest;
	u8 src;
	u8 flags_seq_tag;
};

struct mctp_ctrl_hdr {
	u8 ic_msg_type;		/* 0x00 for control */
	u8 rq_d_inst;		/* RQ=1 request, D=0, Instance ID */
	u8 cmd;
};

struct pldm_msg_hdr {
	u8 ic_msg_type;		/* 0x01 = PLDM */
	u8 rq_d_inst;		/* RQ(7)|D(6)|instance_id(4:0) */
	u8 pldm_type;		/* 0x00=Discovery, 0x02=Monitoring, 0x04=FRU */
	u8 cmd;			/* PLDM command code */
};

/*
 * Numeric Sensor PDR for simulated temperature sensor (DSP0248 Table 87).
 * sensor_id=1, base_unit=°C, unit_modifier=-2 (reading × 0.01 = °C),
 * sensor_data_size=sint16 (3), max=200.00°C, min=-10.00°C.
 * Thresholds: warning [0, 60]°C  critical [-5, 70]°C
 * base_oem_unit_handle / aux_oem_unit_handle are uint8 per libpldm struct.
 */
static const u8 sim_temp_pdr[] = {
	/* PDR Header (10 bytes) */
	0x01, 0x00, 0x00, 0x00,	/* record_handle = 1 */
	0x01,			/* pdr_header_version = 1 */
	0x02,			/* pdr_type = 2 (Numeric Sensor PDR) */
	0x00, 0x00,		/* record_change_number = 0 */
	0x47, 0x00,		/* data_length = 71 */

	/* PDR Data (71 bytes) */
	0x00, 0x00,		/* terminus_handle = 0 */
	0x01, 0x00,		/* sensor_id = 1 */
	0x24, 0x00,		/* entity_type = 0x0024 (Processor) */
	0x01, 0x00,		/* entity_instance_number = 1 */
	0x00, 0x00,		/* container_id = 0 */
	0x00,			/* sensor_init = 0 */
	0x01,			/* sensor_auxiliary_names_pdr = true (PDR handle 2) */
	0x02,			/* base_unit = 2 (Degrees C) */
	0xFE,			/* unit_modifier = -2 */
	0x00,			/* rate_unit = 0 */
	0x00,			/* base_oem_unit_handle = 0 (uint8, per libpldm) */
	0x00,			/* aux_unit = 0 */
	0x00,			/* aux_unit_modifier = 0 */
	0x00,			/* aux_rate_unit = 0 */
	0x00,			/* rel = 0 */
	0x00,			/* aux_oem_unit_handle = 0 (uint8, per libpldm) */
	0x01,			/* is_linear = true */
	0x03,			/* sensor_data_size = 3 (sint16) */
	0x00, 0x00, 0x80, 0x3F,	/* resolution = 1.0 (float32 LE) */
	0x00, 0x00, 0x00, 0x00,	/* offset = 0.0 (float32) */
	0x00, 0x00,		/* accuracy = 0 */
	0x00,			/* plus_tolerance = 0 */
	0x00,			/* minus_tolerance = 0 */
	0x00, 0x00,		/* hysteresis = 0 (sint16) */
	0x1B,			/* supported_thresholds: upperWarning|upperCritical|lowerWarning|lowerCritical */
	0x00,			/* threshold_and_hysteresis_volatility = 0 */
	0x00, 0x00, 0x00, 0x00,	/* state_transition_interval = 0.0 */
	0x00, 0x00, 0x20, 0x41,	/* update_interval = 10.0 */
	0x20, 0x4E,		/* max_readable = 20000 (200.00°C) sint16 LE */
	0x18, 0xFC,		/* min_readable = -1000 (-10.00°C) sint16 LE */
	0x03,			/* range_field_format = 3 (sint16) */
	0x78,			/* range_field_support: warningHigh|warningLow|criticalHigh|criticalLow */
	0x00, 0x00,		/* nominal_value = 0 */
	0x00, 0x00,		/* normal_max = 0 */
	0x00, 0x00,		/* normal_min = 0 */
	0x70, 0x17,		/* warning_high  =  6000 → 60.00°C */
	0x00, 0x00,		/* warning_low   =     0 →  0.00°C */
	0x58, 0x1B,		/* critical_high =  7000 → 70.00°C */
	0x0C, 0xFE,		/* critical_low  =  -500 → -5.00°C */
	0x00, 0x00,		/* fatal_high = 0 */
	0x00, 0x00,		/* fatal_low  = 0 */
};

/*
 * Sensor Auxiliary Names PDR (DSP0248 type=6) for sensor_id=1.
 * Provides the display name "PLDM Sensor 1" (UTF-16BE, language="en").
 * base_oem_unit_handle / aux_oem_unit_handle are uint8 per libpldm struct.
 */
static const u8 sim_sensor_aux_names_pdr[] = {
	/* PDR Header (10 bytes) */
	0x02, 0x00, 0x00, 0x00,	/* record_handle = 2 */
	0x01,			/* pdr_header_version = 1 */
	0x06,			/* pdr_type = 6 (Sensor Auxiliary Names PDR) */
	0x00, 0x00,		/* record_change_number = 0 */
	0x25, 0x00,		/* data_length = 37 */

	/* PDR Data (37 bytes) */
	0x00, 0x00,		/* terminus_handle = 0 */
	0x01, 0x00,		/* sensor_id = 1 */
	0x01,			/* sensor_count = 1 */
	/* names[]: nameStringCount + language_tag\0 + UTF-16BE name\0 */
	0x01,			/* nameStringCount = 1 */
	0x65, 0x6E, 0x00,	/* language_tag = "en\0" */
	/* UTF-16BE "PLDM Sensor 1\0" */
	0x00, 0x50,		/* P */
	0x00, 0x4C,		/* L */
	0x00, 0x44,		/* D */
	0x00, 0x4D,		/* M */
	0x00, 0x20,		/*   */
	0x00, 0x53,		/* S */
	0x00, 0x65,		/* e */
	0x00, 0x6E,		/* n */
	0x00, 0x73,		/* s */
	0x00, 0x6F,		/* o */
	0x00, 0x72,		/* r */
	0x00, 0x20,		/*   */
	0x00, 0x31,		/* 1 */
	0x00, 0x00,		/* null terminator */
};

/*
 * FRU Record Table (DSP0257): one General record set with 5 fields.
 * Manufacturer="JMicron", Model="JM1000", PartNumber="P0001",
 * Serial="S0001", Name="MCTP Simulator".
 */
static const u8 sim_fru_table[] = {
	/* FRU Record Set Header (5 bytes) */
	0x01, 0x00,	/* record_set_id = 1 */
	0x01,		/* record_type = 1 (General) */
	0x05,		/* num_fields = 5 */
	0x01,		/* encoding_type = 1 (ASCII) */
	/* Field: Manufacturer (type=0x05, len=7) */
	0x05, 0x07, 'J', 'M', 'i', 'c', 'r', 'o', 'n',
	/* Field: Model (type=0x02, len=6) */
	0x02, 0x06, 'J', 'M', '1', '0', '0', '0',
	/* Field: Part Number (type=0x03, len=5) */
	0x03, 0x05, 'P', '0', '0', '0', '1',
	/* Field: Serial Number (type=0x04, len=5) */
	0x04, 0x05, 'S', '0', '0', '0', '1',
	/* Field: Name (type=0x08, len=14) */
	0x08, 0x0E, 'M', 'C', 'T', 'P', ' ', 'S', 'i', 'm', 'u', 'l', 'a', 't', 'o', 'r',
};

/* Deferred work: set net device MTU to MCTP_I2C_MINMTU after mctp-i2c probes */
static void mctp_i2c_sim_set_mtu_work(struct work_struct *work)
{
	struct mctp_i2c_sim *sim =
		container_of(work, struct mctp_i2c_sim, mtu_work.work);
	struct net_device *dev;
	char ifname[IFNAMSIZ];

	snprintf(ifname, sizeof(ifname), "mctpi2c%d", sim->adapter.nr);
	dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		dev_warn(&sim->pdev->dev,
			 "net device %s not found, MTU not set\n", ifname);
		return;
	}

	dev_set_mtu(dev, MCTP_I2C_MINMTU);
	dev_info(&sim->pdev->dev,
		 "set %s mtu to %d (MCTP_I2C_MINMTU)\n", ifname, MCTP_I2C_MINMTU);
	dev_put(dev);
}

/* Inject a response frame into the mctp-i2c slave callback */
static void sim_inject_response(struct mctp_i2c_sim *sim,
				const u8 *buf, size_t len)
{
	u8 val;
	size_t i;

	if (!sim->slave) {
		pr_info("mctp-i2c-sim: inject_response: slave is NULL\n");
		return;
	}

	pr_info("mctp-i2c-sim: injecting response len=%zu to slave 0x%02x\n",
		len, sim->slave->addr);
	/* Signal start of write transaction from endpoint to BMC */
	i2c_slave_event(sim->slave, I2C_SLAVE_WRITE_REQUESTED, &val);

	for (i = 0; i < len; i++) {
		val = buf[i];
		i2c_slave_event(sim->slave, I2C_SLAVE_WRITE_RECEIVED, &val);
	}

	/* Signal end of transaction (triggers mctp_i2c_recv) */
	i2c_slave_event(sim->slave, I2C_SLAVE_STOP, &val);
}

/* Build and inject an MCTP Control Protocol response */
static void sim_send_ctrl_response(struct mctp_i2c_sim *sim,
				   u8 dest_addr, u8 src_eid, u8 dest_eid,
				   u8 mctp_tag, u8 ctrl_inst_id, u8 cmd,
				   const u8 *payload, size_t payload_len)
{
	/*
	 * Wire frame (DSP0237):
	 * [dest_slave][0x0f][byte_count][source_slave]
	 * [MCTP hdr: ver dest src flags_seq_tag]
	 * [ctrl hdr: ic_msg_type rq_d_inst cmd]
	 * [completion_code]
	 * [payload...]
	 * [PEC]
	 */
	u8 buf[64];
	struct mctp_i2c_hdr *i2c_hdr = (struct mctp_i2c_hdr *)buf;
	struct mctp_hdr *mctp_hdr_p;
	struct mctp_ctrl_hdr *ctrl_hdr;
	u8 *data;
	size_t data_len;
	u8 pec;

	/* MCTP payload = mctp_hdr + ctrl_hdr + completion_code + payload */
	data_len = sizeof(struct mctp_hdr) + sizeof(struct mctp_ctrl_hdr) +
		   1 + payload_len;

	if (sizeof(struct mctp_i2c_hdr) + data_len + 1 > sizeof(buf)) {
		pr_warn("mctp-i2c-sim: response too large\n");
		return;
	}

	i2c_hdr->dest_slave  = dest_addr << 1;
	i2c_hdr->command     = MCTP_I2C_COMMANDCODE;
	/* byte_count = source_slave + MCTP payload */
	i2c_hdr->byte_count  = 1 + data_len;
	i2c_hdr->source_slave = (SIM_EP_ADDR << 1) | 0x01;

	mctp_hdr_p = (struct mctp_hdr *)(buf + sizeof(struct mctp_i2c_hdr));
	mctp_hdr_p->ver           = MCTP_HDR_VER;
	mctp_hdr_p->dest          = dest_eid;
	mctp_hdr_p->src           = sim->ep_eid;
	/* Tag Owner=0 in response; preserve tag value from request */
	mctp_hdr_p->flags_seq_tag = MCTP_HDR_SOM | MCTP_HDR_EOM | (mctp_tag & 0x07);
	pr_info("mctp-i2c-sim: >> cmd=0x%02x dst=%d src=%d tag=0x%02x\n",
		cmd, dest_eid, sim->ep_eid, mctp_hdr_p->flags_seq_tag & 0x07);

	ctrl_hdr = (struct mctp_ctrl_hdr *)(mctp_hdr_p + 1);
	ctrl_hdr->ic_msg_type = MCTP_CTRL_MSG_TYPE;
	ctrl_hdr->rq_d_inst   = ctrl_inst_id & 0x1f;  /* RQ=0 response */
	ctrl_hdr->cmd         = cmd;

	data = (u8 *)(ctrl_hdr + 1);
	data[0] = 0x00; /* completion code: success */
	if (payload_len)
		memcpy(data + 1, payload, payload_len);

	/* Append PEC (excludes dest_slave byte per DSP0237) */
	pec = i2c_smbus_pec(0, buf, sizeof(struct mctp_i2c_hdr) + data_len);
	buf[sizeof(struct mctp_i2c_hdr) + data_len] = pec;

	sim_inject_response(sim, buf + 1,
			    sizeof(struct mctp_i2c_hdr) - 1 + data_len + 1);
}

/*
 * Build and inject an MCTP message, fragmenting if payload_len > MCTP_I2C_MAX_PAYLOAD.
 */
static void sim_send_fragmented_msg(struct mctp_i2c_sim *sim,
				    u8 dest_addr, u8 dest_eid,
				    u8 mctp_tag,
				    const u8 *payload, size_t payload_len)
{
	/* buf must fit the largest single I2C frame */
	u8 buf[sizeof(struct mctp_i2c_hdr) + MCTP_I2C_MAX_PAYLOAD +
	       sizeof(struct mctp_hdr) + 1];
	struct mctp_i2c_hdr *i2c_hdr = (struct mctp_i2c_hdr *)buf;
	struct mctp_hdr *mctp_hdr_p;
	size_t offset = 0;
	u8 seq = 0;
	u8 pec;

	pr_info("mctp-i2c-sim: TX >> sending %zu bytes\n", payload_len);
	pr_info("mctp-i2c-sim: TX raw: %*phN\n",
		(int)payload_len, payload);

	while (offset < payload_len) {
		size_t frag_len = min(payload_len - offset,
				      (size_t)MCTP_I2C_MAX_PAYLOAD);
		size_t data_len = sizeof(struct mctp_hdr) + frag_len;
		bool is_som = (offset == 0);
		bool is_eom = (offset + frag_len >= payload_len);
		u8 flags = 0;

		if (is_som)
			flags |= MCTP_HDR_SOM;
		if (is_eom)
			flags |= MCTP_HDR_EOM;
		flags |= (seq & 0x03) << 4;	/* sequence number bits[5:4] */
		flags |= (mctp_tag & 0x07);	/* TO=0 in response */

		i2c_hdr->dest_slave   = dest_addr << 1;
		i2c_hdr->command      = MCTP_I2C_COMMANDCODE;
		i2c_hdr->byte_count   = 1 + data_len;
		i2c_hdr->source_slave = (SIM_EP_ADDR << 1) | 0x01;

		mctp_hdr_p = (struct mctp_hdr *)(buf + sizeof(struct mctp_i2c_hdr));
		mctp_hdr_p->ver           = MCTP_HDR_VER;
		mctp_hdr_p->dest          = dest_eid;
		mctp_hdr_p->src           = sim->ep_eid;
		mctp_hdr_p->flags_seq_tag = flags;

		memcpy((u8 *)(mctp_hdr_p + 1), payload + offset, frag_len);

		pec = i2c_smbus_pec(0, buf,
				    sizeof(struct mctp_i2c_hdr) + data_len);
		buf[sizeof(struct mctp_i2c_hdr) + data_len] = pec;

		if (payload_len > MCTP_I2C_MAX_PAYLOAD)
			pr_info("mctp-i2c-sim: TX >> frag offset=%zu/%zu som=%d eom=%d seq=%d\n",
				offset + frag_len, payload_len, is_som, is_eom, seq);

		sim_inject_response(sim, buf + 1,
				    sizeof(struct mctp_i2c_hdr) - 1 + data_len + 1);

		offset += frag_len;
		seq++;
	}
}


/*
 * Build and inject an MCTP message with TO=1 (simulator is tag owner).
 * Used for FWUP Phase 2 active requests sent from simulator to BMC.
 */
static void sim_send_fragmented_request(struct mctp_i2c_sim *sim,
					u8 dest_addr, u8 dest_eid,
					u8 tag,
					const u8 *payload, size_t payload_len)
{
	u8 buf[sizeof(struct mctp_i2c_hdr) + MCTP_I2C_MAX_PAYLOAD +
	       sizeof(struct mctp_hdr) + 1];
	struct mctp_i2c_hdr *i2c_hdr = (struct mctp_i2c_hdr *)buf;
	struct mctp_hdr *mctp_hdr_p;
	size_t offset = 0;
	u8 seq = 0;
	u8 pec;

	while (offset < payload_len) {
		size_t frag_len = min(payload_len - offset,
				      (size_t)MCTP_I2C_MAX_PAYLOAD);
		size_t data_len = sizeof(struct mctp_hdr) + frag_len;
		bool is_som = (offset == 0);
		bool is_eom = (offset + frag_len >= payload_len);
		u8 flags = 0;

		if (is_som)
			flags |= MCTP_HDR_SOM;
		if (is_eom)
			flags |= MCTP_HDR_EOM;
		flags |= (seq & 0x03) << 4;
		flags |= MCTP_HDR_TO | (tag & 0x07);	/* TO=1: simulator owns tag */

		i2c_hdr->dest_slave   = dest_addr << 1;
		i2c_hdr->command      = MCTP_I2C_COMMANDCODE;
		i2c_hdr->byte_count   = 1 + data_len;
		i2c_hdr->source_slave = (SIM_EP_ADDR << 1) | 0x01;

		mctp_hdr_p = (struct mctp_hdr *)(buf + sizeof(struct mctp_i2c_hdr));
		mctp_hdr_p->ver           = MCTP_HDR_VER;
		mctp_hdr_p->dest          = dest_eid;
		mctp_hdr_p->src           = sim->ep_eid;
		mctp_hdr_p->flags_seq_tag = flags;

		memcpy((u8 *)(mctp_hdr_p + 1), payload + offset, frag_len);

		pec = i2c_smbus_pec(0, buf,
				    sizeof(struct mctp_i2c_hdr) + data_len);
		buf[sizeof(struct mctp_i2c_hdr) + data_len] = pec;

		sim_inject_response(sim, buf + 1,
				    sizeof(struct mctp_i2c_hdr) - 1 + data_len + 1);

		offset += frag_len;
		seq++;
	}
}

/* Build and inject a PLDM request (RQ=1, TO=1) for FWUP Phase 2 */
static void sim_send_pldm_request(struct mctp_i2c_sim *sim,
				  u8 dest_addr, u8 dest_eid, u8 tag,
				  u8 inst_id, u8 pldm_type, u8 cmd,
				  const u8 *data, size_t data_len)
{
	u8 payload[256];
	size_t payload_len;

	payload[0] = MCTP_MSG_TYPE_PLDM;
	payload[1] = 0x80 | (inst_id & 0x1f);	/* RQ=1, D=0 */
	payload[2] = pldm_type;
	payload[3] = cmd;
	if (data && data_len)
		memcpy(payload + 4, data, data_len);
	payload_len = 4 + data_len;

	pr_info("mctp-i2c-sim: FWUP >> type=0x%02x cmd=0x%02x inst=%u\n",
		pldm_type, cmd, inst_id);

	sim_send_fragmented_request(sim, dest_addr, dest_eid, tag,
				    payload, payload_len);
}

/* Build and inject a PLDM response */
static void sim_send_pldm_response(struct mctp_i2c_sim *sim,
				   u8 dest_addr, u8 dest_eid, u8 mctp_tag,
				   u8 inst_id, u8 pldm_type, u8 cmd,
				   u8 cc, const u8 *data, size_t data_len)
{
	u8 payload[256];
	size_t payload_len;

	payload[0] = MCTP_MSG_TYPE_PLDM;
	payload[1] = inst_id & 0x1f;    /* RQ=0, D=0 response */
	payload[2] = pldm_type;
	payload[3] = cmd;
	payload[4] = cc;                /* completion code */
	if (data && data_len)
		memcpy(payload + 5, data, data_len);
	payload_len = 5 + data_len;

	pr_info("mctp-i2c-sim: PLDM >> type=0x%02x cmd=0x%02x inst=%u cc=0x%02x len=%zu\n",
		pldm_type, cmd, inst_id, cc, payload_len);

	sim_send_fragmented_msg(sim, dest_addr, dest_eid, mctp_tag,
				payload, payload_len);
}

/* Handle PLDM Discovery (type=0x00) commands */
static void sim_handle_pldm_discovery(struct mctp_i2c_sim *sim,
				      u8 dest_addr, u8 dest_eid, u8 mctp_tag,
				      u8 inst_id, u8 cmd,
				      const u8 *payload, size_t payload_len)
{
	u8 resp[64];
	size_t resp_len = 0;

	switch (cmd) {
	case PLDM_CMD_GET_TID:
		pr_info("mctp-i2c-sim: PLDM GetTID → TID=1\n");
		resp[0] = 0x01; /* TID = 1 */
		resp_len = 1;
		break;

	case PLDM_CMD_GET_PLDM_VERSION:
		pr_info("mctp-i2c-sim: PLDM GetPLDMVersion\n");
		/* resp: next_transfer_handle(4), transfer_flag(1), version_data(4) */
		memset(resp, 0, 9);
		resp[4] = 0x05; /* transfer_flag: start and end */
		memcpy(resp + 5, pldm_version_100, 4);
		resp_len = 9;
		break;

	case PLDM_CMD_GET_PLDM_TYPES:
		pr_info("mctp-i2c-sim: PLDM GetPLDMTypes → type0,type2,type4,type5\n");
		memset(resp, 0, 8);
		resp[0] = BIT(PLDM_TYPE_DISCOVERY) | BIT(PLDM_TYPE_MONITORING) |
			  BIT(PLDM_TYPE_FRU) | BIT(PLDM_TYPE_FWUP);
		resp_len = 8;
		break;

	case PLDM_CMD_GET_PLDM_COMMANDS:
		if (payload_len < 1)
			break;
		memset(resp, 0, 32);
		if (payload[0] == PLDM_TYPE_DISCOVERY) {
			pr_info("mctp-i2c-sim: PLDM GetPLDMCommands(Discovery)\n");
			resp[0] = BIT(PLDM_CMD_GET_DEVICE_IDENTIFIERS) |
				  BIT(PLDM_CMD_GET_TID) |
				  BIT(PLDM_CMD_GET_PLDM_VERSION) |
				  BIT(PLDM_CMD_GET_PLDM_TYPES) |
				  BIT(PLDM_CMD_GET_PLDM_COMMANDS);
		} else if (payload[0] == PLDM_TYPE_MONITORING) {
			pr_info("mctp-i2c-sim: PLDM GetPLDMCommands(Monitoring)\n");
			/* GetSensorReading=0x11(17) → byte2 bit1 */
			resp[2] = BIT(1);
			/* GetPDRRepositoryInfo=0x50(80) → byte10 bit0 */
			/* GetPDR=0x51(81) → byte10 bit1 */
			resp[10] = BIT(0) | BIT(1);
		} else if (payload[0] == PLDM_TYPE_FRU) {
			pr_info("mctp-i2c-sim: PLDM GetPLDMCommands(FRU)\n");
			/* GetFRURecordTableMetadata=0x01 → byte0 bit1 */
			/* GetFRURecordTable=0x02 → byte0 bit2 */
			resp[0] = BIT(1) | BIT(2);
		} else if (payload[0] == PLDM_TYPE_FWUP) {
			pr_info("mctp-i2c-sim: PLDM GetPLDMCommands(FWUP)\n");
			/* Phase 1: QueryDeviceIdentifiers=0x01, GetFirmwareParameters=0x02 */
			resp[0] = BIT(PLDM_CMD_FWUP_QUERY_DEVICE_IDENTIFIERS) |
				  BIT(PLDM_CMD_FWUP_GET_FIRMWARE_PARAMETERS);
			/* Phase 2 (byte2): RequestUpdate=0x10 */
			resp[2] = BIT(PLDM_CMD_FWUP_REQUEST_UPDATE & 0x07);
			/* Phase 2 (byte2): PassComponentTable=0x13, UpdateComponent=0x14 */
			/* Phase 2 (byte2): RequestFirmwareData=0x15, TransferComplete=0x16 */
			/* Phase 2 (byte2): VerifyComplete=0x17, ApplyComplete=0x18 */
			/* Phase 2 (byte3): ActivateFirmware=0x1a */
			resp[2] |= BIT(3) | BIT(4) | BIT(5) | BIT(6) | BIT(7);
			resp[3]  = BIT(0) | BIT(2);
		}
		resp_len = 32;
		break;

	case PLDM_CMD_GET_DEVICE_IDENTIFIERS:
		pr_info("mctp-i2c-sim: PLDM GetDeviceIdentifiers → none\n");
		/* resp: descriptor_count(1)=0, total_size(4)=0 */
		memset(resp, 0, 5);
		resp_len = 5;
		break;

	default:
		pr_info("mctp-i2c-sim: PLDM Discovery unhandled cmd=0x%02x\n", cmd);
		sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
				       inst_id, PLDM_TYPE_DISCOVERY, cmd,
				       PLDM_ERROR_UNSUPPORTED_PLDM_CMD, NULL, 0);
		return;
	}

	sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
			       inst_id, PLDM_TYPE_DISCOVERY, cmd,
			       PLDM_SUCCESS, resp, resp_len);
}


/* Handle PLDM Platform Monitoring (type=0x02) commands */
static void sim_handle_pldm_monitoring(struct mctp_i2c_sim *sim,
				       u8 dest_addr, u8 dest_eid, u8 mctp_tag,
				       u8 inst_id, u8 cmd,
				       const u8 *payload, size_t payload_len)
{
	u8 resp[128];
	size_t resp_len = 0;

	switch (cmd) {
	case PLDM_CMD_GET_PDR_REPO_INFO:
		pr_info("mctp-i2c-sim: PLDM GetPDRRepositoryInfo → 2 records\n");
		memset(resp, 0, 40);
		resp[0] = 0x00;         /* repository_state = available */
		/* record_count (uint32 LE) = 2 */
		resp[27] = 0x02;
		/* repository_size (uint32 LE) = sum of all PDR sizes */
		resp[31] = (sizeof(sim_temp_pdr) + sizeof(sim_sensor_aux_names_pdr)) & 0xff;
		/* largest_record_size (uint32 LE) = sizeof(sim_temp_pdr) */
		resp[35] = sizeof(sim_temp_pdr);
		resp_len = 40;
		break;

	case PLDM_CMD_GET_PDR: {
		u32 record_handle = 0;

		if (payload_len >= 4)
			record_handle = payload[0] | ((u32)payload[1] << 8) |
					((u32)payload[2] << 16) | ((u32)payload[3] << 24);

		if (record_handle > 2) {
			pr_info("mctp-i2c-sim: PLDM GetPDR handle=%u → INVALID_RECORD_HANDLE\n",
				record_handle);
			sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
					       inst_id, PLDM_TYPE_MONITORING, cmd,
					       PLDM_INVALID_RECORD_HANDLE, NULL, 0);
			return;
		}

		if (record_handle <= 1) {
			/* handle=0 (first) or handle=1: Numeric Sensor PDR */
			pr_info("mctp-i2c-sim: PLDM GetPDR handle=%u → Numeric Sensor PDR (%zu bytes)\n",
				record_handle, sizeof(sim_temp_pdr));
			memset(resp, 0, 11);
			resp[0] = 0x02; /* next_record_handle = 2 (Sensor Aux Names PDR) */
			resp[8] = 0x05; /* transfer_flag: start and end */
			resp[9] = sizeof(sim_temp_pdr) & 0xff;
			resp[10] = (sizeof(sim_temp_pdr) >> 8) & 0xff;
			memcpy(resp + 11, sim_temp_pdr, sizeof(sim_temp_pdr));
			resp_len = 11 + sizeof(sim_temp_pdr);
		} else {
			/* handle=2: Sensor Auxiliary Names PDR */
			pr_info("mctp-i2c-sim: PLDM GetPDR handle=%u → Sensor Aux Names PDR (%zu bytes)\n",
				record_handle, sizeof(sim_sensor_aux_names_pdr));
			memset(resp, 0, 11);
			/* next_record_handle = 0 (no more records) */
			resp[8] = 0x05; /* transfer_flag: start and end */
			resp[9] = sizeof(sim_sensor_aux_names_pdr) & 0xff;
			resp[10] = (sizeof(sim_sensor_aux_names_pdr) >> 8) & 0xff;
			memcpy(resp + 11, sim_sensor_aux_names_pdr, sizeof(sim_sensor_aux_names_pdr));
			resp_len = 11 + sizeof(sim_sensor_aux_names_pdr);
		}
		break;
	}

	case PLDM_CMD_GET_SENSOR_READING: {
		s16 reading = SIM_TEMP_READING;

		pr_info("mctp-i2c-sim: PLDM GetSensorReading → %d (%d.%02d°C)\n",
			reading, reading / 100, reading % 100);

		resp[0] = 0x03;         /* sensor_data_size = sint16 */
		resp[1] = 0x00;         /* sensor_operational_state = enabled */
		resp[2] = 0x00;         /* sensor_event_message_enable */
		resp[3] = 0x00;         /* present_state */
		resp[4] = 0x00;         /* previous_state */
		resp[5] = 0x00;         /* event_state */
		resp[6] = (u8)(reading & 0xff);
		resp[7] = (u8)((reading >> 8) & 0xff);
		resp_len = 8;
		break;
	}

	default:
		pr_info("mctp-i2c-sim: PLDM Monitoring unhandled cmd=0x%02x\n", cmd);
		sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
				       inst_id, PLDM_TYPE_MONITORING, cmd,
				       PLDM_ERROR_UNSUPPORTED_PLDM_CMD, NULL, 0);
		return;
	}

	sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
			       inst_id, PLDM_TYPE_MONITORING, cmd,
			       PLDM_SUCCESS, resp, resp_len);
}

/* Handle PLDM FRU (type=0x04) commands */
static void sim_handle_pldm_fru(struct mctp_i2c_sim *sim,
				u8 dest_addr, u8 dest_eid, u8 mctp_tag,
				u8 inst_id, u8 cmd,
				const u8 *payload, size_t payload_len)
{
	/* max resp: GetFRURecordTable = 4+1+sizeof(fru_table)+4 bytes */
	u8 resp[5 + sizeof(sim_fru_table) + 4];
	size_t resp_len = 0;
	u32 fru_crc;

	switch (cmd) {
	case PLDM_CMD_GET_FRU_RECORD_TABLE_METADATA:
		pr_info("mctp-i2c-sim: PLDM GetFRURecordTableMetadata → %zu bytes, 1 record\n",
			sizeof(sim_fru_table));
		fru_crc = crc32_le(0, sim_fru_table, sizeof(sim_fru_table));
		memset(resp, 0, 18);
		resp[0] = 0x01;				/* fruDataMajorVersion = 1 */
		resp[1] = 0x00;				/* fruDataMinorVersion = 0 */
		resp[2] = sizeof(sim_fru_table);	/* fruTableMaximumSize (uint32 LE) */
		resp[6] = sizeof(sim_fru_table);	/* fruTableLength (uint32 LE) */
		resp[10] = 0x01;			/* totalRecordSetIdentifiers (uint16 LE) */
		resp[12] = 0x01;			/* totalTableRecords (uint16 LE) */
		resp[14] = (u8)(fru_crc);		/* checksum (uint32 LE) */
		resp[15] = (u8)(fru_crc >> 8);
		resp[16] = (u8)(fru_crc >> 16);
		resp[17] = (u8)(fru_crc >> 24);
		resp_len = 18;
		break;

	case PLDM_CMD_GET_FRU_RECORD_TABLE:
		pr_info("mctp-i2c-sim: PLDM GetFRURecordTable → %zu bytes\n",
			sizeof(sim_fru_table));
		fru_crc = crc32_le(0, sim_fru_table, sizeof(sim_fru_table));
		memset(resp, 0, 5);
		/* nextDataTransferHandle (uint32 LE) = 0 */
		resp[4] = 0x05;				/* transferFlag: Start and End */
		memcpy(resp + 5, sim_fru_table, sizeof(sim_fru_table));
		resp[5 + sizeof(sim_fru_table) + 0] = (u8)(fru_crc);
		resp[5 + sizeof(sim_fru_table) + 1] = (u8)(fru_crc >> 8);
		resp[5 + sizeof(sim_fru_table) + 2] = (u8)(fru_crc >> 16);
		resp[5 + sizeof(sim_fru_table) + 3] = (u8)(fru_crc >> 24);
		resp_len = 5 + sizeof(sim_fru_table) + 4;
		break;

	default:
		pr_info("mctp-i2c-sim: PLDM FRU unhandled cmd=0x%02x\n", cmd);
		sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
				       inst_id, PLDM_TYPE_FRU, cmd,
				       PLDM_ERROR_UNSUPPORTED_PLDM_CMD, NULL, 0);
		return;
	}

	sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
			       inst_id, PLDM_TYPE_FRU, cmd,
			       PLDM_SUCCESS, resp, resp_len);
}

/* Handle PLDM FWUP (type=0x05) Phase 1 inventory commands (DSP0267) */
static void sim_handle_pldm_fwup(struct mctp_i2c_sim *sim,
				 u8 dest_addr, u8 dest_eid, u8 mctp_tag,
				 u8 inst_id, u8 cmd,
				 const u8 *payload, size_t payload_len)
{
	u8 resp[128];
	size_t resp_len = 0;

	switch (cmd) {
	case PLDM_CMD_FWUP_QUERY_DEVICE_IDENTIFIERS:
		pr_info("mctp-i2c-sim: PLDM QueryDeviceIdentifiers → VID=0x%04X\n",
			SIM_PCI_VENDOR_ID);
		memset(resp, 0, 11);
		/* deviceIdentifiersLength (uint32 LE) = 6 (one descriptor record) */
		resp[0] = 0x06;
		/* descriptorCount = 1 */
		resp[4] = 0x01;
		/* descriptor[0]: PCI Vendor ID (type=0x0000, len=2) */
		resp[5] = 0x00; resp[6] = 0x00;		/* type = 0x0000 */
		resp[7] = 0x02; resp[8] = 0x00;		/* length = 2 */
		resp[9]  = (u8)(SIM_PCI_VENDOR_ID & 0xff);	/* VID low byte */
		resp[10] = (u8)(SIM_PCI_VENDOR_ID >> 8);	/* VID high byte */
		resp_len = 11;
		break;

	case PLDM_CMD_FWUP_GET_FIRMWARE_PARAMETERS: {
		/*
		 * Response layout (DSP0267 Table 26) with dynamic version string.
		 * ver_len = strlen(fw_active_version)
		 * comp_entry_off = 10 + ver_len
		 *
		 * Fixed header (10 bytes):
		 *   [0-3]  capabilitiesDuringUpdate (uint32 LE) = 0
		 *   [4-5]  comp_count (uint16 LE) = 1
		 *   [6]    activeCompImageSetVerStrType = 1 (ASCII)
		 *   [7]    activeCompImageSetVerStrLen  = ver_len
		 *   [8]    pendingCompImageSetVerStrType = 0
		 *   [9]    pendingCompImageSetVerStrLen  = 0
		 *   [10..] activeCompImageSetVerStr (ver_len bytes)
		 * Component entry (comp_entry_off, 39 bytes fixed):
		 *   [+0-1]  comp_classification = 0x000A (Firmware)
		 *   [+2-3]  comp_identifier = 0x0001
		 *   [+9]    active_comp_ver_str_type = 1 (ASCII)
		 *   [+10]   active_comp_ver_str_len = ver_len
		 *   [+33-34] comp_activation_methods = 0x0002 (System Reboot)
		 *   [+39..] active_comp_ver_str (ver_len bytes)
		 * Total resp_len = 49 + 2 * ver_len
		 */
		u8 ver_len = (u8)strnlen(sim->fw_active_version,
					 sizeof(sim->fw_active_version));
		size_t ce = 10 + ver_len;	/* component entry start offset */

		pr_info("mctp-i2c-sim: PLDM GetFirmwareParameters → 1 component v%s\n",
			sim->fw_active_version);
		memset(resp, 0, sizeof(resp));
		resp[4]       = 0x01;		/* comp_count low (uint16 LE) = 1 */
		resp[6]       = 0x01;		/* activeCompImageSetVerStrType: ASCII */
		resp[7]       = ver_len;	/* activeCompImageSetVerStrLen */
		memcpy(resp + 10, sim->fw_active_version, ver_len);
		resp[ce + 0]  = 0x0A;		/* comp_classification low: Firmware */
		resp[ce + 2]  = 0x01;		/* comp_identifier low */
		resp[ce + 9]  = 0x01;		/* active_comp_ver_str_type: ASCII */
		resp[ce + 10] = ver_len;	/* active_comp_ver_str_len */
		resp[ce + 33] = 0x02;		/* comp_activation_methods: System Reboot */
		memcpy(resp + ce + 39, sim->fw_active_version, ver_len);
		resp_len = 49 + 2 * ver_len;
		break;
	}

	case PLDM_CMD_FWUP_REQUEST_UPDATE: {
		unsigned long flags;

		pr_info("mctp-i2c-sim: PLDM RequestUpdate → READY_XFER\n");
		spin_lock_irqsave(&sim->fwup_lock, flags);
		sim->fwup.state     = SIM_FWUP_READY_XFER;
		sim->fwup.dest_addr = dest_addr;
		sim->fwup.dest_eid  = dest_eid;
		sim->fwup.inst_id   = 0;
		spin_unlock_irqrestore(&sim->fwup_lock, flags);
		/* FirmwareDeviceMetaDataLength (uint16 LE) = 0 */
		/* WillSendGetPackageDataCommand (uint8) = 0 */
		resp[0] = 0x00; resp[1] = 0x00; resp[2] = 0x00;
		resp_len = 3;
		break;
	}

	case PLDM_CMD_FWUP_PASS_COMPONENT_TABLE:
		pr_info("mctp-i2c-sim: PLDM PassComponentTable → accepted\n");
		/* ComponentResponse=0 (compatible), ComponentResponseCode=0 */
		resp[0] = 0x00; resp[1] = 0x00;
		resp_len = 2;
		break;

	case PLDM_CMD_FWUP_UPDATE_COMPONENT: {
		unsigned long flags;
		u32 img_size;

		if (payload_len < 13) {
			sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
					       inst_id, PLDM_TYPE_FWUP, cmd,
					       PLDM_ERROR, NULL, 0);
			return;
		}
		img_size = (u32)payload[9]        | ((u32)payload[10] << 8) |
			   ((u32)payload[11] << 16) | ((u32)payload[12] << 24);

		/* Extract new version string (type=byte17, len=byte18, str=byte19+) */
		if (payload_len >= 19) {
			u8 ver_len = payload[18];

			if (ver_len > 0 && payload_len >= (size_t)(19 + ver_len)) {
				u8 copy_len = min_t(u8, ver_len,
						    sizeof(sim->fw_pending_version) - 1);
				memcpy(sim->fw_pending_version, payload + 19, copy_len);
				sim->fw_pending_version[copy_len] = '\0';
			}
		}
		pr_info("mctp-i2c-sim: PLDM UpdateComponent size=%u pending=%s → DOWNLOAD\n",
			img_size, sim->fw_pending_version);

		spin_lock_irqsave(&sim->fwup_lock, flags);
		sim->fwup.state      = SIM_FWUP_DOWNLOAD;
		sim->fwup.total_size = img_size;
		sim->fwup.offset     = 0;
		spin_unlock_irqrestore(&sim->fwup_lock, flags);

		/* ComponentCompatibilityResponse=0, ResponseCode=0 */
		/* UpdateOptionFlagsEnabled (uint32 LE) = 0 */
		/* TimeBeforeRequestFirmwareData (uint16 LE) = 0 ms */
		memset(resp, 0, 7);
		resp_len = 7;

		/* Send response first, then start downloading */
		sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
				       inst_id, PLDM_TYPE_FWUP, cmd,
				       PLDM_SUCCESS, resp, resp_len);
		schedule_delayed_work(&sim->fwup_work, 0);
		return;
	}

	case PLDM_CMD_FWUP_ACTIVATE_FIRMWARE: {
		unsigned long flags;

		spin_lock_irqsave(&sim->fwup_lock, flags);
		if (sim->fw_pending_version[0])
			strscpy(sim->fw_active_version, sim->fw_pending_version,
				sizeof(sim->fw_active_version));
		sim->fw_pending_version[0] = '\0';
		sim->fwup.state = SIM_FWUP_IDLE;
		spin_unlock_irqrestore(&sim->fwup_lock, flags);
		pr_info("mctp-i2c-sim: PLDM ActivateFirmware → IDLE (version=%s)\n",
			sim->fw_active_version);
		/* EstimatedTimeForActivation (uint16 LE) = 0 seconds */
		resp[0] = 0x00; resp[1] = 0x00;
		resp_len = 2;
		break;
	}

	default:
		pr_info("mctp-i2c-sim: PLDM FWUP unhandled cmd=0x%02x\n", cmd);
		sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
				       inst_id, PLDM_TYPE_FWUP, cmd,
				       PLDM_ERROR_UNSUPPORTED_PLDM_CMD, NULL, 0);
		return;
	}

	sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
			       inst_id, PLDM_TYPE_FWUP, cmd,
			       PLDM_SUCCESS, resp, resp_len);
}

/* Delayed work: drive FWUP Phase 2 active requests (RequestFirmwareData etc.) */
static void sim_fwup_active_work(struct work_struct *work)
{
	struct mctp_i2c_sim *sim =
		container_of(work, struct mctp_i2c_sim, fwup_work.work);
	unsigned long flags;
	enum sim_fwup_state state;
	u32 offset, total_size;
	u8 dest_addr, dest_eid, inst_id;
	u8 req[8];

	spin_lock_irqsave(&sim->fwup_lock, flags);
	state      = sim->fwup.state;
	offset     = sim->fwup.offset;
	total_size = sim->fwup.total_size;
	dest_addr  = sim->fwup.dest_addr;
	dest_eid   = sim->fwup.dest_eid;
	inst_id    = sim->fwup.inst_id++;
	spin_unlock_irqrestore(&sim->fwup_lock, flags);

	switch (state) {
	case SIM_FWUP_DOWNLOAD: {
		u32 chunk = min_t(u32, SIM_FWUP_CHUNK_SIZE, total_size - offset);

		pr_info("mctp-i2c-sim: FWUP >> RequestFirmwareData offset=%u/%u chunk=%u\n",
			offset, total_size, chunk);
		req[0] = (u8)(offset);
		req[1] = (u8)(offset >> 8);
		req[2] = (u8)(offset >> 16);
		req[3] = (u8)(offset >> 24);
		req[4] = (u8)(chunk);
		req[5] = (u8)(chunk >> 8);
		req[6] = (u8)(chunk >> 16);
		req[7] = (u8)(chunk >> 24);
		sim_send_pldm_request(sim, dest_addr, dest_eid, SIM_FWUP_TAG,
				      inst_id, PLDM_TYPE_FWUP,
				      PLDM_CMD_FWUP_REQUEST_FIRMWARE_DATA, req, 8);
		break;
	}
	case SIM_FWUP_VERIFY:
		pr_info("mctp-i2c-sim: FWUP >> TransferComplete\n");
		req[0] = 0x00; /* TransferResult = success */
		sim_send_pldm_request(sim, dest_addr, dest_eid, SIM_FWUP_TAG,
				      inst_id, PLDM_TYPE_FWUP,
				      PLDM_CMD_FWUP_TRANSFER_COMPLETE, req, 1);
		break;
	case SIM_FWUP_VERIFY2:
		pr_info("mctp-i2c-sim: FWUP >> VerifyComplete\n");
		req[0] = 0x00; /* VerifyResult = success */
		sim_send_pldm_request(sim, dest_addr, dest_eid, SIM_FWUP_TAG,
				      inst_id, PLDM_TYPE_FWUP,
				      PLDM_CMD_FWUP_VERIFY_COMPLETE, req, 1);
		break;
	case SIM_FWUP_APPLY:
		pr_info("mctp-i2c-sim: FWUP >> ApplyComplete\n");
		req[0] = 0x00; /* ApplyResult = success */
		req[1] = 0x00; /* ComponentActivationMethodsModification low */
		req[2] = 0x00; /* ComponentActivationMethodsModification high */
		sim_send_pldm_request(sim, dest_addr, dest_eid, SIM_FWUP_TAG,
				      inst_id, PLDM_TYPE_FWUP,
				      PLDM_CMD_FWUP_APPLY_COMPLETE, req, 3);
		break;
	default:
		break;
	}
}

/* Handle BMC responses to simulator-initiated FWUP requests (RQ=0) */
static void sim_handle_fwup_response(struct mctp_i2c_sim *sim,
				     u8 cmd,
				     const u8 *payload, size_t payload_len)
{
	unsigned long flags;
	enum sim_fwup_state state;

	spin_lock_irqsave(&sim->fwup_lock, flags);
	state = sim->fwup.state;

	switch (cmd) {
	case PLDM_CMD_FWUP_REQUEST_FIRMWARE_DATA:
		if (state != SIM_FWUP_DOWNLOAD)
			break;
		if (payload_len < 1 || payload[0] != PLDM_SUCCESS) {
			pr_warn("mctp-i2c-sim: FWUP RequestFirmwareData error cc=0x%02x\n",
				payload_len ? payload[0] : 0xff);
			sim->fwup.state = SIM_FWUP_IDLE;
			spin_unlock_irqrestore(&sim->fwup_lock, flags);
			return;
		}
		{
			u32 chunk = (u32)(payload_len - 1);

			sim->fwup.offset += chunk;
			pr_info("mctp-i2c-sim: FWUP data rx offset=%u/%u\n",
				sim->fwup.offset, sim->fwup.total_size);
			if (sim->fwup.offset >= sim->fwup.total_size) {
				pr_info("mctp-i2c-sim: FWUP download done → VERIFY\n");
				sim->fwup.state = SIM_FWUP_VERIFY;
			}
		}
		spin_unlock_irqrestore(&sim->fwup_lock, flags);
		schedule_delayed_work(&sim->fwup_work, 0);
		return;

	case PLDM_CMD_FWUP_TRANSFER_COMPLETE:
		if (state != SIM_FWUP_VERIFY)
			break;
		pr_info("mctp-i2c-sim: FWUP TransferComplete ack → VERIFY2\n");
		sim->fwup.state = SIM_FWUP_VERIFY2;
		spin_unlock_irqrestore(&sim->fwup_lock, flags);
		schedule_delayed_work(&sim->fwup_work, msecs_to_jiffies(100));
		return;

	case PLDM_CMD_FWUP_VERIFY_COMPLETE:
		if (state != SIM_FWUP_VERIFY2)
			break;
		pr_info("mctp-i2c-sim: FWUP VerifyComplete ack → APPLY\n");
		sim->fwup.state = SIM_FWUP_APPLY;
		spin_unlock_irqrestore(&sim->fwup_lock, flags);
		schedule_delayed_work(&sim->fwup_work, msecs_to_jiffies(100));
		return;

	case PLDM_CMD_FWUP_APPLY_COMPLETE:
		if (state != SIM_FWUP_APPLY)
			break;
		pr_info("mctp-i2c-sim: FWUP ApplyComplete ack → ACTIVATING\n");
		sim->fwup.state = SIM_FWUP_ACTIVATING;
		spin_unlock_irqrestore(&sim->fwup_lock, flags);
		return;

	default:
		break;
	}
	spin_unlock_irqrestore(&sim->fwup_lock, flags);
}

/* Dispatch incoming PLDM message to the appropriate handler */
static void sim_process_pldm(struct mctp_i2c_sim *sim,
			     u8 dest_addr, u8 dest_eid, u8 mctp_tag,
			     const struct pldm_msg_hdr *pldm_hdr,
			     const u8 *payload, size_t payload_len)
{
	u8 inst_id  = pldm_hdr->rq_d_inst & 0x1f;
	bool is_req = !!(pldm_hdr->rq_d_inst & 0x80);

	/* BMC response to one of our active FWUP requests */
	if (!is_req && pldm_hdr->pldm_type == PLDM_TYPE_FWUP) {
		sim_handle_fwup_response(sim, pldm_hdr->cmd, payload, payload_len);
		return;
	}

	pr_info("mctp-i2c-sim: PLDM << type=0x%02x cmd=0x%02x inst=%u\n",
		pldm_hdr->pldm_type, pldm_hdr->cmd, inst_id);

	switch (pldm_hdr->pldm_type) {
	case PLDM_TYPE_DISCOVERY:
		sim_handle_pldm_discovery(sim, dest_addr, dest_eid, mctp_tag,
					  inst_id, pldm_hdr->cmd,
					  payload, payload_len);
		break;
	case PLDM_TYPE_MONITORING:
		sim_handle_pldm_monitoring(sim, dest_addr, dest_eid, mctp_tag,
					   inst_id, pldm_hdr->cmd,
					   payload, payload_len);
		break;
	case PLDM_TYPE_FRU:
		sim_handle_pldm_fru(sim, dest_addr, dest_eid, mctp_tag,
				    inst_id, pldm_hdr->cmd,
				    payload, payload_len);
		break;
	case PLDM_TYPE_FWUP:
		sim_handle_pldm_fwup(sim, dest_addr, dest_eid, mctp_tag,
				     inst_id, pldm_hdr->cmd,
				     payload, payload_len);
		break;
	default:
		pr_info("mctp-i2c-sim: PLDM unhandled type=0x%02x cmd=0x%02x → ERROR_UNSUPPORTED\n",
			pldm_hdr->pldm_type, pldm_hdr->cmd);
		sim_send_pldm_response(sim, dest_addr, dest_eid, mctp_tag,
				       inst_id, pldm_hdr->pldm_type, pldm_hdr->cmd,
				       0x05, NULL, 0); /* cc=PLDM_ERROR_UNSUPPORTED_PLDM_CMD */
		break;
	}
}

/* Process an incoming MCTP frame from master_xfer(): dispatch by message type */
static void sim_process_request(struct mctp_i2c_sim *sim,
				const u8 *buf, size_t len)
{
	const struct mctp_i2c_hdr *i2c_hdr = (const struct mctp_i2c_hdr *)buf;
	const struct mctp_hdr *mctp_hdr_p;
	const struct mctp_ctrl_hdr *ctrl_hdr;
	const u8 *payload;
	u8 dest_addr;
	u8 resp[16];
	u8 ic_msg_type;

	/* Relaxed length check: i2c_hdr(4) + mctp_hdr(4) + msg_type(1) = 9 */
	if (len < 9)
		return;

	if (i2c_hdr->command != MCTP_I2C_COMMANDCODE)
		return;

	mctp_hdr_p = (const struct mctp_hdr *)(buf + sizeof(struct mctp_i2c_hdr));
	dest_addr = i2c_hdr->source_slave >> 1;

	/*
	 * Handle non-SOM continuation fragments BEFORE the type byte check.
	 * Type byte is only valid in the SOM fragment.
	 */
	if (!(mctp_hdr_p->flags_seq_tag & MCTP_HDR_SOM)) {
		const u8 *frag = (const u8 *)(mctp_hdr_p + 1);
		size_t cont_len = len - sizeof(struct mctp_i2c_hdr)
				      - sizeof(struct mctp_hdr) - 1;
		bool is_eom = !!(mctp_hdr_p->flags_seq_tag & MCTP_HDR_EOM);

		if (sim->pldm_len > 0) {
			if (sim->pldm_len + cont_len > sizeof(sim->pldm_buf)) {
				sim->pldm_len = 0;
				return;
			}
			memcpy(sim->pldm_buf + sim->pldm_len, frag, cont_len);
			sim->pldm_len += cont_len;
			if (is_eom) {
				const struct pldm_msg_hdr *ph =
					(const struct pldm_msg_hdr *)sim->pldm_buf;
				int p_len = (int)sim->pldm_len - (int)sizeof(*ph);
				size_t pl = p_len > 0 ? (size_t)p_len : 0;

				sim_process_pldm(sim, sim->pldm_dest_addr,
						 sim->pldm_dest_eid, sim->pldm_mctp_tag,
						 ph, (const u8 *)(ph + 1), pl);
				sim->pldm_len = 0;
			}
		} else if (sim->echo_len > 0) {
			if (sim->echo_len + cont_len > sizeof(sim->echo_buf)) {
				sim->echo_len = 0;
				return;
			}
			memcpy(sim->echo_buf + sim->echo_len, frag, cont_len);
			sim->echo_len += cont_len;
			if (is_eom) {
				sim_send_fragmented_msg(sim, sim->echo_dest_addr,
							sim->echo_dest_eid,
							sim->echo_mctp_tag,
							sim->echo_buf, sim->echo_len);
				sim->echo_len = 0;
			}
		}
		return;
	}

	/* SOM fragment: ic_msg_type is valid here */
	ic_msg_type = *((u8 *)(mctp_hdr_p + 1));

	if (ic_msg_type == MCTP_MSG_TYPE_PLDM) {
		const u8 *frag_start = (const u8 *)(mctp_hdr_p + 1);
		size_t frag_len = len - sizeof(struct mctp_i2c_hdr)
				      - sizeof(struct mctp_hdr) - 1;
		bool is_eom = !!(mctp_hdr_p->flags_seq_tag & MCTP_HDR_EOM);

		pr_info("mctp-i2c-sim: PLDM << raw: %*phN\n",
			(int)(len - sizeof(struct mctp_i2c_hdr) - 1), (u8 *)mctp_hdr_p);

		sim->pldm_len       = 0;
		sim->pldm_dest_addr = dest_addr;
		sim->pldm_dest_eid  = mctp_hdr_p->src;
		sim->pldm_mctp_tag  = mctp_hdr_p->flags_seq_tag & 0x07;

		if (frag_len > sizeof(sim->pldm_buf)) {
			pr_warn("mctp-i2c-sim: PLDM SOM too large, dropping\n");
			return;
		}
		memcpy(sim->pldm_buf, frag_start, frag_len);
		sim->pldm_len = frag_len;

		if (is_eom) {
			const struct pldm_msg_hdr *ph =
				(const struct pldm_msg_hdr *)sim->pldm_buf;
			int p_len = (int)sim->pldm_len - (int)sizeof(*ph);
			size_t pl = p_len > 0 ? (size_t)p_len : 0;

			sim_process_pldm(sim, sim->pldm_dest_addr,
					 sim->pldm_dest_eid, sim->pldm_mctp_tag,
					 ph, (const u8 *)(ph + 1), pl);
			sim->pldm_len = 0;
		}
		return;
	}
	if (ic_msg_type == MCTP_MSG_TYPE_ECHO) {

		const u8 *frag_start = (const u8 *)(mctp_hdr_p + 1);
		size_t frag_len = len - sizeof(struct mctp_i2c_hdr)
				      - sizeof(struct mctp_hdr) - 1; /* -1 PEC */
		u8 flags   = mctp_hdr_p->flags_seq_tag;
		bool is_som = !!(flags & MCTP_HDR_SOM);
		bool is_eom = !!(flags & MCTP_HDR_EOM);
		u8 mctp_tag = flags & 0x07;

		pr_info("mctp-i2c-sim: ECHO << frag len=%zu som=%d eom=%d dst=%d src=%d tag=0x%02x\n",
			frag_len, is_som, is_eom,
			mctp_hdr_p->dest, mctp_hdr_p->src, mctp_tag);
		pr_info("mctp-i2c-sim: ECHO RX raw: %*phN\n",
			(int)frag_len, frag_start);

		if (is_som) {
			/* start of new message: reset reassembly state */
			sim->echo_len       = 0;
			sim->echo_dest_addr = dest_addr;
			sim->echo_dest_eid  = mctp_hdr_p->src; /* reply to BMC */
			sim->echo_mctp_tag  = mctp_tag;
		}

		/* append fragment to reassembly buffer */
		if (sim->echo_len + frag_len > sizeof(sim->echo_buf)) {
			pr_warn("mctp-i2c-sim: ECHO reassembly overflow, dropping\n");
			sim->echo_len = 0;
			return;
		}
		memcpy(sim->echo_buf + sim->echo_len, frag_start, frag_len);
		sim->echo_len += frag_len;

		if (is_eom) {
			/* full message received, send echo response */
			pr_info("mctp-i2c-sim: ECHO reassembled total=%zu\n",
				sim->echo_len);
			sim_send_fragmented_msg(sim,
						sim->echo_dest_addr,
						sim->echo_dest_eid,
						sim->echo_mctp_tag,
						sim->echo_buf,
						sim->echo_len);
			sim->echo_len = 0;
		}
		return;
	}

	if (ic_msg_type != MCTP_CTRL_MSG_TYPE)
		return;

	/* Initialize ctrl_hdr for Control Messages */
	ctrl_hdr = (const struct mctp_ctrl_hdr *)(mctp_hdr_p + 1);
	payload  = (const u8 *)(ctrl_hdr + 1);

	/* Only process requests (RQ bit set) */
	if (!(ctrl_hdr->rq_d_inst & 0x80))
		return;


	pr_info("mctp-i2c-sim: << cmd=0x%02x dst=%d src=%d tag=0x%02x\n",
		ctrl_hdr->cmd, mctp_hdr_p->dest, mctp_hdr_p->src,
		mctp_hdr_p->flags_seq_tag & 0x07);

	/* Extract MCTP tag and ctrl instance ID separately */
	{
	u8 mctp_tag    = mctp_hdr_p->flags_seq_tag & 0x07;
	u8 ctrl_inst   = ctrl_hdr->rq_d_inst & 0x1f;

	switch (ctrl_hdr->cmd) {
	case MCTP_CTRL_CMD_GET_EID:
		resp[0] = sim->ep_eid;
		resp[1] = 0x00; /* endpoint type: simple */
		resp[2] = 0x00; /* medium specific info */
		pr_info("mctp-i2c-sim: GET_EID → reply EID=%d (%s)\n",
			sim->ep_eid,
			sim->ep_eid == 0 ? "unassigned" : "assigned");
		sim_send_ctrl_response(sim, dest_addr,
				       mctp_hdr_p->dest, mctp_hdr_p->src,
				       mctp_tag, ctrl_inst,
				       MCTP_CTRL_CMD_GET_EID, resp, 3);
		break;

	case MCTP_CTRL_CMD_SET_EID:
		/* payload[0] = operation, payload[1] = EID */
		if (len >= sizeof(struct mctp_i2c_hdr) + sizeof(struct mctp_hdr) +
			   sizeof(struct mctp_ctrl_hdr) + 2) {
			sim->ep_eid = payload[1];
		}
		resp[0] = 0x00; /* status: accepted */
		resp[1] = sim->ep_eid;
		resp[2] = 0x00; /* pool size */
		pr_info("mctp-i2c-sim: SET_EID → assigned EID=%d\n",
			sim->ep_eid);
		sim_send_ctrl_response(sim, dest_addr,
				       mctp_hdr_p->dest, mctp_hdr_p->src,
				       mctp_tag, ctrl_inst,
				       MCTP_CTRL_CMD_SET_EID, resp, 3);
		break;

	case MCTP_CTRL_CMD_GET_UUID:
		memcpy(resp, sim_uuid, 16);
		pr_info("mctp-i2c-sim: GET_UUID → reply fixed UUID\n");
		sim_send_ctrl_response(sim, dest_addr,
				       mctp_hdr_p->dest, mctp_hdr_p->src,
				       mctp_tag, ctrl_inst,
				       MCTP_CTRL_CMD_GET_UUID, resp, 16);
		break;

	case MCTP_CTRL_CMD_GET_MSG_TYPE:
		resp[0] = 0x03; /* count: 3 types */
		resp[1] = MCTP_CTRL_MSG_TYPE;   /* 0x00: MCTP Control */
		resp[2] = MCTP_MSG_TYPE_PLDM;   /* 0x01: PLDM */
		resp[3] = MCTP_MSG_TYPE_ECHO;   /* 0x7e: echo (vendor defined) */
		pr_info("mctp-i2c-sim: GET_MSG_TYPE → 3 types (Control, PLDM, Echo)\n");
		sim_send_ctrl_response(sim, dest_addr,
				       mctp_hdr_p->dest, mctp_hdr_p->src,
				       mctp_tag, ctrl_inst,
				       MCTP_CTRL_CMD_GET_MSG_TYPE, resp, 4);
		break;

	default:
		pr_info("mctp-i2c-sim: unhandled ctrl cmd=0x%02x\n",
			ctrl_hdr->cmd);
		break;
	}
	} /* end mctp_tag/ctrl_inst block */
}

/* Virtual I2C master_xfer: intercept outgoing MCTP frames */
static int sim_master_xfer(struct i2c_adapter *adap,
			   struct i2c_msg *msgs, int num)
{
	struct mctp_i2c_sim *sim = adap->algo_data;
	struct i2c_msg *msg = &msgs[0];
	u8 frame[256];
	size_t frame_len;

	if (num != 1 || !msg->buf)
		return -EOPNOTSUPP;

	pr_info("mctp-i2c-sim: master_xfer addr=0x%02x len=%d slave=%p\n",
		msg->addr, msg->len, sim->slave);

	if (!sim->slave) {
		pr_warn("mctp-i2c-sim: master_xfer: slave not registered yet\n");
		return -ENXIO;
	}

	if (msg->addr != SIM_EP_ADDR) {
		pr_info("mctp-i2c-sim: unknown addr 0x%02x (expected 0x%02x)\n",
			msg->addr, SIM_EP_ADDR);
		return -ENXIO;
	}

	/*
	 * master_xfer buf starts at [command] (mctp-i2c strips dest_slave).
	 * Reconstruct full DSP0237 frame for processing:
	 * [dest_slave][command][byte_count][source_slave][payload...][PEC]
	 */
	frame[0] = msg->addr << 1;		/* dest_slave */
	frame_len = 1 + msg->len;
	if (frame_len > sizeof(frame))
		return -EMSGSIZE;
	memcpy(frame + 1, msg->buf, msg->len);

	sim_process_request(sim, frame, frame_len);

	return num;
}

static u32 sim_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SLAVE;
}

static int sim_reg_slave(struct i2c_client *client)
{
	struct mctp_i2c_sim *sim = client->adapter->algo_data;

	sim->slave = client;
	pr_info("mctp-i2c-sim: slave registered addr=0x%02x\n", client->addr);
	return 0;
}

static int sim_unreg_slave(struct i2c_client *client)
{
	struct mctp_i2c_sim *sim = client->adapter->algo_data;

	sim->slave = NULL;
	return 0;
}

static const struct i2c_algorithm sim_algo = {
	.master_xfer	= sim_master_xfer,
	.functionality	= sim_functionality,
	.reg_slave	= sim_reg_slave,
	.unreg_slave	= sim_unreg_slave,
};

static int mctp_i2c_sim_probe(struct platform_device *pdev)
{
	struct mctp_i2c_sim *sim;
	int rc;

	sim = devm_kzalloc(&pdev->dev, sizeof(*sim), GFP_KERNEL);
	if (!sim)
		return -ENOMEM;

	sim->ep_eid = SIM_EID_DEFAULT;
	sim->pdev   = pdev;

	sim->adapter.owner      = THIS_MODULE;
	sim->adapter.class      = I2C_CLASS_HWMON;
	sim->adapter.algo       = &sim_algo;
	sim->adapter.algo_data  = sim;
	sim->adapter.dev.parent = &pdev->dev;
	sim->adapter.dev.of_node = pdev->dev.of_node;
	strscpy(sim->adapter.name, "mctp-i2c-sim", sizeof(sim->adapter.name));

	platform_set_drvdata(pdev, sim);

	rc = i2c_add_adapter(&sim->adapter);
	if (rc) {
		dev_err(&pdev->dev, "failed to add i2c adapter: %d\n", rc);
		return rc;
	}

	/* FWUP Phase 2 state machine init */
	spin_lock_init(&sim->fwup_lock);
	sim->fwup.state = SIM_FWUP_IDLE;
	strscpy(sim->fw_active_version, "1.0.0", sizeof(sim->fw_active_version));
	INIT_DELAYED_WORK(&sim->fwup_work, sim_fwup_active_work);

	/* Schedule MTU config after mctp-i2c driver probes the child node */
	INIT_DELAYED_WORK(&sim->mtu_work, mctp_i2c_sim_set_mtu_work);
	schedule_delayed_work(&sim->mtu_work, msecs_to_jiffies(500));

	dev_info(&pdev->dev, "MCTP I2C simulator ready (bus %d)\n",
		 sim->adapter.nr);
	return 0;
}

static void mctp_i2c_sim_remove(struct platform_device *pdev)
{
	struct mctp_i2c_sim *sim = platform_get_drvdata(pdev);

	cancel_delayed_work_sync(&sim->fwup_work);
	cancel_delayed_work_sync(&sim->mtu_work);
	i2c_del_adapter(&sim->adapter);
}

static const struct of_device_id mctp_i2c_sim_of_match[] = {
	{ .compatible = "mctp-i2c-sim" },
	{}
};

static struct platform_driver mctp_i2c_sim_driver = {
	.probe  = mctp_i2c_sim_probe,
	.remove = mctp_i2c_sim_remove,
	.driver = {
		.name           = "mctp-i2c-sim",
		.of_match_table = mctp_i2c_sim_of_match,
	},
};

builtin_platform_driver(mctp_i2c_sim_driver);

MODULE_DESCRIPTION("MCTP I2C simulator");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Anson Ku <ansonku@gmail.com>");

/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include <pthread.h>
#include <string.h>

#include "srsenb/hdr/stack/mac/mac.h"
#include "srsran/adt/pool/obj_pool.h"
#include "srsran/common/rwlock_guard.h"
#include "srsran/common/standard_streams.h"
#include "srsran/common/time_prof.h"
#include "srsran/interfaces/enb_phy_interfaces.h"
#include "srsran/interfaces/enb_rlc_interfaces.h"
#include "srsran/interfaces/enb_rrc_interface_mac.h"
#include "srsran/srslog/event_trace.h"

// #define WRITE_SIB_PCAP
using namespace asn1::rrc;

namespace srsenb {

mac::mac(srsran::ext_task_sched_handle task_sched_, srslog::basic_logger& logger) :
  logger(logger), rar_payload(), common_buffers(SRSRAN_MAX_CARRIERS), task_sched(task_sched_)
{
  pthread_rwlock_init(&rwlock, nullptr);
  stack_task_queue = task_sched.make_task_queue();
}

mac::~mac()
{
  // if (enableADB){ 
  //   adbController.stop();
  //   adbController.thread_cancel();
  //   adbController.wait_thread_finish();
  // }
  stop();
  pthread_rwlock_destroy(&rwlock);
  // printf("1\n");
}

bool mac::init(const mac_args_t&        args_,
               const cell_list_t&       cells_,
               phy_interface_stack_lte* phy,
               rlc_interface_mac*       rlc,
               rrc_interface_mac*       rrc)
{
  started = false;
  phy_h   = phy;
  rlc_h   = rlc;
  rrc_h   = rrc;

  args  = args_;
  cells = cells_;

  scheduler.init(rrc, args.sched);

  /* LLFuzz init*/
  llfuzz_config = llfuzz.read_config_from_file(llfuzz_config_file); // default config file now
  llfuzz.init();

  // set configs for ADB thread
  ADBController& adbController = llfuzz.getADBController();
  adbController.set_enable_adb_cfg(llfuzz_config.enableADB);

  // start adb controller if enabled
  if (llfuzz_config.enableADB){
    // get ADB Controller from LLFuzz
    adbController.start();
    enableADB = true;
  }else{
    enableADB = false;
  }
  // save target layer in MAC instance
  targetLayer = llfuzz_config.targetLayer;
  // atomic variable for modifying RRC reconfig type in RRC interface
  llfuzz_rrc_reconfig_type = llfuzz.get_rrc_reconfig_type();


  llfuzz.set_rrc_interface(rrc);
  rrc_h->set_rrc_reconfig_type(llfuzz_rrc_reconfig_type);

  // Init softbuffer for SI messages
  common_buffers.resize(cells.size());
  for (auto& cc : common_buffers) {
    for (int i = 0; i < NOF_BCCH_DLSCH_MSG; i++) {
      srsran_softbuffer_tx_init(&cc.bcch_softbuffer_tx[i], args.nof_prb);
    }
    // Init softbuffer for PCCH
    srsran_softbuffer_tx_init(&cc.pcch_softbuffer_tx, args.nof_prb);

    // Init softbuffer for RAR
    srsran_softbuffer_tx_init(&cc.rar_softbuffer_tx, args.nof_prb);
  }

  // Initiate common pool of softbuffers
  uint32_t nof_prb          = args.nof_prb;
  auto     init_softbuffers = [nof_prb](void* ptr) {
    new (ptr) ue_cc_softbuffers(nof_prb, SRSRAN_FDD_NOF_HARQ, SRSRAN_FDD_NOF_HARQ);
  };
  auto recycle_softbuffers = [](ue_cc_softbuffers& softbuffers) { softbuffers.clear(); };
  softbuffer_pool.reset(new srsran::background_obj_pool<ue_cc_softbuffers>(
      8, 8, args.nof_prealloc_ues, init_softbuffers, recycle_softbuffers));

  detected_rachs.resize(cells.size());

  started = true;
  return true;
}

void mac::stop()
{
  srsran::rwlock_write_guard lock(rwlock);
  if (started) {
    started = false;

    ue_db.clear();
    for (auto& cc : common_buffers) {
      for (int i = 0; i < NOF_BCCH_DLSCH_MSG; i++) {
        srsran_softbuffer_tx_free(&cc.bcch_softbuffer_tx[i]);
      }
      srsran_softbuffer_tx_free(&cc.pcch_softbuffer_tx);
      srsran_softbuffer_tx_free(&cc.rar_softbuffer_tx);
    }
  }
}

void mac::start_pcap(srsran::mac_pcap* pcap_)
{
  srsran::rwlock_read_guard lock(rwlock);
  pcap = pcap_;
  // Set pcap in all UEs for UL messages
  for (auto& u : ue_db) {
    u.second->start_pcap(pcap);
  }
}

void mac::start_pcap_net(srsran::mac_pcap_net* pcap_net_)
{
  srsran::rwlock_read_guard lock(rwlock);
  pcap_net = pcap_net_;
  // Set pcap in all UEs for UL messages
  for (auto& u : ue_db) {
    u.second->start_pcap_net(pcap_net);
  }
}

/********************************************************
 *
 * RLC interface
 *
 *******************************************************/

int mac::rlc_buffer_state(uint16_t rnti, uint32_t lc_id, uint32_t tx_queue, uint32_t retx_queue)
{
  int                       ret = -1;
  if (check_ue_active(rnti)) {
    if (rnti != SRSRAN_MRNTI) {
      srsran::rwlock_read_guard lock(rwlock);
      ret = scheduler.dl_rlc_buffer_state(rnti, lc_id, tx_queue, retx_queue);
    } else {
      task_sched.defer_callback(0, [this, tx_queue, lc_id]() {
        srsran::rwlock_read_guard lock(rwlock);
        for (uint32_t i = 0; i < mch.num_mtch_sched; i++) {
          if (lc_id == mch.mtch_sched[i].lcid) {
            mch.mtch_sched[i].lcid_buffer_size = tx_queue;
          }
        }
      });
      ret = 0;
    }
  }
  return ret;
}

int mac::bearer_ue_cfg(uint16_t rnti, uint32_t lc_id, mac_lc_ch_cfg_t* cfg)
{
  srsran::rwlock_read_guard lock(rwlock);
  return check_ue_active(rnti) ? scheduler.bearer_ue_cfg(rnti, lc_id, *cfg) : -1;
}

int mac::bearer_ue_rem(uint16_t rnti, uint32_t lc_id)
{
  srsran::rwlock_read_guard lock(rwlock);
  return check_ue_active(rnti) ? scheduler.bearer_ue_rem(rnti, lc_id) : -1;
}

void mac::phy_config_enabled(uint16_t rnti, bool enabled)
{
  scheduler.phy_config_enabled(rnti, enabled);
}

// Update UE configuration
int mac::ue_cfg(uint16_t rnti, const sched_interface::ue_cfg_t* cfg)
{
  srsran::rwlock_read_guard lock(rwlock);
  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }
  ue* ue_ptr = ue_db[rnti].get();

  // Start TA FSM in UE entity
  ue_ptr->start_ta();

  // Update Scheduler configuration
  if (cfg) {
    if (scheduler.ue_cfg(rnti, *cfg) == SRSRAN_ERROR) {
      logger.error("Registering UE rnti=0x%x to SCHED", rnti);
      return SRSRAN_ERROR;
    }
    ue_ptr->ue_cfg(*cfg);
  }

  return SRSRAN_SUCCESS;
}

// Removes UE from DB
int mac::ue_rem(uint16_t rnti)
{
  // Remove UE from the perspective of L2/L3
  {
    srsran::rwlock_read_guard lock(rwlock);
    if (check_ue_active(rnti)) {
      ue_db[rnti]->set_active(false);
    } else {
      logger.error("User rnti=0x%x not found", rnti);
      return SRSRAN_ERROR;
    }
  }
  scheduler.ue_rem(rnti);

  // Remove UE from the perspective of L1
  // Note: Let any pending retx ACK to arrive, so that PHY recognizes rnti
  task_sched.defer_callback(FDD_HARQ_DELAY_DL_MS + FDD_HARQ_DELAY_UL_MS, [this, rnti]() {
    phy_h->rem_rnti(rnti);
    srsran::rwlock_write_guard lock(rwlock);
    ue_db.erase(rnti);
    logger.info("User rnti=0x%x removed from MAC/PHY", rnti);
  });

  llfuzz.removeUE(rnti);
  llfuzz.handleUEDisconnection();

  return SRSRAN_SUCCESS;
}

// Called after Msg3
int mac::ue_set_crnti(uint16_t temp_crnti, uint16_t crnti, const sched_interface::ue_cfg_t& cfg)
{
  srsran::rwlock_read_guard lock(rwlock);
  if (temp_crnti == crnti) {
    // Schedule ConRes Msg4
    scheduler.dl_mac_buffer_state(crnti, (uint32_t)srsran::dl_sch_lcid::CON_RES_ID);
  }
  return ue_cfg(crnti, &cfg);
}

int mac::cell_cfg(const std::vector<sched_interface::cell_cfg_t>& cell_cfg_)
{
  srsran::rwlock_write_guard lock(rwlock);
  cell_config = cell_cfg_;

  if (targetLayer == PHY){
    llfuzz.setCellConfig(cell_cfg_[0].cell.nof_prb, cell_cfg_[0].cell.frame_type);
  }

  return scheduler.cell_cfg(cell_config);
}

void mac::get_metrics(mac_metrics_t& metrics)
{
  srsran::rwlock_read_guard lock(rwlock);
  metrics.ues.reserve(ue_db.size());
  for (auto& u : ue_db) {
    if (not scheduler.ue_exists(u.first)) {
      continue;
    }
    metrics.ues.emplace_back();
    auto& ue_metrics = metrics.ues.back();

    u.second->metrics_read(&ue_metrics);
    scheduler.metrics_read(u.first, ue_metrics);
    ue_metrics.pci = (ue_metrics.cc_idx < cell_config.size()) ? cell_config[ue_metrics.cc_idx].cell.id : 0;
  }
  metrics.cc_info.resize(detected_rachs.size());
  for (unsigned cc = 0, e = detected_rachs.size(); cc != e; ++cc) {
    metrics.cc_info[cc].cc_rach_counter = detected_rachs[cc];
    metrics.cc_info[cc].pci             = (cc < cell_config.size()) ? cell_config[cc].cell.id : 0;
  }
}

void mac::toggle_padding()
{
  do_padding = !do_padding;
}

void mac::add_padding()
{
  srsran::rwlock_read_guard lock(rwlock);
  for (auto it = ue_db.begin(); it != ue_db.end(); ++it) {
    uint16_t cur_rnti = it->first;
    auto     ue       = it;
    scheduler.dl_rlc_buffer_state(ue->first, args.lcid_padding, 20e6, 0);
    ue->second->trigger_padding(args.lcid_padding);
  }
}

/********************************************************
 *
 * PHY interface
 *
 *******************************************************/

int mac::ack_info(uint32_t tti_rx, uint16_t rnti, uint32_t enb_cc_idx, uint32_t tb_idx, bool ack)
{
  logger.set_context(tti_rx);
  srsran::rwlock_read_guard lock(rwlock);

  // if (DEBUG_MODE){
  //   std::string ackStr = (ack) ? "ACK" : "NACK";
  //   std::cout << "[MAC] SF: " << CYAN << tti_rx/10 <<":" << tti_rx%10 << " RNTI: " << rnti << " -- " << ackStr << RESET_COLOR << "\n";
  // }

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  int nof_bytes = scheduler.dl_ack_info(tti_rx, rnti, enb_cc_idx, tb_idx, ack);
  ue_db[rnti]->metrics_tx(ack, nof_bytes);

  rrc_h->set_radiolink_dl_state(rnti, ack);

  return SRSRAN_SUCCESS;
}

int mac::crc_info(uint32_t tti_rx, uint16_t rnti, uint32_t enb_cc_idx, uint32_t nof_bytes, bool crc)
{
  logger.set_context(tti_rx);
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  ue_db[rnti]->set_tti(tti_rx);
  ue_db[rnti]->metrics_rx(crc, nof_bytes);

  rrc_h->set_radiolink_ul_state(rnti, crc);

  // Scheduler uses eNB's CC mapping
  return scheduler.ul_crc_info(tti_rx, rnti, enb_cc_idx, crc);
}

int mac::push_pdu(uint32_t tti_rx,
                  uint16_t rnti,
                  uint32_t enb_cc_idx,
                  uint32_t nof_bytes,
                  bool     crc,
                  uint32_t ul_nof_prbs)
{
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  srsran::unique_byte_buffer_t pdu = ue_db[rnti]->release_pdu(tti_rx, enb_cc_idx);
  if (pdu == nullptr) {
    logger.warning("Could not find MAC UL PDU for rnti=0x%x, cc=%d, tti=%d", rnti, enb_cc_idx, tti_rx);
    return SRSRAN_ERROR;
  }

  // push the pdu through the queue if received correctly
  if (crc) {

    LLState_t rntiState = llfuzz.getCurRNTIState();
    LLState_t fuzzingState = llfuzz.get_fuzzing_state();
    int size = pdu->size();
    if (rntiState == state2 && size <= 60 && activeFuzzer){
      int tti_tx = TTI_ADD(tti_rx, 4);
      pduInfo_t pduInfo = decodePDUuplink(pdu->data(), (int)pdu->size(), tti_tx);
      if (pduInfo.pduDecodingResult == pduRRCConReq){
        // bool updateRet = fuzzer.updateUEState(rnti, state3, tti_rx); // state 3 does not need trigger tti
        // if (updateRet && DEBUG_MODE){
        //   std::cout << "[MAC] SF: " << tti_rx/10 <<":" << tti_rx%10 << YELLOW_TEXT<< " Updated RNTI: " << rnti << " to state 3" << RESET_COLOR << "\n";
        // }
        uint8_t* ptr = pdu->data();
        for (int i = 0; i < 6; i++){
          pduInfo.conResID[i] = ptr[i+1];
        }
        // fuzzer.updateConResID(pduInfo.conResID); // save Contention Resolution ID from message 3
        // if (pduInfo.hasTMSI){ fuzzer.updateTMSI(pduInfo.m_tmsi); } // save from message 3
        llfuzz.updateConResID(pduInfo.conResID);
        if (pduInfo.hasTMSI){ llfuzz.updateTMSI(pduInfo.m_tmsi); }
      }
    }

    if ( rntiState == state4 && activeFuzzer && (targetLayer == RLC || targetLayer == PDCP) && fuzzingState == state4){
      int tti_tx = TTI_ADD(tti_rx, 4);
      pduInfo_t pduInfo = decodePDUuplink(pdu->data(), (int)pdu->size(), tti_tx);
      if (pduInfo.pduDecodingResult == pduRRCReconfigComplete){
        llfuzz.set_received_rrc_reconfig_complete(true);
      }
    }

    logger.info("Pushing PDU rnti=0x%x, tti_rx=%d, nof_bytes=%d", rnti, tti_rx, nof_bytes);
    srsran_expect(nof_bytes == pdu->size(),
                  "Inconsistent PDU length for rnti=0x%x, tti_rx=%d (%d!=%d)",
                  rnti,
                  tti_rx,
                  nof_bytes,
                  (int)pdu->size());
    auto process_pdu_task = [this, rnti, enb_cc_idx, ul_nof_prbs](srsran::unique_byte_buffer_t& pdu) {
      srsran::rwlock_read_guard lock(rwlock);
      if (check_ue_active(rnti)) {
        ue_db[rnti]->process_pdu(std::move(pdu), enb_cc_idx, ul_nof_prbs);
      } else {
        logger.debug("Discarding PDU rnti=0x%x", rnti);
      }
    };
    stack_task_queue.try_push(std::bind(process_pdu_task, std::move(pdu)));
  } else {
    logger.debug("Discarding PDU rnti=0x%x, tti_rx=%d, nof_bytes=%d", rnti, tti_rx, nof_bytes);
  }
  return SRSRAN_SUCCESS;
}

int mac::ri_info(uint32_t tti, uint16_t rnti, uint32_t enb_cc_idx, uint32_t ri_value)
{
  logger.set_context(tti);
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  scheduler.dl_ri_info(tti, rnti, enb_cc_idx, ri_value);
  ue_db[rnti]->metrics_dl_ri(ri_value);

  return SRSRAN_SUCCESS;
}

int mac::pmi_info(uint32_t tti, uint16_t rnti, uint32_t enb_cc_idx, uint32_t pmi_value)
{
  logger.set_context(tti);
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  scheduler.dl_pmi_info(tti, rnti, enb_cc_idx, pmi_value);
  ue_db[rnti]->metrics_dl_pmi(pmi_value);

  return SRSRAN_SUCCESS;
}

int mac::cqi_info(uint32_t tti, uint16_t rnti, uint32_t enb_cc_idx, uint32_t cqi_value)
{
  logger.set_context(tti);
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  scheduler.dl_cqi_info(tti, rnti, enb_cc_idx, cqi_value);
  ue_db[rnti]->metrics_dl_cqi(cqi_value);

  return SRSRAN_SUCCESS;
}

int mac::sb_cqi_info(uint32_t tti, uint16_t rnti, uint32_t enb_cc_idx, uint32_t sb_idx, uint32_t cqi_value)
{
  logger.set_context(tti);
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  scheduler.dl_sb_cqi_info(tti, rnti, enb_cc_idx, sb_idx, cqi_value);
  return SRSRAN_SUCCESS;
}

int mac::snr_info(uint32_t tti_rx, uint16_t rnti, uint32_t enb_cc_idx, float snr, ul_channel_t ch)
{
  logger.set_context(tti_rx);
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  rrc_h->set_radiolink_ul_state(rnti, snr >= args.rlf_min_ul_snr_estim);

  return scheduler.ul_snr_info(tti_rx, rnti, enb_cc_idx, snr, (uint32_t)ch);
}

int mac::ta_info(uint32_t tti, uint16_t rnti, float ta_us)
{
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  uint32_t nof_ta_count = ue_db[rnti]->set_ta_us(ta_us);
  if (nof_ta_count > 0) {
    return scheduler.dl_mac_buffer_state(rnti, (uint32_t)srsran::dl_sch_lcid::TA_CMD, nof_ta_count);
  }
  return SRSRAN_SUCCESS;
}

int mac::sr_detected(uint32_t tti, uint16_t rnti)
{
  logger.set_context(tti);
  srsran::rwlock_read_guard lock(rwlock);

  if (not check_ue_active(rnti)) {
    return SRSRAN_ERROR;
  }

  return scheduler.ul_sr_info(tti, rnti);
}

bool mac::is_valid_rnti_unprotected(uint16_t rnti)
{
  if (not started) {
    logger.info("RACH ignored as eNB is being shutdown");
    return false;
  }
  if (not ue_db.has_space(rnti)) {
    logger.info("Failed to allocate rnti=0x%x. Attempting a different rnti.", rnti);
    return false;
  }
  return true;
}

uint16_t mac::allocate_ue(uint32_t enb_cc_idx)
{
  ue*      inserted_ue = nullptr;
  uint16_t rnti        = SRSRAN_INVALID_RNTI;

  do {
    // Assign new RNTI
    rnti = FIRST_RNTI + (ue_counter.fetch_add(1, std::memory_order_relaxed) % 60000);

    // Pre-check if rnti is valid
    {
      srsran::rwlock_read_guard read_lock(rwlock);
      if (ue_db.full()) {
        logger.warning("Maximum number of connected UEs %zd connected to the eNB. Ignoring PRACH", SRSENB_MAX_UES);
        return SRSRAN_INVALID_RNTI;
      }
      if (not is_valid_rnti_unprotected(rnti)) {
        continue;
      }
    }

    // Allocate and initialize UE object
    unique_rnti_ptr<ue> ue_ptr = make_rnti_obj<ue>(
        rnti, rnti, enb_cc_idx, &scheduler, rrc_h, rlc_h, phy_h, logger, cells.size(), softbuffer_pool.get());

    // Add UE to rnti map
    srsran::rwlock_write_guard rw_lock(rwlock);
    if (not is_valid_rnti_unprotected(rnti)) {
      continue;
    }
    auto ret = ue_db.insert(rnti, std::move(ue_ptr));
    if (ret.has_value()) {
      inserted_ue = ret.value()->second.get();
    } else {
      logger.info("Failed to allocate rnti=0x%x. Attempting a different rnti.", rnti);
    }
  } while (inserted_ue == nullptr);

  // Set PCAP if available
  if (pcap != nullptr) {
    inserted_ue->start_pcap(pcap);
  }

  if (pcap_net != nullptr) {
    inserted_ue->start_pcap_net(pcap_net);
  }

  return rnti;
}

bool mac::is_pending_pdcch_order_prach(const uint32_t preamble_idx, uint16_t& rnti)
{
  for (auto it = pending_po_prachs.begin(); it != pending_po_prachs.end();) {
    auto& pending_po_prach = *it;
    if (pending_po_prach.preamble_idx == preamble_idx) {
      rnti = pending_po_prach.crnti;
      // delete pending PDCCH PRACH from vector
      it = pending_po_prachs.erase(it);
      return true;
    }
    ++it;
  }
  return false;
}

uint16_t mac::reserve_new_crnti(const sched_interface::ue_cfg_t& uecfg)
{
  uint16_t rnti = allocate_ue(uecfg.supported_cc_list[0].enb_cc_idx);
  if (rnti == SRSRAN_INVALID_RNTI) {
    return rnti;
  }

  // Add new user to the scheduler so that it can RX/TX SRB0
  if (ue_cfg(rnti, &uecfg) != SRSRAN_SUCCESS) {
    return SRSRAN_INVALID_RNTI;
  }
  return rnti;
}

void mac::rach_detected(uint32_t tti, uint32_t enb_cc_idx, uint32_t preamble_idx, uint32_t time_adv)
{
  static srsran::mutexed_tprof<srsran::avg_time_stats> rach_tprof("rach_tprof", "MAC", 1);
  logger.set_context(tti);
  auto rach_tprof_meas = rach_tprof.start();

  if (activeFuzzer){
    timePoint_t curTime = std::chrono::high_resolution_clock::now();
    llfuzz.pushRARBuffer(curTime);
  }

  stack_task_queue.push([this, tti, enb_cc_idx, preamble_idx, time_adv, rach_tprof_meas]() mutable {
    uint16_t rnti = 0;
    // check if this is a PRACH from a PDCCH order
    bool is_po_prach = is_pending_pdcch_order_prach(preamble_idx, rnti);
    if (!is_po_prach) {
      rnti = allocate_ue(enb_cc_idx);
      if (rnti == SRSRAN_INVALID_RNTI) {
        return;
      }
    }

    rach_tprof_meas.defer_stop();
    // Generate RAR data
    sched_interface::dl_sched_rar_info_t rar_info = {};
    rar_info.preamble_idx                         = preamble_idx;
    rar_info.ta_cmd                               = time_adv;
    rar_info.temp_crnti                           = rnti;
    rar_info.msg3_size                            = 7;
    rar_info.prach_tti                            = tti;

    // Log this event.
    ++detected_rachs[enb_cc_idx];

    // If this is a PRACH from a PDCCH order, the user already exists
    if (not is_po_prach) {
      // Add new user to the scheduler so that it can RX/TX SRB0
      sched_interface::ue_cfg_t uecfg = {};
      uecfg.supported_cc_list.emplace_back();
      uecfg.supported_cc_list.back().active     = true;
      uecfg.supported_cc_list.back().enb_cc_idx = enb_cc_idx;
      uecfg.ue_bearers[0].direction             = mac_lc_ch_cfg_t::BOTH;
      uecfg.supported_cc_list[0].dl_cfg.tm      = SRSRAN_TM1;
      if (ue_cfg(rnti, &uecfg) != SRSRAN_SUCCESS) {
        return;
      }

      // Register new user in RRC
      if (rrc_h->add_user(rnti, uecfg) == SRSRAN_ERROR) {
        ue_rem(rnti);
        return;
      }
    }

    // Trigger scheduler RACH
    if (scheduler.dl_rach_info(enb_cc_idx, rar_info) != SRSRAN_SUCCESS) {
      ue_rem(rnti);
      return;
    }

    /*Add more RAR if needed by testcase*/
    if (llfuzz.check_inject_rar() && activeFuzzer){
      int nof_inject_rar = llfuzz.get_nof_injecting_rar();
      if (nof_inject_rar > 1){
        for (int i = 0; i < nof_inject_rar - 1;i ++){
          sched_interface::dl_sched_rar_info_t rar_info2 = {};
          rar_info2.preamble_idx                         = preamble_idx;
          rar_info2.ta_cmd                               = time_adv;
          rar_info2.temp_crnti                           = rnti + 1000 + i;
          rar_info2.msg3_size                            = 7;
          rar_info2.prach_tti                            = tti;
          scheduler.dl_rach_info(enb_cc_idx, rar_info2);
        }
        if (DEBUG_MODE){ printf("[RAR] Injected %d nof RAR \n", nof_inject_rar - 1); }
      }
    }

    auto get_pci = [this, enb_cc_idx]() {
      srsran::rwlock_read_guard lock(rwlock);
      return (enb_cc_idx < cell_config.size()) ? cell_config[enb_cc_idx].cell.id : 0;
    };
    uint32_t pci = get_pci();
    logger.info("%sRACH:  tti=%d, cc=%d, pci=%d, preamble=%d, offset=%d, temp_crnti=0x%x",
                (is_po_prach) ? "PDCCH order " : "",
                tti,
                enb_cc_idx,
                pci,
                preamble_idx,
                time_adv,
                rnti);
    srsran::console("%sRACH:  tti=%d, cc=%d, pci=%d, preamble=%d, offset=%d, temp_crnti=0x%x\n",
                    (is_po_prach) ? "PDCCH order " : "",
                    tti,
                    enb_cc_idx,
                    pci,
                    preamble_idx,
                    time_adv,
                    rnti);
    // std::cout << BLUE_TEXT << "[MAC] SF: " << tti/10 <<":" << tti%10 << " RACH:  cc=" << enb_cc_idx << ", pci=" << pci << ", preamble=" << preamble_idx << ", offset=" << time_adv << ", temp_crnti=0x" << std::hex << rnti << std::dec << RESET_COLOR << "\n";
  });
}

void mac::start_fuzzer() {
  if (!activeFuzzer){
    llfuzz.startFuzzer();
    llfuzz.active_speedlog_timer();
  }else{
    llfuzz.stopFuzzing();
  }
  activeFuzzer = !activeFuzzer;
} // start/stop sending test cases

void mac::inject_mac_pdu(uint32_t tti) // T_note: check here
{
  srsran::rwlock_read_guard lock(rwlock);
  
  // random generator
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint8_t> distribution(0, 255); 

  uint16_t      curRNTI       = llfuzz.getCurRNTI();
  LLState_t     curRNTIState  = llfuzz.getCurRNTIState();
  // targetLayer_t targetLayer   = llfuzz.getTargetLayer();
  uint32_t      tempSN        = 0;
  
  // update sequence number
  // only update sequence number if this is the first test case sent after UE enters targeting state
  // otherwise, sequence number will be incremented by 1 by the layer-specific fuzzer instance
  // after sending 1 test case
  nof_sent_test_cases_per_ss = llfuzz.get_nof_sent_test_cases_per_ss();

  if (curRNTIState >= state3 && nof_sent_test_cases_per_ss == 0){
    tempSN = ue_db[curRNTI]->get_sequence_number(curRNTI, 1);
    llfuzz.update_rlc_sequence_number(1, tempSN);
  }
  if (curRNTIState >= state4 && nof_sent_test_cases_per_ss == 0){
    tempSN = ue_db[curRNTI]->get_sequence_number(curRNTI, 2);
    llfuzz.update_rlc_sequence_number(2, tempSN);
    tempSN = ue_db[curRNTI]->get_sequence_number(curRNTI, 3);
    llfuzz.update_rlc_sequence_number(3, tempSN);
  }
    
  int len   = llfuzz.get_injecting_length();
  int lcid  = llfuzz.get_injecting_lcid();

  if (targetLayer == PHY){
    len = 100;
    lcid = 0;
  }
  
  // for (auto it = ue_db.begin(); it != ue_db.end(); ++it) {
  //   uint16_t cur_rnti = it->first;
  // }

  // create PDU to inject
  srsran::unique_byte_buffer_t pdu = srsran::make_byte_buffer();
  uint8_t data[len];
  for (size_t i = 0; i < sizeof(data); i++) {
      data[i] = 0; // distribution(gen); // random generator
  }      
  memcpy(pdu->msg, &data, len);
  pdu->N_bytes = len;
  
  // add PDU to lcid buffer
  rlc_h->mac_control_rlc_write_sdu(curRNTI, lcid, std::move(pdu)); // add MAC SDU drb_to_lcid((lte_drb::drb1))
  
  // if (DEBUG_MODE){ printf("[MAC] SF: %d.%d RNTI = %d, Injected MAC PDU State: %d to lcid %d with length %d \n", tti/10, tti%10, curRNTI, curRNTIState, lcid, len); }
}

int tbs_size_from_itbs_1prb(int Itbs)
{
  switch (Itbs)
  {
  case 0:
    return 16;
    break;
  case 1:
    return 24;
    break;
  case 2:
    return 32;
    break;
  case 3:
    return 40;
    break;
  case 4:
    return 56;
    break;
  case 5:
    return 72;
    break;
    
  default:
    return 0;
    break;
  }
}

void generate_dci_format1A_fuzzing(srsran_dci_dl_t *dci, int nof_bytes){
  if (dci->format != SRSRAN_DCI_FORMAT1A){
    printf("[MAC] DCI format is not 1A yet\n");
    dci->format = SRSRAN_DCI_FORMAT1A;
  }

  // manually allocate DCI and PHY resources for test case
  dci->alloc_type = SRSRAN_RA_ALLOC_TYPE2; // dci 1A always use type 2
  dci->tb[0].cw_idx = 0;
  dci->type2_alloc.riv = 0; // 0/50 +1 = 1, 0 mod 50 = 0 -> start PRB = 0, nof_prb = 1 
  int temp_tbs = 0;
  int temp_itbs = 0;
  while (temp_tbs < nof_bytes*8 && temp_itbs < 28)
  {
    temp_tbs = tbs_size_from_itbs_1prb(temp_itbs);
    if (temp_tbs < nof_bytes*8){
      temp_itbs++;
    }
  }
  dci->tb[0].mcs_idx = temp_itbs;
  dci->isManualDCI = true;
}

void generate_dci_format1A_rar_fuzzing(srsran_dci_dl_t *dci, int nof_bytes){
  if (dci->format != SRSRAN_DCI_FORMAT1A || (dci->rnti >= SRSRAN_RARNTI_END)){
    printf("[MAC] RAR DCI format is not 1A yet or RNTI is not RA_RNTI\n");
    // dci->format = SRSRAN_DCI_FORMAT1A;
    return;
  }

  // DCI 1A RAR uses only 2 or 3 PRBs by design
  // try 2 PRBs first
  dci->type2_alloc.n_prb1a = srsran_ra_type2_t::SRSRAN_RA_TYPE2_NPRB1A_2;
  // increase mcs index one by one and check if the tbs is enough
  for (int i = 0; i < 28; i++){
    if (srsran_ra_tbs_from_idx(i, 2) >= nof_bytes*8){
      dci->tb[0].mcs_idx = i;
      dci->isManualDCI = true;
      return;
    }
  }
  // try 3 PRBs if 2 PRBs are not enough for RAR test cases
  dci->type2_alloc.n_prb1a = srsran_ra_type2_t::SRSRAN_RA_TYPE2_NPRB1A_3;
  for (int i = 0; i < 28; i++){
    if (srsran_ra_tbs_from_idx(i, 3) >= nof_bytes*8){
      dci->tb[0].mcs_idx = i;
      dci->isManualDCI = true;
      return;
    }
  }
  // we reach here because nof_bytes is too large
  printf("[MAC] RAR DCI format 1A is not enough for %d bytes\n", nof_bytes);
}

void generate_dci_format1_allocation_type1_fuzzing(srsran_dci_dl_t *dci, int nof_bytes){
  if (dci->format != SRSRAN_DCI_FORMAT1){
    printf("[MAC] DCI format is not 1 yet (%d)\n", dci->format);
    dci->format = SRSRAN_DCI_FORMAT1;
  }

  // manually allocate DCI and PHY resources for test case
  dci->alloc_type = SRSRAN_RA_ALLOC_TYPE1; // use type 1 to allocate resources
  dci->tb[0].cw_idx = 0;
  dci->type1_alloc.rbg_subset = 0; 
  dci->type1_alloc.shift = 0;
  dci->type1_alloc.vrb_bitmask = 0b1; // 1 PRB 
  int temp_tbs = 0;
  int temp_itbs = 0;
  while (temp_tbs < nof_bytes*8 && temp_itbs < 28)
  {
    temp_tbs = tbs_size_from_itbs_1prb(temp_itbs);
    if (temp_tbs < nof_bytes*8){
      temp_itbs++;
    }
  }
  dci->tb[0].mcs_idx = temp_itbs;  // mcs = 4 -> I_TBS = 4 when 256QAM diabled
  dci->isManualDCI = true;
}

int mac::get_dl_sched(uint32_t tti_tx_dl, dl_sched_list_t& dl_sched_res_list)
{
  if (!started) {
    return 0;
  }

  trace_threshold_complete_event("mac::get_dl_sched", "total_time", std::chrono::microseconds(100));
  logger.set_context(TTI_SUB(tti_tx_dl, FDD_HARQ_DELAY_UL_MS));
  if (do_padding) {
    add_padding();
  }

  srsran::rwlock_read_guard lock(rwlock);

  if (activeFuzzer){
    if (targetLayer != PHY && llfuzz.check_send_test_case_this_SF(tti_tx_dl) && (llfuzz.getState234Phase() == state234Send || llfuzz.getState4Phase() == s4Send)){ 
      inject_mac_pdu(tti_tx_dl);
    }else if (targetLayer == PHY){
      bool sendUplinkDCI = llfuzz.getSendUplinkDCI();
      // check if we need to send testcase this SF; if so, inject MAC PDU
      if (!sendUplinkDCI && llfuzz.check_send_test_case_this_SF(tti_tx_dl) && (llfuzz.getState234Phase() == state234Send || llfuzz.getState4Phase() == s4Send)){ 
        inject_mac_pdu(tti_tx_dl);
      }
    }
  }

  if (activeFuzzer){
    llfuzz.get_signal_from_adb();                // get signal from ADB to control fuzzer
    llfuzz.crashMonitoring(tti_tx_dl);
    llfuzz.recoverUE();                          // only recover UE and fuzzing state if there has been a crash
    llfuzz.check_switch_to_next_state();         // switch state based on current test case index
  }

  /*Config for states*/
  LLState_t curMode = llfuzz.get_fuzzing_mode();

  if (activeFuzzer){
    switch (curMode) // control phases for each state
    {
    case state1:
      llfuzz.state1Control(tti_tx_dl);
      break;
    case state234:
      llfuzz.state234Control(tti_tx_dl);
      break;
    case state4:
      llfuzz.state4Control(tti_tx_dl);
      break;
    // case state1:Size = 
    //   /* code */
    //   break;
    default:
      break;
    }
  }

  bool generate_dci_and_pdsch = false;
  int          tcTotalByte = 0;
  LLState_t   curRNTIState  = llfuzz.getCurRNTIState();
  srsran_pdsch_grant_t dlGrant = {};
  bool isManualDCI = false;
  if (llfuzz.getSendThisSF() && activeFuzzer
                && ((curMode == state234 && llfuzz.getState234Phase() == state234Send) || (curMode == state4 && llfuzz.getState4Phase() == s4Send))){
    generate_dci_and_pdsch = true;
    tcTotalByte = llfuzz.get_total_byte_cur_testcase();
    isManualDCI = llfuzz.get_manual_dci();
  }

  if (activeFuzzer){
    llfuzz.save_testing_speed_log();
  }

  for (uint32_t enb_cc_idx = 0; enb_cc_idx < cell_config.size(); enb_cc_idx++) {
    // Run scheduler with current info
    sched_interface::dl_sched_res_t sched_result = {};
    if (scheduler.dl_sched(tti_tx_dl, enb_cc_idx, sched_result) < 0) {
      logger.error("Running scheduler");
      return SRSRAN_ERROR;
    }

    int         n            = 0;
    dl_sched_t* dl_sched_res = &dl_sched_res_list[enb_cc_idx];

    // Copy data grants
    for (uint32_t i = 0; i < sched_result.data.size(); i++) {
      uint32_t tb_count = 0;

      // Get UE
      uint16_t rnti = sched_result.data[i].dci.rnti;

      if (ue_db.contains(rnti)) {
        // Copy dci info
        dl_sched_res->pdsch[n].dci = sched_result.data[i].dci;
        dl_sched_res->pdsch[n].dci.isManualDCI = false; // set to false by default

        // if (targetLayer == PHY){
        //   // save original DCI for reference
        //   llfuzz.save_orin_dl_dci_for_reference(sched_result.data[i].dci); 
        // }

        /* Manually allocate DCI and PHY resouces for test case*/
        if (generate_dci_and_pdsch && isManualDCI){
          if (sched_result.data[i].dci.format == SRSRAN_DCI_FORMAT1A){
            dlGrant = {};
            generate_dci_format1A_fuzzing(&dl_sched_res->pdsch[n].dci, tcTotalByte);
            // convert allocated dci to dl grant to check if tbs is enough for test case
            
            srsran_ra_dl_grant_to_grant_prb_allocation(&dl_sched_res->pdsch[n].dci, &dlGrant, args.nof_prb);
            dlGrant.tb[0].cw_idx = 0;
            dlGrant.tb[0].mcs_idx = dl_sched_res->pdsch[n].dci.tb[0].mcs_idx;
            // printf("Number of PRB = %d\n", dlGrant.nof_prb);
            srsran_dl_fill_ra_mcs(&dlGrant.tb[0], 0, dlGrant.nof_prb, false);
            if (dlGrant.tb[0].tbs/8 < tcTotalByte){
              printf("[MAC] SF: %d.%d DCI TBS is not enough for test case, rnti = %d, required %d / %d\n", tti_tx_dl/10, tti_tx_dl%10, rnti, tcTotalByte, dlGrant.tb[0].tbs/8);
            }else{
              printf("[MAC] SF: %d.%d Rnti = %d, Allocated DCI 1A %d / %d\n", tti_tx_dl/10, tti_tx_dl%10, rnti, tcTotalByte, dlGrant.tb[0].tbs/8);
              // sched_result.data[i].tbs[0] = dlGrant.tb[0].tbs;
            }
          }else{
            dlGrant = {};
            generate_dci_format1_allocation_type1_fuzzing(&dl_sched_res->pdsch[n].dci, tcTotalByte);
            srsran_ra_dl_grant_to_grant_prb_allocation(&dl_sched_res->pdsch[n].dci, &dlGrant, args.nof_prb);
            dlGrant.tb[0].cw_idx = 0;
            dlGrant.tb[0].mcs_idx = dl_sched_res->pdsch[n].dci.tb[0].mcs_idx;
            // printf("Number of PRB = %d\n", dlGrant.nof_prb);
            srsran_dl_fill_ra_mcs(&dlGrant.tb[0], 0, dlGrant.nof_prb, false); // true: use 256QAM table
            if (dlGrant.tb[0].tbs/8 < tcTotalByte){
              printf("[MAC] SF: %d.%d DCI TBS is not enough for test case, rnti = %d, required %d / %d\n", tti_tx_dl/10, tti_tx_dl%10, rnti, tcTotalByte, dlGrant.tb[0].tbs/8);
            }else{
              printf("[MAC] SF: %d.%d Rnti = %d, Allocated DCI 1 type 1 %d / %d\n", tti_tx_dl/10, tti_tx_dl%10, rnti, tcTotalByte, dlGrant.tb[0].tbs/8);
              // sched_result.data[i].tbs[0] = dlGrant.tb[0].tbs;
            }
          }
        } /* End of manually...*/

        for (uint32_t tb = 0; tb < SRSRAN_MAX_TB; tb++) {
          dl_sched_res->pdsch[n].softbuffer_tx[tb] =
              ue_db[rnti]->get_tx_softbuffer(enb_cc_idx, sched_result.data[i].dci.pid, tb);

          // If the Rx soft-buffer is not given, abort transmission
          if (dl_sched_res->pdsch[n].softbuffer_tx[tb] == nullptr) {
            continue;
          }

          if (sched_result.data[i].nof_pdu_elems[tb] > 0) {
            /* Get PDU if it's a new transmission */
            dl_sched_res->pdsch[n].data[tb] = ue_db[rnti]->generate_pdu(enb_cc_idx,
                                                                        sched_result.data[i].dci.pid,
                                                                        tb,
                                                                        sched_result.data[i].pdu[tb],
                                                                        sched_result.data[i].nof_pdu_elems[tb],
                                                                        sched_result.data[i].tbs[tb]);

            /*Detect DL RRC Con Set & DL RRC Reconfig to switch state of fuzzer later*/
            if (!llfuzz.getSendThisSF() && activeFuzzer){                  // only decode and update state if we don't send testcase this SF
              pduInfo_t pduInfo = decodePDU(dl_sched_res->pdsch[n].data[0], sched_result.data[i].tbs[0], tti_tx_dl);
              if (pduInfo.pduDecodingResult == pduRRCConSet){
                bool updateRet = llfuzz.updateUEState(rnti, state3, tti_tx_dl);                   // update state of UE to state 4 after receiving RRC Connection setup
                if (updateRet){
                  if (targetLayer == RLC || targetLayer == PDCP){
                    int type = llfuzz.check_rrc_reconfig_type(); // update RRC reconfig type to atomic variable
                    if (type != 0){
                      llfuzz.set_received_rrc_reconfig_complete(false); // set to false until UE received RRC reconfiguration complete
                    }
                    // printf("[MAC] RRC reconfig type: %d\n", type);
                  }
                  std::cout << "[MAC] SF: " << tti_tx_dl/10 <<":" << tti_tx_dl%10 << YELLOW_TEXT<< " Updated RNTI: " << rnti << " to state 3" << RESET_COLOR << "\n";
                }
              }else if (pduInfo.pduDecodingResult == pduRRCReconfig){
                bool updateRet = llfuzz.updateUEState(rnti, state4, tti_tx_dl);                   // update state of UE to state 5 after receiving RRC Reconfig
                if (updateRet && DEBUG_MODE){
                  llfuzz.handleRRCReconfig(rnti, pduInfo, tti_tx_dl);                             // handle RRC Reconfig
                  std::cout << "[MAC] SF: " << tti_tx_dl/10 <<":" << tti_tx_dl%10 << YELLOW_TEXT<< " Updated RNTI: " << rnti << " to state 4" << RESET_COLOR << "\n";
                }
              }
            }
            bool save_test_case = false;
            if (activeFuzzer){
              if (llfuzz.getSendThisSF() && (tb == 0)
                && ((curMode == state234 && llfuzz.getState234Phase() == state234Send) || (curMode == state4 && llfuzz.getState4Phase() == s4Send))){
                int actualLen = (isManualDCI) ? dlGrant.tb[0].tbs/8 : sched_result.data[i].tbs[0]; // /8 because when converting resource allocation to tbs in munual dci case, we did not divide by 8
                // std::cout << "[LLFuzz] isManualDCI: " << isManualDCI << ", actualLen: " << actualLen << " --" << dlGrant.tb[0].tbs << "\n";
                llfuzz.send_test_case(tti_tx_dl, rnti, dl_sched_res->pdsch[n].data[0], actualLen); // send test case sched_result.data[i].tbs[0]
                save_test_case = true;
                // print dci information
                // if (DEBUG_MODE){
                //   std::cout << "[MAC] SF: " << tti_tx_dl/10 <<":" << tti_tx_dl%10 << " RNTI: " << rnti << " - DCI: " << dl_sched_res->pdsch[n].dci.format << " - TB: " << dlGrant.tb[0].tbs << " - TB: " << actualLen << "\n";
                //   if (dl_sched_res->pdsch[n].dci.format == SRSRAN_DCI_FORMAT1A){
                //     printDCI_format1A(dl_sched_res->pdsch[n].dci);
                //   }
                // }
              }
            }

            if (!dl_sched_res->pdsch[n].data[tb]) {
              logger.error("Error! PDU was not generated (rnti=0x%04x, tb=%d)", rnti, tb);
            }

            if (pcap) {
              int actualLen = (isManualDCI) ? dlGrant.tb[0].tbs/8 : sched_result.data[i].tbs[tb];

              if (!save_test_case){
                pcap->write_dl_crnti(
                    dl_sched_res->pdsch[n].data[tb], actualLen, rnti, true, tti_tx_dl, enb_cc_idx);
              }else{
                // // write a dummy sib message that contains the test case information before the actual test case
                // // first get current test case index and convert to string
                // int curIdx = llfuzz.get_cur_idx();
                // std::string curIdxStr = "TC_IDX: " + std::to_string(curIdx);
                // // then get current test case info:
                // std::string curTestCaseInfo = llfuzz.get_cur_testcase_info();
                // // combine the two strings
                // std::string combinedStr = curIdxStr + " -- " + curTestCaseInfo;
                // // convert the combined string to uint8_t*
                // uint8_t* combinedStrPtr = (uint8_t*)combinedStr.c_str();
                // int combinedStrLen = combinedStr.length();
                // // write the combined string to the pcap in a dummy sib message
                // pcap->write_dl_sirnti(
                //     combinedStrPtr, combinedStrLen, true, tti_tx_dl, enb_cc_idx);
                
                // then write the actual test case
                pcap->write_dl_crnti_ueid(
                    dl_sched_res->pdsch[n].data[tb], actualLen, rnti, true, tti_tx_dl, enb_cc_idx, 0xFF);
              }
              // if (activeFuzzer){
              //   llfuzz.save_mac_packet_to_buffer(dl_sched_res->pdsch[n].data[tb], actualLen, tti_tx_dl, rnti);
              // }
            }
            if (pcap_net) {
              pcap_net->write_dl_crnti(
                  dl_sched_res->pdsch[n].data[tb], sched_result.data[i].tbs[tb], rnti, true, tti_tx_dl, enb_cc_idx);
            }

            if (activeFuzzer && llfuzz.getSendThisSF()){
              bool ret = llfuzz.send_dl_dci_testcase(tti_tx_dl, dl_sched_res->pdsch[n].dci.rnti, dl_sched_res->pdsch[n].dci, dl_sched_res->pdsch_fuzzer[n].dci); 
              // only send DCI test case if send_test_case returns true
              if (ret){ dl_sched_res->sendThisSF = true; }
            }

          } else {
            /* TB not enabled OR no data to send: set pointers to NULL  */
            dl_sched_res->pdsch[n].data[tb] = nullptr;
          }

          tb_count++;
        }

        // Count transmission if at least one TB has successfully added
        if (tb_count > 0) {
          n++;
        }
      } else {
        logger.warning("Invalid DL scheduling result. User 0x%x does not exist", rnti);
      }
    }

    // Copy RAR grants
    for (uint32_t i = 0; i < sched_result.rar.size(); i++) {
      // Copy dci info
      dl_sched_res->pdsch[n].dci = sched_result.rar[i].dci;

      // save original DCI for reference
      // llfuzz.save_orin_dl_dci_for_reference(sched_result.rar[i].dci);

      // Set softbuffer (there are no retx in RAR but a softbuffer is required)
      dl_sched_res->pdsch[n].softbuffer_tx[0] = &common_buffers[enb_cc_idx].rar_softbuffer_tx;

      // Assemble PDU
      dl_sched_res->pdsch[n].data[0] = assemble_rar(sched_result.rar[i].msg3_grant.data(),
                                                    enb_cc_idx,
                                                    sched_result.rar[i].msg3_grant.size(),
                                                    i,
                                                    sched_result.rar[i].tbs,
                                                    tti_tx_dl);

      /*If it is not state 1, UE goes to state 2 after receiving this message*/
      if (curMode != state1 && activeFuzzer){
        for (const auto &grant: sched_result.rar[i].msg3_grant){
            uint16_t tcRNTI = grant.data.temp_crnti;
            if (llfuzz.getUEStateDBSize() == 0 && activeFuzzer){
              llfuzz.addUE(tcRNTI, state2, tti_tx_dl);
              if (DEBUG_MODE){ 
                std::cout << "[MAC] SF: " << tti_tx_dl/10 <<":" << tti_tx_dl%10 << YELLOW_TEXT<< " Added RNTI: " << tcRNTI << " to state 2" << RESET_COLOR << "\n";
              }
            }
            else if ((llfuzz.getUEStateDBSize() == 1) && curMode == state234 && llfuzz.getState234Phase() == state234Send && !llfuzz.getRFLinkIssue() && activeFuzzer){
              llfuzz.clearUEDB(); // clear UE DB to send TC to the new connected UE
              llfuzz.addUE(tcRNTI, state2, tti_tx_dl);
              if (DEBUG_MODE){ 
                std::cout << "[MAC] SF: " << tti_tx_dl/10 <<":" << tti_tx_dl%10 << YELLOW_TEXT<< " Clear UEDB and Updated new RNTI: " << tcRNTI << " to state 2" << RESET_COLOR << "\n";
              }
            }
        }
      }

      /* Save pcap before it is modified*/
      if (activeFuzzer && curMode == state1 && llfuzz.getState1Phase() == state1Send && pcap){
        pcap->write_dl_ranti(dl_sched_res->pdsch[n].data[0],
                            sched_result.rar[i].tbs,
                            dl_sched_res->pdsch[n].dci.rnti,
                            true,
                            tti_tx_dl,
                            enb_cc_idx);
        llfuzz.save_legitimate_rar(dl_sched_res->pdsch[n].data[0], sched_result.rar[i].tbs);
        // save rar for reference
      }


      if (activeFuzzer && curMode == state1 && llfuzz.getState1Phase() == state1Send && pcap){
        // modify dci
        isManualDCI = llfuzz.get_manual_dci();
        if (isManualDCI){
          tcTotalByte = llfuzz.get_total_byte_cur_testcase();
          generate_dci_format1A_rar_fuzzing(&dl_sched_res->pdsch[n].dci, tcTotalByte);
          
          if (dl_sched_res->pdsch[n].dci.isManualDCI){ // manual dci here means we have successfully allocated dci
            int allocated_nof_prb = (dl_sched_res->pdsch[n].dci.type2_alloc.n_prb1a == srsran_ra_type2_t::SRSRAN_RA_TYPE2_NPRB1A_2) ? 2 : 3;
            sched_result.rar[i].tbs = srsran_ra_tbs_from_idx(dl_sched_res->pdsch[n].dci.tb[0].mcs_idx, allocated_nof_prb) / 8;
            printf("[MAC] SF: %d.%d RAR DCI 1A is allocated, rnti = %d, allocated %d bytes\n", tti_tx_dl/10, tti_tx_dl%10, dl_sched_res->pdsch[n].dci.rnti, sched_result.rar[i].tbs);
          }
        }

        
      }

      if (targetLayer == MAC && activeFuzzer){
        int nofGrant = (int)sched_result.rar[i].msg3_grant.size();
        llfuzz.send_rar_test_case(nofGrant, tti_tx_dl, dl_sched_res->pdsch[n].data[0], sched_result.rar[i].tbs); // send RAR test case
      }

      if (pcap) {
        pcap->write_dl_ranti(dl_sched_res->pdsch[n].data[0],
                             sched_result.rar[i].tbs,
                             dl_sched_res->pdsch[n].dci.rnti,
                             true,
                             tti_tx_dl,
                             enb_cc_idx);

        // if (activeFuzzer && curMode == state1 && llfuzz.getState1Phase() == state1Send){
        //   llfuzz.save_mac_packet_to_buffer(dl_sched_res->pdsch[n].data[0], sched_result.rar[i].tbs, tti_tx_dl, dl_sched_res->pdsch[n].dci.rnti);
        // }
                    }
      if (pcap_net) {
        pcap_net->write_dl_ranti(dl_sched_res->pdsch[n].data[0],
                                 sched_result.rar[i].tbs,
                                 dl_sched_res->pdsch[n].dci.rnti,
                                 true,
                                 tti_tx_dl,
                                 enb_cc_idx);
      }

      // send DCI 1A with RA-RNTI
      if (activeFuzzer && targetLayer == PHY && curMode == state1 && llfuzz.getState1Phase() == state1Send){
        bool dci_ret = llfuzz.send_RAR_DCI(tti_tx_dl, dl_sched_res->pdsch[n].dci.rnti, dl_sched_res->pdsch[n].dci, dl_sched_res->pdsch_fuzzer[n].dci);
        // only send DCI test case if send_RAR_DCI returns true
        if (dci_ret){ dl_sched_res->sendThisSF = true; }
      }

      n++;
    }

    // Copy SI and Paging grants
    for (uint32_t i = 0; i < sched_result.bc.size(); i++) {
      // Copy dci info
      dl_sched_res->pdsch[n].dci = sched_result.bc[i].dci;

      // save original DCI for reference
      // llfuzz.save_orin_dl_dci_for_reference(sched_result.bc[i].dci);

      // Set softbuffer
      if (sched_result.bc[i].type == sched_interface::dl_sched_bc_t::BCCH) {
        dl_sched_res->pdsch[n].softbuffer_tx[0] =
            &common_buffers[enb_cc_idx].bcch_softbuffer_tx[sched_result.bc[i].index];
        dl_sched_res->pdsch[n].data[0] = rrc_h->read_pdu_bcch_dlsch(enb_cc_idx, sched_result.bc[i].index);
#ifdef WRITE_SIB_PCAP
        if (pcap) {
          pcap->write_dl_sirnti(dl_sched_res->pdsch[n].data[0], sched_result.bc[i].tbs, true, tti_tx_dl, enb_cc_idx);
        }
        if (pcap_net) {
          pcap_net->write_dl_sirnti(
              dl_sched_res->pdsch[n].data[0], sched_result.bc[i].tbs, true, tti_tx_dl, enb_cc_idx);
        }
#endif
      } else {
        dl_sched_res->pdsch[n].softbuffer_tx[0] = &common_buffers[enb_cc_idx].pcch_softbuffer_tx;
        dl_sched_res->pdsch[n].data[0]          = common_buffers[enb_cc_idx].pcch_payload_buffer;
        rrc_h->read_pdu_pcch(tti_tx_dl, common_buffers[enb_cc_idx].pcch_payload_buffer, pcch_payload_buffer_len);

        if (pcap) {
          pcap->write_dl_pch(dl_sched_res->pdsch[n].data[0], sched_result.bc[i].tbs, true, tti_tx_dl, enb_cc_idx);
        }
        if (pcap_net) {
          pcap_net->write_dl_pch(dl_sched_res->pdsch[n].data[0], sched_result.bc[i].tbs, true, tti_tx_dl, enb_cc_idx);
        }
      }

      n++;
    }

    // Copy PDCCH order grants
    for (uint32_t i = 0; i < sched_result.po.size(); i++) {
      uint16_t rnti = sched_result.po[i].dci.rnti;
      if (ue_db.contains(rnti)) {
        // Copy dci info
        dl_sched_res->pdsch[n].dci = sched_result.po[i].dci;
        if (pcap) {
          pcap->write_dl_pch(dl_sched_res->pdsch[n].data[0], sched_result.po[i].tbs, true, tti_tx_dl, enb_cc_idx);
        }
        if (pcap_net) {
          pcap_net->write_dl_pch(dl_sched_res->pdsch[n].data[0], sched_result.po[i].tbs, true, tti_tx_dl, enb_cc_idx);
        }
        n++;
      } else {
        logger.warning("Invalid PDCCH order scheduling result. User 0x%x does not exist", rnti);
      }
    }

    dl_sched_res->nof_grants = n;

    // Number of CCH symbols
    dl_sched_res->cfi = sched_result.cfi;
  }

  // Count number of TTIs for all active users
  for (auto& u : ue_db) {
    u.second->metrics_cnt();
  }

  return SRSRAN_SUCCESS;
}

void mac::build_mch_sched(uint32_t tbs)
{
  int sfs_per_sched_period = mcch.pmch_info_list[0].sf_alloc_end;
  int bytes_per_sf         = tbs / 8 - 6; // leave 6 bytes for header

  int total_space_avail_bytes = sfs_per_sched_period * bytes_per_sf;

  int total_bytes_to_tx = 0;

  // calculate total bytes to be scheduled
  for (uint32_t i = 0; i < mch.num_mtch_sched; i++) {
    total_bytes_to_tx += mch.mtch_sched[i].lcid_buffer_size;
    mch.mtch_sched[i].stop = 0;
  }

  int last_mtch_stop = 0;

  if (total_bytes_to_tx > 0 && total_bytes_to_tx >= total_space_avail_bytes) {
    for (uint32_t i = 0; i < mch.num_mtch_sched; i++) {
      double ratio           = mch.mtch_sched[i].lcid_buffer_size / total_bytes_to_tx;
      float  assigned_sfs    = floor(sfs_per_sched_period * ratio);
      mch.mtch_sched[i].stop = last_mtch_stop + (uint32_t)assigned_sfs;
      last_mtch_stop         = mch.mtch_sched[i].stop;
    }
  } else {
    for (uint32_t i = 0; i < mch.num_mtch_sched; i++) {
      float assigned_sfs     = ceil(((float)mch.mtch_sched[i].lcid_buffer_size) / ((float)bytes_per_sf));
      mch.mtch_sched[i].stop = last_mtch_stop + (uint32_t)assigned_sfs;
      last_mtch_stop         = mch.mtch_sched[i].stop;
    }
  }
}

int mac::get_mch_sched(uint32_t tti, bool is_mcch, dl_sched_list_t& dl_sched_res_list)
{
  srsran::rwlock_read_guard lock(rwlock);
  dl_sched_t*               dl_sched_res = &dl_sched_res_list[0];
  logger.set_context(tti);
  srsran_ra_tb_t mcs      = {};
  srsran_ra_tb_t mcs_data = {};
  mcs.mcs_idx             = enum_to_number(this->sib13.mbsfn_area_info_list[0].mcch_cfg.sig_mcs);
  mcs_data.mcs_idx        = this->mcch.pmch_info_list[0].data_mcs;
  srsran_dl_fill_ra_mcs(&mcs, 0, cell_config[0].cell.nof_prb, false);
  srsran_dl_fill_ra_mcs(&mcs_data, 0, cell_config[0].cell.nof_prb, false);
  if (is_mcch) {
    build_mch_sched(mcs_data.tbs);
    mch.mcch_payload              = mcch_payload_buffer;
    mch.current_sf_allocation_num = 1;
    logger.info("MCH Sched Info: LCID: %d, Stop: %d, tti is %d ",
                mch.mtch_sched[0].lcid,
                mch.mtch_sched[mch.num_mtch_sched - 1].stop,
                tti);
    phy_h->set_mch_period_stop(mch.mtch_sched[mch.num_mtch_sched - 1].stop);
    for (uint32_t i = 0; i < mch.num_mtch_sched; i++) {
      mch.pdu[i].lcid = (uint32_t)srsran::mch_lcid::MCH_SCHED_INFO;
      // m1u.mtch_sched[i].lcid = 1+i;
    }

    mch.pdu[mch.num_mtch_sched].lcid   = 0;
    mch.pdu[mch.num_mtch_sched].nbytes = current_mcch_length;
    dl_sched_res->pdsch[0].dci.rnti    = SRSRAN_MRNTI;

    // we use TTI % HARQ to make sure we use different buffers for consecutive TTIs to avoid races between PHY workers
    ue_db[SRSRAN_MRNTI]->metrics_tx(true, mcs.tbs);
    dl_sched_res->pdsch[0].data[0] =
        ue_db[SRSRAN_MRNTI]->generate_mch_pdu(tti % SRSRAN_FDD_NOF_HARQ, mch, mch.num_mtch_sched + 1, mcs.tbs / 8);
  } else {
    uint32_t current_lcid = 1;
    uint32_t mtch_index   = 0;
    uint32_t mtch_stop    = mch.mtch_sched[mch.num_mtch_sched - 1].stop;

    for (uint32_t i = 0; i < mch.num_mtch_sched; i++) {
      if (mch.current_sf_allocation_num <= mch.mtch_sched[i].stop) {
        current_lcid = mch.mtch_sched[i].lcid;
        mtch_index   = i;
        break;
      }
    }
    if (mch.current_sf_allocation_num <= mtch_stop) {
      int requested_bytes = (mcs_data.tbs / 8 > (int)mch.mtch_sched[mtch_index].lcid_buffer_size)
                                ? (mch.mtch_sched[mtch_index].lcid_buffer_size)
                                : ((mcs_data.tbs / 8) - 2);
      int bytes_received = ue_db[SRSRAN_MRNTI]->read_pdu(current_lcid, mtch_payload_buffer, requested_bytes);
      mch.pdu[0].lcid    = current_lcid;
      mch.pdu[0].nbytes  = bytes_received;
      mch.mtch_sched[0].mtch_payload  = mtch_payload_buffer;
      dl_sched_res->pdsch[0].dci.rnti = SRSRAN_MRNTI;
      if (bytes_received) {
        ue_db[SRSRAN_MRNTI]->metrics_tx(true, mcs.tbs);
        dl_sched_res->pdsch[0].data[0] =
            ue_db[SRSRAN_MRNTI]->generate_mch_pdu(tti % SRSRAN_FDD_NOF_HARQ, mch, 1, mcs_data.tbs / 8);
      }
    } else {
      dl_sched_res->pdsch[0].dci.rnti = 0;
      dl_sched_res->pdsch[0].data[0]  = nullptr;
    }
    mch.current_sf_allocation_num++;
  }

  // Count number of TTIs for all active users
  for (auto& u : ue_db) {
    u.second->metrics_cnt();
  }
  return SRSRAN_SUCCESS;
}

uint8_t* mac::assemble_rar(sched_interface::dl_sched_rar_grant_t* grants,
                           uint32_t                               enb_cc_idx,
                           uint32_t                               nof_grants,
                           uint32_t                               rar_idx,
                           uint32_t                               pdu_len,
                           uint32_t                               tti)
{
  uint8_t grant_buffer[64] = {};
  if (pdu_len < rar_payload_len && rar_idx < rar_pdu_msg.size()) {
    srsran::rar_pdu* pdu = &rar_pdu_msg[rar_idx];
    rar_payload[enb_cc_idx][rar_idx].clear();
    pdu->init_tx(&rar_payload[enb_cc_idx][rar_idx], pdu_len);
    if (args.prach_bi > 0 and args.prach_bi <= 12) {
      pdu->set_backoff(args.prach_bi);
    }
    for (uint32_t i = 0; i < nof_grants; i++) {
      srsran_dci_rar_pack(&grants[i].grant, grant_buffer);
      if (pdu->new_subh()) {
        pdu->get()->set_rapid(grants[i].data.preamble_idx);
        pdu->get()->set_ta_cmd(grants[i].data.ta_cmd);
        pdu->get()->set_temp_crnti(grants[i].data.temp_crnti);
        pdu->get()->set_sched_grant(grant_buffer);
      }
    }
    if (pdu->write_packet(rar_payload[enb_cc_idx][rar_idx].msg)) {
      return rar_payload[enb_cc_idx][rar_idx].msg;
    }
  }

  logger.error("Assembling RAR: rar_idx=%d, pdu_len=%d, rar_payload_len=%d, nof_grants=%d",
               rar_idx,
               pdu_len,
               int(rar_payload_len),
               nof_grants);
  return nullptr;
}

int mac::get_ul_sched(uint32_t tti_tx_ul, ul_sched_list_t& ul_sched_res_list)
{
  if (!started) {
    return SRSRAN_SUCCESS;
  }

  logger.set_context(TTI_SUB(tti_tx_ul, FDD_HARQ_DELAY_UL_MS + FDD_HARQ_DELAY_DL_MS));

  srsran::rwlock_read_guard lock(rwlock);

  bool sendUplinkDCI = false;
  if (targetLayer == PHY && activeFuzzer){
    sendUplinkDCI = llfuzz.getSendUplinkDCI();
  }

  bool            sendThisSF_UL = false;
  if (sendUplinkDCI && targetLayer == PHY && activeFuzzer){
    sendThisSF_UL = llfuzz.checksendTC_UL(tti_tx_ul); // check send testcase this SF
    // if (sendThisSF_UL){
    //   printf("[MAC] SF: %d.%d Send UL DCI test case\n", tti_tx_ul/10, tti_tx_ul%10);
    // }
  }

  // Execute UE FSMs (e.g. TA)
  for (auto& ue : ue_db) {
    ue.second->tic();
  }

  for (uint32_t enb_cc_idx = 0; enb_cc_idx < cell_config.size(); enb_cc_idx++) {
    ul_sched_t* phy_ul_sched_res = &ul_sched_res_list[enb_cc_idx];

    // Run scheduler with current info
    sched_interface::ul_sched_res_t sched_result = {};
    if (scheduler.ul_sched(tti_tx_ul, enb_cc_idx, sched_result) < 0) {
      logger.error("Running scheduler");
      return SRSRAN_ERROR;
    }

    // Copy DCI grants
    phy_ul_sched_res->nof_grants = 0;
    int n                        = 0;
    for (uint32_t i = 0; i < sched_result.pusch.size(); i++) {
      if (sched_result.pusch[i].tbs > 0) {
        // Get UE
        uint16_t rnti = sched_result.pusch[i].dci.rnti;

        // llfuzz.save_orin_ul_dci_for_reference(sched_result.pusch[i].dci);

        if (ue_db.contains(rnti)) {
          // Copy grant info
          phy_ul_sched_res->pusch[n].current_tx_nb = sched_result.pusch[i].current_tx_nb;
          phy_ul_sched_res->pusch[n].pid           = TTI_RX(tti_tx_ul) % SRSRAN_FDD_NOF_HARQ;
          phy_ul_sched_res->pusch[n].needs_pdcch   = sched_result.pusch[i].needs_pdcch;
          phy_ul_sched_res->pusch[n].dci           = sched_result.pusch[i].dci;
          phy_ul_sched_res->pusch[n].softbuffer_rx = ue_db[rnti]->get_rx_softbuffer(enb_cc_idx, tti_tx_ul);

          // If the Rx soft-buffer is not given, abort reception
          if (phy_ul_sched_res->pusch[n].softbuffer_rx == nullptr) {
            logger.warning("Failed to retrieve UL softbuffer for tti=%d, cc=%d", tti_tx_ul, enb_cc_idx);
            continue;
          }

          if (sched_result.pusch[n].current_tx_nb == 0) {
            srsran_softbuffer_rx_reset_tbs(phy_ul_sched_res->pusch[n].softbuffer_rx, sched_result.pusch[i].tbs * 8);
          }
          phy_ul_sched_res->pusch[n].data =
              ue_db[rnti]->request_buffer(tti_tx_ul, enb_cc_idx, sched_result.pusch[i].tbs);
          if (phy_ul_sched_res->pusch[n].data) {
            phy_ul_sched_res->nof_grants++;
          } else {
            logger.error("Grant for rnti=0x%x could not be allocated due to lack of buffers", rnti);
          }

          if (sendThisSF_UL && sendUplinkDCI && (targetLayer == PHY) && activeFuzzer){
            // printf("[MAC] SF: %d.%d Send UL DCI test case 222\n", tti_tx_ul/10, tti_tx_ul%10);
            bool ret = llfuzz.send_ul_dci_testcase(tti_tx_ul, phy_ul_sched_res->pusch[n].dci.rnti, phy_ul_sched_res->pusch[n].dci, phy_ul_sched_res->pusch_fuzzer[n].dci); 
            // only send DCI test case if send_test_case returns true
            if (ret){
              // printf("[MAC] SF: %d.%d Send UL DCI test case 333\n", tti_tx_ul/10, tti_tx_ul%10);
              phy_ul_sched_res->sendThisSF_UL = true; 
              phy_ul_sched_res->pusch_fuzzer[n].needs_pdcch = true;
            }else{
              phy_ul_sched_res->sendThisSF_UL = false; 
            }
          }else{
            // if (activeFuzzer){
            //   printf("[MAC] SF: %d.%d Not send UL DCI test case %d %d %d %d\n", tti_tx_ul/10, tti_tx_ul%10, sendThisSF_UL, sendUplinkDCI, targetLayer, activeFuzzer);
            // }
            phy_ul_sched_res->sendThisSF_UL = false;
          }

          n++;
        } else {
          logger.warning("Invalid UL scheduling result. User 0x%x does not exist", rnti);
        }
      } else {
        logger.warning("Grant %d for rnti=0x%x has zero TBS", i, sched_result.pusch[i].dci.rnti);
      }
    }

    // Copy PHICH actions
    for (uint32_t i = 0; i < sched_result.phich.size(); i++) {
      phy_ul_sched_res->phich[i].ack  = sched_result.phich[i].phich == sched_interface::ul_sched_phich_t::ACK;
      phy_ul_sched_res->phich[i].rnti = sched_result.phich[i].rnti;
    }
    phy_ul_sched_res->nof_phich = sched_result.phich.size();
  }
  // clear old buffers from all users
  for (auto& u : ue_db) {
    u.second->clear_old_buffers(tti_tx_ul);
  }
  return SRSRAN_SUCCESS;
}

void mac::write_mcch(const srsran::sib2_mbms_t* sib2_,
                     const srsran::sib13_t*     sib13_,
                     const srsran::mcch_msg_t*  mcch_,
                     const uint8_t*             mcch_payload,
                     const uint8_t              mcch_payload_length)
{
  srsran::rwlock_write_guard lock(rwlock);
  mcch               = *mcch_;
  mch.num_mtch_sched = this->mcch.pmch_info_list[0].nof_mbms_session_info;
  for (uint32_t i = 0; i < mch.num_mtch_sched; ++i) {
    mch.mtch_sched[i].lcid = this->mcch.pmch_info_list[0].mbms_session_info_list[i].lc_ch_id;
  }
  sib2  = *sib2_;
  sib13 = *sib13_;
  memcpy(mcch_payload_buffer, mcch_payload, mcch_payload_length * sizeof(uint8_t));
  current_mcch_length = mcch_payload_length;

  unique_rnti_ptr<ue> ue_ptr = make_rnti_obj<ue>(
      SRSRAN_MRNTI, SRSRAN_MRNTI, 0, &scheduler, rrc_h, rlc_h, phy_h, logger, cells.size(), softbuffer_pool.get());

  auto ret = ue_db.insert(SRSRAN_MRNTI, std::move(ue_ptr));
  if (!ret) {
    logger.info("Failed to allocate rnti=0x%x.for eMBMS", SRSRAN_MRNTI);
  }
}

// Internal helper function, caller must hold UE DB rwlock
bool mac::check_ue_active(uint16_t rnti)
{
  if (not ue_db.contains(rnti)) {
    logger.error("User rnti=0x%x not found", rnti);
    return false;
  }
  return ue_db[rnti]->is_active();
}

} // namespace srsenb

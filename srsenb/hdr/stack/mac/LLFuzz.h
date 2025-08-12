#pragma once

#include "srsran/common/mac_pcap.h"
#include "fuzzer_base.h"
#include "macfuzzer.h"
#include "rlcfuzzer.h"
#include "pdcpfuzzer.h"
#include "phyfuzzer.h"
#include "utility.h"

#include <fstream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <signal.h>     // for kill()
#include <unistd.h>    // for getppid()
#include <errno.h>     // for errno

namespace srsenb {

static int  adbStopPipe[2]     = {false};
static int  toAdbInterface[2] = {(int)checkADB}; // 1: switch airplane mode
static int  fromAdbInterface[2] = {(int)noAction}; // 1: crash detected from ADB
static int  pingPipe[2]; // to transfer UE ip to adb thread to ping
static int  ttiPipe[2];  // to inform adb thread about current tti

/*Thread for adb control*/
class ADBController: public srsran::thread{
public:
  ADBController();
  ~ADBController();
  int  runADBThread();
  void stop(){ adbStop = true; }
  void set_enable_adb_cfg(bool enableADB_cfg_){ enableADB_cfg = enableADB_cfg_; }
protected:
  virtual void run_thread() override;
private:
  bool              adbStop       = {false};
  bool              adbConnected  = false;
  bool              enableADB_cfg = {false};
  std::string       adbCommand =  "adb devices";
  std::string       adbResult;
  const std::string airplaneOff  = "adb shell nohup cmd connectivity airplane-mode disable &";
  const std::string airplaneOn   = "adb shell nohup cmd connectivity airplane-mode enable &";
  const std::string CellDataOn   = "adb shell nohup svc data enable &";
  const std::string CellDataOff  = "adb shell nohup svc data disable &";
  const std::string wifiOff      = "adb shell nohup svc wifi disable &";
  const std::string wifiOn       = "adb shell nohup svc wifi enable &";
  const std::string crashString1 = "RADIO_OFF_OR_UNAVAILABLE";
  const std::string crashString2 = "Modem Reset";
  const std::string crashString3 = "CRASH";
  const std::string crashString4 = "everybody panic"; // for google pixel
  const std::string cleanADB     = "adb logcat -c -b radio";
  const std::string checkCellData = "adb shell settings get global mobile_data";
  const std::string rebootUEcmd   = "adb reboot";
  const std::string screenOff     = "adb shell input keyevent 26";
  const std::string querryWebcmd  = "adb shell am start -a android.intent.action.VIEW -d https://vnexpress.net/";
  const std::string checkCrash    = "adb logcat -b radio *:E -d | grep \"RADIO_OFF_OR_UNAVAILABLE\\|Modem Reset\\|CRASH\"";
  fuzzingTimer_t    adbTimer;
  std::future<int>  adbFuture;
  adbPhase_t        adbPhase = {adbNoPhase};
  int               prevTTI = 0;
};


struct LLFuzz_config_t{
    targetLayer_t targetLayer;
    LLState_t fuzzingState;
    bool enableADB;
    int startIdx;
    LLState_t fuzzingMode;
    bool verifyingMode;
    uint64_t imsi;
    bool sendUplinkDCI;
    int  transmission_mode;
    int  recoverTimerThres;
    int  waitingConnTimerThres;
    int  waitConnAfterPagingThres;
    int nof_test_cases_per_ss;
    bool enableNotWorkingReboot;
    int  nofFailedConnReboot;
    bool enableSpeedLog;
    std::string speedLogFilename;
    std::string crashLogFilename;
    std::string crashPcapFilename;
    std::string enbPCAPFilename;
};

class LLFuzz{
public:
    LLFuzz();
    ~LLFuzz();
    void init();
    LLFuzz_config_t read_config_from_file(std::string& filename);
    void startFuzzer();
    void resetIndex();
    void stopFuzzing();
    
    void generate_test_cases();
    bool check_send_test_case_this_SF(int tti);
    bool checksendTC_UL(int tti_rx_ul); // only PHY fuzzer
    int  check_rrc_reconfig_type();
    
    // UE State management
    void clearUEDB();
    void removeUE(uint16_t rnti);
    void addUE(uint16_t rnti, LLState_t state, int tti);
    bool updateUEState(uint16_t rnti, LLState_t state, int tti);
    void updateConResID(uint8_t* conResID_);
    void handleUEDisconnection();
    void notifyRLF();
    
    void updateTMSI(uint32_t tmsi_);
    void update_rlc_sequence_number(uint16_t lcid, uint16_t sn);
    
    // RRC interface
    void set_rrc_interface(rrc_interface_mac* rrc_h_){ rrc_h = rrc_h_; }
    void stopTimer(fuzzingTimer_t& timer){ timer.running = false; }
    void startTimer(fuzzingTimer_t& timer){ timer.running = true; timer.activeTime = std::chrono::high_resolution_clock::now(); }
    void startnotWorkingTimer(){ startTimer(notWorkingTimer); }
    void stopnotWorkingTimer (){ stopTimer(notWorkingTimer); }
    
    void save_legitimate_rar(uint8_t* ptr, int len);
    bool check_inject_rar();
    int  get_nof_injecting_rar();
    
    LLState_t         get_fuzzing_mode()  { return fuzzingMode; }
    uint16_t          getCurRNTI()        { return curRNTI; }
    LLState_t         getCurRNTIState()   { return curRNTIState; }
    int               get_cur_idx()       { return idx[fuzzingState]; }
    int               getUEStateDBSize()  { return (int)ueStateDB.size(); }
    targetLayer_t     getTargetLayer()    { return targetLayer; }
    state1Phase_t     getState1Phase()    { return state1Phase; }
    state234Phase_t   getState234Phase()   { return state234Phase; }
    state4Phase_t     getState4Phase()    { return state4Phase; }
    bool              getSendThisSF()     { return sendTCThisSF; }
    bool              getRFLinkIssue() { return rfLinkIssue; }
    std::atomic<int>* get_rrc_reconfig_type(){ return &rrc_reconfig_type; }
    std::string       get_cur_testcase_info();
    LLState_t         get_fuzzing_state() { return fuzzingState; }
    
    int               get_injecting_length();
    int               get_injecting_lcid();
    int               get_total_byte_cur_testcase();
    bool              get_manual_dci();
    bool              getSendUplinkDCI();
    int               get_nof_sent_test_cases_per_ss(){ return nof_sent_test_cases_per_ss; }

    void crashMonitoring(int tti_tx_dl);
    void recoverUE();
    
    void get_signal_from_adb();
    void check_switch_to_next_state();
    void state1Control(int tti_tx_dl);
    void state234Control(int tti_tx_dl);
    void state4Control(int tti_tx_dl);
    void handleRRCReconfig(uint16_t rnti, pduInfo_t pduInfo, int tti_tx_dl);

    void send_rar_test_case(int nofGrant, int tti_tx_dl, uint8_t *payload, int len);
    void send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen);

    // save RAR trigger times to avoid sending TC in a short time
    void pushRARBuffer(timePoint_t time);

    // PHY Fuzzer
    void setCellConfig(int nofPRB_, bool isFDD);
    void save_orin_dl_dci_for_reference(srsran_dci_dl_t source);
    void save_orin_ul_dci_for_reference(srsran_dci_ul_t source);
    bool send_RAR_DCI(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t &target_dci);
    bool send_dl_dci_testcase(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci);
    bool send_ul_dci_testcase(int tti_tx_ul, uint16_t rnti, srsran_dci_ul_t &orin_dci, srsran_dci_ul_t& target_dci);

    void save_testing_speed_log();
    void active_speedlog_timer(){ if (enableSpeedLog) startTimer(speedLogTimer); }

    // void save_mac_packet_to_buffer(uint8_t* payload, int len, uint32_t tti, uint16_t rnti);
    // void save_mac_packet_buffer_to_pcap();

    ADBController& getADBController() { return adbController; }

    void set_received_rrc_reconfig_complete(bool received){ fuzzer->set_received_rrc_reconfig_complete(received); }

private:
    std::unique_ptr<FuzzerBase_t>     fuzzer        = nullptr;
    std::string                       config_file   = "../config/llfuzz.conf";
    targetLayer_t                     targetLayer   = MAC;
    LLState_t                         fuzzingState  = {startUp};       // there are 5 state
    state1Phase_t                     state1Phase   = {state1noPhase};
    state234Phase_t                    state234Phase  = {state234noPhase};
    state4Phase_t                     state4Phase   = {s4None};

    std::map<uint16_t, ueStateTTI_t>  ueStateDB;         // DB to contain states of active UEs
    std::mutex                        ueStateMutex;
    uint16_t                          curRNTI      = 0;
    LLState_t                         curRNTIState = {startUp};
    int                               curTTI       = 0;

    // adb interface
    bool                              enableADB = true;
    fromAdbCommand_t                  fromADB = {noAction};
    bool                              isAirPlaneOn = false; // to prevent sending TC when airplane mode is on
    LLState_t                         prevState    = {stateUnknown}; // for crash handling
    int                               nofCrash = 0;

    int             startIdx = 0;
    int             nof_sent_test_cases_per_ss = 0;
    int             idx[7]  = {0, 0, 0, 0, 0, 0, 0};
    int             total_idx[7] = {0, 0, 0, 0, 0, 0, 0};
    int             total_idx_phy_ul[7] = {0, 0, 0, 0, 0, 0, 0}; // for ul dci test case
    bool            sendTCThisSF      = false;
    // bool            state234Enable[7]  = {false, false, false, true, true, false, false};  // in mode 234, enable a single or multiple states, state5 when state234 should be tested seperately, in fuzzingstate 5, it also should be disabled
    LLState_t       verifyingState    = {state4};     // should be state 2/3/4/5
    // LLState_t       verifyingStateDef = {state4};    // default state for verifying state whenever fuzzer is switched to verify mode
    LLState_t       fuzzingMode       = {state234};  // 3 modes to run: state1/234/5
    LLState_t       fuzzingModeOrin   = {state234};  // Original fuzzingMode for reference
    bool            readFromFileMode  = true;
    bool            MediaTek          = false;
    int             nofRARSendingPhase= 0; // optimizing for MTK, send TC in the 2nd RAR procedure
    timePoint_t     lastRARtime;           // to check if multiple RAR during a short time
    bool            rarCondition      = true;
    // bool            receivedRRCReconfigComplete = true; // to check if UE received RRC reconfiguration complete after sending specific configuration in rrc reconfiguration
    bool            sendUplinkDCI     = false;
    int             transmission_mode = 1;


    // interface to RRC to send RRC release and paging
    rrc_interface_mac* rrc_h = nullptr;
    std::atomic<int>   rrc_reconfig_type{0}; // to modify rrc reconfig type
    bool               rfLinkIssue = false;
    bool               handlingRFLink = false;
    fuzzingTimer_t     finishCrash;
    fuzzingTimer_t     recoverTimer;
    int                recoverTimerThres = 5000; // 1000ms
    fuzzingTimer_t     ueRebootTimer;
    fuzzingTimer_t     waitingUEidleTimer;
    fuzzingTimer_t     sendPagingDelayTimer;
    int                sendPagingDelayThres = 50; // 50ms
    int                waitConnAfterPagingThres = 800; // 1000ms
    fuzzingTimer_t     pagingTimer;
    fuzzingTimer_t     rfLinkTimer;
    fuzzingTimer_t     finishingTimer;
    fuzzingTimer_t     adbDelayTimer; // to prevent mac accepts UE connection before ADB switch airplane mode   
    fuzzingTimer_t     enInternetTimer;
    fuzzingTimer_t     querryWebTimer;
    fuzzingTimer_t     webDelayTimer;
    fuzzingTimer_t     ueDisconnTimer;
    bool               sendRRCRelease = false;
    fuzzingTimer_t     rrcReleaseTimer;    // to prevent release UE immediately after connection
    fuzzingTimer_t     notWorkingTimer;
    fuzzingTimer_t     waitingConnTimer;
    int                waitingConnTimerThres = 3000; // 3000ms
    fuzzingTimer_t     state4Timer;
    int                timeOutCnt = 0; // to detect when UE cannot recover after many time switching airplane mode
    const float        releaseDelayNormal = 200; // 100ms or 1000ms
    const float        releaseDelayVerify = 1000; //
    const int          ueDisconnTimerThres = 800;


    uint8_t            m_tmsi[4] = {0};    // 4 bytes of m_tmsi
    uint8_t            conResID[6] = {0};  // contention resolution id
    uint16_t           lastRNTI = 0;
    uint8_t            mmec;
    uint32_t           ueid   = 737;       // imsi 13
    // const uint32_t                  ueid   = 739;       // imsi 15 mode 1024 to send paging;
    // const uint32_t                  ueid   = 741;       // imsi (17) mode 1024 to send paging;

    int                nof_user_dci_ul = 0;
    int                nof_sent_dci_ul = 0;
    int                nof_ul_dci_per_ss = 1;
    int                nof_test_cases_per_ss = 3;

    // testing speed log
    bool               enableSpeedLog = true;
    std::ofstream      speedLog;
    std::string        speedFilename = "speedLog.txt";
    std::string        crashLogFilename = "crashLog.txt";
    int                interval = 5; // 5 seconds
    fuzzingTimer_t     speedLogTimer;

    bool                enableNotWorkingReboot = false;
    int                 nofFailedConnReboot = 10;

    // save recent mac packet to pcap file
    bool                          saveMacPacket = false;
    // RingBuffer<mac_packet_t, 10>  macPacketBuffer;
    // std::string                   crash_pcap_filename = "../pcap/crash.pcap";
    // srsran::mac_pcap              crash_pcap;

    // move adbController to inside this class
    ADBController adbController;
};

}
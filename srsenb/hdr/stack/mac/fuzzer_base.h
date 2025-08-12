#pragma once

#include <cstdint>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include "srsran/phy/phch/dci.h"

namespace srsenb {

/*Lower layer state*/
enum LLState_t { 
  state1        = 1, 
  state2        = 2, 
  state3        = 3, 
  state4        = 4, 
  // state5        = 5, 
  startUp       = 6,
  crashHandling = 7,
  state234      = 23,
  stateUnknown  = 0 
};

enum state1Phase_t { 
  state1Prepare             = 0, 
  state1PrepareWaitingUE    = 1, // wait UE connects in preparation phase
  state1PrepareWaitingADB   = 2,
  state1Paging              = 3,
  state1Send                = 4, 
  state1WaitingCon          = 5, // wait UE connecs after sending 1 test case
  state1WaitingUEIdle       = 6,
  state1noPhase             = 7
};

enum state234Phase_t { 
  state234Prepare             = 0, 
  state234PrepareWaitingUE    = 1, // wait UE connects in preparation phase
  state234PrepareWaitingADB   = 2,
  state234Paging              = 3,
  state234Send                = 4, 
  state234WaitingCon          = 5, // wait UE connecs after sending 1 test case
  state234WaitingUEIdle       = 6,
  state234RebootUE            = 7,
  state234noPhase             = 8
};

enum state4Phase_t { 
  s4Prepare = 0, // control ADB to prepare for State 5
  s4WaitConn= 1,
  s4Send    = 2, // Send test case
  s4Web     = 3, // Control ADB for access a website, maintain connection
  s4UEDisconn = 4, 
  s4None    = 5
};

struct ueStateTTI_t{
  LLState_t state = stateUnknown;
  int        tti   = 0;
};

enum targetLayer_t{
    PHY,
    MAC,
    RLC,
    PDCP
};

// struct rarTestcase;

struct rlcChunk_t
{
    bool E = 0;
    uint16_t L = 0; // LI indicator in sub-header   
    uint16_t dataLen = 0; // actual dataLen, canbe different from L
};

struct rlcUMpdu_t
{
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    uint8_t FI = 0;
    bool E = 0;
    uint16_t SN = 0;
    uint8_t snLen = 10;
    uint16_t um1DataLen = 0; // used when UM1 that does not any sub-header
    uint16_t nofChunk = 0; // if n chunk, there are n-1 chunk headers
    std::vector<rlcChunk_t> chunk;
    bool hasPadding = false;
};

struct rlcAMpdu_t
{
    bool DC = 1;              // this decides Control/Data PDU
    bool RF = 0;              // Re-segmentation flag, 0: normal AMD PDU, 1: AMD PDU segment
    bool P = 0;
    uint8_t FI = 0;
    bool E = 1;
    uint16_t SN = 0;
    uint8_t snLen = 10;        // default 10 bits, can be 16 bits
    uint8_t liLen = 11;       // default 11 bits, can be 15 bits
    bool LSF = 0;             // Last segment flag for AMD PDU segment
    bool R1_1 = 0;
    bool R1_2 = 0;
    uint16_t SO = 0;
    uint16_t am1DataLen = 0;  // used when AM1 that does not any sub-header
    uint16_t nofChunk = 0;    // if n chunk, there are n-1 chunk headers
    std::vector<rlcChunk_t> chunk;
    bool hasPadding = 0;
    /*This part is for control PDU if DC = 1*/
    uint8_t CPT = 0;
    uint16_t ackSN = 0;
    bool     E1 = 0;
    uint16_t nackSN = 0;
    bool     E12 = 0;
    bool     E2 = 0;
};

struct rarSubHeader_t{
  bool  isLast = false;
  bool  E = 0;
  bool  T = 0; //fixed T = 1 is rar grant, T = 0 is BI
  bool  is_correct_pid = false;
  int   pid = 0; 
  bool  R1 = 0;
  bool  R2 = 0;
  uint8_t BI = 0;
  void print() {
      std::cout << "[H] "
                << "E: " << std::setw(2) << E << " "
                << "T: " << std::setw(2) << T << " "
                << "pid: " << std::setw(4) << pid << " "
                << "R1: " << std::setw(2) << R1 << " "
                << "R2: " << std::setw(2) << R2 << " "
                << "BI: " << std::setw(3) << static_cast<int>(BI) << " "
                << "c_pid: " << std::setw(2) << is_correct_pid
                << std::endl;
  }
  void print_to_file(std::ofstream& file) {
    if (file.is_open()){
      file << "[H] "
                << "E: " << std::setw(2) << E << " "
                << "T: " << std::setw(2) << T << " "
                << "pid: " << std::setw(4) << pid << " "
                << "R1: " << std::setw(2) << R1 << " "
                << "R2: " << std::setw(2) << R2 << " "
                << "BI: " << std::setw(3) << static_cast<int>(BI) << " "
                << "c_pid: " << std::setw(2) << is_correct_pid
                << std::endl;
    }
  }
};

struct rarSubPayload_t{
  bool isLastGrant = false; // last payload that has rar grant, not the last payload in general
  bool R = 0;
  uint16_t ta = 0;
  int ulGrant = 103436;  // default value from legetimate rar
  uint16_t tcrnti = 64;  // default value from legetimate rar
  void print() {
      std::cout << "[P] "
                << "R: " << std::setw(2) << R << " "
                << "ta: " << std::setw(5) << ta << " "
                << "ulGrant: " << std::setw(8) << ulGrant << " "
                << "tcrnti: " << std::setw(5) << tcrnti << " "
                << "L_grant: " << std::setw(2) << isLastGrant
                << std::endl;
  }
  void print_to_file(std::ofstream& file) {
    if (file.is_open()){
      file << "[P] "
                << "R: " << std::setw(2) << R << " "
                << "ta: " << std::setw(5) << ta << " "
                << "ulGrant: " << std::setw(8) << ulGrant << " "
                << "tcrnti: " << std::setw(5) << tcrnti << " "
                << "L_grant: " << std::setw(2) << isLastGrant
                << std::endl;
                }
  }
};

class FuzzerBase_t {
private:

public:
    virtual ~FuzzerBase_t() = default; // Virtual destructor

    void set_fuzzing_config(LLState_t targetState, bool verifyingMode, int startIdx, bool sendUplinkDCI, std::string crashLogFilename_, int nof_test_cases_per_ss_, int transmission_mode_){
        this->fuzzingState = targetState;
        this->readFromFileMode = verifyingMode;
        this->startIdx = startIdx;
        this->sendUplinkDCI = sendUplinkDCI;
        this->transmission_mode = transmission_mode_;
        for (int i = 0; i < 6; i++)
        {
            idx[i] = startIdx;
        }
        logFilename = crashLogFilename_;
        nof_test_cases_per_ss = nof_test_cases_per_ss_;

        // init crash log file
        crashLog.open(logFilename);
    }

    void close_crash_log_file(){
        crashLog.close();
    }

    void set_start_fuzzing_index(int startIdx_){
        this->startIdx = startIdx_;
        for (int i = 0; i < 6; i++)
        {
            idx[i] = startIdx_;
        }
    }

    virtual void        generate_test_cases() = 0;
    virtual void        update_rlc_sequence_number(uint16_t lcid, uint16_t sn)  = 0;
    virtual  int        check_rrc_reconfig_type() = 0;

    int                 get_cur_testcase_idx(LLState_t state, bool verifyingMode);
    virtual std::string get_cur_testcase_info() = 0;

    // virtual int         get_cur_testcase_idx_phy_ul(LLState_t, bool)            = 0;    
    virtual int         get_total_byte_cur_testcase()   = 0;
    virtual bool        get_manual_dci()                = 0;
    virtual int         get_total_idx(LLState_t, bool)  = 0;
    virtual int         get_total_idx_phy_ul(LLState_t, bool)  = 0;
    virtual void        saveCrashtoFile(int oracle)     = 0;

    virtual int         get_nof_injecting_rar() = 0;
    virtual int         get_injecting_length()  = 0;
    virtual int         get_injecting_lcid()    = 0;
    bool                getSendUplinkDCI() { return sendUplinkDCI; } // only for PHY fuzzer
    virtual void        send_rar_test_case(int nofGrant, int tti_tx_dl, uint8_t *payload, int len)     = 0;
    virtual void        send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen) = 0;

    // PHY Fuzzer
    virtual void        setCellConfig(int nofPRB_, bool isFDD) = 0;
    virtual bool        send_RAR_DCI(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t &target_dci) = 0;
    virtual bool        send_dl_dci_testcase(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci) = 0;
    virtual bool        send_ul_dci_testcase(int tti_tx_ul, uint16_t rnti, srsran_dci_ul_t &orin_dci, srsran_dci_ul_t& target_dci) = 0;
    virtual void        save_orin_dl_dci_for_reference(srsran_dci_dl_t source) = 0;
    virtual void        save_orin_ul_dci_for_reference(srsran_dci_ul_t source) = 0;
    // virtual bool        getSendUplinkDCI() = 0;
    void save_legitimate_rar(uint8_t* ptr, int len);

    void set_fuzzing_State(LLState_t state){
      fuzzingState = state;
      idx[fuzzingState] = 0;
    }

    virtual void        resize_crash_log_buffer() = 0;
    void                set_received_rrc_reconfig_complete(bool received){ receivedRRCReconfigComplete = received; }

protected:
    LLState_t           fuzzingState  = {startUp};
    int                 startIdx = 0;
    bool                readFromFileMode = false;
    bool                sendUplinkDCI = false;
    int                 transmission_mode = 1;         
    // uint32_t            ueid = 137;
    int                 idx[30] = {0}; // index of curent test case. idx[1]: test case index for state 1, ...
    rarSubHeader_t      legitimate_rar_subheader  = {0}; // for assigning legitimate rar subheader
    rarSubPayload_t     legitimate_rar_grant      = {0}; // for assigning legitimate rar grant

    int             nof_test_cases_per_ss = 5;
    int             nofCrash = 0;
    std::ofstream   crashLog;                         // log file
    std::string     logFilename = "crashLog.txt";

    bool            receivedRRCReconfigComplete = true; // to check if UE received RRC reconfiguration complete after sending specific configuration in rrc reconfiguration

};


}

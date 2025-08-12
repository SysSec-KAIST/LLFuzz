#pragma once

#include <deque>
#include <ctime>
#include <atomic>
#include <string>
#include <vector>
#include <future>
#include <map>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "utility.h"
#include <unistd.h>
#include <bitset>
#include "srsran/interfaces/enb_rrc_interface_mac.h"
#include "srsran/asn1/asn1_utils.h"
#include <sstream>
#include "srsran/common/threads.h"
#include <iomanip>
#include <random>  
#include <mutex>
#include "srsran/phy/phch/dci.h"
#include "srsran/phy/phch/ra.h"
#include "fuzzer_base.h"

namespace srsenb {

enum phyTestCaseType_t{
    format0 = 0,
    format1 = 1
    // ...
};

class phyFuzzer_t: public FuzzerBase_t
{
public:
    phyFuzzer_t();
    ~phyFuzzer_t();
    // void set_fuzzing_config(LLState_t targetState, bool verifyingMode, int startIdx) override final;
    void setCellConfig(int nofPRB_, bool isFDD) override final ;
    void resetIndex();

    void generate_test_cases() override final;
    // void switchState() override final;

    void logCrash();
    void saveCrashtoFile(int oracle) override final;
    
    // 0/1/1A/1C/2/2A/2B-> 1A PDCCH order, 1A RA/P/SI-RNTI, 1C RA/P/SI-RNTI, 
    // void mutatePDCPDataPDUSRB(std::vector<phyTestCase_t>& pduDB, int lcid);
    void mutateDCI1A_CRNTI(std::vector<phyTestCase_t>& pduDB);
    // 0: 1A with RA_RNTI, 1: 1A with P-RNTI, 2: 1A with SI-RNTI, 3: PDCCH order
    void mutateDCI1A_PDCCH_order(std::vector<phyTestCase_t>& pduDB);
    // 0: 1A with RA_RNTI, 1: 1A with P-RNTI, 2: 1A with SI-RNTI, 3: PDCCH order
    void mutateDCI1A_broadcast_RNTI(std::vector<phyTestCase_t>& pduDB);
    void mutateDCI1_type0(std::vector<phyTestCase_t>& pduDB);
    void mutateDCI1_type1(std::vector<phyTestCase_t>& pduDB);
    void mutateDCI2A_type0(std::vector<phyTestCase_t>& pduDB);
    void mutateDCI2A_type1(std::vector<phyTestCase_t>& pduDB);
    void mutateDCI2_type0(std::vector<phyTestCase_t>& pduDB);
    void mutateDCI2_type1(std::vector<phyTestCase_t>& pduDB);
    void mutateDCI1C(std::vector<phyTestCase_t>& pduDB);
    void mutateDCI0_FDD(std::vector<phyTestCaseUL_t>& pduDB);

    phyTestCase_t    getCurTestCase();
    phyTestCaseUL_t  getCurTestCase_UL();
    bool             getSendThisSF()     { return sendTCThisSF; }
    int              getCurrentTTI()     { return curTTI; }

    void update_rlc_sequence_number(uint16_t lcid, uint16_t sn) override final;
    // int  get_cur_testcase_idx(LLState_t, bool) override final;
    // int  get_cur_testcase_idx_phy_ul(LLState_t, bool) override final; 
    int  get_total_byte_cur_testcase() override final{ return 0;}
    bool get_manual_dci() override final {return false;}
    int  get_total_idx(LLState_t, bool) override final;
    int  get_total_idx_phy_ul(LLState_t, bool) override final;
    int  get_nof_injecting_rar() override final { return 0;}
    int  get_injecting_length()  override final { return 10;} // always 10 to generate a random DCI 
    int  get_injecting_lcid()    override final { return 0;}  // always 0 to generate a random DCI
    // bool getSendUplinkDCI() override final {return sendUplinkDCI;}
    std::string get_cur_testcase_info() override final{
      return "";
    }

    // bool checksendTC(int tti_tx_dl);
    // bool checksendTC_UL(int tti_rx_ul);

    void send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen){} // not used for PHY fuzzer

    int  check_rrc_reconfig_type() override final {return 0;} // not used for PHY fuzzer
    bool send_RAR_DCI(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t &target_dci) override final;
    bool send_dl_dci_testcase(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci) override final; 
    bool send_ul_dci_testcase(int tti_tx_ul, uint16_t rnti, srsran_dci_ul_t &orin_dci, srsran_dci_ul_t& target_dci) override final;
    // void postProcess(int tti_tx_dl, uint16_t rnti);
    // void postProcess_UL(int tti_tx_ul, uint16_t rnti);

    void send_rar_test_case(int nofGrant, int tti_tx_dl, uint8_t *payload, int len) override final {} // does not need for PHY
    
    void generatePDU(phyTestCase_t& testCase, uint8_t* packet, int pdcpIdx, int actualLen);

    void writeTCtoFile(std::ofstream& file, phyTestCase_t& pdu); //write test case to file
    void readTCfromFile(const std::string& filename); //read test case from file

    std::string getTestCaseTypeString(phyTestCaseType_t& type);
    void        printPDUtestcase(phyTestCase_t& pdu, int tti, int actualLen);

    void        increase_nof_user_dci(){nof_user_dci++;}
    void        increase_nof_user_dci_ul(){nof_user_dci_ul++;}
    void        reset_nof_user_dci(){nof_user_dci = 0;}

    /* Check if having DCI original version*/
    bool check_has_dci1A_orin(){ return has_dci1A_orin; }
    bool check_has_dci1_orin(){ return has_dci1_orin; }
    bool check_has_dci2A_orin(){ return has_dci2A_orin; }
    bool check_has_dci2_orin(){ return has_dci2_orin; }
    bool check_has_dci0_orin(){ return has_dci0_orin; }
    bool check_has_dci1A_broadcast_orin(){ return has_dci1A_broadcast_orin; }

    void save_orin_dl_dci_for_reference(srsran_dci_dl_t source) override final;
    void save_orin_ul_dci_for_reference(srsran_dci_ul_t source) override final;
    void save_dci_to_file(srsran_dci_dl_t dci, std::string filename);
    void save_ul_dci_to_file(srsran_dci_ul_t dci, std::string filename);
    srsran_dci_dl_t read_dci_from_file(std::string filename);
    srsran_dci_ul_t read_ul_dci_from_file(std::string filename);

    srsran_dci_dl_t get_orin_dl_dci1A(){ return dci1A_orin; }
    srsran_dci_dl_t get_orin_dl_dci1(){ return dci1_orin; }
    srsran_dci_dl_t get_orin_dl_dci2A(){ return dci2A_orin; }
    srsran_dci_dl_t get_orin_dl_dci2(){ return dci2_orin; }
    srsran_dci_ul_t get_orin_dl_dci0(){ return dci0_orin; }
    srsran_dci_dl_t get_orin_dl_dci1A_broadcast(){ return dci1A_broadcast_orin; }    
    
    void resize_crash_log_buffer() override final{
      crashBuffer.resize(nof_test_cases_per_ss);
    }
   
  private:
    phyTestCase_t                     curTestCase;
    phyTestCaseUL_t                   curTestCaseUL;

    std::vector<phyTestCase_t>         lv1PDUtemp;
    std::vector<phyTestCase_t>         lv2PDUtemp;
    std::vector<phyTestCase_t>         lv3PDUtemp;
    std::vector<phyTestCase_t>         lv4PDUtemp;
    
    std::vector<phyTestCaseUL_t>        lv1PDUtempUL;
    std::vector<phyTestCaseUL_t>        lv2PDUtempUL;
    std::vector<phyTestCaseUL_t>        lv3PDUtempUL;
    std::vector<phyTestCaseUL_t>        lv4PDUtempUL;

    std::vector<phyTestCase_t>          testcaseDB[7];
    std::vector<phyTestCaseUL_t>        testcaseDB_UL[7];
    std::vector<phyTestCase_t>          verifyDB[7]; // state 2 idx 2, ...
    std::vector<phyTestCaseUL_t>        verifyDB_UL[7]; // state 2 idx 2, ...
    RingBuffer<int, 5>                  recent_testcases[7]; // index of recent test cases when crash happens| state 2: 2, ...

    bool                                sendTCThisSF = false;
    bool                                rarCondition = false; // if two RARs are sent in a short time, not send TC
    int                                 curTTI;


    std::ofstream                       verifiedCrash;
    std::string                         verifiedCrashFilename = "verifiedCrash.txt";
    RingBuffer<phyTestCase_t, 5>        crashBuffer; // state 2: 2, ...
    RingBuffer<phyTestCaseUL_t, 5>      crashBuffer_UL; // state 2: 2, ...
    RingBuffer<phyTestCase_t, 1 >       verifiedcrashBuffer[7];

    /* Std file to write test case to file*/
    std::ofstream   tcFile;
    std::string     tcFilename = "tc.txt";
    std::ofstream   terminalLog;
    std::string     terminalFilename = "terminalLog.txt";

    // sequence number
    std::map<uint16_t, uint16_t> rlcSNmap;

    /* main configs*/
    // int             startIdx          = 0;                   // set start index if previous section was terminated
    bool            state234Enable[7] = {false, false, false, false, false, true, false};  // in state 234, enable a single or multiple states
    // bool            readFromFileMode  = false;
    std::string     fromFile          = "";
    // bool            sendUplinkDCI     = false;

    std::atomic_int* fuzzer_signal = nullptr;

    // fuzzer mutex for multi-threading
    int nof_user_dci = 0;
    int nof_user_dci_ul = 0;
    // cell configs to determine structure of DCIs
    int nofPRB = 50;
    bool isFDD = true;

    // Timer Threshold
    int waitingConnTimerThres   = 3000;
    int enInternetTimerThres    = 300;
    int querryWebTimerThres     = 6000;
    int webDelayTimerThres      = 1000;
    int ueDisconnTimerThres     = 2000;

    /* Legitimate DCIs for reference*/
    srsran_dci_dl_t dci1A_orin;
    srsran_dci_dl_t dci1_orin;
    srsran_dci_dl_t dci2A_orin;
    srsran_dci_dl_t dci2_orin;
    srsran_dci_ul_t dci0_orin;
    srsran_dci_dl_t dci1A_broadcast_orin;
    bool            has_dci1A_orin = true;
    bool            has_dci1_orin = true;
    bool            has_dci2A_orin = true;
    bool            has_dci2_orin = true;
    bool            has_dci0_orin = true;
    bool            has_dci1A_broadcast_orin = true;

    std::string     dci1A_file = "../config/dci1A_.txt";
    std::string     dci1_file = "../config/dci1_.txt";
    std::string     dci2A_file = "../config/dci2A_.txt";
    std::string     dci2_file = "../config/dci2_.txt";
    std::string     dci0_file = "../config/dci0_.txt";
    std::string     dci1A_broadcast_file = "../config/dci1A_broadcast_.txt";

    // reference allocation
    srsran_ra_type0_t type0_alloc_ref;
    srsran_ra_type1_t type1_alloc_ref;
    srsran_ra_type2_t type2_alloc_ref;

};

}
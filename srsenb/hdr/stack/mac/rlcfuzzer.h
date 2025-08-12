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

#include "fuzzer_base.h"


namespace srsenb {
    
static const std::string rlcPDUTypeStr[8] = {"UM1", "UM2", "AM1", "AM2", "Status", "AMS1", "AMS2", "Unknown"};


struct rlcStatusChunk_t
{
    bool E1 = 0; // 1 bit
    bool E2 = 0; // 1 bit
    uint16_t nackSN = 0; // 10 or 16 bits
    uint16_t soStart = 0; // 15 bits or 16 bits
    uint16_t soEnd = 0; // 15 bits or 16 bits
};

struct rlcStatusPdu_t
{
  bool DC = 0;        // this decides Control/Data PDU, 1bit
  uint8_t cpt = 0;    // 3 bits
  uint16_t ackSN = 0; // 10 or 16 bits
  bool E1_0 = 0;      // 1 bit
  uint16_t nackSN = 0;
  uint16_t nofChunk = 0;
  int snLen = 10;
  std::vector<rlcStatusChunk_t> chunk;
};

enum macContainerType_t: uint8_t { 
  singleMAC = 0,
  ccchMAC   = 1,
  mutilMAC  = 2
};

/*  0: singleMAC: 1 mac sub-header associated with RLC PDU
*   1: ccchMAC:   CCCH MAC PDU: 1 ccch sub-header, and 1 sub-header for RLC PDU
*   2: mutilMAC:  Mutil MAC PDU: multiple sub-headers for multiple RLC PDUs
*/
struct rlcPDU_t
{
    rlcPDUType_t        type = rlcUnknown;
    uint16_t            totalByte = 0;
    int                 eIdx = 0;
    int                 lcid = 0;
    bool                countercheck = false;
    macContainerType_t  macType = singleMAC;
    bool                isAll_a = false;
    bool                isCorrectSN = false;
    rlcUMpdu_t          um;
    rlcAMpdu_t          am;
    rlcStatusPdu_t      status;
    uint8_t             rrc_reconfig_type = RLC_NORMAL; // 0: normal, 1: 16-bit SN only, 2: 15-bit LI only, 3: both 16-bit SN and 15-bit LI
    rlcPDU_t(rlcPDUType_t typeInput = rlcUnknown) : type(typeInput), totalByte(0), eIdx(0) 
    {
        // Depending on the type, you can initialize the union here
        // But we need to know the specific type of rlcUMpdu_t and rlcAMpdu_t
        if (type == rlcUM1 || type == rlcUM2)
        {
            um = {};
        }
        else if (type == rlcAM1 || type == rlcAM2 || type == rlcAMSegment1 || type == rlcAMSegment2)
        {
            am = {};
        }
        else if (type == rlcStatus)
        {
            status = {};
        }
        else{
            um = {};
        }
    }
    // ~rlcPDU_t(){
    void print_general_info(){
        std::cout << "------------------------------------------------------------------" << "\n";
        std::cout << "[PDU] Type: " << rlcPDUTypeStr[(int)type] << " -- totalByte: " << totalByte;
        std::cout << " -- eIdx: " << eIdx;
        std::cout << " -- LCID: " << lcid;
        std::cout << " -- CorrectSN: " << isCorrectSN;
        std::cout << " -- RRCConfig: " << rrc_reconfig_type;
        std::cout << "\n";
    }
    void print_general_info_to_file(std::ofstream& file){
        if (file){
            file << "------------------------------------------------------------------" << "\n";
            file << "[PDU] Type: " << rlcPDUTypeStr[(int)type] << " -- totalByte: " << totalByte;
            file << " -- eIdx: " << eIdx;
            file << " -- LCID: " << lcid;
            file << " -- CorrectSN: " << isCorrectSN;
            file << " -- RRCConfig: " << rrc_reconfig_type;
            file << "\n";
        }
    }
    std::string get_general_info_string(){
        std::string info;
        info += "[PDU] Type: " + rlcPDUTypeStr[(int)type];
        info += " -- LCID: " + std::to_string(lcid);
        info += " -- CorrectSN: " + std::to_string(isCorrectSN);
        info += " -- RRCConfig: " + std::to_string(rrc_reconfig_type);
        info += " -- totalByte: " + std::to_string(totalByte);
        info += " -- eIdx: " + std::to_string(eIdx);
        return info;
    }
};

struct rlcHeaderResult_t{
    int nofByte = 0;
    std::vector<uint8_t> pattern;
};

rlcHeaderResult_t generateUM1_1Byte(bool R1, bool R2, bool R3, int FI, int E, int SN, int snLen);
rlcHeaderResult_t generateUM1header(int snLen, bool R1, bool R2, bool R3, int FI, int E, int SN);
rlcHeaderResult_t generateUM2header(int snLen, int eIdx, bool R1, bool R2, bool R3, int FI, int E, int SN, int nofChunk, std::vector<rlcChunk_t>& chunk);
rlcHeaderResult_t generateAM1_1Byte(bool DC, bool RF, bool P, int FI, int E, int SN);
rlcHeaderResult_t generateAM1_1Byte_16bitSN_segment(bool DC, bool RF, bool P, int FI, int E, bool lfs);
rlcHeaderResult_t generateAM1_1Byte_16sn(bool DC, bool RF, bool P, int FI, int E, int SN);
rlcHeaderResult_t generateAM1header(int snLen, bool DC, bool RF, bool P, int FI, int E, int SN);
rlcHeaderResult_t generateAM2header(int snLen, int liLen, int eIdx, bool DC, bool RF, bool P, int FI, int E, int SN, int nofChunk, std::vector<rlcChunk_t>& chunk);
rlcHeaderResult_t generateStatusPDU(int snLen, int eIdx, int cpt, int ackSN, int E1_0, int nackSN, int nofChunk, std::vector<rlcStatusChunk_t>& chunk, int actualLen);

class rlcFuzzer_t: public FuzzerBase_t
{
public:
    rlcFuzzer_t();
    ~rlcFuzzer_t();
    // void set_fuzzing_config(LLState_t targetState, bool verifyingMode, int startIdx) override final;
    void resetIndex();

    int  getFixedHeaderSize(rlcPDUType_t type, int snLen);
    int  calTotalByte(rlcPDU_t& pdu);
    // void printrlcPDU(rlcPDU_t& pdu);
    // void mutateGeneralrlcCE(rlcPDU_t& sket, int ceSize, int ceIdx, std::vector<rlcPDU_t>& db);
    // void mutateRecommendedBitRate(rlcPDU_t& sket, int ceIdx, std::vector<rlcPDU_t>& db);
    // void recursiveMutateSubHeaFormatLCID(int currentSubHeader, 
    //                                     int nofSubHea, 
    //                                     rlcPDU_t& tempPDU,
    //                                     std::vector<rlcPDU_t>& tempDB);
    // void mutateN(int nofSubHea); // mutate packet with N subheaders
    void generate_initial_um1_packet(int snLen, rlcPDU_t& pdu, uint8_t config_type);
    void generate_initial_um2_packet(int snLen, rlcPDU_t& pdu, uint8_t config_type, int nofChunk);
    void generate_initial_am1_packet(int snLen, rlcPDU_t& pdu, uint8_t config_type, bool isSegment);
    void generate_initial_am2_packet(int snLen, int liLen, rlcPDU_t& pdu, uint8_t config_type, int nofChunk, bool isSegment);
    void mutateUM1_sn10(int snLen, std::vector<rlcPDU_t>& db, int lcid);
    void mutateUM2_sn10(int snLen, int nofChunk,std::vector<rlcPDU_t>& db, int lcid);
    void mutateUM1_sn5 (int snLen, std::vector<rlcPDU_t>& db, int lcid);
    void mutateUM2_sn5 (int snLen, int nofChunk , std::vector<rlcPDU_t>& db, int lcid);
    void mutateAM1(int snLen, std::vector<rlcPDU_t>& db, int lcid);
    void mutateAM1_16bitSN(int snLen, std::vector<rlcPDU_t>& db, int lcid);
    void mutateAM2(int snLen, int liLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid);
    void mutateAM2_15bitLI(int snLen, int liLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid);
    void mutateAM1_segment(int snLen, std::vector<rlcPDU_t>& db, int lcid);
    void mutateAM1_segment_16bitSN(int snLen, std::vector<rlcPDU_t>& db, int lcid);
    void mutateAM2_segment(int snLen, int liLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid);
    void mutateAM2_segment_16bitSN(int snLen, int liLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid);
    void mutateStatusPDU_AM(int snLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid);


    void generate_test_cases() override final;
    int  check_rrc_reconfig_type() override final; //  {return (int)curTestCase.rrc_reconfig_type;}
    int  get_total_byte_cur_testcase() override final { return 0;} // does not need for RLC (manual DCI in MAC test cases)
    bool get_manual_dci() override final { return false; } // does not need for RLC

    void saveCrashtoFile(int oracle) override final;
    void logCrash();
    

    LLState_t       getFuzzingState()   { return fuzzingState; }
    rlcPDU_t        getCurTestCase();
    // int             get_cur_testcase_idx(LLState_t, bool) override final;
    int             get_total_idx(LLState_t, bool) override final;
    int             get_injecting_length() override final;
    int             get_injecting_lcid() override final;
    int             get_nof_injecting_rar() override final{ return 0; } // does not need for RLC
    void            update_rlc_sequence_number(uint16_t lcid, uint16_t sn) override final;
    std::string     get_cur_testcase_info() override final{
        return curTestCase.get_general_info_string();
    }

    void send_rar_test_case(int nofGrant, int tti_tx_dl, uint8_t *payload, int len) override final {} // does not need for RLC
    void send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen) override final;
    void generatePDU(rlcPDU_t& testCase, uint8_t* packet, int rlcIdx);

    void writeTCtoFile(std::ofstream& file, rlcPDU_t& pdu); //write test case to file
    void readTCfromFile(const std::string& filename); //read test case from file

    void setCellConfig(int nofPRB_, bool isFDD) override final {} // does not need for RLC
    bool send_RAR_DCI(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t &target_dci) override final {return false;} // does not need for MAC
    bool send_dl_dci_testcase(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci) override final {return false;}
    bool send_ul_dci_testcase(int tti_tx_ul, uint16_t rnti, srsran_dci_ul_t &orin_dci, srsran_dci_ul_t& target_dci) override final {return false;}
    void save_orin_dl_dci_for_reference(srsran_dci_dl_t source) override final {}
    void save_orin_ul_dci_for_reference(srsran_dci_ul_t source) override final {}
    // bool getSendUplinkDCI() override final;
    int  get_total_idx_phy_ul(LLState_t, bool) override final {return 0;}
    void resize_crash_log_buffer() override final{
        crashBuffer.resize(nof_test_cases_per_ss);
    }

  private:
    int                     curTTI;
    std::vector<int>        snList5bit;
    std::vector<int>        snList10bit;
    std::vector<int>        snList16bit;
    std::vector<int>        LI_List11bit;
    std::vector<int>        LI_List15bit;
    bool                    maxL = false;
    rlcPDU_t                curTestCase;
    std::vector<rlcPDU_t>   testcaseDB[7];
    std::vector<rlcPDU_t>   verifyDB[7]; // state 2 idx 2, ...

    RingBuffer<rlcPDU_t, 5> crashBuffer;
    RingBuffer<rlcPDU_t, 1> verifiedcrashBuffer[7];
    RingBuffer<int, 5>      recent_testcases[7]; // index of recent test cases when crash happens| state 2: 2, ...

    int                     verifiedTime = 4;
    std::ofstream           verifiedCrash;
    std::string             verifiedCrashFilename = "verifiedCrash.txt";

    /* Std file to write test case to file*/
    std::ofstream           tcFile;
    std::string             tcFilename = "tc.txt";
    std::ofstream           terminalLog;
    std::string             terminalFilename = "terminalLog.txt";

    // sequence number
    std::map<uint16_t, uint16_t> rlcSNmap;

    /* main configs*/
    bool                    state234Enable[7] = {false, false, false, false, false, true, false};  // in state 234, enable a single or multiple states
    LLState_t               verifyingState = {state4};     // should be state 2/3/4/5
    std::string             fromFile = "verifiedCrash1625.txt";

    std::vector<rlcPDU_t>   lv1PDUtemp;
    std::vector<rlcPDU_t>   lv2PDUtemp;
    std::vector<rlcPDU_t>   lv3PDUtemp;
    std::vector<rlcPDU_t>   lv4PDUtemp;
};

}
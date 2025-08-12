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

#include "srsenb/hdr/stack/mac/fuzzer_base.h"

namespace srsenb {

enum pdcpPDUType_t: int
{
    pdcpData          = -1, // DC = 1
    pdcpStatus        =  0, // DC = 0; pdu type = 0
    pdcpROHCfeedback  =  1, // DC = 0; pdu type = 1
    pdcpLWAstatus     =  2, // DC = 0; pdu type = 2
    pdcpLWAendmarker  =  3, // DC = 0; pdu type = 3
    pdcpUDCfeedback   =  4, // DC = 0; pdu type = 4
    pdcpEHCfeedback   =  5, // DC = 0; pdu type = 5
    pdcpReserved      =  6, // DC = 0; pdu type = reserved
    pdcpUnknown
};

static std::map<int, std::string> pdcpPDUTypeStr = {
    {pdcpData, "DataPDU"},
    {pdcpStatus, "StatusPDU"},
    {pdcpROHCfeedback, "ROHCFeedback"},
    {pdcpLWAstatus, "LWAStatus"},
    {pdcpLWAendmarker, "LWAEndMkr"},
    {pdcpUDCfeedback, "UDCFBk"},
    {pdcpEHCfeedback, "EHCFBk"},
    {pdcpReserved, "Reserved"},
    {pdcpUnknown, "Unknown"}
};

struct pdcpROHCheader_t{
  bool null = false;
};

struct pdcpDataPDU_t
{
    bool isROHC = false;
    pdcpROHCheader_t rohcHeader;
    bool isSRB = false;
    uint8_t snLen = 0;
    const bool DC = 1;
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    bool R4 = 0;
    bool P = 0;
    uint32_t SN = 0;
    uint16_t datasize = 0;
    uint32_t mac = 0;
    bool isWrongMAC = false;
    // define operator=
    pdcpDataPDU_t& operator=(const pdcpDataPDU_t& other)
    {
        isROHC = other.isROHC;
        rohcHeader = other.rohcHeader;
        isSRB = other.isSRB;
        snLen = other.snLen;
        // DC = other.DC;
        R1 = other.R1;
        R2 = other.R2;
        R3 = other.R3;
        SN = other.SN;
        datasize = other.datasize;
        mac = other.mac;
        isWrongMAC = other.isWrongMAC;
        return *this;
    }
};

struct pdcpStatusPDU_t
{
    const bool DC = 0;
    const uint8_t pduType = 0;
    uint8_t snLen = 12;
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    bool R4 = 0;
    bool R5 = 0;
    uint32_t FMS = 0;
    uint16_t nofBitmap = 0;
    std::vector<uint8_t> bitmap;
    // define operator=
    pdcpStatusPDU_t& operator=(const pdcpStatusPDU_t& other)
    {
        snLen = other.snLen;
        // DC = other.DC;
        R1 = other.R1;
        R2 = other.R2;
        R3 = other.R3;
        R4 = other.R4;
        R5 = other.R5;
        FMS = other.FMS;
        nofBitmap = other.nofBitmap;
        bitmap = other.bitmap;
        return *this;
    }
};

struct pdcpROHCfeedbackPDU_t
{
    const bool DC = 0;
    const uint8_t pduType = 1;
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    bool R4 = 0;
    uint16_t nofByte = 0;
    std::vector<uint8_t> feedback; 
    // define operator=
    pdcpROHCfeedbackPDU_t& operator=(const pdcpROHCfeedbackPDU_t& other)
    {
        // DC = other.DC;
        R1 = other.R1;
        R2 = other.R2;
        R3 = other.R3;
        R4 = other.R4;
        nofByte = other.nofByte;
        feedback = other.feedback;
        return *this;
    }
};

struct pdcpLWAstatusPDU_t
{
    const bool DC = 0;
    const uint8_t pduType = 2;
    uint8_t snLen = 12;
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    bool R4 = 0;
    bool R5 = 0;
    bool R6 = 0;
    uint32_t FMS = 0;
    uint32_t HRW = 0;
    uint32_t NMP = 0;
    pdcpLWAstatusPDU_t& operator=(const pdcpLWAstatusPDU_t& other)
    {
        // DC = other.DC;
        snLen = other.snLen;
        R1 = other.R1;
        R2 = other.R2;
        R3 = other.R3;
        R4 = other.R4;
        R5 = other.R5;
        R6 = other.R6;
        FMS = other.FMS;
        HRW = other.HRW;
        NMP = other.NMP;
        return *this;
    }
};

struct pdcpLWAendmarkerPDU_t
{
    const bool DC = 0;
    const uint8_t pduType = 3;
    uint8_t snLen = 12;
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    bool R4 = 0;
    uint32_t LSN = 0;
    // define operator=
    pdcpLWAendmarkerPDU_t& operator=(const pdcpLWAendmarkerPDU_t& other)
    {
        // DC = other.DC;
        snLen = other.snLen;
        R1 = other.R1;
        R2 = other.R2;
        R3 = other.R3;
        R4 = other.R4;
        LSN = other.LSN;
        return *this;
    }
};

struct pdcpUDCfeedbackPDU_t
{
    const bool DC = 0;
    const uint8_t pduType = 4;
    bool FE = 0;
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    // define operator=
    pdcpUDCfeedbackPDU_t& operator=(const pdcpUDCfeedbackPDU_t& other)
    {
        // DC = other.DC;
        FE = other.FE;
        R1 = other.R1;
        R2 = other.R2;
        R3 = other.R3;
        return *this;
    }
};

struct pdcpECHfeedbackPDU_t
{
    const bool DC = 0;
    const uint8_t pduType = 4;
    bool FE = 0;
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    bool R4 = 0;
    uint16_t nofBytes = 0;
    std::vector<uint8_t> feedback;
    // define operator=
    pdcpECHfeedbackPDU_t& operator=(const pdcpECHfeedbackPDU_t& other)
    {
        // DC = other.DC;
        FE = other.FE;
        R1 = other.R1;
        R2 = other.R2;
        R3 = other.R3;
        R4 = other.R4;
        nofBytes = other.nofBytes;
        feedback = other.feedback;
        return *this;
    }
};

struct pdcpReservedPDU_t
{
    const bool DC = 0;
    uint8_t pduType = 0;
    uint8_t snLen = 12;
    bool R1 = 0;
    bool R2 = 0;
    bool R3 = 0;
    bool R4 = 0;
    std::vector<uint8_t> others; // other bytes following
    // define operator=
    pdcpReservedPDU_t& operator=(const pdcpReservedPDU_t& other)
    {
        snLen = other.snLen;
        pduType = other.pduType;
        R1 = other.R1;
        R2 = other.R2;
        R3 = other.R3;
        R4 = other.R4;
        others = other.others;
        return *this;
    }
};


struct pdcpPDU_t
{
  pdcpPDUType_t       type    = pdcpUnknown;
  rlcPDUType_t        rlcType = rlcUnknown; // should be UM1 or AM1
  uint16_t            totalByte = 0;
  int                 eIdx = 0;
  int                 lcid = 0;
  int                 rlcSN = 0;
  uint8_t             rrc_reconfig_type = PDCP_NORMAL;
  std::shared_ptr<pdcpDataPDU_t>          data;
  std::shared_ptr<pdcpStatusPDU_t>        status;
  std::shared_ptr<pdcpROHCfeedbackPDU_t>  rohcFeedback;
  std::shared_ptr<pdcpLWAstatusPDU_t>     lwaStatus;
  std::shared_ptr<pdcpLWAendmarkerPDU_t>  lwaEndmarker;
  std::shared_ptr<pdcpUDCfeedbackPDU_t>   udcFeedback;
  std::shared_ptr<pdcpECHfeedbackPDU_t>   echFeedback;
  std::shared_ptr<pdcpReservedPDU_t>      reserved;
  // pdcpPDUunion_t      pdu;
  pdcpPDU_t(pdcpPDUType_t typeInput = pdcpUnknown) : type(typeInput), totalByte(0), eIdx(0), rrc_reconfig_type(0)
  {
    // Depending on the type, you can initialize the union here
    // But we need to know the specific type of pdcpPDU_t
    if (type == pdcpData)
    {
        data = std::make_shared<pdcpDataPDU_t>();
    }
    else if (type == pdcpStatus)
    {
        status = std::make_shared<pdcpStatusPDU_t>();
    }
    else if (type == pdcpROHCfeedback)
    {
        rohcFeedback = std::make_shared<pdcpROHCfeedbackPDU_t>();
    }
    else if (type == pdcpLWAstatus)
    {
        lwaStatus = std::make_shared<pdcpLWAstatusPDU_t>();
    }
    else if (type == pdcpLWAendmarker)
    {
        lwaEndmarker = std::make_shared<pdcpLWAendmarkerPDU_t>();
    }
    else if (type == pdcpUDCfeedback)
    {
        udcFeedback = std::make_shared<pdcpUDCfeedbackPDU_t>();
    }
    else if (type == pdcpEHCfeedback)
    {
        echFeedback = std::make_shared<pdcpECHfeedbackPDU_t>();
    }
    else if(type == pdcpReserved)
    {
        reserved = std::make_shared<pdcpReservedPDU_t>();
    }
    else{
        data = std::make_shared<pdcpDataPDU_t>();
    }
  }
  // define operator=
  pdcpPDU_t& operator=(const pdcpPDU_t& other)
  {
    type = other.type;
    rlcType = other.rlcType;
    totalByte = other.totalByte;
    eIdx = other.eIdx;
    lcid = other.lcid;
    rlcSN = other.rlcSN;
    rrc_reconfig_type = other.rrc_reconfig_type;
    if (type == pdcpData)
    {
        data = std::make_shared<pdcpDataPDU_t>(*other.data);
    }
    else if (type == pdcpStatus)
    {
        status = std::make_shared<pdcpStatusPDU_t>(*other.status);
    }
    else if (type == pdcpROHCfeedback)
    {
        rohcFeedback = std::make_shared<pdcpROHCfeedbackPDU_t>(*other.rohcFeedback);
    }
    else if (type == pdcpLWAstatus)
    {
        lwaStatus = std::make_shared<pdcpLWAstatusPDU_t>(*other.lwaStatus);
    }
    else if (type == pdcpLWAendmarker)
    {
        lwaEndmarker = std::make_shared<pdcpLWAendmarkerPDU_t>(*other.lwaEndmarker);
    }
    else if (type == pdcpUDCfeedback)
    {
        udcFeedback = std::make_shared<pdcpUDCfeedbackPDU_t>(*other.udcFeedback);
    }
    else if (type == pdcpEHCfeedback)
    {
        echFeedback = std::make_shared<pdcpECHfeedbackPDU_t>(*other.echFeedback);
    }else if (type == pdcpReserved)
    {
        reserved = std::make_shared<pdcpReservedPDU_t>(*other.reserved);
    }
    return *this;
  }

  void print_general_info_to_file(std::ofstream& file){
    if (file){
        file << "------------------------------------------------------------------" << "\n";
        file << "[PDU] Type: " << pdcpPDUTypeStr[(int)type] << " -- totalByte: " << totalByte;
        file << " -- eIdx: " << eIdx;
        file << " -- LCID: " << lcid;
        file << " -- rlcSN: " << rlcSN;
        file << " -- RRCConfig: " << rrc_reconfig_type;
        file << "\n";
    }
  }
  std::string get_general_info_string(){
    std::string info;
    info += "[PDU] Type: " + pdcpPDUTypeStr[(int)type];
    info += " -- LCID: " + std::to_string(lcid);
    info += " -- rlcSN: " + std::to_string(rlcSN);
    info += " -- RRCConfig: " + std::to_string(rrc_reconfig_type);
    info += " -- totalByte: " + std::to_string(totalByte);
    info += " -- eIdx: " + std::to_string(eIdx);
    return info;
  }
};

struct pdcpHeaderResult_t{
    int nofByte = 0;
    std::vector<uint8_t> pattern;
};

class pdcpFuzzer_t: public FuzzerBase_t
{
public:
    pdcpFuzzer_t();
    ~pdcpFuzzer_t();
    // void set_fuzzing_config(LLState_t targetState, bool verifyingMode, int startIdx) override final;
    void resetIndex();

    void generate_test_cases() override final; 
    // void switchState() override final;
    int  get_total_byte_cur_testcase() override final { return 0;} // does not need for PDCP
    bool get_manual_dci() override final { return false; } // does not need for PDCP
    std::string get_cur_testcase_info() override final{
      return curTestCase.get_general_info_string();
    }

    void saveCrashtoFile(int oracle) override final;
    void logCrash();
    
    int getFixedHeaderSize(pdcpPDUType_t type, bool isSRB, int snLen);
    int calTotalByte(pdcpPDU_t& pdu);

    // functions to generate initial packets
    void generate_initial_pdcp_data_pdu_srb(pdcpPDU_t& initial_pdu, int snLen);
    void generate_initial_pdcp_data_pdu_drb(pdcpPDU_t& initial_pdu, int snLen);
    void generate_initial_pdcp_status_pdu(pdcpPDU_t& initial_pdu, int snLen);
    void generate_initial_pdcp_lwa_status_pdu(pdcpPDU_t& initial_pdu, int snLen);
    void generate_initial_pdcp_lwa_endmarker_pdu(pdcpPDU_t& initial_pdu, int snLen);
    
    void mutatePDCPDataPDUSRB(std::vector<pdcpPDU_t>& pduDB, int lcid);
    void mutatePDCPDataPDUDRB_12bitSN(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutatePDCPDataPDUDRB_7bitSN(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutatePDCPDataPDUDRB_15bitSN(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutatePDCPDataPDUDRB_18bitSN(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);

    void mutateROHCFeedback(std::vector<pdcpPDU_t>& pduDB, int lcid);
    void recursiveBitmapMutation(int depth, int maxDepth, std::vector<uint8_t>& bitmapList, pdcpPDU_t& pdu, std::vector<pdcpPDU_t>& pduDB);
    void mutatePdcpStatusPDU_12bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutatePdcpStatusPDU_15bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutatePdcpStatusPDU_18bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void recursive_FSM_mutation(int depth, int maxDepth, std::vector<int>& snLenList, pdcpPDU_t& pdu, std::vector<pdcpPDU_t>& pduDB);
    void mutateLWAStatus_12bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutateLWAStatus_15bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutateLWAStatus_18bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);    
    void mutateLWASEndMarker_12bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutateLWASEndMarker_15bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);
    void mutateLWASEndMarker_18bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen);

    void mutateUDCFeedback(std::vector<pdcpPDU_t>& pduDB, int lcid);
    void mutateEHCFeedback(std::vector<pdcpPDU_t>& pduDB, int lcid);
    void mutatePDCPReserved(std::vector<pdcpPDU_t>& pduDB, int lcid);

    // int  get_cur_testcase_idx(LLState_t, bool) override final;
    int  get_total_idx(LLState_t, bool) override final;
    int  get_injecting_length() override final;
    int  get_injecting_lcid() override final;
    int  get_nof_injecting_rar() override final{ return 0; } // does not need for PDCP
    
    void update_rlc_sequence_number(uint16_t lcid, uint16_t sn) override final;
    int  check_rrc_reconfig_type() override final; // {return (int)curTestCase.rrc_reconfig_type;}

    pdcpPDU_t getCurTestCase();
    void send_rar_test_case(int nofGrant, int tti_tx_dl, uint8_t *payload, int len) override final {} // does not need for PDCP
    void send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen) override final;
    
    pdcpHeaderResult_t generatePdcpDataPDU_SRB(pdcpDataPDU_t& dataSRB);
    pdcpHeaderResult_t generatePdcpDataPDU_DRB(pdcpDataPDU_t& dataDRB, int snLen, int eIdx);
    pdcpHeaderResult_t generateROHCFeedback(pdcpROHCfeedbackPDU_t& rohc, int eIdx);
    pdcpHeaderResult_t generatePdcpStatus(pdcpStatusPDU_t& status, int eIdx);
    pdcpHeaderResult_t generatePdcpStatus(pdcpLWAstatusPDU_t& lwaStatus, int eIdx);
    pdcpHeaderResult_t generateLWAStatus(pdcpLWAstatusPDU_t& lwaStatus, int eIdx);
    pdcpHeaderResult_t generateLWAEndMarker(pdcpLWAendmarkerPDU_t& lwaEndMarker, int eIdx);
    pdcpHeaderResult_t generateUDCFeedback(pdcpUDCfeedbackPDU_t& udcFeedback, int eIdx, int totalByte);
    pdcpHeaderResult_t generateEHCFeedback(pdcpECHfeedbackPDU_t& ehcFeedback, int eIdx, int totalByte);
    pdcpHeaderResult_t generateReservedPDU(pdcpReservedPDU_t& reservedPDU, int eIdx, int totalByte);
    void generatePDU(pdcpPDU_t& testCase, uint8_t* packet, int pdcpIdx, int actualLen);

    void writeTCtoFile(std::ofstream& file, pdcpPDU_t& pdu); //write test case to file
    void readTCfromFile(const std::string& filename); //read test case from file

    std::string getPDUTypeString(pdcpPDUType_t& type);
    void        printPDUtestcase(pdcpPDU_t& pdu, int tti, int actualLen);
    void        print_test_case_to_file(pdcpPDU_t& pdu, std::ofstream& file);

    void setCellConfig(int nofPRB_, bool isFDD) override final {} // does not need for PDCP
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
    int                            curTTI;
    // LLState_t                      fuzzingState = {startUp};       // there are 5 state
    pdcpPDU_t                      curTestCase;
    LLState_t                      curRNTIState = {stateUnknown};
    // int                            idx[10] = {0}; // idx[1]: test case index for state 1, ...

    std::vector<int>               rList;
    std::vector<int>               snList5bit;
    std::vector<int>               snList12bit;
    std::vector<int>               snList7bit;
    std::vector<int>               snList15bit;
    std::vector<int>               snList18bit;
    std::vector<pdcpPDU_t>         testcaseDB[7];
    std::vector<pdcpPDU_t>         verifyDB[7]; // state 2 idx 2, ...

    std::ofstream               verifiedCrash;
    std::string                 verifiedCrashFilename = "verifiedCrash.txt";
    RingBuffer<pdcpPDU_t, 5>    crashBuffer; // state 2: 2, ...
    RingBuffer<pdcpPDU_t, 1 >   verifiedcrashBuffer[7];
    RingBuffer<int, 5>      recent_testcases[7]; // index of recent test cases when crash happens| state 2: 2, ...

    /* Std file to write test case to file*/
    std::ofstream               tcFile;
    std::string                 tcFilename = "tc.txt";
    std::ofstream               terminalLog;
    std::string                 terminalFilename = "terminalLog.txt";

    // sequence number
    std::map<uint16_t, uint16_t> rlcSNmap;

    /* main configs*/
    // int                         startIdx = 0;                   // set start index if previous section was terminated
    bool                        state234Enable[7] = {false, false, false, false, false, true, false};  // in state 234, enable a single or multiple states
    // bool                        readFromFileMode = false;
    std::string                 fromFile = "";
    bool                        maxL = true;
};

}
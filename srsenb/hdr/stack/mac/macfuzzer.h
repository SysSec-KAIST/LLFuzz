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

#include "srsenb/hdr/stack/mac/fuzzer_base.h"

namespace srsenb {

const std::vector<std::string> headerTypeStr = {"A", "B", "C", "D", "Ae", "Be", "Ce", "De", "none"};
static std::vector<std::string> ce_name_str;

struct macSubHeader_t{
  macSubHeaderType_t type = none;
  bool  isLast    = false;
  bool  isCE      = false;
  bool  cePayload = false;
  bool  hasID     = false;
  bool  isWrongID = false;
  bool  hasL      = false;
  bool  R1e       = false; // for typeAe, typeBe, typeCe, typeDe
  bool  R2e       = false; // for typeAe, typeBe, typeCe, typeDe
  uint8_t   eLCID = 0;     // for typeAe, typeBe, typeCe, typeDe
  uint8_t   headerSize = 0;
  uint8_t   R         = 0;
  uint8_t   F2        = 0;
  uint8_t   E         = 0;
  uint8_t   lcid      = 0;
  uint8_t   F         = 0;
  uint16_t  L         = 0;
  bool operator==(const macSubHeader_t& rhs) {
    // Check if the fields are equal.
    return type == rhs.type &&
          isLast == rhs.isLast &&
          isCE == rhs.isCE &&
          cePayload == rhs.cePayload &&
          hasID == rhs.hasID &&
          isWrongID == rhs.isWrongID &&
          hasL == rhs.hasL &&
          headerSize == rhs.headerSize &&
          R == rhs.R &&
          F2 == rhs.F2 &&
          E == rhs.E &&
          lcid == rhs.lcid &&
          F == rhs.F &&
          L == rhs.L;
  }
  void print() {
    std::cout << "[SuH] Type: " << std::setw(2) << headerTypeStr[type];
    std::cout << " -- LCID: " << std::setw(3) << (int)lcid;
    if (type >= typeAe){
      std::cout << " -- eLCID: " << std::setw(4) << (int)eLCID;
      std::cout << " -- R1e: " << std::setw(1) << (int)R1e;
      std::cout << " -- R2e: " << std::setw(1) << (int)R2e;
    }
    std::cout << " -- R: " << std::setw(1) << (int)R;
    std::cout << " -- F2: " << std::setw(1) << (int)F2;
    std::cout << " -- F: " << std::setw(1) << (int)F;
    std::cout << " -- L: " << std::setw(4) << (int)L;
    std::cout << " -- E: " << std::setw(1) << (int)E;
    if (lcid >= 17){
      std::cout << " -- " << ce_name_str[lcid];
    }
    std::cout << "\n";
  }
  void print_to_file(std::ofstream& file) {
    if (file.is_open()){
      // same as print() but for file and no color
      file << "[SuH] Type: " << std::setw(2) << headerTypeStr[type];
      file << " -- LCID: " << std::setw(3) << (int)lcid;
      if (type >= typeAe){
        file << " -- eLCID: " << std::setw(4) << (int)eLCID;
        file << " -- R1e: " << std::setw(1) << (int)R1e;
        file << " -- R2e: " << std::setw(1) << (int)R2e;
      }
      file << " -- R: " << std::setw(1) << (int)R;
      file << " -- F2: " << std::setw(1) << (int)F2;
      file << " -- F: " << std::setw(1) << (int)F;
      file << " -- L: " << std::setw(4) << (int)L;
      file << " -- E: " << std::setw(1) << (int)E;
      if (lcid >= 17){
        file << " -- " << ce_name_str[lcid];
      }
      file << "\n";
    }
  }
};

struct macSubPayload_t{
  int                       size = 0;
  bool                      mutatingCE = false;
  int                       lcidCE = 0;
  general_MAC_CE_t          general_ce = {0};     // 
  contention_resl_CE_t      contention_ce = {0};  // 
  timing_advance_CE_t       timing_ce = {0};      // lcid = 29
  recommended_bitrate_CE_t  bitrate_ce  = {0};    // lcid = 22
  uint8_t payload[6] = {0}; // max size of mac ce is 6 bytes
  bool operator==(const macSubPayload_t& rhs){
    return (size == rhs.size);
  }
  void print() {
    int width = (size < 100)? 2: 4;
    std::cout << "[SuP] Size: " << std::setw(width) << size;
    if (mutatingCE){
      std::cout << " -- LCID_CE: " << std::setw(3) << lcidCE;
      if (lcidCE == 22){
        bitrate_ce.print();
      }else if (lcidCE == 28){
        contention_ce.print();
      }else if (lcidCE == 29){
        timing_ce.print();
      }else{
        general_ce.print();
      }
    }
    std::cout << "\n";
  }
  void print_to_file(std::ofstream& file) {
    if (file.is_open()){
      // same as print() but for file and no color
      file << "[SuP] Size: " << std::setw(2) << size;
      if (mutatingCE){
        file << " -- LCID_CE: " << std::setw(3) << lcidCE;
        if (lcidCE == 22){
          bitrate_ce.print();
        }else if (lcidCE == 28){
          contention_ce.print();
        }else if (lcidCE == 29){
          timing_ce.print();
        }else{
          general_ce.print();
        }
      }
      file << "\n";
    }
  }
};

struct macRAR_t{
  std::vector<rarSubHeader_t> subHea;
  std::vector<rarSubPayload_t> subPay;
};

struct macPDU_t{
  uint16_t            nofSubHea = 0;
  uint16_t            orinSubH  = 0; // original number of subheaders if offset happens
  int8_t              eIdx      = 0; //expected index that make crash happen
  int8_t              orinEIdx  = 0; // only use for offset
  uint16_t            totalByte = 0;
  uint16_t            orinByte  = 0; // original total bytes if offset happens
  uint16_t            actualLen = 0; // only used for saving test case, not to generate test case
  bool                verify    = false;
  uint16_t            verifyLen = 0;
  bool                mutatingMacCE = false;
  bool                iseLCID   = false;
  bool                isMutateLastSubHea = false;
  bool                isAll_a   = false;
  bool                isManualDCI = false;
  std::vector<macSubHeader_t>  subHea;
  std::vector<macSubPayload_t> subPay;
  // for rar test cases
  macRAR_t            rar; 
  bool operator==(const macPDU_t& rhs){
    // Check if the fields are equal.
    bool ret = true;
    if (nofSubHea != rhs.nofSubHea || eIdx != rhs.eIdx || totalByte != rhs.totalByte){
      ret = false;
    }
    for(int i = 0; i < nofSubHea; i++){
      if (!(subHea[i] == rhs.subHea[i]) || !(subPay[i] == rhs.subPay[i])){
        ret = false;
      }
    }
    return ret;
  }

  void print_general_info(){
    std::cout << "------------------------------------------------------------------" << "\n";
    std::cout << "[PDU] NofSubHea: " << orinSubH << "|" << nofSubHea;
    std::cout << " -- totalByte: " << orinByte << "|" << totalByte;
    std::cout << " -- iseLCID: " << iseLCID;
    std::cout << " -- MutatingMacCE: " << mutatingMacCE; 
    std::cout << BLUE_TEXT << " -- eIdx: " << (int)orinEIdx << "|" << (int)eIdx << RESET_COLOR;
    std::cout << "\n";
  }
  void print_general_info_to_file(std::ofstream& file){
    if (file.is_open()){
      // same as print_general_info() but for file and no color
      file << "------------------------------------------------------------------" << "\n";
      file << "[PDU] NofSubHea: " << orinSubH << "|" << nofSubHea;
      file << " -- totalByte: " << orinByte << "|" << totalByte;
      file << " -- iseLCID: " << iseLCID;
      file << " -- MutatingMacCE: " << mutatingMacCE; 
      file << " -- eIdx: " << (int)orinEIdx << "|" << (int)eIdx;
      file << "\n";
    }
  }
  // build and return a string of general info
  std::string get_general_info_string(){
    std::string info;
    info += "[PDU] NofSubHea: " + std::to_string(orinSubH) + "|" + std::to_string(nofSubHea);
    info += " -- iseLCID: " + std::to_string(iseLCID) + "\n";
    info += " -- MutatingMacCE: " + std::to_string(mutatingMacCE);
    info += " -- totalByte: " + std::to_string(orinByte) + "|" + std::to_string(totalByte) ;
    info += " -- eIdx: " + std::to_string(orinEIdx) + "|" + std::to_string(eIdx);
    return info;
  }
};

struct headerResult{
  uint8_t pattern[6];
  int len = 0;
};

using payloadResult = headerResult;

void                allocVectorPDU(macPDU_t& pdu, int nofSubHea);
rarResult_t         formRarPayload(bool R, int ta, int grant, int rnti);
rarResult_t         formBiHeader  (bool E, bool R1, bool R2, int bi);
rarResult_t         formRarHeader (bool E, int pid);
int                 formSubHeaderTypeD(int R, int F2, int E, int lcID);
headerResult        formSubHeaderTypeD_eLCID(int R, int F2, int E, int lcID);
headerResult        formSubHeader(bool isLast, macSubHeaderType_t type, uint8_t R, uint8_t F2, 
                                                            uint8_t E, int lcID, int len);
headerResult        formSubHeaderFree(int eIdx, uint8_t R, uint8_t F2, uint8_t E, int lcID, 
                                                                        uint8_t F, int len);
headerResult        formSubHeader_eLCID(bool isLast, macSubHeaderType_t type, uint8_t R, uint8_t F2, 
                                                            uint8_t E, int lcID, int len);
headerResult        formSubHeaderFree_eLCID(int eIdx, uint8_t R, uint8_t F2, uint8_t E, int lcID, 
                                                                        uint8_t F, int len);
void                printPDUtestcase(macPDU_t& pdu, bool isOffset, macPDU_t &offsetPDU, int tti, int actualLen);

class macFuzzer_t: public FuzzerBase_t
{
public:
    macFuzzer_t();
    ~macFuzzer_t();
    // void set_fuzzing_config(LLState_t targetState, bool verifyingMode, int startIdx) override final;
    void resetIndex();

    void autoFillMacPDU(macPDU_t& pdu, int nofSubHea, int eIdx, std::vector<macSubHeader_t>& subHea, std::vector<macSubPayload_t>& subPay, int totalByte);
    void autoFillSubHea(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                                                          bool isWrongID, int R, int lcid, int L, int eIdx, int hIdx);
    void autoFillSubHea_boundary(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                                                          bool isWrongID, int R, int lcid, int L, int eIdx, int hIdx);
    void autoFillSubHea_1(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                                                          bool isWrongID, int R, int lcid, int L, int eIdx, int hIdx); // for testcase with 1 subheader
    void autoFillSubHea_eLCID(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                                                          int elcid, int L, int eIdx, int hIdx);
    void autoFillSubHea_eLCID_1(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                                                          int elcid, int L, int eIdx, int hIdx);
    bool checkGenEidx(macPDU_t& pdu, int eIdx);
    bool checkGenWrongID(const macPDU_t& pdu, int idIdx);
    bool check_is_CE(int lcid);
    void assign_legitimate_subheade_and_subpayload(int subHeader_idx, bool isLast, macSubHeaderType_t type, macSubHeader_t& subHea, macSubPayload_t& subPay);
    void assign_legitimate_subheade_and_subpayload_numerous_subheaders(int subHeader_idx, bool isLast, macSubHeaderType_t type, macSubHeader_t& subHea, macSubPayload_t& subPay);

    int  calTotalByte(macPDU_t& pdu);
    int  calTotalByte_eLCID(macPDU_t& pdu);
    void printMacPDU(macPDU_t& pdu);

    void mutateGeneralMacCE(macPDU_t& sket, int ceSize, int ceIdx, std::vector<macPDU_t>& db);
    void mutateContentionReslCE(macPDU_t& sket, int ceIdx, std::vector<macPDU_t>& db);
    void mutateTimingAdvanceCE(macPDU_t& sket, int ceIdx, std::vector<macPDU_t>& db);
    void mutateRecommendedBitRate(macPDU_t& sket, int ceIdx, std::vector<macPDU_t>& db);
    void recursiveMutateSubHeaFormatLCID(int currentSubHeader, 
                                        int nofSubHea, 
                                        macPDU_t& tempPDU,
                                        std::vector<macPDU_t>& tempDB);
    void recursiveMutateSubHeaFormatLCID_boundary(int currentSubHeader, 
                                        int nofSubHea, 
                                        macPDU_t& tempPDU,
                                        std::vector<macPDU_t>& tempDB);
    void recursiveMutate_eLCID(int currentSubHeader, 
                                int nofSubHea, 
                                macPDU_t& tempPDU,
                                std::vector<macSubHeaderType_t> heaTypes,
                                std::vector<macPDU_t>& tempDB);   
    void recursiveMutateLCID_given_subhea_format(int currentSubHeader, 
                                                int nofSubHea,
                                                std::vector<macSubHeaderType_t>& heaTypes,
                                                macPDU_t& tempPDU,
                                                std::vector<macPDU_t>& tempDB, int list_idx);

    void mutate_1(std::vector<macPDU_t>& db); // mutate packet with 1 subheader
    void mutate_1_new(std::vector<macPDU_t>& db, macSubHeaderType_t headerType); // mutate packet with 1 subheader with new length (DCI) consideration
    void mutate_1_new_typeD(std::vector<macPDU_t>& db); // only CE
    void mutate_1_new_typeABC(std::vector<macPDU_t>& db);
    void generate_initial_eLCID_packet(macPDU_t& initial_pdu, int nofSubHea, std::vector<macSubHeaderType_t> headerTypes, bool every_short);
    void mutate_1_eLCID_new(std::vector<macPDU_t>& db, macSubHeaderType_t headerType); // mutate packet with 1 subheader with new length (DCI) consideration
    void mutate_last_subhea(int nofSubHea, std::vector<macPDU_t>& db);
    void mutateN(int nofSubHea); // mutate packet with N subheaders
    void mutateN_boundary(int nofSubHea);

    // new function
    void mutate_packet_n_subheaders(int nof_subheaders, std::vector<macSubHeaderType_t> headerTypes, bool mutate_ce , int list_idx, std::vector<macPDU_t>& db); // 
    // generate test cases with 50 subheaders in type AA..D, BB..D, CC..D, DD..D
    void mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(int nof_subheaders, std::vector<macSubHeaderType_t> headerTypes, std::vector<macPDU_t>& db, bool is_list2);
    // generate test cases with 50 subheaders in type DAA..D
    void mutate_packet_numerous_subheader_DAAD(int nof_subheaders, std::vector<macSubHeaderType_t> headerTypes, std::vector<macPDU_t>& db); //

    void mutate_eLCID(int nofSubHea, std::vector<macSubHeaderType_t> headerTypes, std::vector<srsenb::macPDU_t>& db); // mutate packet with eLCID, only apply for a few numbers of subheaders
    void mutate_eLCID_new(int nofSubHea, std::vector<macSubHeaderType_t> headerTypes, std::vector<srsenb::macPDU_t>& db);
    void mutate_eLCID_long(int nofSubHea, std::vector<srsenb::macPDU_t>& db);

    void mutate_mac_rar_minus_eidx(macPDU_t& orin_rar, int eIdx, std::vector<macPDU_t>& db);
    void mutate_mac_rar_positive_eidx(macPDU_t& orin_rar, int eIdx, std::vector<macPDU_t>& db);
    void mutate_rar_subheader(macPDU_t& macpdu, int subheader_idx, std::vector<macPDU_t>& db);
    void mutate_rar_subpayload(macPDU_t& macpdu, int subheader_idx, std::vector<macPDU_t>& db);
    // mutate RAR packet with N subheaders, header type: 0 = BI, 1 = RAR
    void generate_initial_rar_packet(macPDU_t& initial_rar, int nof_subheaders, std::vector<bool>& rarHeaderTypes);
    void mutate_rar_n_subheaders(int nof_subheaders, std::vector<bool>& rarHeaderTypes, std::vector<macPDU_t>& db);
    void mutate_rar_numerous_subheader(int nof_subheaders, std::vector<bool>& rarHeaderTypes, std::vector<macPDU_t>& db);
    void mutate_rar_1_subheader(int nof_subheaders, std::vector<bool>& rarHeaderTypes, std::vector<macPDU_t>& db); 
    
    void load_manual_testcase();
    void initiate_mutation_values();
    void generate_test_cases() override final;
    // void switchState() override final;
    void stopFuzzing();
    
    void saveCrashtoFile(int oracle) override final;
    void update_rlc_sequence_number(uint16_t lcid, uint16_t sn) override final;
    
    
    macPDU_t getCurTestCase();
    int      get_total_idx(LLState_t, bool) override final;
    int      get_injecting_length() override final;
    int      get_injecting_lcid() override final;
    int      get_total_byte_cur_testcase() override final;
    bool     get_manual_dci() override final;
    int      get_nof_injecting_rar();
    // int      get_cur_testcase_idx(LLState_t, bool) override final;
    std::string get_cur_testcase_info() override final{
      return curTestCase.get_general_info_string();
    }

    bool check_offset_rar_testcase(macPDU_t& rar, int actualLen);
    void assemble_rar_packet(macPDU_t& rar, uint8_t* payload, int len);
    void print_rar_testcase(macPDU_t rar, bool isOffset, int actualLen);
    void send_rar_test_case(int nofGrant, int tti_tx_dl, uint8_t* payload, int len) override final;
    void send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen) override final;
    bool checkOffsetSubHea(macPDU_t &testcase, int actualLen);
    bool checkOffsetSubHea_new(macPDU_t &testcase, int actualLen);
    int  checkOffsetSubHea_eLCID(macPDU_t &testcase, int actualLen);
    int  checkOffsetSubHea_eLCID_new(macPDU_t &testcase, int actualLen);
    void generatePDU(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen);
    void generatePDU_new(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen);
    void generatePDU_eLCID(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen);
    void generatePDU_1(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen); // for testcase with 1 subheader
    void generatePDU_mutateLastSubhea(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen); // for testcase with 1 subheader

    void writeTCtoFile(std::ofstream& file, macPDU_t& pdu); //write test case to file
    void readTCfromFile(const std::string& filename); //read test case from file

    int  check_rrc_reconfig_type() override final {return 0;} // not used for MAC fuzzer
    void setCellConfig(int nofPRB_, bool isFDD) override final {} // does not need for RLC
    bool send_RAR_DCI(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t &target_dci) override final { return false;} // does not need for MAC
    bool send_dl_dci_testcase(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci) override final {return false;}
    bool send_ul_dci_testcase(int tti_tx_ul, uint16_t rnti, srsran_dci_ul_t &orin_dci, srsran_dci_ul_t& target_dci) override final {return false;}
    void save_orin_dl_dci_for_reference(srsran_dci_dl_t source) override final {}
    void save_orin_ul_dci_for_reference(srsran_dci_ul_t source) override final {}
    // bool getSendUplinkDCI() override final;
    int  get_total_idx_phy_ul(LLState_t, bool) override final {return 0;}

    bool get_is_old_device() { return is_old_device; }

    void resize_crash_log_buffer() override final{
      crashBuffer.resize(nof_test_cases_per_ss);
    }

private:
    // LLState_t                      fuzzingState = {startUp};       // there are 5 state | move to base class
    macPDU_t                       curTestCase;
    int                            rarTcIdx = 0;
    int                            tcIdx = 0;
    int                            reIdx = 0;
    bool                           is_old_device       = false; // for old device, such as samsung galaxy Note 5, andriod 7.0
    // int                            idx[10] = {0}; // idx[1]: test case index for state 1, ...

    std::map<macSubHeaderType_t, int> heaSizeMap;
    std::vector<int>              lcidNoCEList;              // except CE 0->15
    std::vector<int>              lcidNoCEList2;              // except CE 0->15
    std::vector<int>              lcidNoCEListState234;      // 0,1 for state 234
    std::vector<int>              lcidNoCEListState234Arr[2];// make 2 lists for random selection
    std::vector<int>              lcidCEList;               // only ce value, no padding
    std::vector<int>              lcidCEList2;
    std::vector<int>              lcidCEListArr[2];         // make 2 lists for random selection
    std::vector<int>              lcidCEpayloadList;
    std::map<int, int>            cePaySize;
    std::vector<macSubHeaderType_t>  typeList;           // all possible types of sub-header
    std::vector<macSubHeaderType_t>  typeListArr[2];     // make 2 lists for random selection
    std::vector<macSubHeaderType_t>  typeListArr_boundary[2];     // make 2 lists for random selection
    std::vector<macSubHeaderType_t>  typeListLast;       // all possible types of sub-header in the last position
    std::vector<int>              rList;
    std::vector<int>              lcidAllList;      // 0->31
    std::vector<int>              lcidAllList2;
    std::vector<int>              lcidAllList234;
    std::vector<int>              lcidAllList234Arr[2]; // make 2 lists for random selection
    std::vector<int>              lcidChannelList;  // only logical channels
    std::vector<int>              lcidReservedList; // only reserved values
    std::vector<bool>             idList;
    std::vector<int>              len7bitList;
    std::vector<int>              len15bitList;
    std::vector<int>              len16bitList;
    std::vector<int>              eLCIDlist;
    std::vector<int>              f2List;  
    std::map<macSubHeaderType_t, std::vector<int>> LListRef;

    std::vector<bool>             boolList;
    std::vector<int>              pidList;
    std::vector<int>              biList;
    std::vector<int>              taList;
    std::vector<int>              ulGrantList;
    std::vector<int>              tcrntiList;
    const int                     max_rar_bytes = 277;

    std::vector<macPDU_t>         lv1PDUtemp;
    std::vector<macPDU_t>         lv2PDUtemp;
    std::vector<macPDU_t>         lv3PDUtemp;
    std::vector<macPDU_t>         lv4PDUtemp;
    std::vector<macPDU_t>         testcaseDB[7];

    // std::vector<rarTestcase>      tcState1DB;
    std::vector<macPDU_t>         tcState4DB;
    std::vector<macPDU_t>         tcState234DB;
    std::vector<macPDU_t>         verifyDB[7]; // state 2 idx 2, ...
    // std::vector<rarTestcase>      rarTestcaseDB;

    int         curTTI;
    uint8_t     conResID[6] = {0};  // contention resolution id

    std::string             fromFile = "crashLogNote20U_eLCID_idx448_fixed.txt";
    int                     verifiedTime = 4;
    std::ofstream           verifiedCrash;
    std::string             logRLCackFilename = "crashLogRLCack.txt";
    std::string             verifiedCrashFilename = "verifiedCrash.txt";
    RingBuffer<macPDU_t, 5> crashBuffer; // state 2: 2, ...
    RingBuffer<macPDU_t, 1> verifiedcrashBuffer[7];
    RingBuffer<int, 5>      recent_testcases[7]; // index of recent test cases when crash happens| state 2: 2, ...
    

    /* Std file to write test case to file*/
    std::ofstream   tcFile;
    std::string     tcFilename = "tc.txt";
    std::ofstream   terminalLog;
    std::string     terminalFilename = "terminalLog.txt";
    
    
    /* Index control*/
    // int             startIdx = 0;                     // set start index if previous section was terminated
    LLState_t       verifyingState    = {state4};     // should be state 2/3/4/5
    // bool            readFromFileMode  = true;
    
    // sequence number
    std::map<uint16_t, uint16_t> rlcSNmap;

};

}

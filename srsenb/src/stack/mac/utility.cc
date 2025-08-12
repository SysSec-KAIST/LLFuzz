#include "srsenb/hdr/stack/mac/utility.h"

namespace srsenb {

bool checkTimer(fuzzingTimer_t& checkingTimer, float thresMilisecond){
    bool ret = false;
    if (checkingTimer.running){
        auto curTime = std::chrono::high_resolution_clock::now();
        auto curInterval = std::chrono::duration_cast<std::chrono::milliseconds>(curTime - checkingTimer.activeTime).count();
        if (curInterval >= thresMilisecond){ ret = true;}
    }
    return ret;
}

void stopFuzzingTimer(fuzzingTimer_t& fuzzingTimer){
    fuzzingTimer.running = false;
    // fuzzingTimer.activeTime = 0;
}

int set_non_blocking_mode(int filedes) {
    int flags;

    // Get the current file descriptor flags
    flags = fcntl(filedes, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl - get flags");
        return -1; // Return error
    }

    // Set the file descriptor's flag to non-blocking mode
    flags |= O_NONBLOCK;
    if (fcntl(filedes, F_SETFL, flags) == -1) {
        perror("fcntl - set flags");
        return -1; // Return error
    }

    return 0; // Success
}

bool checkRFLinkIssue(RingBuffer<timePoint_t, 6>& rarVector){
    bool ret = false;
    if (rarVector.size() >= 6){
        timePoint_t head = rarVector.getHead();
        timePoint_t tail = rarVector.getTail();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(tail - head).count();
        if (duration < 800 and duration >= 10){ 
          ret = true;
          std::cout << "[RF ] RFLink interval = " << duration << std::endl;
        }
    }
    return ret;
}

int getTXtti(uint rxtti){
  int ret = rxtti - 4;
  if (ret < 0){
    ret = ret + 10240;
  }
  return ret;
}

uint32_t nBitRandomGen(uint32_t n) {
    if (n == 0) {
        return 0;
    }
    
    // Generate a random number in the range [0, 2^n - 1]
    uint32_t maxValue = static_cast<uint32_t>(pow(2, n) - 1);
    uint32_t randomValue = rand() % (maxValue + 1);
    
    return randomValue;
}

pduInfo_t decodePDU(uint8_t* ptr, int len, int tti_tx_dl){
    pduInfo_t ret;
    ret.pduDecodingResult = pduUnknown;
    srsran::sch_pdu pdu(20, srslog::fetch_basic_logger("MAC"));
    pdu.init_rx(len, false);
    pdu.parse_packet(ptr);

    while (pdu.next())
    {
        if (pdu.get()->is_sdu() && pdu.get()->get_sdu_lcid() == 0)
        {
            int payload_length = pdu.get()->get_payload_size();
            uint8_t *sdu_ptr = pdu.get()->get_sdu_ptr();
            asn1::rrc::dl_ccch_msg_s  dl_ccch_msg;
            asn1::cbit_ref bref(sdu_ptr, payload_length);
            if (dl_ccch_msg.unpack(bref) == asn1::SRSASN_SUCCESS &&
                dl_ccch_msg.msg.type().value == asn1::rrc::dl_ccch_msg_type_c::types_opts::c1) {

                switch (dl_ccch_msg.msg.c1().type().value) {
                    case asn1::rrc::dl_ccch_msg_type_c::c1_c_::types::rrc_conn_setup:
                    // std::cout << "[MAC] SF: " << tti_tx_dl/10 <<":" << tti_tx_dl%10
                    // << " => Detected RRC Con Setup " << std::endl;
                    ret.pduDecodingResult = pduRRCConSet;
                    break;
                    default:
                    break;
                }
            }
        }
        else if (pdu.get()->is_sdu() && pdu.get()->get_sdu_lcid() == 1){
            int payload_length = pdu.get()->get_payload_size();
            uint8_t *sdu_ptr = pdu.get()->get_sdu_ptr() + 3;
            asn1::rrc::dl_dcch_msg_s  dl_dcch_msg;
            asn1::cbit_ref bref(sdu_ptr, payload_length);
            if (dl_dcch_msg.unpack(bref) == asn1::SRSASN_SUCCESS &&
                dl_dcch_msg.msg.type() == asn1::rrc::dl_dcch_msg_type_c::types::c1) {

                if (dl_dcch_msg.msg.c1().type() == asn1::rrc::dl_dcch_msg_type_c::c1_c_::types::rrc_conn_recfg){
                    // std::cout << "[MAC] SF: " << tti_tx_dl/10 <<":" << tti_tx_dl%10
                    // << " => Detected RRC Reconfig " << std::endl;

                    /* Decode RRC Conn Reconfig to obtain IP address of UE*/
                    asn1::rrc::rrc_conn_recfg_s mob_reconf;
                    mob_reconf = dl_dcch_msg.msg.c1().rrc_conn_recfg();
                    uint32_t nas_size = mob_reconf.crit_exts.c1().rrc_conn_recfg_r8().ded_info_nas_list[0].size(); // nas list has many nas msg
                    LIBLTE_BYTE_MSG_STRUCT nas_msg;
                    nas_msg.N_bytes = nas_size;
                    
                    if (nas_size > 10){ // only decode there is a nas message
                        /*assume that our nas message is in index 0*/
                        memcpy(nas_msg.msg, mob_reconf.crit_exts.c1().rrc_conn_recfg_r8().ded_info_nas_list[0].data(), nas_size);
                        uint8  pd           = 0;
                        uint8  msg_type     = 0;
                        liblte_mme_parse_msg_header(&nas_msg, &pd, &msg_type);
                        if (msg_type == LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT){
                            LIBLTE_MME_ATTACH_ACCEPT_MSG_STRUCT attach_accept = {};
                            LIBLTE_ERROR_ENUM err = liblte_mme_unpack_attach_accept_msg(&nas_msg, &attach_accept);
                            if (err == LIBLTE_SUCCESS){
                                LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req = {};
                                liblte_mme_unpack_activate_default_eps_bearer_context_request_msg(&attach_accept.esm_msg,
                                                                                                &act_def_eps_bearer_context_req);
                                if (LIBLTE_MME_PDN_TYPE_IPV4 == act_def_eps_bearer_context_req.pdn_addr.pdn_type) {
                                    ret.hasIP = true;
                                    for (int ip = 0; ip < 4; ip++){
                                        ret.ip[ip] = act_def_eps_bearer_context_req.pdn_addr.addr[ip];
                                    }
                                }
                                
                                if (attach_accept.guti_present){
                                    ret.mmec = attach_accept.guti.guti.mme_code;
                                    ret.m_tmsi = attach_accept.guti.guti.m_tmsi;
                                    // print m_tmsi from uint32_t to hex, add sfn and sf_idx form tti_dl
                                    // std::cout << "SF: " << tti_tx_dl/10 << ":" << tti_tx_dl%10 << " Updated m_tmsi from RRC Reconfig: 0x" 
                                    //         << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)(ret.m_tmsi >> 24)
                                    //         << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)(ret.m_tmsi >> 16)
                                    //         << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)(ret.m_tmsi >> 8)
                                    //         << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)(ret.m_tmsi & 0xFF)
                                    //         << std::dec << std::endl;
                                }
                            }
                        }
                    }
                    ret.pduDecodingResult = pduRRCReconfig;

                }
            }
        }
    }
    return ret;
}

pduInfo_t decodePDUuplink(uint8_t *pdu_ptr, int length, int tti_tx_ul)
{
    pduInfo_t ret = {};
    srsran::sch_pdu pdu(10, srslog::fetch_basic_logger("MAC"));
    pdu.init_rx(length, true);
    pdu.parse_packet(pdu_ptr);
    while (pdu.next())
    {
        if (pdu.get()->is_sdu() && pdu.get()->get_sdu_lcid() == 0)
        {
            int sdu_length = pdu.get()->get_payload_size();
            uint8_t *sdu_ptr = pdu.get()->get_sdu_ptr();
            asn1::rrc::ul_ccch_msg_s ul_ccch_msg;
            asn1::cbit_ref bref(sdu_ptr, sdu_length);
            int asn1_result = ul_ccch_msg.unpack(bref);
            if (asn1_result == asn1::SRSASN_SUCCESS && ul_ccch_msg.msg.type() == asn1::rrc::ul_ccch_msg_type_c::types_opts::c1)
            {
                if (ul_ccch_msg.msg.c1().type().value == asn1::rrc::ul_ccch_msg_type_c::c1_c_::types::rrc_conn_request)
                {
                    ret.pduDecodingResult = pduRRCConReq;
                    asn1::rrc::rrc_conn_request_s con_request = ul_ccch_msg.msg.c1().rrc_conn_request();
                    asn1::rrc::rrc_conn_request_r8_ies_s *msg_r8 = &con_request.crit_exts.rrc_conn_request_r8();
                    if (msg_r8->ue_id.type() == asn1::rrc::init_ue_id_c::types::s_tmsi)
                    {
                        ret.m_tmsi = msg_r8->ue_id.s_tmsi().m_tmsi.to_number();
                        ret.hasTMSI = true;
                    }
                    if (DEBUG_MODE)
                    {
                        // std::cout << "[MAC] Detected RRC Con Req" << std::endl;
                    }
                }
            }
        }else if (pdu.get()->is_sdu() && pdu.get()->get_sdu_lcid() == 1){
            // try to decode RRC Reconfiguration complete
            int sdu_length = pdu.get()->get_payload_size();
            uint8_t *sdu_ptr = pdu.get()->get_sdu_ptr();

            // skip rlc and pdcp header
            if (sdu_length < 8){
                ret.pduDecodingResult = pduUnknown;
                continue;
            }
            sdu_ptr += 3;
            sdu_length -= 3;

            //ignore MAC-I
            sdu_length -= 4;

            asn1::rrc::ul_dcch_msg_s ul_dcch_msg;
            asn1::cbit_ref bref(sdu_ptr, sdu_length);
            int asn1_result = ul_dcch_msg.unpack(bref);
            if (asn1_result == asn1::SRSASN_SUCCESS && ul_dcch_msg.msg.type() == asn1::rrc::ul_dcch_msg_type_c::types_opts::c1)
            {
                // Handle RRC Reconfiguration Complete message
                if (ul_dcch_msg.msg.c1().type().value == asn1::rrc::ul_dcch_msg_type_c::c1_c_::types::rrc_conn_recfg_complete)
                {
                    ret.pduDecodingResult = pduRRCReconfigComplete;
                    if (DEBUG_MODE)
                    {
                        std::cout << "[MAC] Detected RRC Reconfig Complete" << std::endl;
                    }
                }
            }
        }
    }

    return ret;
}

void print8BitBinary(uint8_t value) {
    for (int i = 7; i >= 0; i--) {
        std::cout << ((value >> i) & 0x01);
    }
    std::cout << std::endl;
}

void print8BitBinaryNoEndl(uint8_t value) {
    for (int i = 7; i >= 0; i--) {
        std::cout << ((value >> i) & 0x01);
    }
}

uint8_t modifyLCID(uint8_t original_data, int newLCID){
  int a0 = (original_data >> 7) & 0x1;
  int a1 = (original_data >> 6) & 0x1;
  int a2 = (original_data >> 5) & 0x1;

  // Create the modified_data by combining the modified bits and desired_value
  uint8_t modified_data = (a0 << 7) | (a1 << 6) | (a2 << 5) | newLCID;
  return modified_data;
}

uint8_t setReserved(uint8_t orin_data){
  uint8_t modified_data = orin_data | 0b10000000;
  return modified_data;
}

uint8_t setF2(uint8_t data) {
  // Get the mask to set the b1 bit to 1.
  uint8_t mask = 0b01000000;

  // OR the data with the mask.
  uint8_t modified_data = data | mask;

  return modified_data;
}

std::string getfromADBString(fromAdbCommand_t adbMac){
    std::string ret = "";
    switch (adbMac){
        case crashDetected:
            ret = "crashDetected";
            break;
        case recovered:
            ret = "recovered";
            break;
        case adbConfigSuccess:
            ret = "adbConfigSuccess";
            break;
        case noAction:
            ret = "noAction";
            break;
        case adbAirPlaneOn:
            ret = "adbAirPlaneOn";
            break;
        default:
            break;
    }
    return ret;
}

bool checkSendTCttiState2Decoy(int triggerTTI, int curTTI){
    bool ret  = false;
    int head = (triggerTTI + 3); // 2
    int tail = (triggerTTI + 3); // 4
    if ( head < 10240 && tail < 10240){
        if (curTTI >= head && curTTI <= tail){
            ret = true;
        }
    }else if (head < 10240 && tail > 10240){
        if (curTTI >= head || curTTI <= (tail - 10240)){
            ret = true;
        }
    }else if (head > 10240 && tail > 10240){
        if (curTTI >= (head - 10240) && curTTI <= (tail - 10240)){
            ret = true;
        }
    }   
    return ret;
}

bool checkSendTCttiState3Decoy(int triggerTTI, int curTTI){
    bool ret  = false;
    int head = (triggerTTI + 4); // 3
    int tail = (triggerTTI + 4); // 5
    if ( head < 10240 && tail < 10240){
        if (curTTI >= head && curTTI <= tail){
            ret = true;
        }
    }else if (head < 10240 && tail > 10240){
        if (curTTI >= head || curTTI <= (tail - 10240)){
            ret = true;
        }
    }else if (head > 10240 && tail > 10240){
        if (curTTI >= (head - 10240) && curTTI <= (tail - 10240)){
            ret = true;
        }
    }   
    return ret;
}


bool checkSendTCttiState2(int triggerTTI, int curTTI, int nof_test_cases_per_ss){
    bool ret  = false;
    // int head = (triggerTTI + 8); // 2
    // int tail = (triggerTTI + 8); // 4

    for (int i = 0; i < nof_test_cases_per_ss; i++){
        if (curTTI == triggerTTI + 7 + i){
            return true;
        }
    }

    // if ( head < 10240 && tail < 10240){
    //     if (curTTI >= head && curTTI <= tail){
    //         ret = true;
    //     }
    // }else if (head < 10240 && tail > 10240){
    //     if (curTTI >= head || curTTI <= (tail - 10240)){
    //         ret = true;
    //     }
    // }else if (head > 10240 && tail > 10240){
    //     if (curTTI >= (head - 10240) && curTTI <= (tail - 10240)){
    //         ret = true;
    //     }
    // }   

    return ret;
}

bool checkSendTCttiState3(int triggerTTI, int curTTI, int nof_test_cases_per_ss){
    bool ret  = false;
    // int head = (triggerTTI + 4); // 3
    // int tail = (triggerTTI + 4); // 5

    for (int i = 0; i < nof_test_cases_per_ss; i++){
        if (curTTI == triggerTTI + 25 + i){ // 25
            return true;
        }
    }

    // if ((curTTI == triggerTTI + 4) || (curTTI == triggerTTI + 5) || (curTTI == triggerTTI + 6) || (curTTI == triggerTTI + 7)|| (curTTI == triggerTTI + 8)){
    //     return true;
    // }

    // if ( head < 10240 && tail < 10240){
    //     if (curTTI >= head && curTTI <= tail){
    //         ret = true;
    //     }
    // }else if (head < 10240 && tail > 10240){
    //     if (curTTI >= head || curTTI <= (tail - 10240)){
    //         ret = true;
    //     }
    // }else if (head > 10240 && tail > 10240){
    //     if (curTTI >= (head - 10240) && curTTI <= (tail - 10240)){
    //         ret = true;
    //     }
    // }   
    return ret;
}

bool checkSendTCttiState4(int triggerTTI, int curTTI, int nof_test_cases_per_ss){
    bool ret  = false;
    // int head = (triggerTTI + 60);
    // int tail = (triggerTTI + 60); //13

    for (int i = 0; i < nof_test_cases_per_ss; i++){
        if (curTTI == triggerTTI + 40 + i){
            return true;
        }
    }

    // if ((curTTI == triggerTTI + 60) || (curTTI == triggerTTI + 61) || (curTTI == triggerTTI + 63) || (curTTI == triggerTTI + 64)){
    // if ((curTTI == triggerTTI + 30)){
    //     return true;
    // }

    // if ( head < 10240 && tail < 10240){
    //     if (curTTI >= head && curTTI <= tail){ // && (curTTI%3 == 0)
    //         ret = true;
    //     }
    // }else if (head < 10240 && tail > 10240){
    //     if ((curTTI >= head || curTTI <= (tail - 10240)) ){ //&& (curTTI%3 == 0)
    //         ret = true;
    //     }
    // }else if (head > 10240 && tail > 10240){
    //     if (curTTI >= (head - 10240) && curTTI <= (tail - 10240) ){ //&& (curTTI%3 == 0)
    //         ret = true;
    //     }
    // }   
    return ret;
}

// bool checkSendTCttiState2(int triggerTTI, int curTTI){
//     bool ret  = false;
//     int head = (triggerTTI + 2); // 2
//     int tail = (triggerTTI + 3); // 4
//     if ( head < 10240 && tail < 10240){
//         if (curTTI >= head && curTTI <= tail){
//             ret = true;
//         }
//     }else if (head < 10240 && tail > 10240){
//         if (curTTI >= head || curTTI <= (tail - 10240)){
//             ret = true;
//         }
//     }else if (head > 10240 && tail > 10240){
//         if (curTTI >= (head - 10240) && curTTI <= (tail - 10240)){
//             ret = true;
//         }
//     }   
//     return ret;
// }

// bool checkSendTCttiState3(int triggerTTI, int curTTI){
//     bool ret  = false;
//     int head = (triggerTTI + 3); // 3
//     int tail = (triggerTTI + 5); // 5
//     if ( head < 10240 && tail < 10240){
//         if (curTTI >= head && curTTI <= tail){
//             ret = true;
//         }
//     }else if (head < 10240 && tail > 10240){
//         if (curTTI >= head || curTTI <= (tail - 10240)){
//             ret = true;
//         }
//     }else if (head > 10240 && tail > 10240){
//         if (curTTI >= (head - 10240) && curTTI <= (tail - 10240)){
//             ret = true;
//         }
//     }   
//     return ret;
// }

// bool checkSendTCttiState4(int triggerTTI, int curTTI){
//     bool ret  = false;
//     int head = (triggerTTI + 2);
//     int tail = (triggerTTI + 6); //13
//     if ( head < 10240 && tail < 10240){
//         if (curTTI >= head && curTTI <= tail){
//             ret = true;
//         }
//     }else if (head < 10240 && tail > 10240){
//         if (curTTI >= head || curTTI <= (tail - 10240)){
//             ret = true;
//         }
//     }else if (head > 10240 && tail > 10240){
//         if (curTTI >= (head - 10240) && curTTI <= (tail - 10240)){
//             ret = true;
//         }
//     }   
//     return ret;
// }

// bool checkSendTCttiState4(int triggerTTI, int curTTI){
//     bool ret  = false;
//     int head = (triggerTTI + 4);
//     int tail = (triggerTTI + 16); //13
//     if ( head < 10240 && tail < 10240){
//         if (curTTI >= head && curTTI <= tail && (curTTI%3 == 0)){ // && (curTTI%3 == 0)
//             ret = true;
//         }
//     }else if (head < 10240 && tail > 10240){
//         if ((curTTI >= head || curTTI <= (tail - 10240)) && (curTTI%3 == 0)){ //&& (curTTI%3 == 0)
//             ret = true;
//         }
//     }else if (head > 10240 && tail > 10240){
//         if (curTTI >= (head - 10240) && curTTI <= (tail - 10240) && (curTTI%3 == 0)){ //&& (curTTI%3 == 0)
//             ret = true;
//         }
//     }   
//     return ret;
// }


bool checkSendTCttiState5(int triggerTTI, int curTTI){
    bool ret  = false;
    int head = (triggerTTI + 8);
    int tail = (triggerTTI + 8); //13
    if ( head < 10240 && tail < 10240){
        if (curTTI >= head && curTTI <= tail){ // && (curTTI%3 == 0)
            ret = true;
        }
    }else if (head < 10240 && tail > 10240){
        if ((curTTI >= head || curTTI <= (tail - 10240)) ){ //&& (curTTI%3 == 0)
            ret = true;
        }
    }else if (head > 10240 && tail > 10240){
        if (curTTI >= (head - 10240) && curTTI <= (tail - 10240) ){ //&& (curTTI%3 == 0)
            ret = true;
        }
    }   
    return ret;
}

bool checkSendTCttiState5Condition2(int triggerTTI, int curTTI){
    bool ret  = false;
    if (curTTI%20 == 0){
        ret = true;
    }  
    return ret;
}

bool checkSendTCttiState4VerifyMode(int triggerTTI, int curTTI){
    bool ret  = false;
    int head = (triggerTTI + 5);
    int tail = (triggerTTI + 5);
    if ( head < 10240 && tail < 10240){
        if (curTTI >= head && curTTI <= tail){
            ret = true;
        }
    }else if (head < 10240 && tail > 10240){
        if (curTTI >= head || curTTI <= (tail - 10240)){
            ret = true;
        }
    }else if (head > 10240 && tail > 10240){
        if (curTTI >= (head - 10240) && curTTI <= (tail - 10240)){
            ret = true;
        }
    }   
    return ret;
}

bool checkSendTCbyDCIState5_UL(int &nof_user_dci_ul, int reserved){
    bool ret  = false;
    if (nof_user_dci_ul >= 2){
        ret = true;
        nof_user_dci_ul = 0;
    }
    return ret;
}

int formMacSubHeaderTypeD(int R, int F2, int E, int lcID){
    return (std::pow(2,7)*R + std::pow(2, 6)*F2 + std::pow(2, 5)*E + lcID);
}
  
macHeaderResult_t formMacSubHeader(bool isLast, macSubHeaderType_t type, uint8_t R, uint8_t F2, uint8_t E, int lcID, int len){
    macHeaderResult_t result;
    if (isLast || type == typeD){ // E= 0 for the last header
        result.len = 1;
        result.pattern[0] = formMacSubHeaderTypeD(R, F2, E, lcID);
    }else{
        result.pattern[0] = formMacSubHeaderTypeD(R, F2, E, lcID); //calculate 1st byte based on R F2 E LCID, all the same for all types
        if (type == typeA){ 
        result.len = 2;
        result.pattern[1] = len; // F = 0, so 2nd byte is equal to L
        }
        if (type == typeB){ 
        result.len = 3; //3 bytes
        int value = std::pow(2,15)*1 + len;     // F2 = 0, F = 1, so 2 bytes length will be equal to value = ...
        result.pattern[1] = static_cast<uint8_t>(value >> 8); //value is presented to 16 bits pattern, get first 8 bits
        result.pattern[2] = static_cast<uint8_t>(value & 0xFF); // last 8 bits.
        }
        if (type == typeC){ 
        result.len = 3;
        result.pattern[1] = static_cast<uint8_t>(len >> 8); // 16 bits for length, F2 = 1, no F, get first 8 bits
        result.pattern[2] = static_cast<uint8_t>(len & 0xFF); // last 8 bits.
        }
    }
    return result;
}

void printDCI_format1A(phyTestCase_t& pdu){
    // print location of dci:
    std::cout << "[PHY] DCI location: " << " -- L: " << (int) pdu.location.L << " -- ncce: " << (int) pdu.location.ncce << std::endl;
    std::cout << "[PHY] DCI 1A: " ;
    std::cout << "Alloc Type: " << (int) pdu.alloc_type << " -- isLocalized: " << (int) pdu.type2_alloc.mode \
    << " -- NGap: " << (int) pdu.type2_alloc.n_gap << " -- RIV: " << (int)pdu.type2_alloc.riv << " -- pdcch_order: " << (int)pdu.is_pdcch_order << std::endl;
    std::cout << "[PHY] TB0: MCS: " << (int) pdu.tb[0].mcs_idx << " -- RV: " << (int) pdu.tb[0].rv << " -- HARQ: " << (int)pdu.pid ;
    std::cout << " -- MCS: " << (int)pdu.tb[0].mcs_idx << "|" << (int)pdu.tb[1].mcs_idx << " -- TPC: " << (int)pdu.tpc_pucch << " -- srs: " << (int)pdu.srs_request << std::endl;
    // std::cout << std::endl;
}

void printDCI_format1(phyTestCase_t& pdu){
    // print location of dci:
    std::cout << "[PHY] DCI location: " << " -- L: " << (int) pdu.location.L << " -- ncce: " << (int) pdu.location.ncce << std::endl;
    std::cout << "[PHY] DCI_1: " ;
    std::cout << "Alloc Type: " << (int) pdu.alloc_type; 
    if (pdu.alloc_type == 0){
        std::cout << " -- rbg_bitmask: " << pdu.type0_alloc.rbg_bitmask << std::endl ;
    }else if ( pdu.alloc_type == 1){
        std::cout << " -- vrg_bitmask: " << pdu.type1_alloc.vrb_bitmask << " -- subset: " << pdu.type1_alloc.rbg_subset << " -- shift: " << pdu.type1_alloc.shift << std::endl;
    }
    std::cout << "[PHY] TB0: MCS: " << (int) pdu.tb[0].mcs_idx << " -- RV: " << (int) pdu.tb[0].rv << " -- HARQ: " << (int)pdu.pid ;
    std::cout << " -- MCS: " << (int)pdu.tb[0].mcs_idx << "|" << (int)pdu.tb[1].mcs_idx << " -- TPC: " << (int)pdu.tpc_pucch << " -- srs: " << (int)pdu.srs_request << std::endl;
    // std::cout << std::endl;
}

void printDCI_format2(phyTestCase_t& pdu){
    // print location of dci:
    std::cout << "[PHY] DCI location: " << " -- L: " << (int) pdu.location.L << " -- ncce: " << (int) pdu.location.ncce << std::endl;
    std::cout << "[PHY] DCI_2: " ;
    std::cout << "Alloc Type: " << (int) pdu.alloc_type; 
    if (pdu.alloc_type == 0){
        std::cout << " -- rbg_bitmask: " << pdu.type0_alloc.rbg_bitmask << " -- cw_swap: " << pdu.tb_cw_swap << std::endl ;
    }else if ( pdu.alloc_type == 1){
        std::cout << " -- vrg_bitmask: " << pdu.type1_alloc.vrb_bitmask << " -- subset: " << pdu.type1_alloc.rbg_subset << " -- shift: " << pdu.type1_alloc.shift <<  " -- cw_swap: " << pdu.tb_cw_swap << std::endl;
    }
    std::cout << "[PHY] MCS: " << (int) pdu.tb[0].mcs_idx << "|" << (int) pdu.tb[1].mcs_idx << " -- ndi: " << pdu.tb[0].ndi << "|" << pdu.tb[1].ndi\
    << " -- RV: " << (int) pdu.tb[0].rv << "|" << (int) pdu.tb[1].rv << std::endl;
    std::cout <<  " -- HARQ: " << (int)pdu.pid << " -- TPC: " << (int)pdu.tpc_pucch << " -- precoding: " << (int)pdu.pinfo << std::endl;
    // std::cout << std::endl;
}

void printDCI_format2A(phyTestCase_t& pdu){
    std::cout << "[PHY] DCI_2: " ;
    std::cout << "Alloc Type: " << (int) pdu.alloc_type; 
    if (pdu.alloc_type == 0){
        std::cout << " -- rbg_bitmask: " << pdu.type0_alloc.rbg_bitmask << " -- cw_swap: " << pdu.tb_cw_swap << std::endl ;
    }else if ( pdu.alloc_type == 1){
        std::cout << " -- vrg_bitmask: " << pdu.type1_alloc.vrb_bitmask << " -- subset: " << pdu.type1_alloc.rbg_subset << " -- shift: " << pdu.type1_alloc.shift <<  " -- cw_swap: " << pdu.tb_cw_swap << std::endl;
    }
    std::cout << "[PHY] MCS: " << (int) pdu.tb[0].mcs_idx << "|" << (int) pdu.tb[1].mcs_idx << " -- ndi: " << pdu.tb[0].ndi << "|" << pdu.tb[1].ndi\
    << " -- RV: " << (int) pdu.tb[0].rv << "|" << (int) pdu.tb[1].rv << std::endl;
    std::cout <<  " -- HARQ: " << (int)pdu.pid << " -- TPC: " << (int)pdu.tpc_pucch << " -- precoding: " << (int)pdu.pinfo << std::endl;
    // std::cout << std::endl;
}

void printDCI_format1C(phyTestCase_t& pdu){
    std::cout << "[PHY] DCI 1C: " ;
    std::cout << "Alloc Type: " << (int) pdu.alloc_type; 
    if (pdu.alloc_type == 0){
        std::cout << " -- rbg_bitmask: " << pdu.type0_alloc.rbg_bitmask << std::endl ;
    }else if ( pdu.alloc_type == 1){
        std::cout << " -- vrg_bitmask: " << pdu.type1_alloc.vrb_bitmask << " -- subset: " << pdu.type1_alloc.rbg_subset << " -- shift: " << pdu.type1_alloc.shift << std::endl;
    }else if (pdu.alloc_type == 2){
        std::cout << " -- isLocalized: " << (int) pdu.type2_alloc.mode << " -- NGap: " << (int) pdu.type2_alloc.n_gap << " -- RIV: " << (int)pdu.type2_alloc.riv << std::endl;
    }
    std::cout << "[PHY] TB0: MCS: " << (int) pdu.tb[0].mcs_idx << " -- RV: " << (int) pdu.tb[0].rv << " -- HARQ: " << (int)pdu.pid << std::endl ;
    // std::cout << " -- MCS: " << (int)pdu.tb[0].mcs_idx << "|" << (int)pdu.tb[1].mcs_idx << " -- TPC: " << (int)pdu.tpc_pucch << " -- srs: " << (int)pdu.srs_request << std::endl;
    // std::cout << std::endl;
}

void printDCI_format0(phyTestCaseUL_t& pdu){
    std::cout << "[PHY] DCI 0: " ;
    std::cout << "Alloc Type 2, " << " -- NGap: " << (int) pdu.type2_alloc.n_gap << " -- RIV: " << (int)pdu.type2_alloc.riv << " --cqi_r: " << pdu.cqi_request << std::endl;
    std::cout << "[PHY] TB0: MCS: " << (int) pdu.tb.mcs_idx << " -- RV: " << (int) pdu.tb.rv << " -- n_dmrs: " << (int)pdu.n_dmrs;
    std::cout << " -- MCS: " << (int)pdu.tb.mcs_idx << " -- TPC: " << (int)pdu.tpc_pusch << " -- srs: " << (int)pdu.srs_request << std::endl;
    // std::cout << std::endl;
}


} // namespace srsenb

/*Backup code*/
// std::string exec(const char* cmd) {
//     char buffer[1024];
//     std::string result = "";
//     FILE* pipe = popen(cmd, "r");
//     if (!pipe) throw std::runtime_error("popen() failed!");

//     while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
//         result += buffer;
//     }

//     pclose(pipe);
//     return result;
// }

// std::string executeCommand(const char* cmd) {
//     std::string result;
//     char buffer[1000];
    
//     // Use popen to open a pipe and execute the command
//     FILE* pipe = popen(cmd, "r");
//     if (!pipe) {
//         throw std::runtime_error("popen() failed!");
//     }
    
//     // Read the command's output into the result string
//     while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
//         result += buffer;
//     }
    
//     pclose(pipe);
    
//     return result;
// }

#include "srsenb/hdr/stack/mac/fuzzer_base.h"

namespace srsenb {


void FuzzerBase_t::save_legitimate_rar(uint8_t* ptr, int len){
    // first byte is rar subheader
    int pos = 0;
    if (len >= 1){
        legitimate_rar_subheader.T = 1; //  always 1 for rar subheader
        // get the last 6 bits for pid
        legitimate_rar_subheader.pid = ptr[pos] & 0x3F;
        pos++;
    }
    if (pos + 6 <= len){
        // get first 2 bytes from pos
        uint16_t temp = ptr[pos] << 8 | ptr[pos + 1];
        legitimate_rar_grant.R = 0; // always 0 for legitimate rar grant
        // next 11 bits for ta
        legitimate_rar_grant.ta = (temp >> 4) & 0x7FF;
        
        // combine pos +1, pos + 2, pos + 3 into uint32_t
        uint32_t temp2 = ptr[pos + 1] << 16 | ptr[pos + 2] << 8 | ptr[pos + 3];
        // get ul grant
        legitimate_rar_grant.ulGrant = temp2 & 0xFFFFF; // 20 bits
        // get tcrnti
        legitimate_rar_grant.tcrnti = ptr[pos + 4] << 8 | ptr[pos + 5];
    }
    // std::cout << "[LLFuzz] Legitimate pid: " << legitimate_rar_subheader.pid << " ta: " << legitimate_rar_grant.ta << " ulGrant: " << legitimate_rar_grant.ulGrant << " tcrnti: " << legitimate_rar_grant.tcrnti << std::endl;
}    

int FuzzerBase_t::get_cur_testcase_idx(LLState_t state, bool verifyingMode){
    if (state > 5){
    std::cerr << "[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n";
    std::exit(EXIT_FAILURE);
    return 0;
    }else{
    return idx[state];
    }
}


}
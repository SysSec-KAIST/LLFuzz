#include "srsenb/hdr/stack/mac/phyfuzzer.h"


namespace srsenb {

phyFuzzer_t::phyFuzzer_t()
{
    // crashLog.open(logFilename); // init log file
    tcFile.open(tcFilename);    // init test case file
    terminalLog.open(terminalFilename); // init terminal log file
    verifiedCrash.open(verifiedCrashFilename); // init verified crash file
    idx[5] = startIdx; // verify crash
    idx[4] = startIdx; // verify crash
    idx[3] = startIdx;
    idx[2] = startIdx;
    state234Enable[(int)state2] = true;
    state234Enable[(int)state3] = true;
    state234Enable[(int)state4] = true;

    // load legitimate DCIs
    dci1A_orin = read_dci_from_file(dci1A_file);
    dci1_orin = read_dci_from_file(dci1_file);
    dci2A_orin = read_dci_from_file(dci2A_file);
    dci2_orin = read_dci_from_file(dci2_file);
    dci0_orin = read_ul_dci_from_file(dci0_file);
    dci1A_broadcast_orin = read_dci_from_file(dci1A_broadcast_file);
    std::cout << "[PHY] Load legitimate DCIs successfully" << "\n";
}

phyFuzzer_t::~phyFuzzer_t()
{
    // crashLog.close();
    tcFile.close();
    terminalLog.close();
    verifiedCrash.close();
}

// void phyFuzzer_t::set_fuzzing_config(LLState_t targetState_, bool verifyingMode_, int startIdx_){
//     fuzzingState = targetState_;
//     readFromFileMode = verifyingMode_;
//     startIdx = startIdx_;
// }

void phyFuzzer_t::setCellConfig(int nofPRB_, bool isTDD){
    nofPRB = nofPRB_;
    isFDD = !isTDD;
}

// TODO:
void phyFuzzer_t::saveCrashtoFile(int oracle){
    std::ofstream& crashLogFile = crashLog;
    crashLogFile << "Detected Crash index: " << nofCrash << "\n";
    
    // Get the current time point
    auto currentTime = std::chrono::system_clock::now();
    // Convert the time point to a time_t object
    std::time_t time = std::chrono::system_clock::to_time_t(currentTime);
    // Extract the milliseconds from the time point
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime.time_since_epoch()).count() % 1000;
    // Format the time as "hh:mm:ss"
    char timeStr[9];
    std::strftime(timeStr, sizeof(timeStr), "%H:%M:%S", std::localtime(&time));

    crashLogFile << " Time: " << timeStr << ":" << ms << "\n";
    crashLogFile << " State: " << fuzzingState << "\n";
    crashLogFile << " Uplink: " << sendUplinkDCI << "\n";

    // save recent testcase index to file
    std::deque<int> recent_idx = recent_testcases[fuzzingState].getBuffer();
    crashLogFile << " Recent Index: ";
    for (int i = 0; i < (int)recent_idx.size(); i++){
        crashLogFile << recent_idx[i];
        if (i != (int)recent_idx.size() - 1){
            crashLogFile << ", ";
        }else{
            crashLogFile << ".";
        }
    }

    crashLogFile << "\n";
    crashLogFile << "\n";
    nofCrash++;
}

int getnofBit_LoczdDRB(int nofPRB){
    int ret = 0;
    switch (nofPRB)
    {
    case 100:
        ret = 13;
        break;
    case 75:
        ret = 12;
        break;
    case 50:
        ret = 11;
        break;    
    case 25:
        ret = 9;
        break;  
    case 15:
        ret = 7;
        break;   
    case 6:
        ret = 5;
        break;            
    default:
        break;
    }
    return ret;
}

int getnofBit_DisDRB(int nofPRB){
    int ret = 0;
    switch (nofPRB)
    {
    case 100:
        ret = 12;
        break;
    case 75:
        ret = 11;
        break;
    case 50:
        ret = 10;
        break;    
    case 25:
        ret = 9;
        break;  
    case 15:
        ret = 7;
        break;   
    case 6:
        ret = 5;
        break;            
    default:
        break;
    }
    return ret;
}

void asign_legitimate_value_dl(phyTestCase_t &source, phyTestCase_t &target){
    target.alloc_type = source.alloc_type;
    switch (target.alloc_type)
    {
    case SRSRAN_RA_ALLOC_TYPE0:
        target.type0_alloc = source.type0_alloc;
        break;
    case SRSRAN_RA_ALLOC_TYPE1:
        target.type1_alloc = source.type1_alloc;
        break;
    case SRSRAN_RA_ALLOC_TYPE2:
        target.type2_alloc = source.type2_alloc;
        break;
    
    default:
        break;
    }

    for (int i = 0; i < 2; i++){
        target.tb[i] = source.tb[i];
    }
    target.tb_cw_swap = source.tb_cw_swap;
    target.pinfo = source.pinfo;
    target.pconf = source.pconf;
    target.power_offset = source.power_offset;
    target.tpc_pucch = source.tpc_pucch;
    target.is_pdcch_order = source.is_pdcch_order;
    target.preamble_idx = source.preamble_idx;
    target.prach_mask_idx = source.prach_mask_idx;
    target.cif = source.cif;
    target.cif_present = source.cif_present;
    target.srs_request = source.srs_request;
    target.srs_request_present = source.srs_request_present;
    target.pid = source.pid;
    target.dai  = source.dai;
    target.is_tdd = source.is_tdd;
    target.is_dwpts = source.is_dwpts;
    target.sram_id = source.sram_id;
}

void asign_legitimate_value_ul(phyTestCaseUL_t &source, phyTestCaseUL_t &target){
    target.type2_alloc = source.type2_alloc;

    target.tb = source.tb;
    target.n_dmrs = source.n_dmrs;
    target.dai  = source.dai;
    target.ul_idx = source.ul_idx;
    target.is_tdd = source.is_tdd;
    target.tpc_pusch = source.tpc_pusch;
    target.cif = source.cif;
    target.cif_present = source.cif_present;
    target.multiple_csi_request = source.multiple_csi_request;
    target.multiple_csi_request_present = source.multiple_csi_request_present;
    target.ra_type = source.ra_type;
    target.ra_type_present = source.ra_type_present;
    target.srs_request = source.srs_request;
    target.srs_request_present = source.srs_request_present;
}

// DCI 1A, allocation type 2, used to transmit RAR, SIB, Paging, and user data in all TMs with 1 antenna port
// Structures for [C_RNTI], [RA-RNTI, P-RNTI, SI-RNTI], and [PDCCH order] are different
void phyFuzzer_t::mutateDCI1A_CRNTI(std::vector<phyTestCase_t>& pduDB){
    int nofBit_DRB = 0;
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> drbList[14];
    for (int i = 5; i < 14; i++){
        drbList[i].push_back(0);
        for (int j = 0; j < i; j++){
            drbList[i].push_back(1 << j);
        }
    }
    std::vector<int> L_or_D_List = {0,1};
    std::vector<int> NGapList = {0,1};
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> harqList;
    harqList.push_back(0);
    for (int i = 0; i < nofBit_harq + 1; i++){
        harqList.push_back(1 << i);
    }
    std::vector<int> rvList = {0,1,2,3};
    std::vector<int> tpcList = {0,1,2,3};
    std::vector<int> srsList = {0,1};

    // generate initial dci
    phyTestCase_t initial_dci;
    asign_legitimate_value_dl(dci1A_orin, initial_dci);
    initial_dci.alloc_type = SRSRAN_RA_ALLOC_TYPE2;
    initial_dci.type2_alloc = type2_alloc_ref;
    initial_dci.format = SRSRAN_DCI_FORMAT1A;
    initial_dci.tpc_pucch = 0;

    for (auto const & l_or_d: L_or_D_List){
        for (auto const & ngap: NGapList){
            nofBit_DRB = (l_or_d == 0)? getnofBit_LoczdDRB(nofPRB): getnofBit_DisDRB(nofPRB);
            for (auto const & drb: drbList[nofBit_DRB]){
                phyTestCase_t lv1pdu;
                lv1pdu = initial_dci;
                lv1pdu.type2_alloc.mode = (l_or_d == 0)? srsran_ra_type2_t::SRSRAN_RA_TYPE2_LOC: srsran_ra_type2_t::SRSRAN_RA_TYPE2_DIST;
                lv1pdu.type2_alloc.n_gap = ngap == 0? srsran_ra_type2_t::SRSRAN_RA_TYPE2_NG1: srsran_ra_type2_t::SRSRAN_RA_TYPE2_NG2;
                lv1pdu.type2_alloc.riv = drb;
                pduDB.push_back(lv1pdu);
            }
            
        }
    }

    for (auto const & mcs: mcsList){
        for (auto const & harq: harqList){
            phyTestCase_t lv2pdu;
            lv2pdu = initial_dci;
            lv2pdu.tb[0].mcs_idx = mcs;
            lv2pdu.tb[1].mcs_idx = mcs;
            lv2pdu.pid = harq;
            pduDB.push_back(lv2pdu);
        }
    }

    for (auto const & rv: rvList){
        for (auto const & tpc: tpcList){
            for (auto const & srs: srsList){
                phyTestCase_t tc;
                tc = initial_dci;
                tc.tb[0].rv = rv;
                tc.tb[1].rv = rv;
                tc.tpc_pucch = tpc;
                tc.srs_request = srs;
                pduDB.push_back(tc);
            }
        }
    }
    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

void phyFuzzer_t::mutateDCI1A_broadcast_RNTI(std::vector<phyTestCase_t>& pduDB){ // same type 2 as original srseNB
    int nofBit_DRB = 0;
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> drbList[14];
    for (int i = 5; i < 14; i++){
        drbList[i].push_back(0);
        for (int j = 0; j < i; j++){
            drbList[i].push_back(1 << j);
        }
    }
    std::vector<int> L_or_D_List = {0,1};
    std::vector<int> NGapList = {0,1};
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> harqList;
    harqList.push_back(0);
    for (int i = 0; i < nofBit_harq + 1; i++){
        harqList.push_back(1 << i);
    }
    std::vector<int> rvList = {0,1,2,3};
    std::vector<int> tpcList = {0,1}; // only 2 values for broadcast rnti
    // std::vector<int> srsList = {0,1}; // only for UE specific RNTI

    phyTestCase_t initial_dci;
    asign_legitimate_value_dl(dci1A_broadcast_orin, initial_dci);
    initial_dci.alloc_type = SRSRAN_RA_ALLOC_TYPE2;
    initial_dci.type2_alloc = type2_alloc_ref;
    initial_dci.format = SRSRAN_DCI_FORMAT1A;
    initial_dci.tpc_pucch = 0;


    for (auto const & l_or_d: L_or_D_List){
        for (auto const & ngap: NGapList){
            nofBit_DRB = (l_or_d == 0)? getnofBit_LoczdDRB(nofPRB): getnofBit_DisDRB(nofPRB);
            for (auto const & drb: drbList[nofBit_DRB]){
                phyTestCase_t lv1pdu;
                lv1pdu = initial_dci;
                lv1pdu.type2_alloc.mode = (l_or_d == 0)? srsran_ra_type2_t::SRSRAN_RA_TYPE2_LOC: srsran_ra_type2_t::SRSRAN_RA_TYPE2_DIST;
                lv1pdu.type2_alloc.n_gap = ngap == 0? srsran_ra_type2_t::SRSRAN_RA_TYPE2_NG1: srsran_ra_type2_t::SRSRAN_RA_TYPE2_NG2;
                lv1pdu.type2_alloc.riv = drb;
                pduDB.push_back(lv1pdu);
            }
            
        }
    }

    for (auto const & mcs: mcsList){
        for (auto const & harq: harqList){
            phyTestCase_t lv2pdu;
            lv2pdu = initial_dci;
            lv2pdu.tb[0].mcs_idx = mcs;
            lv2pdu.tb[1].mcs_idx = mcs;
            lv2pdu.pid = harq;
            pduDB.push_back(lv2pdu);
        }
    }

    // for (auto const & rv: rvList){
    //     for (auto const & tpc: tpcList){
    //         for (auto const & srs: srsList){
    //             phyTestCase_t tc;
    //             asign_legitimate_value_dl(dci1A_orin, tc);
    //             tc.format = SRSRAN_DCI_FORMAT1A;
    //             tc.tb[0].rv = rv;
    //             tc.tb[1].rv = rv;
    //             tc.tpc_pucch = tpc;
    //             tc.srs_request = srs;
    //             pduDB.push_back(tc);
    //         }
    //     }
    // }
    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

int getnofBit_DCI1C(int nofPRB){
    int ret = 0;
    switch (nofPRB)
    {
    case 100:
        ret = 9;
        break;
    case 75:
        ret = 6;
        break;
    case 50:
        ret = 5;
        break;    
    case 25:
        ret = 4;
        break;  
    case 15:
        ret = 2;
        break;   
    default:
        break;
    }
    return ret;
}

void phyFuzzer_t::mutateDCI1C(std::vector<phyTestCase_t>& pduDB){ // same type 2 as original srseNB
    int nofBit_DRB = 0;
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> drbList[14];
    for (int i = 3; i < 10; i++){  // from 3 to 9 bit length of resource block assignment
        drbList[i].push_back(0);
        for (int j = 0; j < i; j++){
            drbList[i].push_back(1 << j);
        }
    }
    std::vector<int> NGapList = {0,1};
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }

    nofBit_DRB = getnofBit_DCI1C(nofPRB);
    for (auto const &drb: drbList[nofBit_DRB]){
        for (auto const& ngap: NGapList){
            for (auto const& mcs: mcsList){
                phyTestCase_t lv1pdu;
                lv1pdu.alloc_type = SRSRAN_RA_ALLOC_TYPE2;
                lv1pdu.format = SRSRAN_DCI_FORMAT1C;
                lv1pdu.type2_alloc.riv = drb;
                lv1pdu.tb[0].mcs_idx = mcs;
                lv1pdu.tb[1].mcs_idx = mcs;
                lv1pdu.type2_alloc.n_gap = ngap == 0? srsran_ra_type2_t::SRSRAN_RA_TYPE2_NG1: srsran_ra_type2_t::SRSRAN_RA_TYPE2_NG2;
                pduDB.push_back(lv1pdu);
            }
        }
    }

    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

// T_note: TODO: modify dci pack function of srsran
void phyFuzzer_t::mutateDCI1A_PDCCH_order(std::vector<phyTestCase_t>& pduDB){
    int nofBit_DRB = 0;
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> drbList[14];
    for (int i = 5; i < 14; i++){
        drbList[i].push_back(0);
        for (int j = 0; j < i; j++){
            drbList[i].push_back(1 << j);
        }
    }
    std::vector<int> preamble_idx_list;
    for (int i = 0; i < 64; i = i + 4){
        preamble_idx_list.push_back(i);
    }
    std::vector<int> prach_mask_idx_list;
    for (int i = 0; i < 16; i = i + 2){
        prach_mask_idx_list.push_back(i);
    }

    int nof_bit_drb = getnofBit_LoczdDRB(nofPRB);

    for (auto &drb: drbList[nof_bit_drb]){
        for (auto &pream_idx: preamble_idx_list){
            for (auto &prach_mask_idx: prach_mask_idx_list){
                phyTestCase_t lv1pdu;
                lv1pdu.format = SRSRAN_DCI_FORMAT1A;
                lv1pdu.is_pdcch_order = true;
                lv1pdu.alloc_type = SRSRAN_RA_ALLOC_TYPE2;
                lv1pdu.type2_alloc.mode = srsran_ra_type2_t::SRSRAN_RA_TYPE2_LOC;
                lv1pdu.type2_alloc.riv = drb;
                lv1pdu.preamble_idx = pream_idx;
                lv1pdu.prach_mask_idx = prach_mask_idx;
                pduDB.push_back(lv1pdu);
            }
        }
    }

    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

int getnofBit_type0_DCI1(int nofPRB){
    int ret = 0;
    switch (nofPRB)
    {
    case 100:
        ret = 25;
        break;
    case 75:
        ret = 19;
        break;
    case 50:
        ret = 17;
        break;    
    case 25:
        ret = 13;
        break;  
    case 15:
        ret = 8;
        break;   
    case 6:
        ret = 6;
        break;            
    default:
        break;
    }
    return ret;
}


void phyFuzzer_t::mutateDCI1_type0(std::vector<phyTestCase_t>& pduDB){  // same type as srsran, orin dci will be type 0
    const srsran_ra_type_t type = SRSRAN_RA_ALLOC_TYPE0; // fixed type as we are mutating DCI1 type 0
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> rbgList[26];
    for (int i = 6; i < 26; i++){
        rbgList[i].push_back(0);
        for (int j = 0; j < i; j++){
            rbgList[i].push_back(1 << j);
        }
    }
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> harqList;
    harqList.push_back(0);
    for (int i = 0; i < nofBit_harq + 1; i++){
        harqList.push_back(1 << i);
    }
    std::vector<int> rvList = {0,1,2,3};
    std::vector<int> tpcList = {0,1,2,3};
    std::vector<int> srsList = {0,1};

    // generate initial dci
    phyTestCase_t initial_dci;
    asign_legitimate_value_dl(dci1_orin, initial_dci);
    initial_dci.alloc_type = type;
    initial_dci.type0_alloc = type0_alloc_ref;
    initial_dci.tpc_pucch = 0;
    initial_dci.format = SRSRAN_DCI_FORMAT1;


    int nofBit_RBG = getnofBit_type0_DCI1(nofPRB);
    for (auto const & rbg: rbgList[nofBit_RBG]){
        phyTestCase_t lv1pdu;
        lv1pdu = initial_dci;
        // lv1pdu.format = SRSRAN_DCI_FORMAT1;
        lv1pdu.type0_alloc.rbg_bitmask = rbg;   
        pduDB.push_back(lv1pdu);
    }

    for (auto const & mcs: mcsList){
        for (auto const & harq: harqList){
            phyTestCase_t lv2pdu;
            lv2pdu = initial_dci;
            lv2pdu.tb[0].mcs_idx = mcs;
            lv2pdu.tb[1].mcs_idx = mcs;
            lv2pdu.pid = harq;
            pduDB.push_back(lv2pdu);
        }
    }

    for (auto const & rv: rvList){
        for (auto const & tpc: tpcList){
            for (auto const & srs: srsList){
                phyTestCase_t tc;
                tc = initial_dci;
                tc.tb[0].rv = rv;
                tc.tb[1].rv = rv;
                tc.tpc_pucch = tpc;
                tc.srs_request = srs;
                pduDB.push_back(tc);
            }
        }
    }
    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

int getnofBit_ra_type1_DCI1(int nofPRB){
    int ret = 0;
    switch (nofPRB)
    {
    case 100:
        ret = 22;
        break;
    case 75:
        ret = 16;
        break;
    case 50:
        ret = 14;
        break;    
    case 25:
        ret = 13;
        break;  
    case 15:
        ret = 6;
        break;   
    case 6:
        ret = 0; // not available
        break;            
    default:
        ret = 0;
        break;
    }
    return ret;
}

void phyFuzzer_t::mutateDCI1_type1(std::vector<phyTestCase_t>& pduDB){
    const srsran_ra_type_t type = SRSRAN_RA_ALLOC_TYPE1; // fixed type as we are mutating DCI1 type 0
    int nofBit_subset = (nofPRB >= 50)? 2: 1;
    std::vector<int> subsetList[3];
    subsetList[1] = {0,1};      // 1 bit
    subsetList[2] = {0,1,2,3};  //  2 bits
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> vrb_bitmask[23];
    for (int i = 6; i < 23; i++){
        vrb_bitmask[i].push_back(0);
        for (int j = 0; j < i; j++){
            vrb_bitmask[i].push_back(1 << j);
        }
    }
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> harqList;
    harqList.push_back(0);
    for (int i = 0; i < nofBit_harq + 1; i++){
        harqList.push_back(1 << i);

    }
    std::vector<int> shiftList = {0,1};

    std::vector<int> rvList = {0,1,2,3};
    std::vector<int> tpcList = {0,1,2,3};
    std::vector<int> srsList = {0,1};

    phyTestCase_t initial_dci;
    asign_legitimate_value_dl(dci1_orin, initial_dci);
    initial_dci.alloc_type = type;
    initial_dci.type1_alloc = type1_alloc_ref;
    initial_dci.tpc_pucch = 0;
    initial_dci.format = SRSRAN_DCI_FORMAT1;


    int nofBit_bitmask = getnofBit_ra_type1_DCI1(nofPRB);
    for (auto const & subset: subsetList[nofBit_subset]){
        for (auto const & shift: shiftList){
            for (auto const & bitmask: vrb_bitmask[nofBit_bitmask]){
                phyTestCase_t lv1pdu;
                lv1pdu = initial_dci;
                lv1pdu.type1_alloc.rbg_subset = subset;
                lv1pdu.type1_alloc.shift = shift;
                lv1pdu.type0_alloc.rbg_bitmask = bitmask;   
                pduDB.push_back(lv1pdu);
            }
        }
    }

    for (auto const & mcs: mcsList){
        for (auto const & harq: harqList){
            phyTestCase_t lv2pdu;
            lv2pdu = initial_dci;
            lv2pdu.type1_alloc.rbg_subset = 0;
            lv2pdu.type1_alloc.shift = 0;
            lv2pdu.type0_alloc.rbg_bitmask = 0b1;
            lv2pdu.tb[0].mcs_idx = mcs;
            lv2pdu.tb[1].mcs_idx = mcs;
            lv2pdu.pid = harq;
            pduDB.push_back(lv2pdu);
        }
    }

    for (auto const & rv: rvList){
        for (auto const & tpc: tpcList){
            for (auto const & srs: srsList){
                phyTestCase_t tc;
                tc = initial_dci;
                tc.type1_alloc.rbg_subset = 0;
                tc.type1_alloc.shift = 0;
                tc.type0_alloc.rbg_bitmask = 0b1;
                tc.tb[0].rv = rv;
                tc.tb[1].rv = rv;
                tc.tpc_pucch = tpc;
                tc.srs_request = srs;
                pduDB.push_back(tc);
            }
        }
    }
    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

void phyFuzzer_t::mutateDCI2A_type0(std::vector<phyTestCase_t>& pduDB){ // same as srsran, orin dci will be type 0
    const srsran_ra_type_t type = SRSRAN_RA_ALLOC_TYPE0; // fixed type as we are mutating DCI1 type 0
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> rbgList[26];
    for (int i = 6; i < 26; i++){
        rbgList[i].push_back(0);
        for (int j = 0; j < i; j++){
            rbgList[i].push_back(1 << j);
        }
    }
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> harqList;
    harqList.push_back(0);
    for (int i = 0; i < nofBit_harq + 1; i++){
        harqList.push_back(1 << i);
    }
    std::vector<int> rvList = {0,1,2,3};
    std::vector<int> tpcList = {0,1,2,3};
    std::vector<int> srsList = {0,1};

    std::vector<int> swapList = {0,1};
    std::vector<int> ndiList = {0,1};
    // std::vector<int> precodingList = {0,1,4,7}; // 3 bits only as we only have 2 antennas

    phyTestCase_t initial_dci;
    asign_legitimate_value_dl(dci2A_orin, initial_dci);
    initial_dci.alloc_type = type;
    initial_dci.type0_alloc = type0_alloc_ref;
    initial_dci.format = SRSRAN_DCI_FORMAT2A;
    initial_dci.tpc_pucch = 0;


    int nofBit_RBG = getnofBit_type0_DCI1(nofPRB);  // same as DCI1 type 0
    for (auto const & rbg: rbgList[nofBit_RBG]){
        phyTestCase_t lv1pdu;
        lv1pdu = initial_dci;
        lv1pdu.type0_alloc.rbg_bitmask = rbg;   
        pduDB.push_back(lv1pdu);
    }

    for (auto const & mcs: mcsList){
        for (auto const & harq: harqList){
            for (auto const & ndi: ndiList){
                phyTestCase_t lv2pdu;
                lv2pdu = initial_dci;
                lv2pdu.tb[0].mcs_idx = mcs;
                lv2pdu.tb[1].mcs_idx = mcs;
                lv2pdu.tb[0].ndi = ndi;
                lv2pdu.tb[1].ndi = ndi;
                lv2pdu.pid = harq;
                pduDB.push_back(lv2pdu);
            }
        }
    }

    for (auto const & rv: rvList){ 
        for (auto const & tpc: tpcList){
            for (auto const & swap: swapList){  // no precoding as we only have 2 antennas
                phyTestCase_t tc;
                tc = initial_dci;
                tc.tb[0].rv = rv;
                tc.tb[1].rv = rv;
                tc.tpc_pucch = tpc;
                tc.tb_cw_swap = swap;
                pduDB.push_back(tc);
            }
        }
    }
    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();}

void phyFuzzer_t::mutateDCI2A_type1(std::vector<phyTestCase_t>& pduDB){
    const srsran_ra_type_t type = SRSRAN_RA_ALLOC_TYPE1; // fixed type as we are mutating DCI1 type 0
    int nofBit_subset = (nofPRB >= 50)? 2: 1;
    std::vector<int> subsetList[3];
    subsetList[1] = {0,1};      // 1 bit
    subsetList[2] = {0,1,2,3};  //  2 bits
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> vrb_bitmask[23];
    for (int i = 6; i < 23; i++){
        vrb_bitmask[i].push_back(0);
        for (int j = 0; j < i; j++){
            vrb_bitmask[i].push_back(1 << j);
        }
    }
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> harqList;
    harqList.push_back(0);
    for (int i = 0; i < nofBit_harq + 1; i++){
        harqList.push_back(1 << i);

    }
    std::vector<int> shiftList = {0,1};

    std::vector<int> rvList = {0,1,2,3};
    std::vector<int> tpcList = {0,1,2,3};
    std::vector<int> srsList = {0,1};

    std::vector<int> swapList = {0,1};
    std::vector<int> ndiList = {0,1};

    phyTestCase_t initial_dci;
    asign_legitimate_value_dl(dci2A_orin, initial_dci);
    initial_dci.alloc_type = type;
    initial_dci.type1_alloc = type1_alloc_ref;
    initial_dci.tpc_pucch = 0;
    initial_dci.format = SRSRAN_DCI_FORMAT2A;

    int nofBit_bitmask = getnofBit_ra_type1_DCI1(nofPRB); // same as DCI1 type 1
    for (auto const & subset: subsetList[nofBit_subset]){
        for (auto const & shift: shiftList){
            for (auto const & bitmask: vrb_bitmask[nofBit_bitmask]){
                phyTestCase_t lv1pdu;
                lv1pdu = initial_dci;
                lv1pdu.type1_alloc.rbg_subset = subset;
                lv1pdu.type1_alloc.shift = shift;
                lv1pdu.type0_alloc.rbg_bitmask = bitmask;   
                pduDB.push_back(lv1pdu);
            }
        }
    }

    for (auto const & mcs: mcsList){
        for (auto const & harq: harqList){
            for (auto const & ndi: ndiList){
                phyTestCase_t lv2pdu;
                lv2pdu = initial_dci;
                lv2pdu.type1_alloc.rbg_subset = 0;
                lv2pdu.type1_alloc.shift = 0;
                lv2pdu.type0_alloc.rbg_bitmask = 0b1;

                lv2pdu.tb[0].mcs_idx = mcs;
                lv2pdu.tb[1].mcs_idx = mcs;
                lv2pdu.tb[0].ndi = ndi;
                lv2pdu.tb[1].ndi = ndi;
                lv2pdu.pid = harq;
                pduDB.push_back(lv2pdu);
            }
        }
    }

    for (auto const & rv: rvList){
        for (auto const & tpc: tpcList){
            for (auto const & swap: swapList){  // no precoding as we only have 2 antennas
                phyTestCase_t tc ;
                tc = initial_dci;
                tc.type1_alloc.rbg_subset = 0;
                tc.type1_alloc.shift = 0;
                tc.type0_alloc.rbg_bitmask = 0b1;
                tc.tb[0].rv = rv;
                tc.tb[1].rv = rv;
                tc.tpc_pucch = tpc;
                tc.tb_cw_swap = swap;
                pduDB.push_back(tc);
            }
        }
    }

    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

void phyFuzzer_t::mutateDCI2_type0(std::vector<phyTestCase_t>& pduDB){ // same as srsran, orin dci will be type 0
    const srsran_ra_type_t type = SRSRAN_RA_ALLOC_TYPE0; // fixed type as we are mutating DCI1 type 0
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> rbgList[26];
    for (int i = 6; i < 26; i++){
        rbgList[i].push_back(0);
        for (int j = 0; j < i; j = j + 2){
            rbgList[i].push_back(1 << j);
        }
    }
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> harqList;
    harqList.push_back(0);
    for (int i = 0; i < nofBit_harq + 1; i++){
        harqList.push_back(1 << i);
    }
    std::vector<int> rvList = {0,1,2,3};
    std::vector<int> tpcList = {0,1,2,3};
    std::vector<int> srsList = {0,1};

    std::vector<int> swapList = {0,1};
    std::vector<int> ndiList = {0,1};
    std::vector<int> precodingList = {0,1,2,3,4,5,6,7}; // 3 bits only as we only have 2 antennas    

    // generate initial dci
    phyTestCase_t initial_dci;
    asign_legitimate_value_dl(dci2_orin, initial_dci);
    initial_dci.alloc_type = type;
    initial_dci.type0_alloc = type0_alloc_ref;
    initial_dci.format = SRSRAN_DCI_FORMAT2;
    initial_dci.tpc_pucch = 0;


    int nofBit_RBG = getnofBit_type0_DCI1(nofPRB);  // same as DCI1 type 0
    for (auto const & rbg: rbgList[nofBit_RBG]){
        phyTestCase_t lv1pdu;
        lv1pdu = initial_dci;
        lv1pdu.type0_alloc.rbg_bitmask = rbg;   
        pduDB.push_back(lv1pdu);
    }

    for (auto const & mcs: mcsList){
        for (auto const & harq: harqList){
            for (auto const & ndi: ndiList){
                    phyTestCase_t lv2pdu;
                    lv2pdu = initial_dci;
                    lv2pdu.tb[0].mcs_idx = mcs;
                    lv2pdu.tb[1].mcs_idx = mcs;
                    lv2pdu.tb[0].ndi = ndi;
                    lv2pdu.tb[1].ndi = ndi;
                    lv2pdu.pid = harq;
                    pduDB.push_back(lv2pdu);
            }
        }
    }

    for (auto const & rv: rvList){ 
        for (auto const & tpc: tpcList){
            for (auto const & swap: swapList){  // no precoding as we only have max 2 antennas
                    phyTestCase_t lv3pdu;
                    lv3pdu = initial_dci;
                    lv3pdu.tb[0].rv = rv;
                    lv3pdu.tb[1].rv = rv;
                    lv3pdu.tpc_pucch = tpc;
                    lv3pdu.tb_cw_swap = swap;
                    lv3PDUtemp.push_back(lv3pdu);
            }
        }
    }

    for (auto const & precoding: precodingList){
        for (auto const & lv3pdu: lv3PDUtemp){
            phyTestCase_t tc = lv3pdu;
            tc.pinfo = precoding;
            pduDB.push_back(tc);
        }
    }

    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

void phyFuzzer_t::mutateDCI2_type1(std::vector<phyTestCase_t>& pduDB){
    const srsran_ra_type_t type = SRSRAN_RA_ALLOC_TYPE1; // fixed type as we are mutating DCI type 1
    int nofBit_subset = (nofPRB >= 50)? 2: 1;
    std::vector<int> subsetList[3];
    subsetList[1] = {0,1};      // 1 bit
    subsetList[2] = {0,1,2,3};  //  2 bits
    int nofBit_harq = (isFDD)? 3: 4;
    std::vector<int> vrb_bitmask[23];
    for (int i = 6; i < 23; i++){
        vrb_bitmask[i].push_back(0);
        for (int j = 0; j < i; j = j + 2){
            vrb_bitmask[i].push_back(1 << j);
        }
    }
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> harqList;
    harqList.push_back(0);
    for (int i = 0; i < nofBit_harq + 1; i++){
        harqList.push_back(1 << i);

    }
    std::vector<int> shiftList = {0,1};

    std::vector<int> rvList = {0,1,2,3};
    std::vector<int> tpcList = {0,1,2,3};
    std::vector<int> srsList = {0,1};

    std::vector<int> swapList = {0,1};
    std::vector<int> ndiList = {0,1};
    std::vector<int> precodingList = {0,1,2,3,4,5,6,7}; // 3 bits only as we only have 2 antennas 

    int nofBit_bitmask = getnofBit_ra_type1_DCI1(nofPRB); // same as DCI1 type 1
    for (auto const & subset: subsetList[nofBit_subset]){
        for (auto const & shift: shiftList){
            for (auto const & bitmask: vrb_bitmask[nofBit_bitmask]){
                phyTestCase_t lv1pdu;
                asign_legitimate_value_dl(dci2_orin, lv1pdu);
                lv1pdu.alloc_type = type;
                lv1pdu.format = SRSRAN_DCI_FORMAT2;
                lv1pdu.type1_alloc.rbg_subset = subset;
                lv1pdu.type1_alloc.shift = shift;
                lv1pdu.type0_alloc.rbg_bitmask = bitmask;   
                pduDB.push_back(lv1pdu);
            }
        }
    }

    for (auto const & mcs: mcsList){
        for (auto const & harq: harqList){
            for (auto const & ndi: ndiList){
                    phyTestCase_t lv2pdu ;
                    asign_legitimate_value_dl(dci2_orin, lv2pdu);
                    lv2pdu.alloc_type = type;
                    lv2pdu.format = SRSRAN_DCI_FORMAT2;
                    lv2pdu.type1_alloc.rbg_subset = 0;
                    lv2pdu.type1_alloc.shift = 0;
                    lv2pdu.type0_alloc.rbg_bitmask = 0b1;

                    lv2pdu.tb[0].mcs_idx = mcs;
                    lv2pdu.tb[1].mcs_idx = mcs;
                    lv2pdu.tb[0].ndi = ndi;
                    lv2pdu.tb[1].ndi = ndi;
                    lv2pdu.pid = harq;
                    pduDB.push_back(lv2pdu);
            }
        }
    }

    for (auto const & rv: rvList){
        for (auto const & tpc: tpcList){
            for (auto const & swap: swapList){  // no precoding as we only have 2 antennas
                    phyTestCase_t lv3PDU;
                    asign_legitimate_value_dl(dci2_orin, lv3PDU);
                    lv3PDU.alloc_type = type;
                    lv3PDU.format = SRSRAN_DCI_FORMAT2;
                    lv3PDU.type1_alloc.rbg_subset = 0;
                    lv3PDU.type1_alloc.shift = 0;
                    lv3PDU.type0_alloc.rbg_bitmask = 0b1;
                    lv3PDU.tb[0].rv = rv;
                    lv3PDU.tb[1].rv = rv;
                    lv3PDU.tpc_pucch = tpc;
                    lv3PDU.tb_cw_swap = swap;
                    lv3PDUtemp.push_back(lv3PDU);
            }
        }
    }

    for (auto const & precoding: precodingList){
        for (auto const & lv3PDU: lv3PDUtemp){
            phyTestCase_t tc = lv3PDU;
            tc.pinfo = precoding;
            pduDB.push_back(tc);
        }
    }

    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
    lv3PDUtemp.clear();
    lv3PDUtemp.shrink_to_fit();
}

void phyFuzzer_t::mutateDCI0_FDD(std::vector<phyTestCaseUL_t>& pduDB){ // same as srsran, orin dci will be same type
    int nofBit_DRB = 0;
    int nofBit_hopping = (nofPRB >= 50)? 2: 1;
    nofBit_DRB = getnofBit_LoczdDRB(nofPRB); // same as DCI 1A type 0 localized 
    nofBit_hopping = (nofPRB >= 50)? 2: 1;
    std::vector<int> hoppingList[3];
    hoppingList[1] = {0,1};      // 1 bit
    hoppingList[2] = {0,1,2,3};  //  2 bits
    std::vector<int> drbList[14];
    for (int i = 2; i < 14; i++){
        drbList[i].push_back(0);
        for (int j = 0; j < i; j++){
            drbList[i].push_back(1 << j);
        }
    }
    std::vector<int> mcsList;
    // mcsList from 0 to 31
    mcsList.reserve(32);
    for (int i = 0; i < 32; i++){
        mcsList.push_back(i);
    }
    std::vector<int> ndiList = {0,1};
    std::vector<int> tpcList = {0,1,2,3};
    std::vector<int> dmrsList = {0,1,2,3,4,5,6,7}; // 3 bits
    std::vector<int> srsList = {0,1};
    std::vector<int> csiList = {0,1};
    std::vector<int> hoppingFlagList = {0,1};
    std::vector<int> cycShiftList = {0,1,2,3,4,5,6,7}; // 3 bits

    phyTestCaseUL_t initial_dci;
    asign_legitimate_value_ul(dci0_orin, initial_dci);
    initial_dci.ra_type = SRSRAN_RA_ALLOC_TYPE2;
    initial_dci.type2_alloc = type2_alloc_ref;
    initial_dci.format = SRSRAN_DCI_FORMAT0;
    initial_dci.tpc_pusch = 0;
    
    for (auto const & hopFlag: hoppingFlagList){
        for (auto const & hopping: hoppingList[nofBit_hopping]){
            nofBit_DRB = (hopFlag == 0)? nofBit_DRB: nofBit_DRB - nofBit_hopping; // reduce nofBit_DRB if hopping is enabled
            for (auto const & drb: drbList[nofBit_DRB]){
                phyTestCaseUL_t lv1pdu;
                lv1pdu = initial_dci;
                lv1pdu.freq_hop_fl = (hopFlag == 0)? srsran_dci_ul_t::SRSRAN_RA_PUSCH_HOP_DISABLED: ((hopping == 0)? 
                                                        srsran_dci_ul_t::SRSRAN_RA_PUSCH_HOP_QUART:(hopping == 1)?
                                                        srsran_dci_ul_t::SRSRAN_RA_PUSCH_HOP_QUART_NEG: ((hopping == 2)? 
                                                        srsran_dci_ul_t::SRSRAN_RA_PUSCH_HOP_HALF: srsran_dci_ul_t::SRSRAN_RA_PUSCH_HOP_TYPE2));
                lv1pdu.type2_alloc.riv = drb;
                pduDB.push_back(lv1pdu);
            }
            
        }
    }

    for (auto const & mcs: mcsList){
        for (auto const & ndi: ndiList){
            for (auto const & csi: csiList){
                    phyTestCaseUL_t lv2pdu;
                    lv2pdu = initial_dci;
                    lv2pdu.cqi_request = csi;
                    lv2pdu.tb.mcs_idx = mcs;
                    lv2pdu.tb.ndi = ndi;
                    lv2PDUtempUL.push_back(lv2pdu);
            }
        }
    }

    for (auto const & dmrs: dmrsList){
        for (auto const & tpc: tpcList){
            for (auto const & srs: srsList){
                    phyTestCaseUL_t tc;
                    tc = initial_dci;
                    tc.n_dmrs = dmrs;
                    tc.tpc_pusch = tpc;
                    tc.srs_request = srs;
                    pduDB.push_back(tc);
            }
        }
    }
    //clean lv1PDUtemp, lv2PDUtemp, lv3PDUtemp
    lv1PDUtempUL.clear();
    lv1PDUtempUL.shrink_to_fit();
    lv2PDUtempUL.clear();
    lv2PDUtempUL.shrink_to_fit();
}

void phyFuzzer_t::generate_test_cases(){

    // generate reference allocation
    // allocation type 0
    type0_alloc_ref.rbg_bitmask = 0b1; // 1 Resource Block Group
    // allocation type 1
    type1_alloc_ref.vrb_bitmask = 0b111; // 3 RBs = 1 RB Group
    type1_alloc_ref.rbg_subset  = 0;     // fisrt subset
    type1_alloc_ref.shift       = 0;     // no shift
    // allocation type 2
    type2_alloc_ref.riv     = 0; // 0/nof_PRB + 1 = 1, 0 mod nof_PRB = 0 -> start PRB = 0, nof_prb = 1 
    type2_alloc_ref.n_prb1a = srsran_ra_type2_t::SRSRAN_RA_TYPE2_NPRB1A_2; // 2 RBs in case of broadcast
    type2_alloc_ref.n_gap   = srsran_ra_type2_t::SRSRAN_RA_TYPE2_NG1;
    type2_alloc_ref.mode    = srsran_ra_type2_t::SRSRAN_RA_TYPE2_LOC;


    if (!readFromFileMode){
        // TM1, TM2 
        if ((fuzzingState == state3 || fuzzingState == state4) && transmission_mode <= 2){
            mutateDCI1_type0(testcaseDB[state4]);
            mutateDCI1_type1(testcaseDB[state4]);
            // std::cout << "[MTT] Mutating DCI1 type 0 and type 1, number of test cases: " 
            //         << testcaseDB[state4].size() << "\n";

            mutateDCI1_type0(testcaseDB[state3]);
            mutateDCI1_type1(testcaseDB[state3]);
        }


        if ((fuzzingState == state3 || fuzzingState == state4) && transmission_mode == 3){

            //TM3 - DCI2A
            mutateDCI2A_type0(testcaseDB[state4]);
            mutateDCI2A_type1(testcaseDB[state4]);
            // std::cout << "[MTT] Mutating DCI2A type 0 and type 1, number of test cases: " 
            //         << testcaseDB[state4].size() << "\n";
            mutateDCI2A_type0(testcaseDB[state3]);
            mutateDCI2A_type1(testcaseDB[state3]);
            // std::cout << "[MTT] Mutating DCI2A type 0 and type 1, number of test cases: " 
            //         << testcaseDB[state3].size() << "\n";
        }

        if (fuzzingState == state4 && transmission_mode == 4){
            // TM4 - DCI2
            mutateDCI2_type0(testcaseDB[state4]);
            mutateDCI2_type1(testcaseDB[state4]);
            // std::cout << "[MTT] Mutating DCI2 type 0 and type 1, number of test cases: " 
            //         << testcaseDB[state4].size() << "\n";
            mutateDCI2_type0(testcaseDB[state3]);
            mutateDCI2_type1(testcaseDB[state3]);
            // std::cout << "[MTT] Mutating DCI2 type 0 and type 1, number of test cases: " 
            //         << testcaseDB[state3].size() << "\n";
        }

        mutateDCI1A_CRNTI(testcaseDB[state4]);
        // std::cout << "[MTT] Mutating DCI1A CRNTI, number of test cases: " 
        //           << testcaseDB[state4].size() << "\n";
        mutateDCI1A_CRNTI(testcaseDB[state2]);

        // PDCCH order dci format 1A
        mutateDCI1A_PDCCH_order(testcaseDB[state4]);
        // std::cout << "[MTT] Mutating DCI1A PDCCH order, number of test cases: " 
        //           << testcaseDB[state4].size() << "\n";
        
        mutateDCI1A_broadcast_RNTI(testcaseDB[state1]);  // also RA-RNTI, P-RNTI, state 1 for RA-RNTI
        mutateDCI1C(testcaseDB[state1]);
        // std::cout << "[MTT] Mutating DCI1A SI-RNTI, number of test cases: " 
        //           << testcaseDB[state1].size() << "\n";
        

        if (fuzzingState == state4 && transmission_mode == 4){
            // DCI 0 Uplink
            mutateDCI0_FDD(testcaseDB_UL[state4]);
            mutateDCI0_FDD(testcaseDB_UL[state3]);
            // std::cout << "[MTT] Mutating DCI0 FDD, number of test cases: " 
            //           << testcaseDB_UL[state4].size() << "\n";
        }
        
        // std::cout << "[MTT] 1. DL Test case DB state1 size: " << testcaseDB[state1].size() << "\n";
        // std::cout << "[MTT] 2. DL Test case DB state2 size: " << testcaseDB[state2].size() << "\n";
        // std::cout << "[MTT] 3. DL Test case DB state3 size: " << testcaseDB[state3].size() << "\n";
        // std::cout << "[MTT] 4. DL Test case DB state4 size: " << testcaseDB[state4].size() << "\n";
        // std::cout << "[MTT] 5. UL Test case State 3 DB size: " << testcaseDB_UL[state3].size() << "\n";
        // std::cout << "[MTT] 6. UL Test case State 4 DB size: " << testcaseDB_UL[state4].size() << "\n";


    }else{ // readfromFile
    
    }

}

// int phyFuzzer_t::get_cur_testcase_idx(LLState_t state, bool isverifying){
//     if (state > 5){
//         ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
//     }
//     return idx[state];
// }

// int phyFuzzer_t::get_cur_testcase_idx_phy_ul(LLState_t state, bool isverifying){
//     if (state > 5){
//         ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
//     }
//     return idx[state];
// }

int phyFuzzer_t::get_total_idx(LLState_t state, bool isverifying){
    if (state > 5){
        ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
    }
    return (isverifying)?verifyDB[state].size():testcaseDB[state].size();
}

int phyFuzzer_t::get_total_idx_phy_ul(LLState_t state, bool isverifying){
    if (state > 5){
        ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
    }
    return (isverifying)?verifyDB_UL[state].size():testcaseDB_UL[state].size();
}

// void phyFuzzer_t::switchState(phyState_t state){
//     // std::unique_lock<std::mutex> FuzzerLock(fuzzerMutex);
//     fuzzingState = state;
//     switch (fuzzingState)
//     {
//     case state1:
//         // state1Phase = state1Prepare;
//         break;
//     case state234:
//         state234Phase = state234Prepare;
//         break;
//     case state5:
//         s5Phase = s5Prepare;
//         break;
//     case stateUnknown:
//         fuzzingState = stateUnknown;
//         s5Phase = s5None;
//         state234Phase = state234noPhase;
//         break;
//     default:
//         break;
//     }
//     // reset index
//     idx[2] = startIdx;
//     idx[3] = startIdx;
//     idx[4] = startIdx;
//     idx[5] = startIdx;

//     if (DEBUG_MODE){ 
//       printf("[MAC] Switch Fuzzer to state %d \n", state); 
//     }
//     // FuzzerLock.unlock();
// }


void phyFuzzer_t::printPDUtestcase(phyTestCase_t& pdu, int tti, int actualLen){

    std::cout << "\n";
}

void copy_dci_msg(srsran_dci_dl_t& source, srsran_dci_dl_t& target){
    target.format = source.format;
    target.rnti = source.rnti;
    target.location = source.location;
    target.ue_cc_idx = source.ue_cc_idx;

    target.alloc_type = source.alloc_type;
    if (target.alloc_type == SRSRAN_RA_ALLOC_TYPE0){
        target.type0_alloc.rbg_bitmask = source.type0_alloc.rbg_bitmask;
    }else if (target.alloc_type == SRSRAN_RA_ALLOC_TYPE1){
        target.type1_alloc.vrb_bitmask = source.type1_alloc.vrb_bitmask;
        target.type1_alloc.rbg_subset = source.type1_alloc.rbg_subset;
        target.type1_alloc.shift = source.type1_alloc.shift;
    }else if (target.alloc_type == SRSRAN_RA_ALLOC_TYPE2){
        target.type2_alloc.riv = source.type2_alloc.riv;
        target.type2_alloc.n_prb1a = source.type2_alloc.n_prb1a;
        target.type2_alloc.n_gap = source.type2_alloc.n_gap;
        target.type2_alloc.mode = source.type2_alloc.mode;
    }

    target.tb[0].mcs_idx = source.tb[0].mcs_idx;
    target.tb[1].mcs_idx = source.tb[1].mcs_idx;
    target.tb[0].ndi = source.tb[0].ndi;
    target.tb[1].ndi = source.tb[1].ndi;
    target.tb[0].rv = source.tb[0].rv;
    target.tb[1].rv = source.tb[1].rv;
    target.tb[0].cw_idx = source.tb[0].cw_idx;
    target.tb[1].cw_idx = source.tb[1].cw_idx;
    target.pinfo = source.pinfo;

    target.pconf = source.pconf;
    target.power_offset = source.power_offset;
    target.tpc_pucch = source.tpc_pucch;

    target.is_pdcch_order = source.is_pdcch_order;
    target.preamble_idx = source.preamble_idx;
    target.prach_mask_idx = source.prach_mask_idx;

    target.cif = source.cif;
    target.cif_present = source.cif_present;
    target.srs_request = source.srs_request;
    target.srs_request_present = source.srs_request_present;

    target.pid = source.pid;
    target.dai = source.dai;
    target.is_tdd = source.is_tdd;
    target.is_dwpts = source.is_dwpts;
    target.sram_id = source.sram_id;

    target.isManualDCI = source.isManualDCI;
}

bool phyFuzzer_t::send_RAR_DCI(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci){
    int ret = false;
    if (idx[1] < (int)testcaseDB[1].size()){
        // copy DCI from testcaseDB to target DCI
        target_dci = testcaseDB[fuzzingState][idx[fuzzingState]];
        //copy CCE allocation from orin DCI to target DCI
        target_dci.rnti = orin_dci.rnti;
        target_dci.location = orin_dci.location;
        target_dci.tb[0].ndi = orin_dci.tb[0].ndi;
        target_dci.tb[1].ndi = orin_dci.tb[1].ndi;

        // print DCI info
        std::cout << "[PHY] SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << " -- RNTI: " << rnti << " -- State: " \
        << fuzzingState << " -- Idx: " << idx[fuzzingState] << "|" << (int)testcaseDB[fuzzingState].size() << "\n";
        if (target_dci.format == SRSRAN_DCI_FORMAT1A){
            printDCI_format1A(target_dci);
        }else if (target_dci.format == SRSRAN_DCI_FORMAT1C){
            printDCI_format1C(target_dci);
        }else{
            // printf("[PHY] DCI format %d \n", (int)curTestCase.format);
        }

        recent_testcases[fuzzingState].push(idx[fuzzingState]);

        // increase index
        idx[fuzzingState]++;
        // if (idx[1] == (int)testcaseDB[1].size()){
        //     std::cout << " Finish sending all test cases in state " << fuzzingState << "\n";
        //     std::cout << " Switch to state Unknown" << "\n";
        //     switchState(stateUnknown);
        // }
        ret = true;
    }else{
        ret = false;
    }
    return ret;
}

bool phyFuzzer_t::send_dl_dci_testcase(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci){
    int ret = false;
    if (idx[fuzzingState] < (int)testcaseDB[fuzzingState].size()){
        curTestCase = testcaseDB[fuzzingState][idx[fuzzingState]];

        // copy DCI from testcaseDB to target DCI
        target_dci = curTestCase;
        //copy CCE allocation from orin DCI to target DCI
        target_dci.rnti = orin_dci.rnti;
        target_dci.location.L = orin_dci.location.L;
        target_dci.location.ncce = orin_dci.location.ncce;
        target_dci.tb[0].ndi = orin_dci.tb[0].ndi;
        target_dci.tb[1].ndi = orin_dci.tb[1].ndi;

        // print DCI info
        std::cout << "[PHY] SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << " -- RNTI: " << rnti << " -- State: " \
        << fuzzingState << " -- Idx: " << idx[fuzzingState] << "|" << testcaseDB[fuzzingState].size() << "\n";
        switch (target_dci.format)
        {
            case SRSRAN_DCI_FORMAT1A:
                printDCI_format1A(target_dci);
                break;
            case SRSRAN_DCI_FORMAT1:
                printDCI_format1(target_dci);
                break;
            case SRSRAN_DCI_FORMAT2:
                printDCI_format2(target_dci);
                break;
            case SRSRAN_DCI_FORMAT2A:
                printDCI_format2A(target_dci);
                break;
            case SRSRAN_DCI_FORMAT1C:
                printDCI_format1C(target_dci);
                break;
            default:
                break;
        }

        recent_testcases[fuzzingState].push(idx[fuzzingState]);

        // increase index
        if (idx[fuzzingState] < (int)testcaseDB[fuzzingState].size()){
            idx[fuzzingState]++;
        }
        // if (idx[fuzzingState] == (int)testcaseDB[fuzzingState].size()){
        //     std::cout << " Finish sending all test cases in state " << fuzzingState << "\n";
        //     std::cout << " Switch to state Unknown" << "\n";
        //     switchState(stateUnknown);
        // }
        
        ret = true;
    }else{
        ret = false;
    }
    return ret;
    
}

bool phyFuzzer_t::send_ul_dci_testcase(int tti_tx_ul, uint16_t rnti, srsran_dci_ul_t &orin_dci, srsran_dci_ul_t& target_dci){
    int ret = false;
    if (idx[fuzzingState] < (int)testcaseDB_UL[fuzzingState].size()){
        curTestCaseUL = testcaseDB_UL[fuzzingState][idx[fuzzingState]];

        // copy DCI from testcaseDB to target DCI
        target_dci = curTestCaseUL;
        //copy CCE allocation from orin DCI to target DCI
        target_dci.rnti = orin_dci.rnti;
        target_dci.location = orin_dci.location;

        // print DCI info
        std::cout << "[PHY] UL_SF: " << tti_tx_ul/10 << "." << tti_tx_ul%10 << " -- RNTI: " << rnti << " -- State: " \
        << fuzzingState << " -- Idx: " << idx[fuzzingState] << "|" << testcaseDB_UL[fuzzingState].size() << "\n";
        printDCI_format0(curTestCaseUL);

        recent_testcases[fuzzingState].push(idx[fuzzingState]);

        // increase index
        if (idx[fuzzingState] < (int)testcaseDB_UL[fuzzingState].size()){
            idx[fuzzingState]++;
        }

        // if (idx[fuzzingState] == (int)testcaseDB_UL[fuzzingState].size()){
        //     std::cout << " Finish sending all test cases in state " << fuzzingState << "\n";
        //     std::cout << " Switch to state Unknown" << "\n";
        //     switchState(stateUnknown);
        // }
        
        ret = true;
    }else{
        ret = false;
    }
    return ret;
    
}


// void phyFuzzer_t::postProcess(int tti_tx_dl, uint16_t rnti){
//     // std::unique_lock<std::mutex> FuzzerLock(fuzzerMutex);
//     // print DCI info
//     std::cout << "[PHY] SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << " -- RNTI: " << 0 << " -- State: "         // curRNTI
//     << fuzzingState << " -- Idx: " << idx[fuzzingState] << "|" << testcaseDB[fuzzingState].size() << "\n";

//     switch (curTestCase.format)
//     {
//         case SRSRAN_DCI_FORMAT1A:
//             printDCI_format1A(curTestCase);
//             break;
//         case SRSRAN_DCI_FORMAT1:
//             printDCI_format1(curTestCase);
//             break;
//         case SRSRAN_DCI_FORMAT2:
//             printDCI_format2(curTestCase);
//             break;
//         case SRSRAN_DCI_FORMAT2A:
//             printDCI_format2A(curTestCase);
//             break;
//         default:
//             break;
//     }

//     // save test cases to buffer
//     crashBuffer[fuzzingState].push(curTestCase);

//     // encrease test case index
//     if (idx[fuzzingState] < (int)testcaseDB[fuzzingState].size()){
//         idx[fuzzingState]++;
//     }else{
//         // std::cout << " Finish sending all test cases in state " << fuzzingState << "\n";
//         // switchState(stateUnknown);
//     }

//     // FuzzerLock.unlock();
// }

// void phyFuzzer_t::postProcess_UL(int tti_tx_ul, uint16_t rnti){
//     // std::unique_lock<std::mutex> FuzzerLock(fuzzerMutex);
//     // print DCI info
//     std::cout << "[PHY] SF: " << tti_tx_ul/10 << "." << tti_tx_ul%10 << " -- RNTI: " << 0 << " -- State: "    // 0
//     << fuzzingState << " -- Idx: " << idx[fuzzingState] << "|" << testcaseDB_UL[fuzzingState].size() << "\n";

//     switch (curTestCaseUL.format)
//     {
//         case SRSRAN_DCI_FORMAT0:
//         printDCI_format0(curTestCaseUL);
//             break;
//         default:
//             break;
//     }

//     // save test cases to buffer
//     crashBuffer_UL[fuzzingState].push(curTestCaseUL);

//     // encrease test case index
//     if (idx[fuzzingState] < (int)testcaseDB_UL[fuzzingState].size()){
//         idx[fuzzingState]++;
//     }else{
//         // std::cout << " Finish sending all test cases in state " << fuzzingState << "\n";
//         // switchState(stateUnknown);
//     }

//     // FuzzerLock.unlock();
// }

void phyFuzzer_t::writeTCtoFile(std::ofstream& file, phyTestCase_t& pdu){
    if (file){
        std::cout << "\n";
    }
}

void phyFuzzer_t::resetIndex(){
    idx[5] = startIdx; // verify crash
    idx[4] = startIdx; // verify crash
    idx[3] = startIdx;
    idx[2] = startIdx;
    
}

void phyFuzzer_t::update_rlc_sequence_number(uint16_t lcid, uint16_t sn){
    rlcSNmap[lcid] = sn;
}

void phyFuzzer_t::save_orin_dl_dci_for_reference(srsran_dci_dl_t source){
    srsran_dci_format_t format = source.format;
    uint16_t rnti = source.rnti;
    
    if(format == SRSRAN_DCI_FORMAT1 && !has_dci1_orin){ 
        dci1_orin = source;
        has_dci1_orin = true;
        // save dci to file
        save_dci_to_file(dci1_orin, dci1_file);
        printf("[PHY] Save DCI1 to file\n");
    }else if (format == SRSRAN_DCI_FORMAT2 && !has_dci2_orin){
        dci2_orin = source;
        has_dci2_orin = true;
        // save dci to file
        save_dci_to_file(dci2_orin, dci2_file);
        printf("[PHY] Save DCI2 to file\n");
    }else if (format == SRSRAN_DCI_FORMAT2A && !has_dci2A_orin){
        dci2A_orin = source;
        has_dci2A_orin = true;
        // save dci to file
        save_dci_to_file(dci2A_orin, dci2A_file);
        printf("[PHY] Save DCI2A to file\n");
    }else if (format == SRSRAN_DCI_FORMAT1A && rnti > SRSRAN_RARNTI_END && rnti < SRSRAN_PRNTI && !has_dci1A_orin){
        dci1A_orin = source;
        has_dci1A_orin = true;
        // save dci to file
        save_dci_to_file(dci1A_orin, dci1A_file);
        printf("[PHY] Save DCI1A to file\n");
    } else if (format == SRSRAN_DCI_FORMAT1A && ((rnti > SRSRAN_RARNTI_START && rnti < SRSRAN_RARNTI_END) || rnti == SRSRAN_PRNTI || rnti == SRSRAN_SIRNTI) && !has_dci1A_broadcast_orin){
        dci1A_broadcast_orin = source;
        has_dci1A_broadcast_orin = true;
        // save dci to file
        save_dci_to_file(dci1A_broadcast_orin, dci1A_broadcast_file);
        printf("[PHY] Save DCI1A broadcast to file\n");
    }

}

void phyFuzzer_t::save_orin_ul_dci_for_reference(srsran_dci_ul_t source){
    srsran_dci_format_t format = source.format;
    uint16_t rnti = source.rnti;
    if (format == SRSRAN_DCI_FORMAT0 && !has_dci0_orin){
        dci0_orin = source;
        has_dci0_orin = true;
        // save dci to file
        save_ul_dci_to_file(dci0_orin, dci0_file);
        printf("[PHY] Save DCI0 to file\n");
    }
}

void phyFuzzer_t::save_dci_to_file(srsran_dci_dl_t dci, std::string filename){
    // Open file
    std::ofstream file;
    file.open(filename, std::ios::out | std::ios::app);
    
    if (file){
        // Write the structure to the file
        file << dci.rnti << "\n";
        file << dci.format << "\n";
        file << dci.location.L << "\n";
        file << dci.location.ncce << "\n";
        file << dci.ue_cc_idx << "\n";
        file << dci.alloc_type << "\n";
        
        switch (dci.alloc_type) {
            case SRSRAN_RA_ALLOC_TYPE0:
                file << dci.type0_alloc.rbg_bitmask << "\n";
                break;
            case SRSRAN_RA_ALLOC_TYPE1:
                file << dci.type1_alloc.vrb_bitmask << "\n";
                file << dci.type1_alloc.rbg_subset << "\n";
                file << dci.type1_alloc.shift << "\n";
                break;
            case SRSRAN_RA_ALLOC_TYPE2:
                file << dci.type2_alloc.riv << "\n";
                file << dci.type2_alloc.n_prb1a << "\n";
                file << dci.type2_alloc.n_gap << "\n";
                file << dci.type2_alloc.mode << "\n";
                break;
        }

        for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
            file << dci.tb[i].mcs_idx << "\n";
            file << dci.tb[i].rv << "\n";
            file << dci.tb[i].ndi << "\n";
            file << dci.tb[i].cw_idx << "\n";
        }

        file << dci.tb_cw_swap << "\n";
        file << dci.pinfo << "\n";
        file << dci.pconf << "\n";
        file << dci.power_offset << "\n";
        file << dci.tpc_pucch << "\n";
        file << dci.is_pdcch_order << "\n";
        file << dci.preamble_idx << "\n";
        file << dci.prach_mask_idx << "\n";
        file << dci.cif << "\n";
        file << dci.cif_present << "\n";
        file << dci.srs_request << "\n";
        file << dci.srs_request_present << "\n";
        file << dci.pid << "\n";
        file << dci.dai << "\n";
        file << dci.is_tdd << "\n";
        file << dci.is_dwpts << "\n";
        file << dci.sram_id << "\n";
        file << dci.isManualDCI << "\n";

        // Close the file
        file.close();
    } else {
        std::cerr << "Unable to open file: " << filename << "\n";
    }
}

srsran_dci_dl_t phyFuzzer_t::read_dci_from_file(std::string filename){
    srsran_dci_dl_t dci;
    std::ifstream file;
    file.open(filename, std::ios::in);
    
    if (file){
        // Read the structure from the file
        file >> dci.rnti;
        int format;
        file >> format;
        dci.format = static_cast<srsran_dci_format_t>(format);
        file >> dci.location.L;
        file >> dci.location.ncce;
        file >> dci.ue_cc_idx;
        int alloc_type;
        file >> alloc_type;
        dci.alloc_type = static_cast<srsran_ra_type_t>(alloc_type);
        
        switch (dci.alloc_type) {
            case SRSRAN_RA_ALLOC_TYPE0:
                file >> dci.type0_alloc.rbg_bitmask;
                break;
            case SRSRAN_RA_ALLOC_TYPE1:
                file >> dci.type1_alloc.vrb_bitmask;
                file >> dci.type1_alloc.rbg_subset;
                file >> dci.type1_alloc.shift;
                break;
            case SRSRAN_RA_ALLOC_TYPE2:
                file >> dci.type2_alloc.riv;
                int n_prb1a, n_gap, mode;
                file >> n_prb1a;
                dci.type2_alloc.n_prb1a = static_cast<decltype(dci.type2_alloc.n_prb1a)>(n_prb1a);
                file >> n_gap;
                dci.type2_alloc.n_gap = static_cast<decltype(dci.type2_alloc.n_gap)>(n_gap);
                file >> mode;
                dci.type2_alloc.mode = static_cast<decltype(dci.type2_alloc.mode)>(mode);
                break;
        }

        for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
            file >> dci.tb[i].mcs_idx;
            file >> dci.tb[i].rv;
            file >> dci.tb[i].ndi;
            file >> dci.tb[i].cw_idx;
        }

        file >> dci.tb_cw_swap;
        file >> dci.pinfo;
        file >> dci.pconf;
        file >> dci.power_offset;
        file >> dci.tpc_pucch;
        file >> dci.is_pdcch_order;
        file >> dci.preamble_idx;
        file >> dci.prach_mask_idx;
        file >> dci.cif;
        file >> dci.cif_present;
        file >> dci.srs_request;
        file >> dci.srs_request_present;
        file >> dci.pid;
        file >> dci.dai;
        file >> dci.is_tdd;
        file >> dci.is_dwpts;
        file >> dci.sram_id;
        file >> dci.isManualDCI;

        // Close the file
        file.close();
    } else {
        std::cerr << "Unable to open file: " << filename << "\n";
    }

    return dci;
}

void phyFuzzer_t::save_ul_dci_to_file(srsran_dci_ul_t dci, std::string filename) {
    // Open file
    std::ofstream file;
    file.open(filename, std::ios::out | std::ios::app);
    
    if (file) {
        // Write the structure to the file
        file << dci.rnti << "\n";
        file << dci.format << "\n";
        file << dci.location.L << "\n";
        file << dci.location.ncce << "\n";
        file << dci.ue_cc_idx << "\n";
        
        // Write type2_alloc
        file << dci.type2_alloc.riv << "\n";
        file << dci.type2_alloc.n_prb1a << "\n";
        file << dci.type2_alloc.n_gap << "\n";
        file << dci.type2_alloc.mode << "\n";
        
        // Write frequency hopping flag
        file << dci.freq_hop_fl << "\n";
        
        // Write transport block info
        file << dci.tb.mcs_idx << "\n";
        file << dci.tb.rv << "\n";
        file << dci.tb.ndi << "\n";
        file << dci.tb.cw_idx << "\n";
        
        file << dci.n_dmrs << "\n";
        file << dci.cqi_request << "\n";
        
        // Write TDD parameters
        file << dci.dai << "\n";
        file << dci.ul_idx << "\n";
        file << dci.is_tdd << "\n";
        
        // Write power control
        file << static_cast<int>(dci.tpc_pusch) << "\n";
        
        // Write Release 10 parameters
        file << dci.cif << "\n";
        file << dci.cif_present << "\n";
        file << static_cast<int>(dci.multiple_csi_request) << "\n";
        file << dci.multiple_csi_request_present << "\n";
        file << dci.srs_request << "\n";
        file << dci.srs_request_present << "\n";
        file << dci.ra_type << "\n";
        file << dci.ra_type_present << "\n";
        
        // Close the file
        file.close();
    } else {
        std::cerr << "Unable to open file: " << filename << "\n";
    }
}

srsran_dci_ul_t phyFuzzer_t::read_ul_dci_from_file(std::string filename) {
    srsran_dci_ul_t dci;
    std::ifstream file;
    file.open(filename, std::ios::in);

    if (file) {
        // Read the structure from the file
        file >> dci.rnti;
        int format;
        file >> format;
        dci.format = static_cast<srsran_dci_format_t>(format);
        file >> dci.location.L;
        file >> dci.location.ncce;
        file >> dci.ue_cc_idx;
        
        // Read type2_alloc
        file >> dci.type2_alloc.riv;
        int n_prb1a, n_gap, mode;
        file >> n_prb1a;
        dci.type2_alloc.n_prb1a = static_cast<decltype(dci.type2_alloc.n_prb1a)>(n_prb1a);
        file >> n_gap;
        dci.type2_alloc.n_gap = static_cast<decltype(dci.type2_alloc.n_gap)>(n_gap);
        file >> mode;
        dci.type2_alloc.mode = static_cast<decltype(dci.type2_alloc.mode)>(mode);
        
        // Read frequency hopping flag
        int freq_hop;
        file >> freq_hop;
        dci.freq_hop_fl = static_cast<decltype(dci.freq_hop_fl)>(freq_hop);
        
        // Read transport block info
        file >> dci.tb.mcs_idx;
        file >> dci.tb.rv;
        file >> dci.tb.ndi;
        file >> dci.tb.cw_idx;
        
        file >> dci.n_dmrs;
        file >> dci.cqi_request;
        
        // Read TDD parameters
        file >> dci.dai;
        file >> dci.ul_idx;
        file >> dci.is_tdd;
        
        // Read power control
        int tpc_pusch;
        file >> tpc_pusch;
        dci.tpc_pusch = static_cast<uint8_t>(tpc_pusch);
        
        // Read Release 10 parameters
        file >> dci.cif;
        file >> dci.cif_present;
        int multiple_csi_request;
        file >> multiple_csi_request;
        dci.multiple_csi_request = static_cast<uint8_t>(multiple_csi_request);
        file >> dci.multiple_csi_request_present;
        file >> dci.srs_request;
        file >> dci.srs_request_present;
        int ra_type;
        file >> ra_type;
        dci.ra_type = static_cast<srsran_ra_type_t>(ra_type);
        file >> dci.ra_type_present;
        
        // Close the file
        file.close();
    } else {
        std::cerr << "Unable to open file: " << filename << "\n";
    }

    return dci;
}

} // namespace srsran



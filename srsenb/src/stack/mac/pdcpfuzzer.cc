#include "srsenb/hdr/stack/mac/pdcpfuzzer.h"
#include "srsenb/hdr/stack/mac/utility.h"


namespace srsenb {

pdcpFuzzer_t::pdcpFuzzer_t()
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
}

pdcpFuzzer_t::~pdcpFuzzer_t()
{
    // crashLog.close();
    tcFile.close();
    terminalLog.close();
    verifiedCrash.close();
}

// void pdcpFuzzer_t::set_fuzzing_config(LLState_t targetState_, bool verifyingMode_, int startIdx_){
//     fuzzingState = targetState_;
//     readFromFileMode = verifyingMode_;
//     startIdx = startIdx_;
// }

void pdcpFuzzer_t::print_test_case_to_file(pdcpPDU_t& pdu, std::ofstream& file) {
    pdcpPDUType_t type = pdu.type;
    std::string typeStr = getPDUTypeString(type);

    file << "[PDU] Type = " << typeStr << " - LCID: " << pdu.lcid << " - totalByte = " << (int)pdu.totalByte 
         << " -- rlcSN = " << (int)pdu.rlcSN << " -- rlcType: " << (int)pdu.rlcType 
         << " - eIdx = " << (int)pdu.eIdx << "\n";

    if (type == pdcpData) {
        std::shared_ptr<pdcpDataPDU_t> data = pdu.data;
        file << "[PDU] isSRB: " << data->isSRB << " -- snLen: " << (int)pdu.data->snLen << " -- R1: " << data->R1 
             << " -- P: " << data->P << " -- SN: " << data->SN << " -- dataSz: " << data->datasize 
             << " -- WMAC: " << data->isWrongMAC << "\n";
    } else if (type == pdcpStatus) {
        std::shared_ptr<pdcpStatusPDU_t> status = pdu.status;
        file << "[PDU] FMS: " << status->FMS << " -- nofBitmap: " << status->nofBitmap << "\n";
        if (status->nofBitmap > 0) {
            file << "[PDU] Bitmap: ";
            int nofBitmaptemp = (status->nofBitmap > 3) ? 3 : status->nofBitmap;
            for (int i = 0; i < nofBitmaptemp; i++) {
                file << (int)status->bitmap[i] << " ";
            }
            file << "\n";
        }
    } else if (type == pdcpROHCfeedback) {
        std::shared_ptr<pdcpROHCfeedbackPDU_t> rohc = pdu.rohcFeedback;
        file << "[PDU] nofBytes: " << rohc->nofByte << "\n";
        if (rohc->nofByte > 0) {
            file << "[PDU] Feedback: ";
            int nofBytestemp = (rohc->nofByte > 3) ? 3 : rohc->nofByte;
            for (int i = 0; i < nofBytestemp; i++) {
                file << (int)rohc->feedback[i] << " ";
            }
            file << "\n";
        }
    } else if (type == pdcpLWAstatus) {
        std::shared_ptr<pdcpLWAstatusPDU_t> lwaStatus = pdu.lwaStatus;
        file << "[PDU] FMS: " << lwaStatus->FMS << " -- HRW: " << lwaStatus->HRW << " -- NMP: " << lwaStatus->NMP << "\n";
    } else if (type == pdcpLWAendmarker) {
        std::shared_ptr<pdcpLWAendmarkerPDU_t> lwaEndMarker = pdu.lwaEndmarker;
        file << "[PDU] LSN: " << lwaEndMarker->LSN << "\n";
    } else if (type == pdcpUDCfeedback) {
        std::shared_ptr<pdcpUDCfeedbackPDU_t> udcFeedback = pdu.udcFeedback;
        file << "[PDU] FE: " << udcFeedback->FE << "\n";
    } else if (type == pdcpEHCfeedback) {
        std::shared_ptr<pdcpECHfeedbackPDU_t> ehcFeedback = pdu.echFeedback;
        file << "[PDU] nofBytes: " << ehcFeedback->nofBytes << "\n";
        if (ehcFeedback->nofBytes > 0) {
            file << "[PDU] Feedback: ";
            int nofBytestemp = (ehcFeedback->nofBytes > 3) ? 3 : ehcFeedback->nofBytes;
            for (int i = 0; i < nofBytestemp; i++) {
                file << (int)ehcFeedback->feedback[i] << " ";
            }
            file << "\n";
        }
    } else if (type == pdcpReserved) {
        std::shared_ptr<pdcpReservedPDU_t> reservedPDU = pdu.reserved;
        file << "[PDU] pduType: " << (int)reservedPDU->pduType << "\n";
    }

    file << "\n";
}

// TODO:
void pdcpFuzzer_t::saveCrashtoFile(int oracle){
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

    // save recent testcase in the crash buffer to file
    std::deque<pdcpPDU_t> recent_pdu = crashBuffer.getBuffer();
    crashLogFile << " Recent PDU: " << "\n";
    for (int i = 0; i < (int)recent_pdu.size(); i++){
        recent_pdu[i].print_general_info_to_file(crashLogFile);
        print_test_case_to_file(recent_pdu[i], crashLogFile);
    }

    crashLogFile << "\n";
    crashLogFile << "\n";
    nofCrash++;
}

int pdcpFuzzer_t::getFixedHeaderSize(pdcpPDUType_t type, bool isSRB, int snLen){
    int size = 0;
    switch (type)
    {
    case pdcpData:
        if  (isSRB){ size = 1;}
        else { size = 2;}
    // case rlcUM2:
    //     if (snLen == 10){ size = 2; }
    //     else if (snLen == 5){ size = 1; }
    //     break;
    // case rlcAM1:
    // case rlcAM2:
    //     if (snLen == 16){ size = 3; }
    //     else if (snLen == 10){ size = 2; }
    //     break;
    //     /* code */
    //     break;
    // case rlcAMSegment1:
    // case rlcAMSegment2:
    //     if (snLen == 10) {size = 4;}
    //     else if (snLen == 16) {size = 5;}
    //     break;
    default:
        break;
    }
    return size;
}

void allocVectorPDU(pdcpPDU_t& pdu, int nofChunk){
//   for (int n = 0; n < nofChunk; n++){
//     rlcChunk_t newChunk = {};
//   }
}

int pdcpFuzzer_t::calTotalByte(pdcpPDU_t& pdu){
    int totalByte = 0;
    switch (pdu.type)
    {
    case pdcpData:
        if (pdu.data->isSRB){
            if (pdu.eIdx == -1){ totalByte = 1; }
            if (pdu.eIdx == -2){ totalByte = 2; }
            if (pdu.eIdx == -3){ totalByte = 3; }
            if (pdu.eIdx == -4){ totalByte = 4; }
            if (pdu.eIdx == -5){ totalByte = 5; }
            if (pdu.eIdx == -6){ totalByte = pdu.data->datasize + 5 + getFixedHeaderSize(pdcpData, pdu.data->isSRB, 5); } // 5 bytes for MAC-I
        }
        else{ 
            // general part for all snLen
            if (pdu.eIdx == -1){ totalByte = 1; }
            if (pdu.eIdx == -2){ totalByte = 2; }
            if (pdu.eIdx == -3){ totalByte = 3; }
            // specific part for each snLen
            if (pdu.data->snLen == 18){
                if (pdu.eIdx == 0){ totalByte = 4;} // 1 byte data
            }
        }
        break;
    case pdcpROHCfeedback:
        if (pdu.eIdx < 5){
            totalByte = 1 + pdu.rohcFeedback->nofByte; // 1 byte for fixed header and nofByte for feedback
        }
        break;
    case pdcpStatus:
        /* eIdx = -1: 1 byte  (12 bit SN)
        *  eIdx =  0: 2 bytes, all 1 bits
        *  eIdx =  1: 3 bytes
        *  eIdx =  2: 4 bytes
        *  eIdx =  3: 5 bytes
        *  eIdx =  4: 1000 bytes, all 0 or 1 until the middle, and full 1 bits
        *  
        */
        if (pdu.eIdx < 4){ totalByte = pdu.eIdx + 2; }
        if (pdu.eIdx == 4 ){ totalByte = 1000 + 2; } // 1000 bytes bitmap + 2 bytes fixed header
        break;
    case pdcpLWAstatus:
        /* eIdx = -1: 1 byte (12 bit SN)
        *  eIdx =  0: 2 bytes, all 1 bits
        *  eIdx =  1: 3 bytes, fms = all 1 bits
        *  eIdx =  2: 4 bytes, fms = all 1 bits
        *  eIdx =  3: 5 bytes, fms = all 1 bits
        *  eIdx =  4: 1000 bytes, all 0 or 1 bitmap, all 1 bit fms
        *  const uint8_t pduType = 2; in structure 
        */
        if (pdu.eIdx < 4 && pdu.lwaStatus->snLen == 12) {totalByte = pdu.eIdx + 2;}
        else if (pdu.eIdx == 4 && pdu.lwaStatus->snLen == 12){ totalByte = 1000; }
        else if (pdu.eIdx < 6 && pdu.lwaStatus->snLen == 15){ totalByte = pdu.eIdx + 2; }
        else if (pdu.eIdx == 6 && pdu.lwaStatus->snLen == 15){ totalByte = 1000; }
        else if (pdu.eIdx < 7 && pdu.lwaStatus->snLen == 18){ totalByte = pdu.eIdx + 2; }
        else if (pdu.eIdx == 7 && pdu.lwaStatus->snLen == 18){ totalByte = 1000; }
        break;
    default:
        break;
    }
    return totalByte;
}

void pdcpFuzzer_t::generate_initial_pdcp_data_pdu_srb(pdcpPDU_t& initial_pdu, int snLen){
    initial_pdu.data->isSRB = true;
    initial_pdu.data->snLen = snLen;
    initial_pdu.data->datasize = 1;
    initial_pdu.data->R1 = 1;
    initial_pdu.data->R2 = 0;
    initial_pdu.data->SN = 0;
}

void pdcpFuzzer_t::generate_initial_pdcp_data_pdu_drb(pdcpPDU_t& initial_pdu, int snLen){
    initial_pdu.data->isSRB = false;
    initial_pdu.data->snLen = snLen;
    // DC already const = 1 for data PDU, 0 for status PDU
    // initial_pdu.data->DC = 1; // 
    initial_pdu.data->datasize = 1;
    initial_pdu.data->R1 = 1;
    initial_pdu.data->R2 = 0;
    initial_pdu.data->R3 = 0;
}

void pdcpFuzzer_t::generate_initial_pdcp_status_pdu(pdcpPDU_t& initial_pdu, int snLen){
    // we dont need to set DC and pduType here because they are const already in the structure
    initial_pdu.status->snLen = snLen;
    initial_pdu.status->FMS = 0;        // this value will be mutated later so just set to 0 here
    initial_pdu.status->nofBitmap = 0;  // this value will be mutated later so just set to 0 here
}

void pdcpFuzzer_t::generate_initial_pdcp_lwa_status_pdu(pdcpPDU_t& initial_pdu, int snLen){
    // we dont need to set DC and pduType here because they are const already in the structure
    initial_pdu.lwaStatus->snLen = snLen;
    initial_pdu.lwaStatus->FMS = 0;        // this value will be mutated later so just set to 0 here
    initial_pdu.lwaStatus->HRW = 0;     // this value will be mutated later so just set to 0 here
    initial_pdu.lwaStatus->NMP = 0;     // this value will be mutated later so just set to 0 here
    initial_pdu.lwaStatus->R1 = 0;  
    initial_pdu.lwaStatus->R2 = 0;  
}

void pdcpFuzzer_t::generate_initial_pdcp_lwa_endmarker_pdu(pdcpPDU_t& initial_pdu, int snLen){
    // we dont need to set DC and pduType here because they are const already in the structure
    initial_pdu.lwaEndmarker->snLen = snLen;
    initial_pdu.lwaEndmarker->LSN = 0;        // this value will be mutated later so just set to 0 here
    initial_pdu.lwaEndmarker->R1 = 0;  
    initial_pdu.lwaEndmarker->R2 = 0;  
    initial_pdu.lwaEndmarker->R3 = 0;  
    initial_pdu.lwaEndmarker->R4 = 0;  
}


/* eIdx = -1: 1 byte
*  eIdx = -2: 2 bytes (for srb, header is always 1 byte, plus 4 bytes for MAC-I)
*  eIdx = -3: 3 bytes 
*  eIdx = -4: 4 bytes 
*  eIdx = -5: 5 bytes, wrong MAC-I 
*  eIdx = -6: R1 = 1
*/
void pdcpFuzzer_t::mutatePDCPDataPDUSRB(std::vector<pdcpPDU_t>& pduDB, int lcid){

    // generate initial pdcp data pdu for SRB. Fixed snLen = 5
    pdcpPDU_t initial_pdu(pdcpData);
    generate_initial_pdcp_data_pdu_srb(initial_pdu, 5);
    
    std::vector<int>& snList = snList5bit; // 5 bit for SRB
    for (int eIdx = -5; eIdx < 0; eIdx++){
        for (auto& sn : snList){
            pdcpPDU_t lv1PDUtemp(pdcpData);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            if (lv1PDUtemp.type == pdcpData){ // 5 bit for SRB
                lv1PDUtemp.data->datasize = 0;
                lv1PDUtemp.data->SN = sn;
            }
            
            // mapping to RLC header
            lv1PDUtemp.rlcType = rlcAM1;
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
            pduDB.push_back(lv1PDUtemp);
        }
    }
    int eIdx = -6;
    for (auto& sn : snList){
        for (auto& r: rList){
            pdcpPDU_t lv2PDUtemp(pdcpData);
            lv2PDUtemp = initial_pdu;
            
            // packet truncation and mutation
            lv2PDUtemp.eIdx = eIdx;
            if (lv2PDUtemp.type == pdcpData){
                // lv2PDUtemp.data->isSRB = true;
                // lv2PDUtemp.data->snLen = 5; // 5 bit for SRB
                lv2PDUtemp.data->datasize = 1;
                lv2PDUtemp.data->SN = sn;
                lv2PDUtemp.data->R1 = r;
            }
            // mapping to RLC header
            lv2PDUtemp.rlcType = rlcAM1;
            // mapping to LCID
            lv2PDUtemp.lcid = lcid;
            // calculate total byte
            lv2PDUtemp.totalByte = calTotalByte(lv2PDUtemp);
            pduDB.push_back(lv2PDUtemp);
        }
        
    }
}

/* eIdx = -1: 1 byte
*  eIdx = -2: 2 bytes (this mean datasize = 0)
*/
void pdcpFuzzer_t::mutatePDCPDataPDUDRB_12bitSN(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){

    // generate initial pdcp data pdu for DRB. Fixed snLen = 12
    pdcpPDU_t initial_pdu(pdcpData);
    generate_initial_pdcp_data_pdu_drb(initial_pdu, 12);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;

    for (int i = -2; i < 0; i ++){
        for (auto& sn: snList){
            for (auto& r: rList){
                pdcpPDU_t lv1PDUtemp(pdcpData);
                lv1PDUtemp.rlcType = rlcUM1;
                lv1PDUtemp = initial_pdu;

                // packet truncation and mutation
                lv1PDUtemp.eIdx = i;
                if (lv1PDUtemp.type == pdcpData){
                    // lv1PDUtemp.data->isSRB = false;
                    // lv1PDUtemp.data->snLen = snLen; 
                    lv1PDUtemp.data->datasize = 0;
                    lv1PDUtemp.data->SN = sn;
                    lv1PDUtemp.data->R1 = r;
                }
                // mapping to RLC header
                lv1PDUtemp.rlcType = rlcUM1;
                // mapping to LCID
                lv1PDUtemp.lcid = lcid;
                // calculate total byte
                lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv1PDUtemp);
            }
        }
    }

}

/* eIdx = -1: 1 byte
*  eIdx = -2: 2 bytes (this mean datasize = 0)
*  Note: 15/18/7 bit SN is not implemented the calTotalByte and composing function yet
*/
void pdcpFuzzer_t::mutatePDCPDataPDUDRB_15bitSN(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){

    // generate initial pdcp data pdu for DRB. Fixed snLen = 15
    pdcpPDU_t initial_pdu(pdcpData);
    generate_initial_pdcp_data_pdu_drb(initial_pdu, 15);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;

    for (int i = -2; i < 0; i ++){
        for (auto& sn: snList){
            for (auto& r: rList){
                pdcpPDU_t lv1PDUtemp(pdcpData);
                lv1PDUtemp = initial_pdu;

                // packet truncation and mutations
                lv1PDUtemp.rrc_reconfig_type = PDCP_15BIT_SN;
                lv1PDUtemp.eIdx = i;
                if (lv1PDUtemp.type == pdcpData){
                    // lv1PDUtemp.data->isSRB = false;
                    // lv1PDUtemp.data->snLen = snLen; 
                    lv1PDUtemp.data->datasize = 0;
                    lv1PDUtemp.data->SN = sn;
                    lv1PDUtemp.data->R1 = r;
                }
                // mapping to RLC header
                lv1PDUtemp.rlcType = rlcAM1;
                // mapping to LCID
                lv1PDUtemp.lcid = lcid;
                // calculate total byte
                lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv1PDUtemp);
            }
        }
    }

}

void pdcpFuzzer_t::mutatePDCPDataPDUDRB_7bitSN(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){

    // generate initial pdcp data pdu for DRB. Fixed snLen = 7
    pdcpPDU_t initial_pdu(pdcpData);
    generate_initial_pdcp_data_pdu_drb(initial_pdu, 7);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;

    for (int i = -2; i < 0; i ++){
        for (auto& sn: snList){
            for (auto& r: rList){
                pdcpPDU_t lv1PDUtemp(pdcpData);
                lv1PDUtemp = initial_pdu;
                // packet truncation and mutations
                lv1PDUtemp.rrc_reconfig_type = PDCP_7BIT_SN;
                lv1PDUtemp.eIdx = i;
                if (lv1PDUtemp.type == pdcpData){
                    // lv1PDUtemp.data->isSRB = false;
                    // lv1PDUtemp.data->snLen = snLen; 
                    lv1PDUtemp.data->datasize = 0;
                    lv1PDUtemp.data->SN = sn;
                    lv1PDUtemp.data->R1 = r;
                }
                // mapping to RLC header
                lv1PDUtemp.rlcType = rlcUM1;
                // mapping to LCID
                lv1PDUtemp.lcid = lcid;
                // calculate total byte
                lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv1PDUtemp);
            }
        }
    }

}

/* eIdx =  0: 1 byte  (datasize = 1 byte)
*  eIdx = -1: 1 byte
*  eIdx = -2: 2 bytes
*  eIdx = -3: 3 bytes (this mean datasize = 0)
*/
void pdcpFuzzer_t::mutatePDCPDataPDUDRB_18bitSN(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){

    // generate initial pdcp data pdu for DRB. Fixed snLen = 18
    pdcpPDU_t initial_pdu(pdcpData);
    generate_initial_pdcp_data_pdu_drb(initial_pdu, 18);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;

    for (int i = -2; i < 0; i ++){
        for (auto& sn: snList){
            for (auto& r: rList){
                for (int p = 0; p < 2; p++){
                    pdcpPDU_t lv1PDUtemp(pdcpData);
                    lv1PDUtemp = initial_pdu;
                    // packet truncation and mutations
                    lv1PDUtemp.rrc_reconfig_type = PDCP_18BIT_SN;
                    lv1PDUtemp.eIdx = i;
                    if (lv1PDUtemp.type == pdcpData){
                        // lv1PDUtemp.data->isSRB = false;
                        // lv1PDUtemp.data->snLen = snLen; 
                        lv1PDUtemp.data->datasize = 0;
                        lv1PDUtemp.data->SN = sn;
                        lv1PDUtemp.data->R1 = r;
                        lv1PDUtemp.data->P = p;
                    }
                    // mapping to RLC header
                    lv1PDUtemp.rlcType = rlcAM1;
                    // mapping to LCID
                    lv1PDUtemp.lcid = lcid;
                    // calculate total byte
                    lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                    pduDB.push_back(lv1PDUtemp);
                }
            }
        }
    }

}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes
*  eIdx =  1: 3 bytes 
*  eIdx =  3: 4 bytes 
*  eIdx =  4: 1000 bytes, random feedback packet
*  
*/
void pdcpFuzzer_t::mutateROHCFeedback(std::vector<pdcpPDU_t>& pduDB, int lcid){
    for (int eIdx = -1; eIdx < 4; eIdx++){
        pdcpPDU_t lv1PDUtemp(pdcpROHCfeedback);
        lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
        lv1PDUtemp.lcid = lcid;
        lv1PDUtemp.eIdx = eIdx;
        if (lv1PDUtemp.type == pdcpROHCfeedback){
            lv1PDUtemp.rohcFeedback->nofByte = eIdx + 1;
            for (int j = 0; j < lv1PDUtemp.rohcFeedback->nofByte; j++){
                for (int k = 0; k < 9; k++){
                    uint8_t feedbacktemp = pow(2, k) - 1;
                    lv1PDUtemp.rohcFeedback->feedback.push_back(feedbacktemp);
                }
            }
        }
        lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
        pduDB.push_back(lv1PDUtemp);
    }
    int eIdx = 4;
    pdcpPDU_t lv1PDUtemp(pdcpROHCfeedback);
    lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
    lv1PDUtemp.lcid = lcid;
    lv1PDUtemp.eIdx = eIdx;
    if (lv1PDUtemp.type == pdcpROHCfeedback){
        lv1PDUtemp.rohcFeedback->nofByte = 1000;
        std::vector<uint8_t> byteList(255, 0); // all 1 or all 0
        for (auto& byte : byteList){
            for (int j = 0; j < lv1PDUtemp.rohcFeedback->nofByte; j++){
                lv1PDUtemp.rohcFeedback->feedback.push_back(byte);
            }
            lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
            pduDB.push_back(lv1PDUtemp);
        }
    }
}

void pdcpFuzzer_t::recursiveBitmapMutation(int depth, int maxDepth, std::vector<uint8_t>& bitmapList, pdcpPDU_t& pdu, std::vector<pdcpPDU_t>& pduDB){
    if (depth == maxDepth){
        pdcpPDU_t finalPDU = pdu;
        finalPDU.totalByte = calTotalByte(finalPDU);
        pduDB.push_back(finalPDU);
    }else{
        for (auto& bitmap: bitmapList){
            pdu.status->bitmap.at(depth) = bitmap;
            recursiveBitmapMutation(depth+1, maxDepth, bitmapList, pdu, pduDB);
        }
    }
}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes, all 1 bits
*  eIdx =  1: 3 bytes
*  eIdx =  2: 4 bytes
*  eIdx =  3: 5 bytes
*  eIdx =  4: 1000 bytes, all 0 or 1 until the middle, and full 1 bits
*  
*/
void pdcpFuzzer_t::mutatePdcpStatusPDU_12bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){

    // generate initial pdcp status pdu for DRB
    pdcpPDU_t initial_pdu(pdcpStatus);
    generate_initial_pdcp_status_pdu(initial_pdu, 12);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    std::vector<uint8_t> bitmapList = {0b00000000, 0b11110000, 0b11111111};

    for (int eIdx = -1; eIdx < 4; eIdx++){
        for (auto& fms: snList){
            pdcpPDU_t lv1PDUtemp(pdcpStatus);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            // mapping to RLC header
            lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;

            if (eIdx < 1){ // only mutate fsm because no bitmap
                lv1PDUtemp.status->FMS = fms;
                lv1PDUtemp.status->nofBitmap = 0;
                lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv1PDUtemp);
            }else if (eIdx >= 1 && eIdx < 4){
                int nofBitmap = eIdx;
                for (int b = 0; b < nofBitmap; b++ ){
                    lv1PDUtemp.status->bitmap.push_back(0xFF); // all 1
                }
                recursiveBitmapMutation(0, nofBitmap, bitmapList, lv1PDUtemp, pduDB);
            }

        }
    }

    int eIdx = 4; // 1000 bytes
    for (auto& fms: snList){
        pdcpPDU_t lv1PDUtemp(pdcpStatus);
        lv1PDUtemp = initial_pdu;

        // packet truncation and mutation
        lv1PDUtemp.eIdx = eIdx;
        // mapping to RLC header
        lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
        // mapping to LCID
        lv1PDUtemp.lcid = lcid;
        // lv1PDUtemp.status->snLen = snLen;

        if (lv1PDUtemp.type == pdcpStatus){
            lv1PDUtemp.status->FMS = fms;
            lv1PDUtemp.status->nofBitmap = 1000;
            for (int j = 0; j < lv1PDUtemp.status->nofBitmap; j++){
                lv1PDUtemp.status->bitmap.push_back(0xFF); // all 1
            }
            for (auto & bitmap: bitmapList){
                pdcpPDU_t lv2PDUtemp = lv1PDUtemp;
                for (int j = 0; j < lv1PDUtemp.status->nofBitmap; j++){
                    lv2PDUtemp.status->bitmap.at(j) = bitmap;
                }
                lv2PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv2PDUtemp);
            }
        }
    }

}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes
*  eIdx =  1: 3 bytes
*  eIdx =  2: 4 bytes, 1 byte bitmap (fixed header is 3 bytes)
*  eIdx =  3: 5 bytes, 2 bytes bitmap
*  eIdx =  4: 1000 bytes, all 0 or 1 bitmap, all 1 bit fms
*  
*/
void pdcpFuzzer_t::mutatePdcpStatusPDU_15bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){

    // generate initial pdcp status pdu for DRB
    pdcpPDU_t initial_pdu(pdcpStatus);
    generate_initial_pdcp_status_pdu(initial_pdu, 15);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    std::vector<uint8_t> bitmapList = {0b00000000, 0b11110000, 0b11111111};

    for (int eIdx = -1; eIdx < 4; eIdx++){
        for (auto& fms: snList){
            pdcpPDU_t lv1PDUtemp(pdcpStatus);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            lv1PDUtemp.rrc_reconfig_type = PDCP_15BIT_SN;
            // mapping to RLC header
            lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;

            if (eIdx < 1){ // only mutate fsm because no bitmap
                lv1PDUtemp.status->FMS = fms;
                lv1PDUtemp.status->nofBitmap = 0;
                lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv1PDUtemp);
            }else if (eIdx >= 2 && eIdx < 4){
                int nofBitmap = eIdx - 1; // fixed header is 3 bytes
                for (int b = 0; b < nofBitmap; b++ ){
                    lv1PDUtemp.status->bitmap.push_back(0xFF); // all 1
                }
                recursiveBitmapMutation(0, nofBitmap, bitmapList, lv1PDUtemp, pduDB);
            }

        }
    }

    int eIdx = 4; // 1000 bytes
    for (auto& fms: snList){
        pdcpPDU_t lv1PDUtemp(pdcpStatus);
        lv1PDUtemp = initial_pdu;

        // packet truncation and mutation
        lv1PDUtemp.eIdx = eIdx;
        lv1PDUtemp.rrc_reconfig_type = PDCP_15BIT_SN;
        // mapping to RLC header
        lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
        // mapping to LCID
        lv1PDUtemp.lcid = lcid;
        // lv1PDUtemp.status->snLen = snLen;
        if (lv1PDUtemp.type == pdcpStatus){
            lv1PDUtemp.status->FMS = fms;
            lv1PDUtemp.status->nofBitmap = 1000;
            for (int j = 0; j < lv1PDUtemp.status->nofBitmap; j++){
                lv1PDUtemp.status->bitmap.push_back(0xFF); // all 1
            }
            for (auto & bitmap: bitmapList){
                pdcpPDU_t lv2PDUtemp = lv1PDUtemp;
                for (int j = 0; j < lv1PDUtemp.status->nofBitmap; j++){
                    lv2PDUtemp.status->bitmap.at(j) = bitmap;
                }
                lv2PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv2PDUtemp);
            }
        }
    }

}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes, all 1 bits
*  eIdx =  1: 3 bytes, fms = all 1 bits
*  eIdx =  2: 4 bytes, fms = all 1 bits
*  eIdx =  3: 5 bytes, fms = all 1 bits
*  eIdx =  4: 1000 bytes, all 0 or 1 bitmap, all 1 bit fms
*  
*/
void pdcpFuzzer_t::mutatePdcpStatusPDU_18bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){

    // generate initial pdcp status pdu for DRB
    pdcpPDU_t initial_pdu(pdcpStatus);
    generate_initial_pdcp_status_pdu(initial_pdu, 18);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    std::vector<uint8_t> bitmapList = {0b00000000, 0b11110000, 0b11111111};

    for (int eIdx = -1; eIdx < 4; eIdx++){
        for (auto& fms: snList){
            pdcpPDU_t lv1PDUtemp(pdcpStatus);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            lv1PDUtemp.rrc_reconfig_type = PDCP_18BIT_SN;
            // mapping to RLC header
            lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;

            if (eIdx < 2){ // only mutate fsm because no bitmap
                lv1PDUtemp.status->FMS = fms;
                lv1PDUtemp.status->nofBitmap = 0;
                lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv1PDUtemp);
            }else if (eIdx >= 3 && eIdx < 4){
                int nofBitmap = eIdx - 1; // fixed header is 3 bytes
                for (int b = 0; b < nofBitmap; b++ ){
                    lv1PDUtemp.status->bitmap.push_back(0xFF); // all 1
                }
                recursiveBitmapMutation(0, nofBitmap, bitmapList, lv1PDUtemp, pduDB);
            }

        }
    }

    int eIdx = 4; // 1000 bytes
    for (auto& fms: snList){
        pdcpPDU_t lv1PDUtemp(pdcpStatus);
        lv1PDUtemp = initial_pdu;

        // packet truncation and mutation
        lv1PDUtemp.eIdx = eIdx;
        lv1PDUtemp.rrc_reconfig_type = PDCP_18BIT_SN;
        // mapping to RLC header
        lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
        // mapping to LCID
        lv1PDUtemp.lcid = lcid;
        // lv1PDUtemp.status->snLen = snLen;
        if (lv1PDUtemp.type == pdcpStatus){
            lv1PDUtemp.status->FMS = fms;
            lv1PDUtemp.status->nofBitmap = 1000;
            for (int j = 0; j < lv1PDUtemp.status->nofBitmap; j++){
                lv1PDUtemp.status->bitmap.push_back(0xFF); // all 1
            }
            for (auto & bitmap: bitmapList){
                pdcpPDU_t lv2PDUtemp = lv1PDUtemp;
                for (int j = 0; j < lv1PDUtemp.status->nofBitmap; j++){
                    lv2PDUtemp.status->bitmap.at(j) = bitmap;
                }
                lv2PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv2PDUtemp);
            }
        }
    }

}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes, all 1 bits
*  eIdx =  1: 3 bytes, fms = all 1 bits
*  eIdx =  2: 4 bytes, fms = all 1 bits
*  eIdx =  3: 5 bytes, fms = all 1 bits
*  eIdx =  4: 1000 bytes, all 0 or 1 bitmap, all 1 bit fms
*  const uint8_t pduType = 2; in structure 
*/
void pdcpFuzzer_t::mutateLWAStatus_12bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){
    // generate initial pdcp lwa status pdu for DRB
    pdcpPDU_t initial_pdu(pdcpLWAstatus);
    generate_initial_pdcp_lwa_status_pdu(initial_pdu, 12);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    for (int eIdx = -1; eIdx < 4; eIdx++){
        for (auto& fms: snList){
            for (auto& hrw: snList)  {
                for (auto& nmp: snList)  {
                    pdcpPDU_t lv1PDUtemp(pdcpLWAstatus);
                    lv1PDUtemp = initial_pdu;

                    // packet truncation and mutation
                    lv1PDUtemp.eIdx = eIdx;
                    // mapping to RLC header
                    lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
                    // mapping to LCID
                    lv1PDUtemp.lcid = lcid;
                    // lv1PDUtemp.status->snLen = snLen;
                    if (lv1PDUtemp.type == pdcpLWAstatus){
                        lv1PDUtemp.lwaStatus->FMS = fms; 
                        lv1PDUtemp.lwaStatus->HRW = hrw; 
                        lv1PDUtemp.lwaStatus->NMP = nmp; 
                    }
                    lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                    pduDB.push_back(lv1PDUtemp);
                }
            }
        }
    }
    int eIdx = 4;
    for (auto& fms: snList){
        pdcpPDU_t lv1PDUtemp(pdcpLWAstatus);
        lv1PDUtemp = initial_pdu;

        // packet truncation and mutation
        lv1PDUtemp.eIdx = eIdx;
        // mapping to RLC header
        lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
        // mapping to LCID
        lv1PDUtemp.lcid = lcid;
        // lv1PDUtemp.status->snLen = snLen;
        if (lv1PDUtemp.type == pdcpLWAstatus){
            lv1PDUtemp.lwaStatus->FMS = fms; 
            lv1PDUtemp.lwaStatus->HRW = fms; 
            lv1PDUtemp.lwaStatus->NMP = fms; 
        }
        lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
        pduDB.push_back(lv1PDUtemp);
    }
}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes,
*  eIdx =  1: 3 bytes, 
*  eIdx =  2: 4 bytes, 
*  eIdx =  3: 5 bytes, 
*  eIdx =  4: 6 bytes,
*  eIdx =  5: 7 bytes, 
*  eIdx =  6: 1000 bytes
*/
void pdcpFuzzer_t::mutateLWAStatus_15bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){
    // generate initial pdcp lwa status pdu for DRB
    pdcpPDU_t initial_pdu(pdcpLWAstatus);
    generate_initial_pdcp_lwa_status_pdu(initial_pdu, 15);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    for (int eIdx = -1; eIdx < 6; eIdx++){
        for (auto& fms: snList){
            for (auto& hrw: snList)  {
                for (auto& nmp: snList)  {
                    pdcpPDU_t lv1PDUtemp(pdcpLWAstatus);
                    lv1PDUtemp = initial_pdu;

                    // packet truncation and mutation
                    lv1PDUtemp.eIdx = eIdx;
                    lv1PDUtemp.rrc_reconfig_type = PDCP_15BIT_SN;
                    // mapping to RLC header
                    lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
                    // mapping to LCID
                    lv1PDUtemp.lcid = lcid;
                    // lv1PDUtemp.status->snLen = snLen;
                    if (lv1PDUtemp.type == pdcpLWAstatus){
                        lv1PDUtemp.lwaStatus->FMS = fms; 
                        lv1PDUtemp.lwaStatus->HRW = hrw; 
                        lv1PDUtemp.lwaStatus->NMP = nmp; 
                    }
                    lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                    pduDB.push_back(lv1PDUtemp);
                }
            }
        }
    }
    int eIdx = 6;
    for (auto& fms: snList){
        for (auto& r: rList){
            pdcpPDU_t lv1PDUtemp(pdcpLWAstatus);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            lv1PDUtemp.rrc_reconfig_type = PDCP_15BIT_SN;
            // mapping to RLC header
            lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;
            if (lv1PDUtemp.type == pdcpLWAstatus){
                lv1PDUtemp.lwaStatus->FMS = fms;
                lv1PDUtemp.lwaStatus->HRW = fms; 
                lv1PDUtemp.lwaStatus->NMP = fms; 
                lv1PDUtemp.lwaStatus->R1 = r;
            }
            lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
            pduDB.push_back(lv1PDUtemp);
        }
    }
}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes,
*  eIdx =  1: 3 bytes, 
*  eIdx =  2: 4 bytes, 
*  eIdx =  3: 5 bytes, 
*  eIdx =  4: 6 bytes,
*  eIdx =  5: 7 bytes, 
*  eIdx =  6: 8 bytes
*  eIdx =  7: 1000 bytes
*  
*/
void pdcpFuzzer_t::mutateLWAStatus_18bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){
    // generate initial pdcp lwa status pdu for DRB
    pdcpPDU_t initial_pdu(pdcpLWAstatus);
    generate_initial_pdcp_lwa_status_pdu(initial_pdu, 18);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    for (int eIdx = -1; eIdx < 7; eIdx++){
        for (auto& fms: snList){
            for (auto& r: rList)  {
                pdcpPDU_t lv1PDUtemp(pdcpLWAstatus);
                lv1PDUtemp = initial_pdu;

                // packet truncation and mutation
                lv1PDUtemp.eIdx = eIdx;
                lv1PDUtemp.rrc_reconfig_type = PDCP_18BIT_SN;
                // mapping to RLC header
                lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
                // mapping to LCID
                lv1PDUtemp.lcid = lcid;
                // lv1PDUtemp.status->snLen = snLen;
                if (lv1PDUtemp.type == pdcpLWAstatus){
                    lv1PDUtemp.lwaStatus->FMS = fms; // set all 1
                    lv1PDUtemp.lwaStatus->HRW = fms; // set all 1
                    lv1PDUtemp.lwaStatus->NMP = fms; // set all 1
                    lv1PDUtemp.lwaStatus->R1 = r;
                }
                lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
                pduDB.push_back(lv1PDUtemp);
            }
        }
    }
    int eIdx = 7;
    for (auto& fms: snList){
        for (auto& r: rList){
            pdcpPDU_t lv1PDUtemp(pdcpLWAstatus);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            lv1PDUtemp.rrc_reconfig_type = PDCP_18BIT_SN;
            // mapping to RLC header
            lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;
            if (lv1PDUtemp.type == pdcpLWAstatus){
                lv1PDUtemp.lwaStatus->FMS = fms; // set all 1
                lv1PDUtemp.lwaStatus->HRW = fms; // set all 1
                lv1PDUtemp.lwaStatus->NMP = fms; // set all 1
                lv1PDUtemp.lwaStatus->R1 = r;
            }
            lv1PDUtemp.totalByte = calTotalByte(lv1PDUtemp);
            pduDB.push_back(lv1PDUtemp);
        }
    }
}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes
*  eIdx =  1: 100 bytes
*  
*/
void pdcpFuzzer_t::mutateLWASEndMarker_12bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){
    // generate initial pdcp lwa endmarker pdu for DRB
    pdcpPDU_t initial_pdu(pdcpLWAendmarker);
    generate_initial_pdcp_lwa_endmarker_pdu(initial_pdu, 12);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    int eIdx = -1;
    for (int eIdx = -1; eIdx < 1; eIdx++){        
        for (auto& sn: snList){
            pdcpPDU_t lv1PDUtemp(pdcpLWAendmarker);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            // mapping to RLC header
            lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            if (lv1PDUtemp.type == pdcpLWAendmarker){
                lv1PDUtemp.lwaEndmarker->LSN = sn; // set all 1
                // lv1PDUtemp.lwaEndmarker->R1 = 1;
            }
            lv1PDUtemp.totalByte = (eIdx == -1)? 1: 2;
            pduDB.push_back(lv1PDUtemp);
        }
    }

    eIdx = 1;
    for (auto& sn: snList){
        // for (auto& r: rList){     
            pdcpPDU_t lv3PDUtemp(pdcpLWAendmarker);
            lv3PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv3PDUtemp.eIdx = eIdx;
            // mapping to RLC header
            lv3PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
            // mapping to LCID
            lv3PDUtemp.lcid = lcid;
            if (lv3PDUtemp.type == pdcpLWAendmarker){
                lv3PDUtemp.lwaEndmarker->LSN = sn; // set all 1
                // lv3PDUtemp.lwaEndmarker->R1 = 1;
            }
            lv3PDUtemp.totalByte = 100;
            pduDB.push_back(lv3PDUtemp);
        // }
    }   

}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes
*  eIdx =  1: 3 bytes
*  eIdx =  2: 100 bytes
*/
void pdcpFuzzer_t::mutateLWASEndMarker_15bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){
    // generate initial pdcp lwa endmarker pdu for DRB
    pdcpPDU_t initial_pdu(pdcpLWAendmarker);
    generate_initial_pdcp_lwa_endmarker_pdu(initial_pdu, 15);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    int eIdx = -1;
    for (int eIdx = -1; eIdx < 2; eIdx++){        
        for (auto& sn: snList){
            pdcpPDU_t lv1PDUtemp(pdcpLWAendmarker);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            lv1PDUtemp.rrc_reconfig_type = PDCP_15BIT_SN;
            // mapping to RLC header
            lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;
            if (lv1PDUtemp.type == pdcpLWAendmarker){
                lv1PDUtemp.lwaEndmarker->LSN = sn; 
                // lv1PDUtemp.lwaEndmarker->R1 = 1;
            }
            lv1PDUtemp.totalByte = eIdx + 2;
            pduDB.push_back(lv1PDUtemp);
        }
    }

    eIdx = 1;
    for (auto& sn: snList){
        // for (auto& r: rList){     
            pdcpPDU_t lv3PDUtemp(pdcpLWAendmarker);
            lv3PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv3PDUtemp.eIdx = eIdx;
            lv3PDUtemp.rrc_reconfig_type = PDCP_15BIT_SN;
            // mapping to RLC header
            lv3PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
            // mapping to LCID
            lv3PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;
            if (lv3PDUtemp.type == pdcpLWAendmarker){
                lv3PDUtemp.lwaEndmarker->LSN = sn; 
                // lv3PDUtemp.lwaEndmarker->R1 = 1;
            }
            lv3PDUtemp.totalByte = 100;
            pduDB.push_back(lv3PDUtemp);
        // }
    }   

}

/* eIdx = -1: 1 byte
*  eIdx =  0: 2 bytes
*  eIdx =  1: 3 bytes, 
*  eIdx =  2: 100 bytes
*/
void pdcpFuzzer_t::mutateLWASEndMarker_18bit(std::vector<pdcpPDU_t>& pduDB, int lcid, int snLen){
    // generate initial pdcp lwa endmarker pdu for DRB
    pdcpPDU_t initial_pdu(pdcpLWAendmarker);
    generate_initial_pdcp_lwa_endmarker_pdu(initial_pdu, 18);

    std::vector<int>& snList = (snLen == 12)? snList12bit: (snLen == 7)? snList7bit: (snLen == 15)? snList15bit: snList18bit;
    int eIdx = -1;
    for (int eIdx = -1; eIdx < 2; eIdx++){        
        for (auto& sn: snList){
            pdcpPDU_t lv1PDUtemp(pdcpLWAendmarker);
            lv1PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv1PDUtemp.eIdx = eIdx;
            lv1PDUtemp.rrc_reconfig_type = PDCP_18BIT_SN;
            // mapping to RLC header
            lv1PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
            // mapping to LCID
            lv1PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;
            if (lv1PDUtemp.type == pdcpLWAendmarker){
                lv1PDUtemp.lwaEndmarker->LSN = sn; // set all 1
                // lv1PDUtemp.lwaEndmarker->R1 = 1;
            }
            lv1PDUtemp.totalByte = eIdx + 2;
            pduDB.push_back(lv1PDUtemp);
        }
    }

    eIdx = 1;
    for (auto& sn: snList){
        // for (auto& r: rList){     
            pdcpPDU_t lv3PDUtemp(pdcpLWAendmarker);
            lv3PDUtemp = initial_pdu;

            // packet truncation and mutation
            lv3PDUtemp.eIdx = eIdx;
            lv3PDUtemp.rrc_reconfig_type = PDCP_18BIT_SN;
            // mapping to RLC header
            lv3PDUtemp.rlcType = rlcAM1;  // because this DRB requires RLC AM mode
            // mapping to LCID
            lv3PDUtemp.lcid = lcid;
            // lv1PDUtemp.status->snLen = snLen;
            if (lv3PDUtemp.type == pdcpLWAendmarker){
                lv3PDUtemp.lwaEndmarker->LSN = sn; // set all 1
                // lv3PDUtemp.lwaEndmarker->R1 = 1;
            }
            lv3PDUtemp.totalByte = 100;
            pduDB.push_back(lv3PDUtemp);
        // }
    }   

}


/* 
*  eIdx =  0: 2 bytes
*  eIdx =  1: 1000 bytes
*  
*/
void pdcpFuzzer_t::mutateUDCFeedback(std::vector<pdcpPDU_t>& pduDB, int lcid){
    int eIdx = 0;
    pdcpPDU_t lv1PDUtemp(pdcpUDCfeedback);
    lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
    lv1PDUtemp.lcid = lcid;
    lv1PDUtemp.eIdx = eIdx;
    if (lv1PDUtemp.type == pdcpUDCfeedback){
        lv1PDUtemp.udcFeedback->FE = 1;
    }
    lv1PDUtemp.totalByte = 2;
    pduDB.push_back(lv1PDUtemp);

    eIdx = 1;
    pdcpPDU_t lv2PDUtemp(pdcpUDCfeedback);
    lv2PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
    lv2PDUtemp.lcid = lcid;
    lv2PDUtemp.eIdx = eIdx;
    if (lv2PDUtemp.type == pdcpUDCfeedback){
        lv2PDUtemp.udcFeedback->FE = 1;
    }
    lv2PDUtemp.totalByte = 1000;
    pduDB.push_back(lv2PDUtemp);
}

/* 
*  eIdx =  0: 10 bytes
*  eIdx =  1: 1000 bytes
*  eIdx = -1: 1 bytes 
*/
void pdcpFuzzer_t::mutateEHCFeedback(std::vector<pdcpPDU_t>& pduDB, int lcid){
    int eIdx = -1;
    pdcpPDU_t lv1PDUtemp(pdcpEHCfeedback);
    lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
    lv1PDUtemp.lcid = lcid;
    lv1PDUtemp.eIdx = eIdx;
    if (lv1PDUtemp.type == pdcpEHCfeedback){
        lv1PDUtemp.echFeedback->nofBytes = 0;
    }
    lv1PDUtemp.totalByte = 1;
    pduDB.push_back(lv1PDUtemp);

    eIdx = 0;
    pdcpPDU_t lv2PDUtemp(pdcpEHCfeedback);
    lv2PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
    lv2PDUtemp.lcid = lcid;
    lv2PDUtemp.eIdx = eIdx;
    if (lv2PDUtemp.type == pdcpEHCfeedback){
        lv2PDUtemp.echFeedback->nofBytes = 9; 
        std::vector<uint8_t> byteList(255, 0); // all 1 or all 0
        for (auto& byte : byteList){
            for (int j = 0; j < lv2PDUtemp.echFeedback->nofBytes; j++){
                lv2PDUtemp.echFeedback->feedback.push_back(byte);
            }
        }
    }
    lv2PDUtemp.totalByte = 10;
    pduDB.push_back(lv2PDUtemp);

    eIdx = 1;
    pdcpPDU_t lv3PDUtemp(pdcpEHCfeedback);
    lv3PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
    lv3PDUtemp.lcid = lcid;
    lv3PDUtemp.eIdx = eIdx;
    if (lv3PDUtemp.type == pdcpEHCfeedback){
        lv3PDUtemp.echFeedback->nofBytes = 1000;
        std::vector<uint8_t> byteList(255, 0); // all 1 or all 0
        for (auto& byte : byteList){
            for (int j = 0; j < lv3PDUtemp.echFeedback->nofBytes; j++){
                lv3PDUtemp.echFeedback->feedback.push_back(byte);
            }
        }
    }
    lv3PDUtemp.totalByte = 1000;
    pduDB.push_back(lv3PDUtemp);

}

/* 
*  eIdx =  0: 1 bytes
*  eIdx =  1: 2 bytes
*/
void pdcpFuzzer_t::mutatePDCPReserved(std::vector<pdcpPDU_t>& pduDB, int lcid){
    int eIdx = 0;
    pdcpPDU_t lv1PDUtemp(pdcpReserved);
    lv1PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
    lv1PDUtemp.lcid = lcid;
    lv1PDUtemp.eIdx = eIdx;
    lv1PDUtemp.totalByte = 1;
    for (uint8_t pduType = 7; pduType < 9; pduType++){
        lv1PDUtemp.reserved->pduType = pduType;
        pduDB.push_back(lv1PDUtemp);
    }
    // pduDB.push_back(lv1PDUtemp);

    eIdx = 1;
    pdcpPDU_t lv2PDUtemp(pdcpReserved);
    lv2PDUtemp.rlcType = (lcid<3)?rlcAM1:rlcUM1;
    lv2PDUtemp.lcid = lcid;
    lv2PDUtemp.eIdx = eIdx;
    lv2PDUtemp.totalByte = 2;
    for (int pduType = 7; pduType < 9; pduType++){
        lv2PDUtemp.reserved->pduType = pduType;
        pduDB.push_back(lv2PDUtemp);
    }
}


void pdcpFuzzer_t::generate_test_cases(){
    // initiate values for mutation
    rList.insert(rList.end(), {0, 1});
    for (int i = 0; i < 6; i = i + 2){
        snList5bit.push_back(pow(2, i) - 1);
    }
    for (int i = 0; i < 13; i= i + 3){
        snList12bit.push_back(pow(2, i) - 1);
    }
    for (int i = 0; i < 8; i = i + 3){
        snList7bit.push_back(pow(2, i) - 1);
    }
    for (int i = 0; i < 16; i = i + 4){
        snList15bit.push_back(pow(2, i) - 1);
    }
    for (int i = 0; i < 19; i= i + 4){
        snList18bit.push_back(pow(2, i) - 1);
    }

    if (!readFromFileMode){
        // state4, pdcp pdu for SRB, lcid 1 & 2
        mutatePDCPDataPDUSRB(testcaseDB[state4], LLFUZZ_DCCH1);
        mutatePDCPDataPDUSRB(testcaseDB[state4], LLFUZZ_DCCH2);

        // std::cout << "[MTT] 1. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        mutatePDCPDataPDUDRB_12bitSN(testcaseDB[state4], LLFUZZ_DTCH, 12);
        // std::cout << "[MTT] 2. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        mutatePDCPDataPDUDRB_7bitSN(testcaseDB[state4], LLFUZZ_DTCH, 7);
        // std::cout << "[MTT] 3. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        mutatePDCPDataPDUDRB_15bitSN(testcaseDB[state4], LLFUZZ_DTCH, 15);
        // std::cout << "[MTT] 4. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        mutatePDCPDataPDUDRB_18bitSN(testcaseDB[state4], LLFUZZ_DTCH, 18);
        // std::cout << "[MTT] 5. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        
        mutatePdcpStatusPDU_12bit(testcaseDB[state4], LLFUZZ_DTCH, 12);    
        // std::cout << "[MTT] 6. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";

        mutatePdcpStatusPDU_15bit(testcaseDB[state4], LLFUZZ_DTCH, 15);    
        // std::cout << "[MTT] 7. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";

        mutatePdcpStatusPDU_18bit(testcaseDB[state4], LLFUZZ_DTCH, 18);    
        // std::cout << "[MTT] 8. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";

        mutateLWAStatus_12bit(testcaseDB[state4], LLFUZZ_DTCH, 12);        
        // std::cout << "[MTT] 9. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        mutateLWAStatus_15bit(testcaseDB[state4], LLFUZZ_DTCH, 18);       
        // std::cout << "[MTT] 10. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        mutateLWAStatus_18bit(testcaseDB[state4], LLFUZZ_DTCH, 18);        
        // std::cout << "[MTT] 11. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";

        mutateLWASEndMarker_12bit(testcaseDB[state4], LLFUZZ_DTCH, 12);    
        // std::cout << "[MTT] 12. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        mutateLWASEndMarker_15bit(testcaseDB[state4], LLFUZZ_DTCH, 15);    
        // std::cout << "[MTT] 13. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";
        mutateLWASEndMarker_18bit(testcaseDB[state4], LLFUZZ_DTCH, 18);    
        // std::cout << "[MTT] 14. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";

        mutateUDCFeedback(testcaseDB[state4], LLFUZZ_DTCH);            
        // std::cout << "[MTT] 15. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";

        mutateEHCFeedback(testcaseDB[state4], LLFUZZ_DTCH);            
        // std::cout << "[MTT] 16. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";

        mutatePDCPReserved(testcaseDB[state4], LLFUZZ_DTCH);           
        // std::cout << "[MTT] 17. Generated Test cases for state 4: " << testcaseDB[state4].size() << "\n";

        // state3, pdcp pdu for SRB, lcid 1 only
        mutatePDCPDataPDUSRB(testcaseDB[state3], LLFUZZ_DCCH1);
        // std::cout << "[MTT] 18. Generated Test cases for state 3: " << testcaseDB[state3].size() << "\n";
    }else{ // readfromFile
    
    }

}

// void pdcpFuzzer_t::switchState(){
//     fuzzingState = ;
//     switch (fuzzingState)
//     {
//     case state1:
//         // state1Phase = state1Prepare;
//         break;
//     case state234:
//         state234Phase = state234Prepare;
//         idx[2] = startIdx;
//         idx[3] = startIdx;
//         idx[4] = startIdx;
//         idx[5] = startIdx;
//         break;
//     case state5:
//         s5Phase = s5Prepare;
//         idx[2] = startIdx;
//         idx[3] = startIdx;
//         idx[4] = startIdx;
//         idx[5] = startIdx;
//         break;
//     case stateUnknown:
//         fuzzingState = stateUnknown;
//         s5Phase = s5None;
//         state234Phase = state234noPhase;
//         break;
//     default:
//         break;
//     }
    
//     if (DEBUG_MODE){ 
//       printf("[MAC] Switch Fuzzer to state %d \n", state); 
//     }
// }

pdcpPDU_t pdcpFuzzer_t::getCurTestCase(){
    if (readFromFileMode){
        curTestCase = verifyDB[fuzzingState][idx[fuzzingState]];
    }else{
        curTestCase = testcaseDB[fuzzingState][idx[fuzzingState]];
    }
    return curTestCase;
}

// int pdcpFuzzer_t::get_cur_testcase_idx(LLState_t state, bool isverifying){
//     if (state > 5){
//         ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
//     }
//     return idx[state];
// }

int pdcpFuzzer_t::get_total_idx(LLState_t state, bool isverifying){
    if (state > 5){
        ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
    }
    return (isverifying)?verifyDB[state].size():testcaseDB[state].size();
}

int pdcpFuzzer_t::get_injecting_lcid(){
    // uint32_t lcid = (fuzzingState == state5)?1:pdcpPDU.lcid;
    return 0;
}

int pdcpFuzzer_t::get_injecting_length(){
    int len = 0;
    
    curTestCase = getCurTestCase();
    
    len = curTestCase.totalByte + 2 + 4 + 4 - 7 + 10 + 10; // + 20 +2 : for ccch sub-header and sub-payload
    len = (len <= 0)?1:len;
  
    return len;
}

pdcpHeaderResult_t pdcpFuzzer_t::generatePdcpDataPDU_SRB(pdcpDataPDU_t& dataSRB){
    pdcpHeaderResult_t headerResult = {};
    headerResult.nofByte = 1;
    uint8_t firstByte = 0;
    firstByte |= dataSRB.R1 << 7;
    firstByte |= dataSRB.R2 << 6;
    firstByte |= dataSRB.R3 << 5;
    firstByte |= dataSRB.SN;
    headerResult.pattern.push_back(firstByte);

    return headerResult;
}

// use eIdx to determine the size of the header, the content of the header is still formed by its fields, but then the actual size will be controled by eIdx
pdcpHeaderResult_t pdcpFuzzer_t::generatePdcpDataPDU_DRB(pdcpDataPDU_t& dataDRB, int snLen, int eIdx){
    pdcpHeaderResult_t headerResult = {};
    uint8_t firstByte = 0;
    uint8_t secondByte = 0;
    uint8_t thirdByte = 0;
    uint8_t oneByte = 0;
    uint16_t twoBytes = 0;
    uint32_t threeBytes = 0;
    switch (snLen)
    {
    case 12:
        headerResult.nofByte = (eIdx == -1)? 1: (eIdx == -2)? 2: 3; // 3: 2 bytes for header and 1 byte for data
        twoBytes |= dataDRB.DC << 15;
        twoBytes |= dataDRB.R1 << 14;
        twoBytes |= dataDRB.R2 << 13;
        twoBytes |= dataDRB.R3 << 12;
        twoBytes |= dataDRB.SN;

        firstByte = static_cast<uint8_t>(twoBytes >> 8);
        secondByte = static_cast<uint8_t>(twoBytes & 0xFF);
        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);   
        break;
    case 7:
        headerResult.nofByte = (eIdx == -1)? 1: 2;
        oneByte |= dataDRB.DC << 7;
        oneByte |= dataDRB.SN;

        headerResult.pattern.push_back(oneByte);   
        break;
    case 15:
        headerResult.nofByte = (eIdx == -1)? 1: (eIdx == -2)? 2: 3; // 3: 2 bytes for header and 1 byte for data
        twoBytes |= dataDRB.DC << 15;
        twoBytes |= dataDRB.SN;

        firstByte = static_cast<uint8_t>(twoBytes >> 8);
        secondByte = static_cast<uint8_t>(twoBytes & 0xFF);
        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);   
        break;
    case 18:
        headerResult.nofByte = (eIdx == -1)? 1: (eIdx == -2)? 2: (eIdx == -3)? 3: 4; // 4: 3 bytes for header and 1 byte for data
        threeBytes |= dataDRB.DC << 23;
        threeBytes |= dataDRB.P  << 22;
        threeBytes |= dataDRB.R1 << 21;
        threeBytes |= dataDRB.R2 << 20;
        threeBytes |= dataDRB.R3 << 19;
        threeBytes |= dataDRB.R4 << 18;
        threeBytes |= dataDRB.SN;

        firstByte = static_cast<uint8_t>(threeBytes >> 16);
        secondByte = static_cast<uint8_t>((threeBytes >> 8) & 0xFF);
        thirdByte = static_cast<uint8_t>(threeBytes & 0xFF);
        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);   
        headerResult.pattern.push_back(thirdByte);
        break;
            
    default:
        break;
    }

    return headerResult;
}

pdcpHeaderResult_t pdcpFuzzer_t::generateROHCFeedback(pdcpROHCfeedbackPDU_t& rohc, int eIdx)
{
    pdcpHeaderResult_t headerResult = {};
    headerResult.nofByte = 1 + rohc.nofByte; // 1 byte for fixed header and nofByte for feedback
    uint8_t firstByte = 0;
    firstByte |= rohc.DC << 7;
    firstByte |= rohc.pduType << 4;
    firstByte |= rohc.R1 << 3;
    firstByte |= rohc.R2 << 2;
    firstByte |= rohc.R3 << 1;
    headerResult.pattern.push_back(firstByte);

    for (int byteIdx = 0; byteIdx < rohc.nofByte; byteIdx++){ // for eIdx = -1, nofByte = 0, so this loop will not be executed
        headerResult.pattern.push_back(rohc.feedback[byteIdx]);
    }

    return headerResult;
}

pdcpHeaderResult_t pdcpFuzzer_t::generatePdcpStatus(pdcpStatusPDU_t& status, int eIdx){
    pdcpHeaderResult_t headerResult = {};
    uint8_t firstByte = 0;
    uint8_t secondByte = 0;
    uint8_t thirdByte = 0;
    uint16_t twobyteheader = 0;
    uint32_t threebyteheader = 0;
    switch (status.snLen)
    {
    case 12:
        if (eIdx == -1){
            headerResult.nofByte = 1;
            firstByte = 0;
            firstByte |= status.DC << 7;
            firstByte |= status.pduType << 4;
            firstByte |= 1 << 3;
            headerResult.pattern.push_back(firstByte);
        }else{
            headerResult.nofByte = 2; // 2 byte for fixed header, bitmap will be added later
            twobyteheader = 0;
            twobyteheader |= status.DC << 15;
            twobyteheader |= status.pduType << 12;
            twobyteheader |= (status.FMS & 0xFFF);
            firstByte = static_cast<uint8_t>(twobyteheader >> 8);
            secondByte = static_cast<uint8_t>(twobyteheader & 0xFF);
            headerResult.pattern.push_back(firstByte);
            headerResult.pattern.push_back(secondByte);
            for (int byteIdx = 0; byteIdx < status.nofBitmap; byteIdx++){
                headerResult.pattern.push_back(status.bitmap[byteIdx]);
            }
        }
        break;
    case 15:
        if (eIdx == -1){
            headerResult.nofByte = 1;
            firstByte = 0;
            firstByte |= status.DC << 7;
            firstByte |= status.pduType << 4;
            firstByte |= 0 << 3;  // reserved bits
            headerResult.pattern.push_back(firstByte);
        }else if (eIdx == 0){ // totally 2 bytes
            headerResult.nofByte = 2;
            twobyteheader = 0;
            twobyteheader |= status.DC << 15;
            twobyteheader |= status.pduType << 12;
            twobyteheader |= 0 << 7; // reserved bits
            twobyteheader |= (status.FMS & 0x7F);
            firstByte = static_cast<uint8_t>(twobyteheader >> 8);
            secondByte = static_cast<uint8_t>(twobyteheader & 0xFF);
            headerResult.pattern.push_back(firstByte);
            headerResult.pattern.push_back(secondByte);
        }else{
            headerResult.nofByte = 3; // 3 byte for fixed header and nofByte for status
            threebyteheader = 0;
            threebyteheader |= status.DC << 23;
            threebyteheader |= status.pduType << 20;
            threebyteheader |= 0 << 15; // reserved bits
            threebyteheader |= status.FMS;
            firstByte = static_cast<uint8_t>(threebyteheader >> 16);
            secondByte = static_cast<uint8_t>((threebyteheader >> 8) & 0xFF);
            thirdByte = static_cast<uint8_t>(threebyteheader & 0xFF);
            headerResult.pattern.push_back(firstByte);
            headerResult.pattern.push_back(secondByte);
            headerResult.pattern.push_back(thirdByte);
            // for (int byteIdx = 0; byteIdx < status.nofBitmap; byteIdx++){
            //     headerResult.pattern.push_back(status.bitmap[byteIdx]);
            // }
        }
        break;
    case 18:
        if (eIdx == -1){
            headerResult.nofByte = 1;
            firstByte = 0;
            firstByte |= status.DC << 7;
            firstByte |= status.pduType << 4;
            firstByte |= 0 << 2;  // reserved bits
            firstByte |= status.FMS & 0x3;
            headerResult.pattern.push_back(firstByte);
        }else if (eIdx == 0){ // totally 2 bytes
            headerResult.nofByte = 2;
            twobyteheader = 0;
            twobyteheader |= status.DC << 15;
            twobyteheader |= status.pduType << 12;
            twobyteheader |= 0 << 2; // reserved bits
            twobyteheader |= (status.FMS & 0x03FF);
            firstByte = static_cast<uint8_t>(twobyteheader >> 8);
            secondByte = static_cast<uint8_t>(twobyteheader & 0xFF);
            headerResult.pattern.push_back(firstByte);
            headerResult.pattern.push_back(secondByte);
        }else{
            headerResult.nofByte = 3; // 3 byte for fixed header and nofByte for status
            threebyteheader = 0;
            threebyteheader |= status.DC << 23;
            threebyteheader |= status.pduType << 20;
            threebyteheader |= 0 << 18; // reserved bits
            threebyteheader |= status.FMS;
            firstByte = static_cast<uint8_t>(threebyteheader >> 16);
            secondByte = static_cast<uint8_t>((threebyteheader >> 8) & 0xFF);
            thirdByte = static_cast<uint8_t>(threebyteheader & 0xFF);
            headerResult.pattern.push_back(firstByte);
            headerResult.pattern.push_back(secondByte);
            headerResult.pattern.push_back(thirdByte);
            // for (int byteIdx = 0; byteIdx < status.nofBitmap; byteIdx++){
            //     headerResult.pattern.push_back(status.bitmap[byteIdx]);
            // }
        }
        break;

    default:
        break;
    }
    return headerResult;
}

pdcpHeaderResult_t pdcpFuzzer_t::generateLWAStatus(pdcpLWAstatusPDU_t& lwaStatus, int eIdx) {
    // generate normal packet first and restrict the size later
    int snLen = lwaStatus.snLen;
    pdcpHeaderResult_t headerResult = {};
    uint8_t firstByte = 0;
    uint8_t secondByte = 0;
    uint8_t thirdByte = 0;
    uint8_t fourthByte = 0;
    uint8_t fifthByte = 0;
    uint8_t sixthByte = 0;
    uint8_t seventhByte = 0;
    uint8_t eighthByte = 0;
    uint64_t bytes = 0;

    switch (snLen) {
    case 12:
        headerResult.nofByte = (eIdx < 3) ? (eIdx + 2) : 5;
        bytes |= static_cast<uint64_t>(lwaStatus.DC) << 39;
        bytes |= static_cast<uint64_t>(lwaStatus.pduType) << 36;
        bytes |= static_cast<uint64_t>(lwaStatus.FMS) << 24;
        bytes |= static_cast<uint64_t>(lwaStatus.HRW) << 12;
        bytes |= static_cast<uint64_t>(lwaStatus.NMP);

        firstByte = static_cast<uint8_t>(bytes >> 32);
        secondByte = static_cast<uint8_t>(bytes >> 24);
        thirdByte = static_cast<uint8_t>(bytes >> 16);
        fourthByte = static_cast<uint8_t>(bytes >> 8);
        fifthByte = static_cast<uint8_t>(bytes & 0xFF);

        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);
        headerResult.pattern.push_back(thirdByte);
        headerResult.pattern.push_back(fourthByte);
        headerResult.pattern.push_back(fifthByte);
        break;
    case 15:
        headerResult.nofByte = (eIdx < 5) ? (eIdx + 2) : 7;
        bytes |= static_cast<uint64_t>(lwaStatus.DC) << 55;
        bytes |= static_cast<uint64_t>(lwaStatus.pduType) << 52;
        bytes |= static_cast<uint64_t>(lwaStatus.R1) << 47; // 5 bits reserved
        bytes |= static_cast<uint64_t>(lwaStatus.FMS) << 32; // 15 bits FMS
        bytes |= static_cast<uint64_t>(lwaStatus.R1) << 31; // 1 bit reserved
        bytes |= static_cast<uint64_t>(lwaStatus.HRW) << 16; // 15 bits HRW
        bytes |= static_cast<uint64_t>(lwaStatus.R1) << 15; // 1 bit reserved
        bytes |= static_cast<uint64_t>(lwaStatus.NMP); // 15 bits NMP

        firstByte = static_cast<uint8_t>(bytes >> 48);
        secondByte = static_cast<uint8_t>(bytes >> 40);
        thirdByte = static_cast<uint8_t>(bytes >> 32);
        fourthByte = static_cast<uint8_t>(bytes >> 24);
        fifthByte = static_cast<uint8_t>(bytes >> 16);
        sixthByte = static_cast<uint8_t>(bytes >> 8);
        seventhByte = static_cast<uint8_t>(bytes & 0xFF);

        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);
        headerResult.pattern.push_back(thirdByte);
        headerResult.pattern.push_back(fourthByte);
        headerResult.pattern.push_back(fifthByte);
        headerResult.pattern.push_back(sixthByte);
        headerResult.pattern.push_back(seventhByte);
        break;
    case 18:
        headerResult.nofByte = (eIdx < 6) ? (eIdx + 2) : 8;
        bytes |= static_cast<uint64_t>(lwaStatus.DC) << 63;
        bytes |= static_cast<uint64_t>(lwaStatus.pduType) << 60;
        bytes |= static_cast<uint64_t>(lwaStatus.R1) << 58; // 2 bits reserved
        bytes |= static_cast<uint64_t>(lwaStatus.FMS) << 40; // 18 bits FMS
        bytes |= static_cast<uint64_t>(lwaStatus.HRW) << 22; // 18 bits HRW
        bytes |= static_cast<uint64_t>(lwaStatus.R1) << 18; // 18 bit reserved
        bytes |= static_cast<uint64_t>(lwaStatus.NMP); // 18 bits NMP

        firstByte = static_cast<uint8_t>(bytes >> 56);
        secondByte = static_cast<uint8_t>(bytes >> 48);
        thirdByte = static_cast<uint8_t>(bytes >> 40);
        fourthByte = static_cast<uint8_t>(bytes >> 32);
        fifthByte = static_cast<uint8_t>(bytes >> 24);
        sixthByte = static_cast<uint8_t>(bytes >> 16);
        seventhByte = static_cast<uint8_t>(bytes >> 8);
        eighthByte = static_cast<uint8_t>(bytes & 0xFF);

        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);
        headerResult.pattern.push_back(thirdByte);
        headerResult.pattern.push_back(fourthByte);
        headerResult.pattern.push_back(fifthByte);
        headerResult.pattern.push_back(sixthByte);
        headerResult.pattern.push_back(seventhByte);
        headerResult.pattern.push_back(eighthByte);
        break;
    
    default:
        break;
    }

    return headerResult;
}

pdcpHeaderResult_t pdcpFuzzer_t::generateLWAEndMarker(pdcpLWAendmarkerPDU_t& lwaEndMarker, int eIdx){
    // generate normal packet first and restrict the size later
    int snLen = lwaEndMarker.snLen;
    pdcpHeaderResult_t headerResult = {};
    uint8_t firstByte = 0;
    uint8_t secondByte = 0;
    uint8_t thirdByte = 0;
    uint32_t bytes = 0;
    switch (snLen)
    {
    case 12:
        headerResult.nofByte = (eIdx < 1)? (eIdx + 2): 2; // for 100 bytes case, 98 bytes are treated as data
        bytes |= lwaEndMarker.DC << 15;
        bytes |= lwaEndMarker.pduType << 12;
        bytes |= lwaEndMarker.LSN;

        firstByte = static_cast<uint8_t>(bytes >> 8);
        secondByte = static_cast<uint8_t>(bytes & 0xFF);
        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);
        break;
    case 15:
        headerResult.nofByte = (eIdx < 2)? (eIdx + 2): 3; // for 100 bytes case, 98 bytes are treated as data
        bytes |= lwaEndMarker.DC << 23;
        bytes |= lwaEndMarker.pduType << 20; // 3 bits reserved
        bytes |= lwaEndMarker.R1 << 15; // 5 bits reserved
        bytes |= lwaEndMarker.LSN; // 15 bits LSN

        firstByte = static_cast<uint8_t>(bytes >> 16);
        secondByte = static_cast<uint8_t>(bytes >> 8);
        thirdByte = static_cast<uint8_t>(bytes & 0xFF);

        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);
        headerResult.pattern.push_back(thirdByte);
        break;
    case 18:
        headerResult.nofByte = (eIdx < 2)? (eIdx + 2): 3; // for 100 bytes case, 98 bytes are treated as data
        bytes |= lwaEndMarker.DC << 23;
        bytes |= lwaEndMarker.pduType << 20; // 3 bits reserved
        bytes |= lwaEndMarker.R1 << 18; // 2 bits reserved
        bytes |= lwaEndMarker.LSN; // 18 bits LSN

        firstByte = static_cast<uint8_t>(bytes >> 16);
        secondByte = static_cast<uint8_t>(bytes >> 8);
        thirdByte = static_cast<uint8_t>(bytes & 0xFF);

        headerResult.pattern.push_back(firstByte);
        headerResult.pattern.push_back(secondByte);
        headerResult.pattern.push_back(thirdByte);
        break;
    
    default:
        break;
    }

    return headerResult;
}

pdcpHeaderResult_t pdcpFuzzer_t::generateUDCFeedback(pdcpUDCfeedbackPDU_t& udcFeedback, int eIdx, int totalByte){
    pdcpHeaderResult_t headerResult = {};
    headerResult.nofByte = 1;
    uint8_t firstByte = 0;
    firstByte |= udcFeedback.DC << 7;
    firstByte |= udcFeedback.pduType << 4;
    firstByte |= udcFeedback.FE << 3;
    firstByte |= udcFeedback.R1 <<2;
    firstByte |= udcFeedback.R2 <<1;
    firstByte |= udcFeedback.R3;
    headerResult.pattern.push_back(firstByte);

    return headerResult;
}

pdcpHeaderResult_t pdcpFuzzer_t::generateEHCFeedback(pdcpECHfeedbackPDU_t& ehcFeedback, int eIdx, int totalByte){
    pdcpHeaderResult_t headerResult = {};
    headerResult.nofByte = totalByte;
    uint8_t firstByte = 0;
    firstByte |= ehcFeedback.DC << 7;
    firstByte |= ehcFeedback.pduType << 4;
    firstByte |= ehcFeedback.R1 << 3;
    firstByte |= ehcFeedback.R3 << 1;
    firstByte |= ehcFeedback.R4;
    headerResult.pattern.push_back(firstByte);
    for (int i = 0; i < totalByte - 1; i++){
        headerResult.pattern.push_back(ehcFeedback.feedback[i]);
    }

    return headerResult;
}

pdcpHeaderResult_t pdcpFuzzer_t::generateReservedPDU(pdcpReservedPDU_t& reservedPDU, int eIdx, int totalByte){
    pdcpHeaderResult_t headerResult = {};
    headerResult.nofByte = totalByte;
    uint8_t firstByte = 0;
    firstByte |= reservedPDU.DC << 7;
    firstByte |= (reservedPDU.pduType & 0x07) << 4;
    firstByte |= reservedPDU.R1 << 3;
    firstByte |= reservedPDU.R2 << 2;
    firstByte |= reservedPDU.R3 << 1;
    firstByte |= reservedPDU.R4;
    headerResult.pattern.push_back(firstByte);
    if (totalByte > 1){
        for (int i = 0; i < totalByte - 1; i++){
            headerResult.pattern.push_back(0xFF);
        }
    }
    return headerResult;
}

void pdcpFuzzer_t::generatePDU(pdcpPDU_t& testCase, uint8_t* packet, int pdcpIdx, int actualLen){
    pdcpHeaderResult_t headerResult = {};
    switch (testCase.type)
    {
    case pdcpData:
        if (testCase.data->isSRB){
            headerResult = generatePdcpDataPDU_SRB(*testCase.data);
        }else{
            headerResult = generatePdcpDataPDU_DRB(*testCase.data, testCase.data->snLen, testCase.eIdx);
        }
        break;
    case pdcpROHCfeedback:
        headerResult = generateROHCFeedback(*testCase.rohcFeedback, testCase.eIdx);
        break;
    case pdcpStatus:
        headerResult = generatePdcpStatus(*testCase.status, testCase.eIdx);
        break;
    case pdcpLWAstatus:
        headerResult = generateLWAStatus(*testCase.lwaStatus, testCase.eIdx);
        break;
    case pdcpLWAendmarker:
        headerResult = generateLWAEndMarker(*testCase.lwaEndmarker, testCase.eIdx);
        break;
    case pdcpUDCfeedback:
        headerResult = generateUDCFeedback(*testCase.udcFeedback, testCase.eIdx, testCase.totalByte);
        break;
    case pdcpEHCfeedback:
        headerResult = generateEHCFeedback(*testCase.echFeedback, testCase.eIdx, testCase.totalByte);
        break;
    case pdcpReserved:
        headerResult = generateReservedPDU(*testCase.reserved, testCase.eIdx, testCase.totalByte);
        break;
    default:
        break;
    }

    // Copy header to packet
    for (int i = 0; i < headerResult.nofByte; i++){ // check available space in packet previously?
        if (pdcpIdx + i >= actualLen){
            // std::cout << "[PDCP] Error: actual length is not enough to contain PDCP test case" << "\n";
            break;
        }else{
            packet[pdcpIdx+i] = headerResult.pattern[i];
        }
    }
    pdcpIdx = pdcpIdx + headerResult.nofByte;

    if (testCase.type == pdcpData && testCase.data->isSRB){ // modify MAC-I
        pdcpIdx = pdcpIdx + testCase.data->datasize;
        if (pdcpIdx < actualLen){
            packet[pdcpIdx] = testCase.data->isWrongMAC? 0x01:0x00;
        }else{
            // std::cout << "[PDCP] Error: actual length is not enough to contain MAC-I" << "\n";
        }
    }else if (testCase.type == pdcpStatus){
        for (int i = 0; i < testCase.status->nofBitmap; i++){
            if (pdcpIdx + i < actualLen){
                packet[pdcpIdx+i] = testCase.status->bitmap[i];
            }else{
                // std::cout << "[PDCP] Error: actual length is not enough to contain bitmap" << "\n";
            }
        }
    }
}




std::string pdcpFuzzer_t::getPDUTypeString(pdcpPDUType_t& type){
    std::string typeStr;
    switch (type)
    {
    case pdcpData:
        typeStr = "DataPDU";
        break;
    case pdcpROHCfeedback:
        typeStr = "ROHCFeedback";
        break;
    case pdcpStatus:
        typeStr = "StatusPDU";
        break;
    case pdcpLWAstatus:
        typeStr = "LWAStatus";
        break;
    case pdcpLWAendmarker:
        typeStr = "LWAEndMkr";
        break;
    case pdcpUDCfeedback:
        typeStr = "UDCFBk";
        break;
    case pdcpEHCfeedback:
        typeStr = "EHCFBk";
        break;
    case pdcpReserved:
        typeStr = "Reserved";
        break;
    default:
        break;
    }
    return typeStr;
}

void pdcpFuzzer_t::printPDUtestcase(pdcpPDU_t& pdu, int tti, int actualLen){
    pdcpPDUType_t type = pdu.type;
    std::string typeStr = getPDUTypeString(type);

    std::cout << "[PDU] Type = " << typeStr << " - LCID: " << pdu.lcid << " - totalByte = " << (int)pdu.totalByte \
    << " - ActualLen = " << actualLen << " -- rlcSN = " << (int)pdu.rlcSN << " -- rlcType: " << (int)pdu.rlcType  <<  BLUE_TEXT << " - eIdx = " << (int)pdu.eIdx << RESET_COLOR << "\n";

    // if (type == pdcpData){
    //     // print content of data pdu
    //     std::shared_ptr<pdcpDataPDU_t> data = pdu.data;
    //     std::cout << "[PDU] isSRB: " << data->isSRB << " -- snLen: " << (int)pdu.data->snLen << " -- R1: " << data->R1 << " -- P: " << data->P << " -- SN: " << data->SN << " -- dataSz: " << data->datasize << " -- WMAC: " << data->isWrongMAC <<  "\n";
    // }else if (type == pdcpStatus){
    //     // print content of status pdu
    //     std::shared_ptr<pdcpStatusPDU_t> status = pdu.status;
    //     std::cout << "[PDU] FMS: " << status->FMS << " -- nofBitmap: " << status->nofBitmap << "\n";
    //     if (status->nofBitmap > 0){
    //         std::cout << "[PDU] Bitmap: ";
    //         int nofBitmaptemp = (status->nofBitmap > 3)?3:status->nofBitmap;
    //         for (int i = 0; i < nofBitmaptemp; i++){
    //             std::cout << (int)status->bitmap[i] << " ";
    //         }
    //         std::cout << "\n";
    //     }
    // }else if (type == pdcpROHCfeedback){
    //     // print content of ROHC feedback pdu
    //     std::shared_ptr<pdcpROHCfeedbackPDU_t> rohc = pdu.rohcFeedback;
    //     std::cout << "[PDU] nofBytes: " << rohc->nofByte << "\n";
    //     if (rohc->nofByte > 0){
    //         std::cout << "[PDU] Feedback: ";
    //         int nofBytestemp = (rohc->nofByte > 3)?3:rohc->nofByte;
    //         for (int i = 0; i < nofBytestemp; i++){
    //             std::cout << (int)rohc->feedback[i] << " ";
    //         }
    //         std::cout << "\n";
    //     }
    //     std::cout << "\n";
    
    // }else if (type == pdcpLWAstatus){
    //     // print content of LWA status pdu
    //     std::shared_ptr<pdcpLWAstatusPDU_t> lwaStatus = pdu.lwaStatus;
    //     std::cout << "[PDU] FMS: " << lwaStatus->FMS << " -- HRW: " << lwaStatus->HRW << " -- NMP: " << lwaStatus->NMP << "\n";
    // }else if (type == pdcpLWAendmarker){
    //     // print content of LWA end marker pdu
    //     std::shared_ptr<pdcpLWAendmarkerPDU_t> lwaEndMarker = pdu.lwaEndmarker;
    //     std::cout << "[PDU] LSN: " << lwaEndMarker->LSN << "\n";
    // }else if (type == pdcpUDCfeedback){
    //     // print content of UDC feedback pdu
    //     std::shared_ptr<pdcpUDCfeedbackPDU_t> udcFeedback = pdu.udcFeedback;
    //     std::cout << "[PDU] FE: " << udcFeedback->FE << "\n";
    // }else if (type == pdcpEHCfeedback){
    //     // print content of EHC feedback pdu
    //     std::shared_ptr<pdcpECHfeedbackPDU_t> ehcFeedback = pdu.echFeedback;
    //     std::cout << "[PDU] nofBytes: " << ehcFeedback->nofBytes << "\n";
    //     if (ehcFeedback->nofBytes > 0){
    //         std::cout << "[PDU] Feedback: ";
    //         int nofBytestemp = (ehcFeedback->nofBytes > 3)?3:ehcFeedback->nofBytes;
    //         for (int i = 0; i < nofBytestemp; i++){
    //             std::cout << (int)ehcFeedback->feedback[i] << " ";
    //         }
    //         std::cout << "\n";
    //     }
    // }else if (type == pdcpReserved){
    //     // print content of reserved pdu
    //     std::shared_ptr<pdcpReservedPDU_t> reservedPDU = pdu.reserved;
    //     std::cout << "[PDU] pduType: " << (int)reservedPDU->pduType << "\n";
    // }

    std::cout << "\n";
}

void pdcpFuzzer_t::send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen){
    // check if we need RRC reconfiguration complete before sending this test case
    if (curTestCase.rrc_reconfig_type != PDCP_NORMAL && !receivedRRCReconfigComplete && fuzzingState == state4){
        std::cout << "[PDCP] Error: Not received RRC Reconfiguration Complete, probably due to unsupported configuration by UE" << "\n";
        return;
    }
    
    int lcID = curTestCase.lcid;
    // update sequence number of RLC PDU
    if (lcID >= 1){ 
        curTestCase.rlcSN = rlcSNmap[lcID];
        curTestCase.rlcSN = rlcSNmap[lcID];
    }

    macSubHeaderType_t macSubHeaderType = (curTestCase.totalByte <= 125)?typeA:typeB; // 125 for PDCP PDU, 2 bytes for RLC header, total 127
    macHeaderResult_t subHeader1 = formMacSubHeader(false, macSubHeaderType, 0, 0, 1, lcID, curTestCase.totalByte + 2); // use UM1 or AM1, 2 bytes for RLC header
    macHeaderResult_t subHeader2 = formMacSubHeader(true, typeD, 0, 0, 0, 31, 0); // 31 is padding
    int startIdx = 0;
    for (int i = 0; i < subHeader1.len; i++){
        payload[i] = subHeader1.pattern[i];
    }
    startIdx = startIdx + subHeader1.len;
    for (int i = 0; i < subHeader2.len; i++){
        payload[startIdx + i] = subHeader2.pattern[i];
    }
    startIdx = startIdx + subHeader2.len;
    int remainingByte = actualLen - subHeader1.len - subHeader2.len; // bytes for MAC header
    if (remainingByte >= curTestCase.totalByte + 2){
        // now form RLC header
        uint16_t rlcHea = 0; // 2 bytes
        if ((lcID < 3) || (curTestCase.rrc_reconfig_type == PDCP_15BIT_SN || curTestCase.rrc_reconfig_type == PDCP_18BIT_SN)){ // SRB, AM1, Figure 6.2.1.4-1, also used for PDCP DRBs that are configured by 15/18 bit SN
            // for DRBs that are configured by 15/18 bit SN, we use default RLC AM1 header, we dont configure RLC SN length, so we can use the same constructor here
            rlcHea |= 1 << 15; // DC = 1 for Data PDU AM1
            rlcHea |= 0 << 14; // RF = 0
            rlcHea |= 1 << 13; // R2 = 0
            rlcHea |= 0 << 11; // FI = 0
            rlcHea |= 0 << 10; // E = 0
            rlcHea |= curTestCase.rlcSN;
            payload[startIdx] = rlcHea >> 8;
            payload[startIdx + 1] = rlcHea & 0xFF;
            startIdx = startIdx + 2;
            int remainingByte2 = actualLen - startIdx;
            if (remainingByte2 >= curTestCase.totalByte){
                generatePDU(curTestCase, payload, startIdx, actualLen);
            }else{
                // std::cout << "[GEN] Error(2): actual length is not enough to contain PDCP PDU" << "\n";
            }
        }else{ // DRB, UM1, Figure 6.2.1.3-2
            rlcHea |= 0 << 15; // R1 = 0
            rlcHea |= 0 << 14; // R2 = 0
            rlcHea |= 0 << 13; // R3 = 0
            rlcHea |= 0 << 11; // Fi = 0
            rlcHea |= 0 << 10; // E = 0
            rlcHea |= curTestCase.rlcSN;
            payload[startIdx] = rlcHea >> 8;
            payload[startIdx + 1] = rlcHea & 0xFF;
            startIdx = startIdx + 2;
            int remainingByte2 = actualLen - startIdx;
            if (remainingByte2 >= curTestCase.totalByte){
                generatePDU(curTestCase, payload, startIdx, actualLen);
            }else{
                // std::cout << "[GEN] Error(2): actual length is not enough to contain PDCP PDU" << "\n";
            }
        }
    }else{
        // std::cout << "[GEN] Error(1): actual length is not enough to contain RLC PDU" << "\n";
    }

    std::vector<pdcpPDU_t> &curDB = (readFromFileMode)?verifyDB[fuzzingState]:testcaseDB[fuzzingState];
    // print test case
    if (DEBUG_MODE){
        std::cout << "[PDCP] SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << " -- Fuzzing State: " << (int)fuzzingState << ", RNTIState =  " \
            << fuzzingState << " -- Idx = " << idx[fuzzingState] << "/" << curDB.size() << " -- nofCrash: " << nofCrash << "\n";
        printPDUtestcase(curTestCase, tti_tx_dl, actualLen);
    }

    // save PDU to crash buffer
    pdcpPDUType_t    curType = curTestCase.type;
    pdcpPDU_t        savePDU(curType);
    savePDU         = curTestCase;
    crashBuffer.push(savePDU);
    recent_testcases[fuzzingState].push(idx[fuzzingState]);

    // update index
    if (idx[fuzzingState] < (int)curDB.size()){
        idx[fuzzingState]++;
    }
    if (idx[fuzzingState] == (int)curDB.size()){
        std::cout << "[RLC] Finish sending RLC test cases for State" << fuzzingState << "\n";
        idx[fuzzingState]++;
        // fuzzingState = stateUnknown;
    }

    // update RLC Sequence Number
    if (lcID >= 1){
        rlcSNmap[lcID]++;
    }

    // if (!readFromFileMode){
    //     if (idx[2] == (int)testcaseDB[2].size() && idx[3] == (int)testcaseDB[3].size() && idx[4] == (int)testcaseDB[4].size() && idx[5] == (int)testcaseDB[5].size()){
    //         std::cout << "[RLC] Finish sending RLC test cases for State 2, 3, 4, 5" << "\n";
    //         switchState(stateUnknown);
    //         fuzzingState = stateUnknown;
    //         // send switch airplane mode to adb
            
    //         // idx[2] = 0;
    //         // idx[3] = 0;
    //         // idx[4] = 0;
    //         // idx[5] = 0;
    //     }
    // }else{
    //     if (verifyingState == state5 && idx[5] == (int)verifyDB[5].size()){
    //         std::cout << "[RLC] Finish verifying RLC test cases for State 5" << "\n";
    //         switchState(stateUnknown);
    //         // send switch airplane mode to adb
            
    //         // idx[2] = 0;
    //         // idx[3] = 0;
    //         // idx[4] = 0;
    //         idx[5] = 0;
    //     }
    // }
}

void pdcpFuzzer_t::writeTCtoFile(std::ofstream& file, pdcpPDU_t& pdu){
    if (file){
        std::cout << "\n";
    }
}

void pdcpFuzzer_t::resetIndex(){
    idx[5] = startIdx; // verify crash
    idx[4] = startIdx; // verify crash
    idx[3] = startIdx;
    idx[2] = startIdx;
    
}

void pdcpFuzzer_t::update_rlc_sequence_number(uint16_t lcid, uint16_t sn){
    rlcSNmap[lcid] = sn;
}

int pdcpFuzzer_t::check_rrc_reconfig_type(){
    curTestCase = getCurTestCase(); // because this funtion is called before check_send_test_case
    return (int)curTestCase.rrc_reconfig_type;
}


}



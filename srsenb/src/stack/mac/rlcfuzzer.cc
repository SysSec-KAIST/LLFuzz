#include "srsenb/hdr/stack/mac/rlcfuzzer.h"
#include "srsenb/hdr/stack/mac/fuzzer_base.h"
#include "srsenb/hdr/stack/mac/utility.h"
#include "srsran/interfaces/enb_rrc_interface_mac.h"


namespace srsenb {

rlcFuzzer_t::rlcFuzzer_t()
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

rlcFuzzer_t::~rlcFuzzer_t()
{
    // crashLog.close();
    tcFile.close();
    terminalLog.close();
    verifiedCrash.close();
}

// void rlcFuzzer_t::set_fuzzing_config(LLState_t targetState_, bool verifyingMode_, int startIdx_){
//     fuzzingState = targetState_;
//     readFromFileMode = verifyingMode_;
//     startIdx = startIdx_;
// }

void print_test_case_to_file(rlcPDU_t& pdu, std::ofstream& file) {
    bool isAM = (pdu.type == rlcAM1 || pdu.type == rlcAM2 || pdu.type == rlcAMSegment1 || pdu.type == rlcAMSegment2);
    bool isUM = (pdu.type == rlcUM1 || pdu.type == rlcUM2);
    bool isStatusPDU = (pdu.type == rlcStatus);

    int nofChunk = (isAM) ? pdu.am.nofChunk : ((isUM) ? pdu.um.nofChunk : pdu.status.nofChunk);
    std::vector<rlcChunk_t>& chunk = (isAM) ? (pdu.am.chunk) : (pdu.um.chunk);
    // std::vector<rlcStatusChunk_t>& statusChunk = pdu.status.chunk;

    std::string pduTypeStr;
    switch (pdu.type) {
        case rlcUM1: pduTypeStr = "UM1"; break;
        case rlcUM2: pduTypeStr = "UM2"; break;
        case rlcAM1: pduTypeStr = "AM1"; break;
        case rlcAM2: pduTypeStr = "AM2"; break;
        case rlcStatus: pduTypeStr = "StatusPDU"; break;
        case rlcAMSegment1: pduTypeStr = "AMS1"; break;
        case rlcAMSegment2: pduTypeStr = "AMS2"; break;
        default: pduTypeStr = "Unknown"; break;
    }
    
    file << "[PDU] Type = " << pduTypeStr << " - LCID: " << pdu.lcid 
         << " - totalByte = " << (int)pdu.totalByte 
         << " - nofChunk: " << nofChunk 
         << " - MT = " << (int)pdu.macType 
         << " -- RRCConfig: " << (int)pdu.rrc_reconfig_type
         << " - eIdx = " << (int)pdu.eIdx << "\n";

    if (isUM) {
        file << "[PDU] R1 = " << (int)pdu.um.R1 
             << " -- R2 = " << (int)pdu.um.R2 
             << " -- R3 = " << (int)pdu.um.R3 
             << " -- FI = " << (int)pdu.um.FI 
             << " -- E = " << (int)pdu.um.E 
             << " -- SN = " << (int)pdu.um.SN 
             << " -- SN_Len = " << (int)pdu.um.snLen << "\n";
    } 
    else if (pdu.type == rlcAM1 || pdu.type == rlcAM2) {
        file << "[PDU] DC = " << (int)pdu.am.DC 
             << " -- RF = " << (int)pdu.am.RF 
             << " -- P = " << (int)pdu.am.P 
             << " -- FI = " << (int)pdu.am.FI 
             << " -- E = " << (int)pdu.am.E 
             << " -- SN = " << (int)pdu.am.SN 
             << " -- SN_Len = " << (int)pdu.am.snLen 
             << " -- LI Len = " << (int)pdu.am.liLen << "\n";
    }
    else if (pdu.type == rlcAMSegment1 || pdu.type == rlcAMSegment2) {
        file << "[PDU] DC = " << (int)pdu.am.DC 
             << " -- RF = " << (int)pdu.am.RF 
             << " -- P = " << (int)pdu.am.P 
             << " -- FI = " << (int)pdu.am.FI 
             << " -- E = " << (int)pdu.am.E 
             << " -- SN = " << (int)pdu.am.SN 
             << " -- SN_Len = " << (int)pdu.am.snLen << "\n"
             << "LI_Len = " << (int)pdu.am.liLen 
             << " -- LSF = " << (int)pdu.am.LSF 
             << " -- SO = " << (int)pdu.am.SO 
             << " -- nofChunk = " << nofChunk << "\n";
    }
    else if (isStatusPDU) {
        file << "[PDU] CPT = " << (int)pdu.status.cpt 
             << " -- ACK_SN = " << (int)pdu.status.ackSN 
             << " -- E1_0 = " << (int)pdu.status.E1_0 
             << " -- NACK_SN = " << (int)pdu.status.nackSN 
             << " -- nofChunk = " << nofChunk << "\n";
    }

    if (nofChunk > 1 && !isStatusPDU) {
        for (int h = 0; h < std::min(3, nofChunk - 1); h++) {
            file << "[PDU] E_" << h << " = " << (int)chunk[h].E 
                 << " -- LI = " << (int)chunk[h].L << "\n";
        }
    }
    else if (nofChunk > 1 && isStatusPDU && pdu.eIdx == 2) {
        file << "[PDU] E1 = " << (int)pdu.status.chunk[0].E1 
             << " -- E2 = " << (int)pdu.status.chunk[0].E2 
             << " -- SOStart = " << (int)pdu.status.chunk[1].soStart 
             << " -- SOEnd = " << (int)pdu.status.chunk[1].soEnd 
             << " -- NACK_SN = " << (int)pdu.status.chunk[1].nackSN << "\n";
    }

    file << "[PDU] --------------\n";
    file.flush();
}

// TODO:
void rlcFuzzer_t::saveCrashtoFile(int oracle){
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
        }
    }

    // save recent testcase in the crash buffer to file
    std::deque<rlcPDU_t> recent_pdu = crashBuffer.getBuffer();
    crashLogFile << " Recent PDU: " << "\n";
    for (int i = 0; i < (int)recent_pdu.size(); i++){
        recent_pdu[i].print_general_info_to_file(crashLogFile);
        print_test_case_to_file(recent_pdu[i], crashLogFile);
    }

    crashLogFile << "\n";
    crashLogFile << "\n";
    nofCrash++;
}

int rlcFuzzer_t::getFixedHeaderSize(rlcPDUType_t type, int snLen){
    int size = 0;
    switch (type)
    {
    case rlcUM1:
    case rlcUM2:
        if (snLen == 10){ size = 2; }
        else if (snLen == 5){ size = 1; }
        break;
    case rlcAM1:
    case rlcAM2:
        if (snLen == 16){ size = 3; }
        else if (snLen == 10){ size = 2; }
        break;
        /* code */
        break;
    case rlcAMSegment1:
    case rlcAMSegment2:
        if (snLen == 10) {size = 4;}
        else if (snLen == 16) {size = 5;}
        break;
    default:
        break;
    }
    return size;
}

void allocVectorPDU(rlcPDU_t& pdu, int nofChunk){
  for (int n = 0; n < nofChunk; n++){
    rlcChunk_t newChunk = {};
    if (pdu.type == rlcUM1 || pdu.type == rlcUM2){
        pdu.um.chunk.push_back(newChunk);
        pdu.um.nofChunk++;
    }else if (pdu.type == rlcAM1 || pdu.type == rlcAM2 || pdu.type == rlcAMSegment1 || pdu.type == rlcAMSegment2){
        pdu.am.chunk.push_back(newChunk);
        pdu.am.nofChunk++;
    }else if (pdu.type == rlcStatus){
        rlcStatusChunk_t newChunkStatus = {};
        pdu.status.chunk.push_back(newChunkStatus);
        pdu.status.nofChunk++;
    }
  }
}

int rlcFuzzer_t::calTotalByte(rlcPDU_t& pdu){
    int totalByte = 0;
    switch (pdu.type)
    {
    case rlcUM1:
        if (pdu.eIdx == -1){ totalByte = 1; }
        else if (pdu.eIdx == 0){ 
            totalByte += getFixedHeaderSize(pdu.type, pdu.um.snLen);
            totalByte += pdu.um.um1DataLen;
        }
        break;
    case rlcUM2:
        if (pdu.eIdx == -3) { totalByte = (pdu.um.snLen == 10)?3:2;} // 3 bytes if snLen = 10, 2 bytes if snLen = 5
        else if (pdu.eIdx == -2) { 
            totalByte += getFixedHeaderSize(pdu.type, pdu.um.snLen);
            int nofSubhea = pdu.um.nofChunk - 1;
            int subHeaderByte = 0;
            if (nofSubhea % 2 == 0) {
                subHeaderByte = nofSubhea*12/8;
            }else{
                subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
            }
            totalByte += subHeaderByte; // no payload for index -2
        }else if (pdu.eIdx == -1) { totalByte = 1;}
        else{
            totalByte += getFixedHeaderSize(pdu.type, pdu.um.snLen);
            int subHeaderByte = 0;
            int nofSubhea = pdu.um.nofChunk - 1;
            //calculate nofByte for subheader
            if (nofSubhea % 2 == 0) {
                subHeaderByte = nofSubhea*12/8;
            }else{
                subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
            }
            totalByte += subHeaderByte; // no payload for index -2
            //calculate nofByte for payload
            for (int i = 0; i < pdu.eIdx+1 ; i++){
                totalByte += pdu.um.chunk[i].dataLen;
            }

        }
        break;
    case rlcAM1:
        if (pdu.eIdx == -1){ totalByte = 1; }
        else if (pdu.eIdx == -2){ // only sn16 has -2 idx
            totalByte = 2;
        }
        else if (pdu.eIdx == 0){ 
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            totalByte += pdu.am.am1DataLen;
        }
        break;
    case rlcAM2:
        if (pdu.eIdx == -3) { totalByte = (pdu.am.snLen == 10)? 3: 4;} // 3 bytes if sn len = 10, 4 bytes if sn len = 16
        else if (pdu.eIdx == -2) { 
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            int nofSubhea = pdu.am.nofChunk - 1;
            int subHeaderByte = 0;
            if (pdu.am.liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (pdu.am.liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            totalByte += subHeaderByte; // no payload for index -2
        }else if (pdu.eIdx == -1) { totalByte = 1;}
        else{
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            int subHeaderByte = 0;
            int nofSubhea = pdu.am.nofChunk - 1;
            //calculate nofByte for subheader
            if (pdu.am.liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (pdu.am.liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            
            totalByte += subHeaderByte; // no payload for index -2
            //calculate nofByte for payload
            for (int i = 0; i < pdu.eIdx+1 ; i++){
                totalByte += pdu.am.chunk[i].dataLen;
            }

        }
        break;
    case rlcStatus:
        if (pdu.eIdx == -3){ totalByte = (pdu.status.snLen == 10)? 4:5; } // E1_0 = 1, E2_1 = 1, E1_2 = 1, E2_2 = 1, but no following byte
        else if (pdu.eIdx == -2){ totalByte = (pdu.status.snLen == 10)? 2:3; } //E1_0 = 1 but no following byte
        else if (pdu.eIdx == -1){ totalByte = 1; }
        else if (pdu.eIdx >= 0 && pdu.status.snLen == 10) { 
            const int fixedByte = 2; // until E1_0
            const int nofChunk = pdu.status.nofChunk; // no -1 as they are all header, no payload
            const int eIdx = pdu.eIdx;
            std::vector<rlcStatusChunk_t>& chunk = pdu.status.chunk;
            int nofBitforChunk = 0; // we are counting bits, not bytes

            if (pdu.status.E1_0 == 1){
                // first chunk (index = 0 also)
                nofBitforChunk += pdu.status.snLen - 1 + 2;                     // -1 as there is 1 bit in previous byte (after E1_0), +2 as E1 E2
                if (chunk[0].E2 == 1){
                    nofBitforChunk += 15*2; // SO start and end
                }

                // count bits from 1 to eIdx - 1
                for (int cIdx = 1; cIdx < eIdx; cIdx++){                        // from 0 as the first chunk is added before, and the size of next chunk is decided by previous E1, E2
                    if (chunk[cIdx - 1].E1 && chunk[cIdx].E2){                      // E1 = 1, E2 = 1
                        nofBitforChunk += pdu.status.snLen + 15*2 + 2;          // snLen + 15*2 for SO, 2 bits E1 E2
                    }else if (chunk[cIdx - 1].E1 && !chunk[cIdx].E2){               // E1 = 1, E2 = 0
                        nofBitforChunk += pdu.status.snLen + 2;                 // snLen + 2 bits E1 E2, no SO
                    }else if (!chunk[cIdx - 1].E1 && !chunk[cIdx].E2){              // E1 = 0, E2 = 0
                        nofBitforChunk += 0;
                    }
                }
                // count bits for eIdx, this one should have a half of required bits to make it break in this point
                int nofBitforEIdx = 0;
                if (eIdx > 0){ // if eIdx == 0, nofBitforEIdx already calculated above
                    if (chunk[eIdx - 1].E1 && chunk[eIdx].E2){                      // E1 = 1, E2 = 1
                        nofBitforEIdx += pdu.status.snLen + 15*2 + 2;               // snLen + 15*2 for SO, 2 bits E1 E2
                    }
                    else if (chunk[eIdx - 1].E1 && !chunk[eIdx].E2){                // E1 = 1, E2 = 0
                        nofBitforEIdx += pdu.status.snLen + 2;                      // snLen + 2 bits E1 E2, no SO
                    } else if (!chunk[eIdx - 1].E1 && !chunk[eIdx].E2){              // E1 = 0, E2 = 0
                        nofBitforEIdx += 0;
                    }
                }
                if (eIdx == 0){
                    nofBitforChunk = nofBitforChunk/2;
                }else if (eIdx != nofChunk - 1 && eIdx > 0){ // if eIdx == nofChunk - 1, it is normal packet
                    nofBitforChunk += nofBitforEIdx/2;
                }else{
                    nofBitforChunk += nofBitforEIdx;
                }
            }

            int nofByteforChunk = (nofBitforChunk + 7)/8; // +7 means round up
            totalByte = fixedByte + nofByteforChunk;
            // printf("[MTT] Status PDU, eIdx = %d, totalByte = %d, Byte for chunk = %d, nofChunk = %d, snLen = %d \n", eIdx, totalByte, nofByteforChunk, nofChunk, pdu.status.snLen);
        }
        else if (pdu.eIdx >= 0 && pdu.status.snLen == 16) { 
            const int fixedByte = 3; // until E1_0
            const int nofChunk = pdu.status.nofChunk; // no -1 as they are all header, no payload
            std::vector<rlcStatusChunk_t>& chunk = pdu.status.chunk;
            int nofBitforChunk = 0;
            const int eIdx = pdu.eIdx;

            if (pdu.status.E1_0 == 1){
                // first chunk (index = 0)
                nofBitforChunk += pdu.status.snLen - 3 + 2;                     // -3 as there are 3 bits in previous byte (after E1_0), +2 as E1 E2
                if (chunk[0].E2 == 1){
                    nofBitforChunk += 16*2; // SO start and end
                }

                // count bits from 1 to eIdx - 1
                for (int cIdx = 1; cIdx < eIdx; cIdx++){                            // from 0 as the first chunk is added before, and the size of next chunk is decided by previous E1, E2
                    if (chunk[cIdx - 1].E1 && chunk[cIdx].E2){                      // E1 = 1, E2 = 1
                        nofBitforChunk += pdu.status.snLen + 16*2 + 2;              // snLen + 16*2 for SO, 2 bits E1 E2
                    }else if (chunk[cIdx - 1].E1 && !chunk[cIdx].E2){               // E1 = 1, E2 = 0
                        nofBitforChunk += pdu.status.snLen + 2;                     // snLen + 2 bits E1 E2, no SO
                    }else if (!chunk[cIdx - 1].E1 && !chunk[cIdx].E2){              // E1 = 0, E2 = 0
                        nofBitforChunk += 0;
                    }
                }
                // count bits for eIdx, this one should have a half of required bits to make it break in this point
                int nofBitforEIdx = 0;
                if (eIdx > 0){ // if eIdx == 0, nofBitforEIdx already calculated above
                    if (chunk[eIdx-1].E1 && chunk[eIdx].E2){                        // E1 = 1, E2 = 1
                        nofBitforEIdx += pdu.status.snLen + 16*2 + 2;               // snLen + 16*2 for SO, 2 bits E1 E2
                    }
                    else if (chunk[eIdx-1].E1 && !chunk[eIdx].E2){                  // E1 = 1, E2 = 0
                        nofBitforEIdx += pdu.status.snLen + 2;                      // snLen + 2 bits E1 E2, no SO
                    } else if (!chunk[eIdx-1].E1 && !chunk[eIdx].E2){               // E1 = 0, E2 = 0
                        nofBitforEIdx += 0;
                    }
                }

                if (eIdx == 0){
                    nofBitforChunk = nofBitforChunk/2;
                }else if (eIdx != nofChunk - 1 && eIdx > 0){ // if eIdx == nofChunk - 1, it is normal packet
                    nofBitforChunk += nofBitforEIdx/2;
                }else{
                    nofBitforChunk += nofBitforEIdx;
                }
            }

            int nofByteforChunk = (nofBitforChunk + 7)/8; // +7 means round up
            totalByte = fixedByte + nofByteforChunk;
        }
        break;
    case rlcAMSegment1:
        if (pdu.eIdx == -1 && pdu.am.snLen == 10){ totalByte = 1; }
        else if (pdu.eIdx == -2 && pdu.am.snLen == 10) { totalByte = 2;}
        else if (pdu.eIdx == -3 && pdu.am.snLen == 10) { totalByte = 3;}
        else if (pdu.eIdx == -4 && pdu.am.snLen == 10) { totalByte = 4;}
        else if (pdu.eIdx == 0 && pdu.am.snLen == 10){ 
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            totalByte += pdu.am.am1DataLen;
        }
        else if (pdu.eIdx == 0 && pdu.am.snLen == 10){ 
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            totalByte += pdu.am.am1DataLen;
        }

        if (pdu.eIdx == -1 && pdu.am.snLen == 16){ totalByte = 1; }
        else if (pdu.eIdx == -2 && pdu.am.snLen == 16) { totalByte = 2;}
        else if (pdu.eIdx == -3 && pdu.am.snLen == 16) { totalByte = 3;}
        else if (pdu.eIdx == 0 && pdu.am.snLen == 16){ 
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            totalByte += pdu.am.am1DataLen;
        }
        else if (pdu.eIdx == 0 && pdu.am.snLen == 16){ 
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            totalByte += pdu.am.am1DataLen;
        }
        break;
    case rlcAMSegment2:
        if (pdu.eIdx == -3 && pdu.am.snLen == 10){ totalByte = 5; }             //-3: subheader has Ex = 1 but there is no available byte behind
        else if (pdu.eIdx == -2 && pdu.am.snLen == 10) { 
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);            // -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
            int nofSubhea = pdu.am.nofChunk - 1;
            int subHeaderByte = 0;
            if (pdu.am.liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (pdu.am.liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            totalByte += subHeaderByte; // no payload for index -2
        }        
        else if (pdu.eIdx == -1 && pdu.am.snLen == 10) { totalByte = 1;}                              // -1: E0 = 1, but only 1 byte totally
        else if (pdu.eIdx >=0 && pdu.am.snLen == 10){
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            int subHeaderByte = 0;
            int nofSubhea = pdu.am.nofChunk - 1;
            //calculate nofByte for subheader
            if (pdu.am.liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (pdu.am.liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            totalByte += subHeaderByte; // no payload for index -2
            //calculate nofByte for payload
            for (int i = 0; i < pdu.eIdx + 1 ; i++){
                totalByte += pdu.am.chunk[i].dataLen;
            }

        }

        if (pdu.eIdx == -3 && pdu.am.snLen == 16){ totalByte = 6; }             //-3: subheader has Ex = 1 but there is no available byte behind
        else if (pdu.eIdx == -2 && pdu.am.snLen == 16) { 
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);            // -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
            int nofSubhea = pdu.am.nofChunk - 1;
            int subHeaderByte = 0;
            if (pdu.am.liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (pdu.am.liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            totalByte += subHeaderByte; // no payload for index -2
        }        
        else if (pdu.eIdx == -1 && pdu.am.snLen == 16) { totalByte = 1;}                              // -1: E0 = 1, but only 1 byte totally
        else if (pdu.eIdx >=0 && pdu.am.snLen == 16){
            totalByte += getFixedHeaderSize(pdu.type, pdu.am.snLen);
            int subHeaderByte = 0;
            int nofSubhea = pdu.am.nofChunk - 1;
            //calculate nofByte for subheader
            if (pdu.am.liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (pdu.am.liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            totalByte += subHeaderByte; // no payload for index -2
            //calculate nofByte for payload
            for (int i = 0; i < pdu.eIdx + 1 ; i++){
                totalByte += pdu.am.chunk[i].dataLen;
            }

        }
        break;
    default:
        break;
    }
    return totalByte;
}

/* eIdx for UM1 (E value in the first header is 0):
*  -1: rlc PDU only has 1 byte, but actually it should have at least 3 bytes (2 for header, 1 for payload)
*   0: normal rlc pdu but mutated sn and FI
*/
void rlcFuzzer_t::mutateUM1_sn10(int snLen, std::vector<rlcPDU_t>& db, int lcid){ 
    // generate initial UM1 packet, this packet is used as seed (or reference) for subsequent mutations
    rlcPDU_t initial_pdu(rlcUM1);
    generate_initial_um1_packet(snLen, initial_pdu, RLC_NORMAL);
    
    // const int E = 0; // E = 0 for UM1
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    for (int eIdx = -1; eIdx < 1; eIdx++){
        if (eIdx == -1){
            for (int FI = 0; FI < 4; FI++){
                for (auto& sn: snList){
                    rlcPDU_t lv1pdu(rlcUM1);
                    lv1pdu = initial_pdu;
                    // packet truncation and mutation
                    lv1pdu.eIdx = eIdx;
                    lv1pdu.um.SN = (sn == -1)?0: sn;
                    // lv1pdu.um.E = E;
                    lv1pdu.um.FI = FI;  
                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                    // mapping to lcid
                    lv1pdu.lcid = lcid;
                    // calculate total byte
                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                    lv1PDUtemp.push_back(std::move(lv1pdu));
                }
            }
            // mutate R
            for (const auto& pdu : lv1PDUtemp){
                for (int R = 0; R <2; R++){
                    rlcPDU_t lv2pdu(rlcUM1);
                    lv2pdu = pdu;
                    lv2pdu.um.R2 = R;
                    lv2pdu.um.SN = -1; // -1 is correct SN
                    db.push_back(std::move(lv2pdu));
                }
            }
            lv1PDUtemp.clear();
            lv1PDUtemp.shrink_to_fit();
        }
        else if (eIdx == 0){
            for (int FI = 0; FI < 4; FI++){
                for (auto& sn: snList){
                    rlcPDU_t lv1pdu(rlcUM1);
                    lv1pdu = initial_pdu;

                    // packet truncation and mutation
                    lv1pdu.eIdx = eIdx;
                    lv1pdu.um.SN = (sn == -1)?0: sn;
                    // lv1pdu.um.E = E;
                    lv1pdu.um.FI = FI;
                    lv1pdu.um.um1DataLen = 10;
                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                    // mapping to lcid
                    lv1pdu.lcid = lcid;
                    // calculate total byte
                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                    lv1PDUtemp.push_back(std::move(lv1pdu));
                }
            }
            // mutate R
            for (const auto& pdu : lv1PDUtemp){
                for (int R = 0; R < 2; R++){
                    rlcPDU_t lv2pdu(rlcUM1);
                    lv2pdu = pdu;
                    lv2pdu.um.R2 = R;
                    db.push_back(std::move(lv2pdu));
                }
            }
            lv1PDUtemp.clear();
            lv1PDUtemp.shrink_to_fit();
        }
    }
}

void rlcFuzzer_t::generate_initial_um1_packet(int snLen, rlcPDU_t& pdu, uint8_t config_type){
    // UM1 does not have data chunk
    pdu.um.snLen = snLen;
    pdu.um.E = 0; // E = 0 for UM1
    pdu.um.FI = 0;
    pdu.um.SN = 0;
    pdu.um.R2 = 0;
    pdu.rrc_reconfig_type = config_type;
}

void rlcFuzzer_t::generate_initial_um2_packet(int snLen, rlcPDU_t& pdu, uint8_t config_type, int nofChunk){
    // check if nofChunk is valid
    if (nofChunk < 2){
        printf("nofChunk should be at least 2\n");
        return;
    }
    // UM2 has data chunk
    pdu.um.snLen = snLen;
    pdu.um.E = 1; // E = 1 for UM2
    pdu.um.FI = 0;
    pdu.um.SN = 0;
    pdu.um.R2 = 0;
    pdu.rrc_reconfig_type = config_type;
    pdu.um.chunk.reserve(nofChunk);
    allocVectorPDU(pdu, nofChunk);
    pdu.um.nofChunk = nofChunk;
    // if we have n chunks, there will be n-1 [E, L] pairs, the n-1 th has E = 0. nofChunk should be at least 2
    // assign first n-1 chunks that have [E, L] pairs
    for (int i = 0; i < nofChunk - 1; i++){
        rlcChunk_t &chunk = pdu.um.chunk[i];
        chunk.E = (i == nofChunk - 2)? 0: 1;
        chunk.L = 10;
        chunk.dataLen = chunk.L;
    }
    // assign the n th chunk that does not have [E, L] pair
    rlcChunk_t &chunk = pdu.um.chunk[nofChunk - 1];
    chunk.E = 0;
    chunk.L = 10; // this value is not used, but we need to assign it to avoid undefined behavior
    chunk.dataLen = chunk.L; 
}

void rlcFuzzer_t::generate_initial_am1_packet(int snLen, rlcPDU_t& pdu, uint8_t config_type, bool isSegment){
    // AM1 does not have data chunk
    pdu.am.snLen = snLen;
    pdu.am.E = 0; // E = 0 for AM1
    pdu.am.DC = 1; // 1 for data PDU
    pdu.am.FI = 0;
    pdu.am.P = 0;
    pdu.am.RF = (isSegment)? 1: 0;
    pdu.am.SN = 0;
    pdu.am.R1_1 = 0;
    pdu.am.R1_2 = 0;
    pdu.rrc_reconfig_type = config_type;
}

void rlcFuzzer_t::generate_initial_am2_packet(int snLen, int liLen, rlcPDU_t& pdu, uint8_t config_type, int nofChunk, bool isSegment){
    // AM2 has data chunk
    pdu.am.snLen = snLen;
    pdu.am.liLen = liLen;
    pdu.am.DC = 1; // 1 for data PDU
    pdu.am.E = 1; // E = 1 for AM2
    pdu.am.P = 0;
    pdu.am.RF = (isSegment)? 1: 0;
    pdu.am.FI = 0;
    pdu.am.SN = 0;
    pdu.am.R1_1 = 0;
    pdu.am.R1_2 = 0;
    pdu.rrc_reconfig_type = config_type;
    pdu.am.chunk.reserve(nofChunk);
    allocVectorPDU(pdu, nofChunk);
    pdu.am.nofChunk = nofChunk;
    // if we have n chunks, there will be n-1 [E, L] pairs, the n-1 th has E = 0. nofChunk should be at least 2
    // assign first n-1 chunks that have [E, L] pairs
    for (int i = 0; i < nofChunk - 1; i++){
        rlcChunk_t &chunk = pdu.am.chunk[i];
        chunk.E = (i == nofChunk - 2)? 0: 1;
        chunk.L = 10;
        chunk.dataLen = chunk.L;
    }
    // assign the n th chunk that does not have [E, L] pair
    rlcChunk_t &chunk = pdu.am.chunk[nofChunk - 1];
    chunk.E = 0;
    chunk.L = 10; // this value is not used, but we need to assign it to avoid undefined behavior
    chunk.dataLen = chunk.L; 
}

/* eIdx for UM1 (E value in the first header is 0), used for packet truncation or marking special muation
*  -1: rlc PDU only has 1 byte, but actually it should have at least 3 bytes (2 for header, 1 for payload)
*   0: normal rlc pdu but mutated sn and FI
*/
void rlcFuzzer_t::mutateUM1_sn5(int snLen, std::vector<rlcPDU_t>& db, int lcid){ 
    
    // generate initial UM1 packet, this packet is used as seed (or reference) for subsequent mutations
    rlcPDU_t initial_pdu(rlcUM1);
    generate_initial_um1_packet(snLen, initial_pdu, RLC_UM_5BIT_SN);
    
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    for (int eIdx = -1; eIdx < 1; eIdx++){
        if (eIdx == -1){
            for (int FI = 0; FI < 4; FI++){
                for (auto& sn: snList){
                rlcPDU_t lv1pdu(rlcUM1);
                lv1pdu = initial_pdu;

                // packet truncation and mutation
                lv1pdu.eIdx = eIdx;
                lv1pdu.um.SN = (sn == -1)?0: sn;
                // lv1pdu.um.E = E;
                lv1pdu.um.FI = FI;
                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                //mapping to lcid
                lv1pdu.lcid = lcid;
                lv1pdu.totalByte = calTotalByte(lv1pdu);
                db.push_back(std::move(lv1pdu));
            }
            }
            // for (const auto& pdu : lv1PDUtemp){ // ------> not mutate R together with FI
            //     for (int R = 0; R <2; R++){
            //         rlcPDU_t lv2pdu(rlcUM1);
            //         lv2pdu = pdu;
            //         lv2pdu.um.R2 = R;
            //         testcaseDB.push_back(std::move(lv2pdu));
            //     }
            // }
            // lv1PDUtemp.clear();
            // lv1PDUtemp.shrink_to_fit();
        }
        else if (eIdx == 0){
            // for (int snIdx = 0; snIdx < 6; snIdx ++){
                for (int FI = 0; FI < 4; FI++){
                    for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcUM1);
                        lv1pdu = initial_pdu;

                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.um.SN = (sn == -1)?0: sn;
                        // lv1pdu.um.E = E;
                        lv1pdu.um.FI = FI;
                        lv1pdu.um.um1DataLen = 10;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                    }
                }
            // }
            // for (const auto& pdu : lv1PDUtemp){  // ------> not mutate R together with FI
            //     for (int R = 0; R < 2; R++){
            //         rlcPDU_t lv2pdu(rlcUM1);
            //         lv2pdu = pdu;
            //         lv2pdu.um.R2 = R;
            //         testcaseDB.push_back(std::move(lv2pdu));
            //     }
            // }
            // lv1PDUtemp.clear();
            // lv1PDUtemp.shrink_to_fit();
        }
    }
}

/* eIdx for UM2 (E value in the first header is 1):
*  -3: subheader has Ex = 1 but there is no available byte behind
*  -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
*  -1: E0 = 1, but only 1 byte totally
*   0->3: the position (idx) of sub-header that L is longer than actual payload
*/
void rlcFuzzer_t::mutateUM2_sn10(int snLen, int nofChunk ,std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    // generate initial UM2 packet, this packet is used as seed (or reference) for subsequent mutations
    rlcPDU_t initial_pdu(rlcUM2);
    generate_initial_um2_packet(snLen, initial_pdu, RLC_NORMAL, nofChunk);
    
    // const int E = 1; // E = 1 for UM2
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    int liLen = 11;
    std::vector<int>& LI_List = (liLen == 11)? LI_List11bit: LI_List15bit;
    if (nofChunk < 20){
        for (int eIdx = -3; eIdx < 0; eIdx++){
            if (eIdx == -3){
                // for (int snIdx = 0; snIdx < 11; snIdx++){
                    for (int FI = 0; FI < 4; FI++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcUM2);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.um.SN = (sn == -1)?0: sn;
                        // lv1pdu.um.E = E;
                        lv1pdu.um.FI = FI;
                        lv1pdu.um.chunk[0].E = 1;
                        lv1pdu.um.chunk[0].L = 10;
                        // if (eIdx == -2){ // all E in [E, LI] are set to 1, even the last one
                        //     for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){ // nofChunk - 1 because the last chunk does not have [E, LI]
                        //         lv1pdu.um.chunk[chunkIdx].E = 1;
                        //         lv1pdu.um.chunk[chunkIdx].L = 10;
                        //     }
                        // }
                        lv1pdu.um.chunk[0].dataLen = 10;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        lv1PDUtemp.push_back(std::move(lv1pdu));
                        }
                        
                    }
                // mutate R
                for (const auto& pdu : lv1PDUtemp){
                    for (int R = 0; R <2; R++){
                        rlcPDU_t lv2pdu(rlcUM2);
                        lv2pdu = pdu;
                        lv2pdu.um.R2 = R;
                        db.push_back(std::move(lv2pdu));
                    }
                }
                lv1PDUtemp.clear();
                lv1PDUtemp.shrink_to_fit();
            }
            else if (eIdx == -2){
                // for (int snIdx = 0; snIdx < 11; snIdx ++){
                    for (int FI = 0; FI < 4; FI++){
                        for (auto& sn: snList){
                            rlcPDU_t lv1pdu(rlcUM2);
                            lv1pdu = initial_pdu;
                            // packet truncation and mutation
                            lv1pdu.eIdx = eIdx;
                            lv1pdu.um.SN = (sn == -1)?0: sn;
                            // lv1pdu.um.E = E;
                            lv1pdu.um.FI = FI;
                            for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                lv1pdu.um.chunk[chunkIdx].E = 1;
                                lv1pdu.um.chunk[chunkIdx].L = (maxL)?(pow(2, snLen) -1): 10;
                                lv1pdu.um.chunk[chunkIdx].dataLen = 0;
                            }
                            lv1pdu.um.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                            // mapping to lcid
                            lv1pdu.lcid = lcid;
                            // calculate total byte
                            lv1pdu.totalByte = calTotalByte(lv1pdu);
                            lv1PDUtemp.push_back(std::move(lv1pdu));
                        }
                    }
                // mutate R
                for (const auto& pdu : lv1PDUtemp){
                    for (int R = 0; R <2; R++){
                        rlcPDU_t lv2pdu(rlcUM2);
                        lv2pdu = pdu;
                        lv2pdu.um.R2 = R;
                        db.push_back(std::move(lv2pdu));
                    }
                }
                lv1PDUtemp.clear();
                lv1PDUtemp.shrink_to_fit();
            }else if (eIdx == -1){
                // printf("eIdx = -1 \n");
                for (int FI = 0; FI < 4; FI++){
                    for (auto& sn: snList){
                    rlcPDU_t lv1pdu(rlcUM2);
                    lv1pdu = initial_pdu;
                    // packet truncation and mutation
                    lv1pdu.eIdx = eIdx;
                    lv1pdu.um.SN = (sn == -1)?0: sn;
                    // lv1pdu.um.E = E;
                    lv1pdu.um.FI = FI;
                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                    // mapping to lcid
                    lv1pdu.lcid = lcid;
                    // calculate total byte
                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                    lv1PDUtemp.push_back(std::move(lv1pdu));
                }
                }
                for (const auto& pdu : lv1PDUtemp){
                    for (int R = 0; R <2; R++){
                        rlcPDU_t lv2pdu(rlcUM2);
                        lv2pdu = pdu;
                        lv2pdu.um.R2 = R;
                        db.push_back(std::move(lv2pdu));
                    }
                }
                lv1PDUtemp.clear();
                lv1PDUtemp.shrink_to_fit();
            }
        }
        for (int eIdx = 0; eIdx < nofChunk; eIdx++){        // eIdx = nofChunk - 1 is normal pdu
            for (auto& li: LI_List){
                for (int FI = 0; FI < 4; FI++){
                    for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcUM2);
                        rlcPDU_t lv1pduCase2(rlcUM2);           // this is for test case with L = 0
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.um.SN = (sn == -1)?0: sn;
                        // lv1pdu.um.E = E;
                        lv1pdu.um.FI = FI;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // assign legitimate values for [E, LI]. If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                        for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                            lv1pdu.um.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                            lv1pdu.um.chunk[chunkIdx].L = 10;
                        }
                        // assign LI value in the eIdx position
                        lv1pdu.um.chunk[eIdx].L = li;

                        // assign legitimate values for dataLen up to eIdx
                        for (int i = 0; i < eIdx; i++){
                            lv1pdu.um.chunk[i].dataLen = 10;
                        }
                        // assign dataLen value in the eIdx position
                        if (eIdx != nofChunk - 1){
                            lv1pdu.um.chunk[eIdx].dataLen = (li == 0)?0: 5;  // this is position that L is longer than actual payload
                        }else{
                            lv1pdu.um.chunk[eIdx].dataLen = 10;
                        }
                        // assign dataLen value from eIdx + 1 to the end
                        for (int i = eIdx + 1; i < nofChunk; i++){
                            lv1pdu.um.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                        }

                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // lv1pduCase2 = lv1pdu;                   // this is for test case with L = 0
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);

                        if (eIdx < nofChunk - 1 || (eIdx == nofChunk - 1 && li == 0)){
                            db.push_back(std::move(lv1pdu));
                        }
                        
                        // test cases with L = 0, only set L = 0 for the sub-header before eIdx
                        // if (eIdx > 0){
                        //     lv1pduCase2.um.chunk[eIdx - 1].L = 0;
                        //     lv1pduCase2.um.chunk[eIdx - 1].dataLen = 0;
                        //     lv1pduCase2.totalByte = calTotalByte(lv1pduCase2);
                        //     db.push_back(std::move(lv1pduCase2));
                        // }
                    }
                }
            }
        }
    }else{ // if there are many chunks (such as 100 chunks of data)
        int eIdx = -2; // only generate test case with eIdx = -2 and 1 normal pdu
        // for (int snIdx = 0; snIdx < 1; snIdx ++){ // sn will be updated later
            for (int FI = 0; FI < 4; FI++){
                for (auto& sn: snList){
                    rlcPDU_t lv1pdu(rlcUM2);
                    lv1pdu = initial_pdu;
                    // packet truncation and mutation
                    lv1pdu.eIdx = eIdx;
                    lv1pdu.um.SN = (sn == -1)?0: sn;
                    // lv1pdu.um.E = E;
                    lv1pdu.um.FI = FI;
                    for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                        lv1pdu.um.chunk[chunkIdx].E = 1; 
                        lv1pdu.um.chunk[chunkIdx].L = (maxL)?(pow(2, 11) -1): 10; // for UM LI Length alaways 11
                        lv1pdu.um.chunk[chunkIdx].dataLen = 0;
                    }
                    lv1pdu.um.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                    // mapping to lcid
                    lv1pdu.lcid = lcid;
                    // calculate total byte
                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                    db.push_back(std::move(lv1pdu));
                }
            // }
            }
        // eIdx = nofChunk - 1;
        int gap = nofChunk/3;
        std::vector<int> eidx_list;
        for (int index = 0; index < nofChunk; index = index + gap){
            eidx_list.push_back(index);
        }
        eidx_list.push_back(nofChunk - 1); // normal packet

        for (auto& eIndex: eidx_list){ // sn will be updated later
            for (int FI = 0; FI < 4; FI++){
                for (auto& sn: snList){
                    for (auto& li: LI_List){
                        rlcPDU_t lv1pdu(rlcUM2);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIndex;
                        lv1pdu.um.SN = (sn == -1)?0: sn;
                        // lv1pdu.um.E = E;
                        lv1pdu.um.FI = FI;
                        // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                        for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                            lv1pdu.um.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                            lv1pdu.um.chunk[chunkIdx].L = 10;
                        }
                        // assign LI value in the eIdx position
                        lv1pdu.um.chunk[eIndex].L = li;

                        // assign legitimate values for dataLen up to eIdx
                        for (int i = 0; i < eIndex; i++){
                            lv1pdu.um.chunk[i].dataLen = 10;
                        }
                        // assign dataLen value in the eIdx position
                        if (eIndex != nofChunk - 1){
                            lv1pdu.um.chunk[eIndex].dataLen = 5;  // this is position that L is longer than actual payload
                        }else{
                            lv1pdu.um.chunk[eIndex].dataLen = 10;
                        }
                        // assign dataLen value from eIdx + 1 to the end
                        for (int i = eIndex + 1; i < nofChunk; i++){
                            lv1pdu.um.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                        }

                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        // push to db
                        if (eIndex < nofChunk - 1 || (eIndex == nofChunk - 1 && li == 0)){
                            db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        }
    }
}

/* eIdx for UM2 (E value in the first header is 1):
*  -3: subheader has Ex = 1 but there is no available byte behind
*  -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
*  -1: E0 = 1, but only 1 byte totally
*   0->3: the position (idx) of sub-header that L is longer than actual payload
*/
void rlcFuzzer_t::mutateUM2_sn5(int snLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid){
    // generate initial pdu
    rlcPDU_t initial_pdu(rlcUM2);
    generate_initial_um2_packet(snLen, initial_pdu, RLC_UM_5BIT_SN, nofChunk);

    // generate sn list
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    int liLen = 11;
    std::vector<int>& LI_List = (liLen == 11)? LI_List11bit: LI_List15bit;
    // const int E = 1; // E = 1 for UM2
    if (nofChunk < 20){
        for (int eIdx = -3; eIdx < 0; eIdx++){
            if (eIdx == -3){
                for (int FI = 0; FI < 4; FI++){
                    for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcUM2);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.um.SN = (sn == -1)?0: sn;
                        // lv1pdu.um.E = E;
                        lv1pdu.um.FI = FI;
                        lv1pdu.um.chunk[0].E = 1;
                        lv1pdu.um.chunk[0].L = 10;
                        lv1pdu.um.chunk[0].dataLen = 10;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                    }
                    
                }
                // for (const auto& pdu : lv1PDUtemp){
                //     for (int R = 0; R <2; R++){
                //         rlcPDU_t lv2pdu(rlcUM2);
                //         lv2pdu = pdu;
                //         lv2pdu.um.R2 = R;
                //         testcaseDB.push_back(std::move(lv2pdu));
                //     }
                // }
                // lv1PDUtemp.clear();
                // lv1PDUtemp.shrink_to_fit();
            }
            else if (eIdx == -2){
                for (int FI = 0; FI < 4; FI++){
                    for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcUM2);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.um.SN = (sn == -1)?0: sn;
                        // lv1pdu.um.E = E;
                        lv1pdu.um.FI = FI;
                        for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                            lv1pdu.um.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                            lv1pdu.um.chunk[chunkIdx].L = (maxL)?(pow(2, snLen) -1): 10;;
                            lv1pdu.um.chunk[chunkIdx].dataLen = 0;
                        }
                        lv1pdu.um.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                    }
                }
                // for (const auto& pdu : lv1PDUtemp){
                //     for (int R = 0; R <2; R++){
                //         rlcPDU_t lv2pdu(rlcUM2);
                //         lv2pdu = pdu;
                //         lv2pdu.um.R2 = R;
                //         testcaseDB.push_back(std::move(lv2pdu));
                //     }
                // }
                // lv1PDUtemp.clear();
                // lv1PDUtemp.shrink_to_fit();
            }else if (eIdx == -1){
                for (int FI = 0; FI < 4; FI++){
                    for (auto& sn: snList){
                    rlcPDU_t lv1pdu(rlcUM2);
                    lv1pdu = initial_pdu;
                    // packet truncation and mutation
                    lv1pdu.eIdx = eIdx;
                        lv1pdu.um.SN = (sn == -1)?0: sn;
                    // lv1pdu.um.E = E;
                    lv1pdu.um.FI = FI;
                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                    // mapping to lcid
                    lv1pdu.lcid = lcid;
                    // calculate total byte
                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                    db.push_back(std::move(lv1pdu));
                    }
                }
                // for (const auto& pdu : lv1PDUtemp){
                //     for (int R = 0; R <2; R++){
                //         rlcPDU_t lv2pdu(rlcUM2);
                //         lv2pdu = pdu;
                //         lv2pdu.um.R2 = R;
                //         testcaseDB.push_back(std::move(lv2pdu));
                //     }
                // }
                // lv1PDUtemp.clear();
                // lv1PDUtemp.shrink_to_fit();
            }
        }
        // printf("eIdx = 0 \n");
        for (int eIdx = 0; eIdx < nofChunk; eIdx++){        // eIdx = nofChunk - 1 is normal pdu
            for (auto& li: LI_List){
                for (int FI = 0; FI < 4; FI++){
                    for (auto& sn: snList){
                    rlcPDU_t lv1pdu(rlcUM2);
                    lv1pdu = initial_pdu;
                    // rlcPDU_t lv1pduCase2(rlcUM2);           // this is for test case with L = 0
                    // lv1pduCase2.um.snLen = snLen;
                    // lv1pduCase2.rrc_reconfig_type = RLC_UM_5BIT_SN;

                    // packet truncation and mutation
                    lv1pdu.eIdx = eIdx;
                    lv1pdu.um.SN = (sn == -1)?0: sn;
                    // lv1pdu.um.E = E;
                    lv1pdu.um.FI = FI;
                    // assign legitimate values for [E, LI]. If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                    for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                        lv1pdu.um.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                        lv1pdu.um.chunk[chunkIdx].L = 10;
                    }
                    // assign LI value in the eIdx position
                    lv1pdu.um.chunk[eIdx].L = li;

                    // assign legitimate values for dataLen up to eIdx
                    for (int i = 0; i < eIdx; i++){
                        lv1pdu.um.chunk[i].dataLen = 10;
                    }
                    // assign dataLen value in the eIdx position
                    if (eIdx != nofChunk - 1){
                        lv1pdu.um.chunk[eIdx].dataLen = (li == 0)?0: 5;  // this is position that L is longer than actual payload
                    }else{
                        lv1pdu.um.chunk[eIdx].dataLen = 10;
                    }
                    // assign dataLen value from eIdx + 1 to the end
                    for (int i = eIdx + 1; i < nofChunk; i++){
                        lv1pdu.um.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                    }

                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                    // lv1pduCase2 = lv1pdu;                   // this is for test case with L = 0
                    // mapping to lcid
                    lv1pdu.lcid = lcid;
                    // calculate total byte
                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                    db.push_back(std::move(lv1pdu));
                    
                    // test cases with L = 0, only set L = 0 for the sub-header before eIdx
                    // if (eIdx > 0){
                    //     lv1pduCase2.um.chunk[eIdx - 1].L = 0;
                    //     lv1pduCase2.um.chunk[eIdx - 1].dataLen = 0;
                    //     lv1pduCase2.totalByte = calTotalByte(lv1pduCase2);
                    //     db.push_back(std::move(lv1pduCase2));
                    // }
                    }
                }
            }
        }
    }else{ // if there are many chunks (such as 100 chunks of data)
        int eIdx = -2; // only generate test case with eIdx = -2 and 1 normal pdu
        // for (int snIdx = 0; snIdx < 1; snIdx ++){ // sn will be updated later
            for (int FI = 0; FI < 4; FI++){
                for (auto& sn: snList){
                rlcPDU_t lv1pdu(rlcUM2);
                lv1pdu = initial_pdu;
                
                // packet truncation and mutation
                lv1pdu.eIdx = eIdx;
                    lv1pdu.um.SN = (sn == -1)?0: sn;
                // lv1pdu.um.E = E;
                lv1pdu.um.FI = FI;
                for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                    lv1pdu.um.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                    lv1pdu.um.chunk[chunkIdx].L = (maxL)?(pow(2, 11) -1): 10;;
                    lv1pdu.um.chunk[chunkIdx].dataLen = 0;
                }
                lv1pdu.um.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                // mapping to lcid
                lv1pdu.lcid = lcid;
                // calculate total byte
                lv1pdu.totalByte = calTotalByte(lv1pdu);
                db.push_back(std::move(lv1pdu));
                }
            }
        // }
        eIdx = nofChunk - 1; // normal pdu
        int gap = nofChunk/3;
        std::vector<int> eidx_list;
        for (int index = 0; index < nofChunk; index = index + gap){
            eidx_list.push_back(index);
        }
        eidx_list.push_back(nofChunk - 1); // normal packet

        for (auto& eIndex: eidx_list){ // sn will be updated later
            for (int FI = 0; FI < 4; FI++){
                for (auto& sn: snList){
                    for (auto& li: LI_List){
                        rlcPDU_t lv1pdu(rlcUM2);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIndex;
                        lv1pdu.um.SN = (sn == -1)?0: sn;
                        // lv1pdu.um.E = E;
                        lv1pdu.um.FI = FI;
                        // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                        for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                            lv1pdu.um.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                            lv1pdu.um.chunk[chunkIdx].L = 10;
                        }
                        // assign LI value in the eIdx position
                        lv1pdu.um.chunk[eIndex].L = li;

                        // assign legitimate values for dataLen up to eIdx
                        for (int i = 0; i < eIndex; i++){
                            lv1pdu.um.chunk[i].dataLen = 10;
                        }
                        if (eIndex != nofChunk - 1){
                            lv1pdu.um.chunk[eIndex].dataLen = 5;  // this is position that L is longer than actual payload
                        }else{
                            lv1pdu.um.chunk[eIndex].dataLen = 10;
                        }
                        // assign dataLen value from eIdx + 1 to the end
                        for (int i = eIndex + 1; i < nofChunk; i++){
                            lv1pdu.um.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                        }

                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        // only push back test case with L = 0 if eIdx < nofChunk - 1 or eIdx == nofChunk - 1 and li == 0
                        if (eIndex < nofChunk - 1 || (eIndex == nofChunk - 1 && li == 0)){
                            db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        }
    }
}

/* eIdx for AM1 (E value in the first header is 0):
*  -1: rlc PDU only has 1 byte, but actually it should have at least 3 bytes (2 for header, 1 for payload)
*   0: normal rlc pdu but mutated sn and FI
*/
void rlcFuzzer_t::mutateAM1(int snLen,std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    // const int E = 0; // E = 0 for AM1
    // const int DC = 1; // DC = 1 for AM1 data pdu
    rlcPDU_t initial_pdu;
    generate_initial_am1_packet(snLen, initial_pdu, RLC_NORMAL, false);

    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    for (int eIdx = -1; eIdx < 1; eIdx++){
        if (eIdx == -1){
            for (int FI = 0; FI < 4; FI++){
                for (int RF = 0; RF < 1; RF++){ // for normal AMD PDU, RF = 0, 1 is segment PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAM1);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                            lv1pdu.am.SN = (sn == -1)?0: sn;
                        // lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        // lv1pdu.am.DC = DC;
                        lv1pdu.am.RF = RF;
                        lv1pdu.am.P = P;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        }
        else if (eIdx == 0){
            // for (int snIdx = 0; snIdx < 11; snIdx ++){
                for (int FI = 0; FI < 4; FI++){
                    for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                            rlcPDU_t lv1pdu(rlcAM1);
                            lv1pdu = initial_pdu;
                            // packet truncation and mutation
                            lv1pdu.eIdx = eIdx;
                                lv1pdu.am.SN = (sn == -1)?0: sn;
                            // lv1pdu.am.E = E;
                            lv1pdu.am.FI = FI;
                            // lv1pdu.am.DC = DC;
                            lv1pdu.am.RF = RF;
                            lv1pdu.am.P = P;
                            lv1pdu.am.am1DataLen = 10;
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                            // mapping to lcid
                            lv1pdu.lcid = lcid;
                            // calculate total byte
                            lv1pdu.totalByte = calTotalByte(lv1pdu);
                            db.push_back(std::move(lv1pdu));
                            }
                        }
                    }
                }
            // }
        }
    }
}


/* eIdx for AM1 (E value in the first header is 0):
*  -2: rlc PDU has 2 bytes
*  -1: rlc PDU only has 1 byte, but actually it should have at least 4 bytes (3 for header, 1 for payload)
*   0: normal rlc pdu but mutated sn and FI
*/
void rlcFuzzer_t::mutateAM1_16bitSN(int snLen,std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    // const int E = 0; // E = 0 for AM1
    // const int DC = 1; // DC = 1 for AM1 data pdu
    rlcPDU_t initial_pdu;
    generate_initial_am1_packet(snLen, initial_pdu, RLC_16BIT_SN, false);

    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    for (int eIdx = -2; eIdx < 1; eIdx++){
        if (eIdx == -1 || eIdx == -2){
            for (int FI = 0; FI < 4; FI++){
                for (int RF = 0; RF < 1; RF++){ // for normal AMD PDU, RF = 0, 1 is segment PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAM1);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                            lv1pdu.am.SN = (sn == -1)?0: sn;
                        // lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        // lv1pdu.am.DC = DC;
                        lv1pdu.am.RF = RF;
                        lv1pdu.am.P = P;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        }
        else if (eIdx == 0){
            // for (int snIdx = 0; snIdx < (snLen + 1); snIdx ++){
                for (int FI = 0; FI < 4; FI++){
                    for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                            rlcPDU_t lv1pdu(rlcAM1);
                            lv1pdu = initial_pdu;
                            lv1pdu.eIdx = eIdx;
                                lv1pdu.am.SN = (sn == -1)?0: sn;
                            // lv1pdu.am.E = E;
                            lv1pdu.am.FI = FI;
                            // lv1pdu.am.DC = DC;
                            lv1pdu.am.RF = RF;
                            lv1pdu.am.P = P;
                            lv1pdu.am.am1DataLen = 10;
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                            // mapping to lcid
                            lv1pdu.lcid = lcid;
                            // calculate total byte
                            lv1pdu.totalByte = calTotalByte(lv1pdu);
                            db.push_back(std::move(lv1pdu));
                            }
                        }
                    }
                }
            // }
        }
    }
}

/* eIdx for AM2 (E value in the first header is 1):
*  -3: subheader has Ex = 1 but there is no available byte behind
*  -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
*  -1: E0 = 1, but only 1 byte totally
*   0->3: the position (idx) of sub-header that L is longer than actual payload
*/
void rlcFuzzer_t::mutateAM2(int snLen, int liLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    // const int E = 1;    // E = 1 for AM2
    // const int DC = 1;   // DC = 1 for AM1 data pdu
    uint8_t config_type = (snLen == 16)? ((liLen == 15)? RLC_16BIT_SN_15BIT_LI: RLC_16BIT_SN): (liLen == 15)? RLC_15BIT_LI: RLC_NORMAL;
    if (lcid == 3 && snLen == 10 && liLen == 11){
        config_type = RLC_10BIT_SN_11BIT_LI;
    }
    rlcPDU_t initial_pdu(rlcAM2);
    generate_initial_am2_packet(snLen, liLen, initial_pdu, config_type, nofChunk, false);

    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    std::vector<int>& LI_List = (liLen == 11)? LI_List11bit: LI_List15bit;
    if (nofChunk < 20){
        for (int eIdx = -3; eIdx < 0; eIdx++){
            if (eIdx == -3){
                if (nofChunk >=2){ // because we need at least 1 sub-header
                    // for (int snIdx = 0; snIdx < 1; snIdx ++){
                        for (int FI = 0; FI < 4; FI++){
                            for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                                for (int P = 0; P < 2; P++){
                                    for (auto& sn: snList){
                                    rlcPDU_t lv1pdu(rlcAM2);
                                    lv1pdu = initial_pdu;
                                    // packet truncation and mutation
                                    lv1pdu.eIdx = eIdx;
                                        lv1pdu.am.SN = (sn == -1)?0: sn;
                                    // lv1pdu.am.E = E;
                                    lv1pdu.am.FI = FI;
                                    // lv1pdu.am.DC = DC;
                                    lv1pdu.am.RF = RF;
                                    lv1pdu.am.P = P;
                                    lv1pdu.am.chunk[0].E = 1;
                                    lv1pdu.am.chunk[0].L = 10;
                                    lv1pdu.am.chunk[0].dataLen = 10;
                                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                    // mapping to lcid
                                    lv1pdu.lcid = lcid;
                                    // calculate total byte
                                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                                    db.push_back(std::move(lv1pdu));
                                    }
                                }
                            }
                        }
                    // }
                }
            }
            else if (eIdx == -2){
                // for (int snIdx = 0; snIdx < + 1; snIdx ++){
                    for (int FI = 0; FI < 4; FI++){
                        for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                            for (int P = 0; P < 2; P++){
                                for (auto& sn: snList){
                                rlcPDU_t lv1pdu(rlcAM2);
                                lv1pdu = initial_pdu;
                                // packet truncation and mutation
                                lv1pdu.eIdx = eIdx;
                                    lv1pdu.am.SN = (sn == -1)?0: sn;
                                // lv1pdu.am.E = E;
                                lv1pdu.am.FI = FI;
                                // lv1pdu.am.DC = DC;
                                lv1pdu.am.RF = RF;
                                lv1pdu.am.P = P;
                                for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                    lv1pdu.am.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                                    lv1pdu.am.chunk[chunkIdx].L = (maxL)?(pow(2, snLen) -1): 10;
                                    lv1pdu.am.chunk[chunkIdx].dataLen = 0;
                                }
                                lv1pdu.am.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                // mapping to lcid
                                lv1pdu.lcid = lcid;
                                // calculate total byte
                                lv1pdu.totalByte = calTotalByte(lv1pdu);
                                db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    }
                // }
            }else if (eIdx == -1){
                for (int FI = 0; FI < 4; FI++){
                    for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                            rlcPDU_t lv1pdu(rlcAM2);
                            lv1pdu = initial_pdu;
                            
                            // packet truncation and mutation
                            lv1pdu.eIdx = eIdx;
                                lv1pdu.am.SN = (sn == -1)?0: sn;
                            // lv1pdu.am.E = E;
                            lv1pdu.am.FI = FI;
                            // lv1pdu.am.DC = DC;
                            lv1pdu.am.RF = RF;
                            lv1pdu.am.P = P;
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                            // mapping to lcid
                            lv1pdu.lcid = lcid;
                            // calculate total byte
                            lv1pdu.totalByte = calTotalByte(lv1pdu);
                            db.push_back(std::move(lv1pdu));
                            }
                        }
                    }
                }
            }
        }
        for (int eIdx = 0; eIdx < nofChunk; eIdx++){        // eIdx = nofChunk - 1 is normal pdu
            for (auto& li: LI_List){
                for (int FI = 0; FI < 4; FI++){
                    for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                            rlcPDU_t lv1pdu(rlcAM2);
                            lv1pdu = initial_pdu;

                            // rlcPDU_t lv1pduCase2(rlcAM2);           // this is for test case with L = 0
                            // lv1pduCase2.rrc_reconfig_type = (snLen == 16)? ((liLen == 15)? RLC_16BIT_SN_15BIT_LI: RLC_16BIT_SN): (liLen == 15)? RLC_15BIT_LI: RLC_NORMAL;
                            // if (lcid == 3 && snLen == 10 && liLen == 11){
                            //     lv1pduCase2.rrc_reconfig_type = RLC_10BIT_SN_11BIT_LI;
                            // }
                            // lv1pduCase2.am.snLen = snLen;
                            // lv1pduCase2.am.liLen = liLen;

                            // packet truncation and mutation
                            lv1pdu.eIdx = eIdx;
                            lv1pdu.am.SN = (sn == -1)?0: sn;
                            lv1pdu.am.FI = FI;
                            // lv1pdu.am.E = E;
                            // lv1pdu.am.DC = DC;
                            lv1pdu.am.RF = RF;
                            lv1pdu.am.P = P;
                            // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                            for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                lv1pdu.am.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                                lv1pdu.am.chunk[chunkIdx].L = 10;
                            }
                            // assign LI value in the eIdx position
                            lv1pdu.am.chunk[eIdx].L = li;
                            
                            // assign legitimate values for dataLen up to eIdx
                            for (int i = 0; i < eIdx; i++){
                                lv1pdu.am.chunk[i].dataLen = 10;
                            }
                            // assign dataLen value in the eIdx position
                            if (eIdx != nofChunk - 1){
                                lv1pdu.am.chunk[eIdx].dataLen = (li == 0)?0: 5;  // this is position that L is longer than actual payload
                            }else{
                                lv1pdu.am.chunk[eIdx].dataLen = 10;
                            }
                            // assign dataLen value from eIdx + 1 to the end
                            for (int i = eIdx + 1; i < nofChunk; i++){
                                lv1pdu.am.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                            }
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                            // lv1pduCase2 = lv1pdu;                   // this is for test case with L = 0
                            // mapping to lcid
                            lv1pdu.lcid = lcid;
                            // calculate total byte
                            lv1pdu.totalByte = calTotalByte(lv1pdu);
                            db.push_back(std::move(lv1pdu));
                            
                            // test cases with L = 0, only set L = 0 for the sub-header before eIdx
                            // if (eIdx > 0){
                            //     lv1pduCase2.am.chunk[eIdx - 1].L = 0;
                            //     lv1pduCase2.am.chunk[eIdx - 1].dataLen = 0;
                            //     lv1pduCase2.totalByte = calTotalByte(lv1pduCase2);
                            //     db.push_back(std::move(lv1pduCase2));
                            // }
                            }
                        }
                    }
                }
            }
        }
    }else {
        int eIdx = -2; // only generate test case with eIdx = -2 and 1 normal pdu
        // for (int snIdx = 0; snIdx < 1; snIdx ++){
            for (int FI = 0; FI < 4; FI++){
                for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAM2);
                        lv1pdu = initial_pdu;
                        
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                            lv1pdu.am.SN = (sn == -1)?0: sn;
                        // lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        // lv1pdu.am.DC = DC;
                        lv1pdu.am.RF = RF;
                        lv1pdu.am.P = P;
                        for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                            lv1pdu.am.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                            lv1pdu.am.chunk[chunkIdx].L = (maxL)?(pow(2, liLen) - 1): 10;;
                            lv1pdu.am.chunk[chunkIdx].dataLen = 0;
                        }
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        lv1pdu.am.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        // }
        eIdx = nofChunk - 1;
        int gap = nofChunk/3;
        std::vector<int> eidx_list;
        for (int index = 0; index < nofChunk; index = index + gap){
            eidx_list.push_back(index);
        }
        eidx_list.push_back(nofChunk - 1); // normal packet

        for (auto& eIndex: eidx_list){
            for (int FI = 0; FI < 4; FI++){
                for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                            for (auto li: LI_List){
                                rlcPDU_t lv1pdu(rlcAM2);
                                lv1pdu = initial_pdu;
                                // packet truncation and mutation
                                lv1pdu.eIdx = eIndex;
                                lv1pdu.am.SN = (sn == -1)?0: sn;
                                lv1pdu.am.FI = FI;
                                // lv1pdu.am.E = E;
                                // lv1pdu.am.DC = DC;
                                lv1pdu.am.RF = RF;
                                lv1pdu.am.P = P;
                                // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                                for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                    lv1pdu.am.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                                    lv1pdu.am.chunk[chunkIdx].L = 10;
                                }
                                // assign LI value in the eIdx position
                                lv1pdu.am.chunk[eIndex].L = li;

                                // assign legitimate values for dataLen up to eIdx
                                for (int i = 0; i < eIndex; i++){
                                    lv1pdu.am.chunk[i].dataLen = 10;
                                }
                                if (eIndex != nofChunk - 1){
                                    lv1pdu.am.chunk[eIndex].dataLen = 5;  // this is position that L is longer than actual payload
                                }else{
                                    lv1pdu.am.chunk[eIndex].dataLen = 10;
                                }
                                // assign dataLen value from eIdx + 1 to the end
                                for (int i = eIndex + 1; i < nofChunk; i++){
                                    lv1pdu.am.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                                }

                                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                // mapping to lcid
                                lv1pdu.lcid = lcid;
                                // calculate total byte
                                lv1pdu.totalByte = calTotalByte(lv1pdu);
                                if (eIndex < nofChunk - 1 || (eIndex == nofChunk - 1 && li == 0)){
                                    db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/* eIdx for AM2 15 bit Length Indicator LI (E value in the first header is 1):
*  -3: subheader has Ex = 1 but there is no available byte behind
*  -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
*  -1: E0 = 1, but only 1 byte totally
*   0->3: the position (idx) of sub-header that L is longer than actual payload
*/
void rlcFuzzer_t::mutateAM2_15bitLI(int snLen, int liLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    // const int E = 1;    // E = 1 for AM2
    // const int DC = 1;   // DC = 1 for AM1 data pdu
    uint8_t rrc_config = (snLen == 16)? ((liLen == 15)? RLC_16BIT_SN_15BIT_LI: RLC_16BIT_SN): (liLen == 15)? RLC_15BIT_LI: RLC_NORMAL;
    rlcPDU_t initial_pdu(rlcAM2);
    generate_initial_am2_packet(snLen, liLen, initial_pdu, rrc_config, nofChunk, false);

    std::vector<int>& LI_List = (liLen == 11)? LI_List11bit: LI_List15bit;
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    if (nofChunk < 20){
        for (int eIdx = -3; eIdx < 0; eIdx++){
            if (eIdx == -3){
                if (nofChunk >=2){ // because we need at least 1 sub-header
                    // for (int snIdx = 0; snIdx < 11; snIdx ++){
                        for (int FI = 0; FI < 4; FI++){
                            for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                                for (int P = 0; P < 2; P++){
                                    for (auto& sn: snList){
                                        rlcPDU_t lv1pdu(rlcAM2);
                                        lv1pdu = initial_pdu;
                                        // packet truncation and mutation
                                        lv1pdu.eIdx = eIdx;
                                            lv1pdu.am.SN = (sn == -1)?0: sn;
                                        // lv1pdu.am.E = E;
                                        lv1pdu.am.FI = FI;
                                        // lv1pdu.am.DC = DC;
                                        lv1pdu.am.RF = RF;
                                        lv1pdu.am.P = P;
                                        lv1pdu.am.chunk[0].E = 1;
                                        lv1pdu.am.chunk[0].L = 10;
                                        lv1pdu.am.chunk[0].dataLen = 10;
                                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                        // mapping to lcid
                                        lv1pdu.lcid = lcid;
                                        // calculate total byte
                                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                                        db.push_back(std::move(lv1pdu));
                                    }
                                }
                            }
                        }
                    // }
                }
            }
            else if (eIdx == -2){
                // for (int snIdx = 0; snIdx < 1; snIdx ++){
                    for (int FI = 0; FI < 4; FI++){
                        for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                            for (int P = 0; P < 2; P++){
                                for (auto& sn: snList){
                                    rlcPDU_t lv1pdu(rlcAM2);
                                    lv1pdu = initial_pdu;
                                    // packet truncation and mutation
                                    lv1pdu.eIdx = eIdx;
                                    lv1pdu.am.SN = (sn == -1)?0: sn;
                                    // lv1pdu.am.E = E;
                                    lv1pdu.am.FI = FI;
                                    // lv1pdu.am.DC = DC;
                                    lv1pdu.am.RF = RF;
                                    lv1pdu.am.P = P;
                                    for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                        lv1pdu.am.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                                        lv1pdu.am.chunk[chunkIdx].L = (maxL)?(pow(2, snLen) -1): 10;
                                        lv1pdu.am.chunk[chunkIdx].dataLen = 0;
                                    }
                                    lv1pdu.am.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                    // mapping to lcid
                                    lv1pdu.lcid = lcid;
                                    // calculate total byte
                                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                                    db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    // }
                }
            }else if (eIdx == -1){
                for (int FI = 0; FI < 4; FI++){
                    for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                                rlcPDU_t lv1pdu(rlcAM2);
                                lv1pdu = initial_pdu;
                                // packet truncation and mutation
                                lv1pdu.eIdx = eIdx;
                                lv1pdu.am.SN = (sn == -1)?0: sn;
                                // lv1pdu.am.E = E;
                                lv1pdu.am.FI = FI;
                                // lv1pdu.am.DC = DC;
                                lv1pdu.am.RF = RF;
                                lv1pdu.am.P = P;
                                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                // mapping to lcid
                                lv1pdu.lcid = lcid;
                                // calculate total byte
                                lv1pdu.totalByte = calTotalByte(lv1pdu);
                                db.push_back(std::move(lv1pdu));
                            }
                        }
                    }
                }
            }
        }
        for (int eIdx = 0; eIdx < nofChunk; eIdx++){        // eIdx = nofChunk - 1 is normal pdu
            for (auto& li: LI_List){
                for (int FI = 0; FI < 4; FI++){
                    for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                            rlcPDU_t lv1pdu(rlcAM2);
                            lv1pdu = initial_pdu;
                            // rlcPDU_t lv1pduCase2(rlcAM2);           // this is for test case with L = 0
                            // lv1pduCase2.rrc_reconfig_type = (snLen == 16)? ((liLen == 15)? RLC_16BIT_SN_15BIT_LI: RLC_16BIT_SN): (liLen == 15)? RLC_15BIT_LI: RLC_NORMAL;
                            // lv1pduCase2.am.snLen = snLen;
                            // lv1pduCase2.am.liLen = liLen;
                            
                            // packet truncation and mutation
                            lv1pdu.eIdx = eIdx;
                            lv1pdu.am.SN = (sn == -1)?0: sn;
                            // lv1pdu.am.E = E;
                            lv1pdu.am.FI = FI;
                            // lv1pdu.am.DC = DC;
                            lv1pdu.am.RF = RF;
                            lv1pdu.am.P = P;
                            // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                            for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                lv1pdu.am.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                                lv1pdu.am.chunk[chunkIdx].L = 10;
                            }
                            // assign LI value in the eIdx position
                            lv1pdu.am.chunk[eIdx].L = li;

                            // assign legitimate values for dataLen up to eIdx
                            for (int i = 0; i < eIdx; i++){
                                lv1pdu.am.chunk[i].dataLen = 10;
                            }
                            if (eIdx != nofChunk - 1){
                                lv1pdu.am.chunk[eIdx].dataLen = (li == 0)?0: 5;  // this is position that L is longer than actual payload
                            }else{
                                lv1pdu.am.chunk[eIdx].dataLen = 10;
                            }
                            // assign dataLen value from eIdx + 1 to the end
                            for (int i = eIdx + 1; i < nofChunk; i++){
                                lv1pdu.am.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                            }
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                            // lv1pduCase2 = lv1pdu;                   // this is for test case with L = 0
                            // mapping to lcid
                            lv1pdu.lcid = lcid;
                            // calculate total byte
                            lv1pdu.totalByte = calTotalByte(lv1pdu);
                            db.push_back(std::move(lv1pdu));
                            
                            // test cases with L = 0, only set L = 0 for the sub-header before eIdx
                            // if (eIdx > 0){
                            //     lv1pduCase2.am.chunk[eIdx - 1].L = 0;
                            //     lv1pduCase2.am.chunk[eIdx - 1].dataLen = 0;
                            //     lv1pduCase2.totalByte = calTotalByte(lv1pduCase2);
                            //     db.push_back(std::move(lv1pduCase2));
                            // }
                            }
                        }
                    }
                }
            }
        }
    }else {
        int eIdx = -2; // only generate test case with eIdx = -2 and 1 normal pdu
        for (int FI = 0; FI < 4; FI++){
            for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                for (int P = 0; P < 2; P++){
                    for (auto& sn: snList){
                    rlcPDU_t lv1pdu(rlcAM2);
                    lv1pdu = initial_pdu;
                    // packet truncation and mutation
                    lv1pdu.eIdx = eIdx;
                        lv1pdu.am.SN = (sn == -1)?0: sn;
                    // lv1pdu.am.E = E;
                    lv1pdu.am.FI = FI;
                    // lv1pdu.am.DC = DC;
                    lv1pdu.am.RF = RF;
                    lv1pdu.am.P = P;
                    for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                        lv1pdu.am.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                        lv1pdu.am.chunk[chunkIdx].L = (maxL)?(pow(2, liLen) - 1): 10;
                        lv1pdu.am.chunk[chunkIdx].dataLen = 0;
                    }
                    lv1pdu.am.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                    // mapping to lcid
                    lv1pdu.lcid = lcid;
                    // calculate total byte
                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                    db.push_back(std::move(lv1pdu));
                    }
                }
            }
        }
        eIdx = nofChunk - 1;
        int gap = nofChunk/3;
        std::vector<int> eidx_list;
        for (int index = 0; index < nofChunk; index = index + gap){
            eidx_list.push_back(index);
        }
        eidx_list.push_back(nofChunk - 1); // normal packet
        for (auto& eIndex: eidx_list){
            for (int FI = 0; FI < 4; FI++){
                for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                            for (auto li: LI_List){
                                rlcPDU_t lv1pdu(rlcAM2);
                                lv1pdu = initial_pdu;
                                // packet truncation and mutation
                                lv1pdu.eIdx = eIndex;
                                lv1pdu.am.SN = (sn == -1)?0: sn;
                                // lv1pdu.am.E = E;
                                lv1pdu.am.FI = FI;
                                // lv1pdu.am.DC = DC;
                                lv1pdu.am.RF = RF;
                                lv1pdu.am.P = P;
                                // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                                for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                    lv1pdu.am.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                                    lv1pdu.am.chunk[chunkIdx].L = 10;
                                }
                                // assign LI value in the eIdx position
                                lv1pdu.am.chunk[eIndex].L = li;

                                // assign legitimate values for dataLen up to eIdx
                                for (int i = 0; i < eIndex; i++){
                                    lv1pdu.am.chunk[i].dataLen = 10;
                                }
                                if (eIndex != nofChunk - 1){
                                    lv1pdu.am.chunk[eIndex].dataLen = 5;  // this is position that L is longer than actual payload
                                }else{
                                    lv1pdu.am.chunk[eIndex].dataLen = 10;
                                }
                                // assign dataLen value from eIdx + 1 to the end
                                for (int i = eIndex + 1; i < nofChunk; i++){
                                    lv1pdu.am.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                                }

                                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                // mapping to lcid
                                lv1pdu.lcid = lcid;
                                // calculate total byte
                                lv1pdu.totalByte = calTotalByte(lv1pdu);
                                // only push back the test case that is not broken in the eIdx position
                                if (eIndex < nofChunk - 1 || (eIndex == nofChunk - 1 && li == 0)){
                                    db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    }
                }
            }
        }

    }
}

/* eIdx for AM1 (E value in the first header is 0):
*  -4: rlc PDU only has 4 bytes, but actually it should have at least 5 bytes (4 for header, 1 for payload)
*  -3: rlc PDU only has 3 bytes, but actually it should have at least 5 bytes (4 for header, 1 for payload)
*  -2: rlc PDU only has 2 bytes, but actually it should have at least 5 bytes (4 for header, 1 for payload)
*  -1: rlc PDU only has 1 byte, but actually it should have at least 5 bytes (4 for header, 1 for payload)
*   0: normal rlc pdu but mutated sn and FI
*/
void rlcFuzzer_t::mutateAM1_segment(int snLen,std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    // const int E = 0; // E = 0 for AM1
    // const int DC = 1; // DC = 1 for AM1 data pdu
    // const int RF = 1; // RF = 1 for segment PDU
    uint8_t config_type = (lcid == 3)? RLC_10BIT_SN_11BIT_LI: RLC_NORMAL;
    rlcPDU_t initial_pdu(rlcAM1);
    generate_initial_am1_packet(snLen, initial_pdu, config_type, true);

    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    for (int eIdx = -4; eIdx < 1; eIdx++){
        if (eIdx == -1 || eIdx == -2){
            for (int FI = 0; FI < 4; FI++){
                // for (int RF = 0; RF < 1; RF++){ // for normal AMD PDU, RF = 0, 1 is segment PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAMSegment1);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.am.SN = (sn == -1)?0: sn;
                        // lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        // lv1pdu.am.DC = DC;
                        // lv1pdu.am.RF = RF;
                        lv1pdu.am.P = P;
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                // }
            }
        }
        if (eIdx == -3 || eIdx == -4){
            for (int FI = 0; FI < 4; FI++){
                for (int lsf = 0; lsf < 2; lsf++){ // for normal AMD PDU, RF = 0, 1 is segment PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAMSegment1);
                        lv1pdu = initial_pdu;
                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.am.SN = (sn == -1)?0: sn;
                        lv1pdu.am.LSF = lsf; // lsf mutation if there are more than 3 bytes
                        // lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        // lv1pdu.am.DC = DC;
                        // lv1pdu.am.RF = RF;
                        lv1pdu.am.P = P;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        }
        else if (eIdx == 0){
            // for (int snIdx = 0; snIdx < 11; snIdx ++){
                for (int FI = 0; FI < 4; FI++){
                    for (int lsf = 0; lsf < 2; lsf++){ // for normal AMD PDU, RF = 0, 1 is segment PDU
                        for (int P = 0; P < 2; P++){
                            for (int soIdx = 0; soIdx < 15; soIdx = soIdx + 5){
                                for (auto& sn: snList){
                                rlcPDU_t lv1pdu(rlcAMSegment1);
                                lv1pdu = initial_pdu;
                                // packet truncation and mutation
                                lv1pdu.eIdx = eIdx;
                                lv1pdu.am.SN = (sn == -1)?0: sn;
                                // lv1pdu.am.E = E;
                                lv1pdu.am.LSF = lsf;
                                lv1pdu.am.FI = FI;
                                // lv1pdu.am.DC = DC;
                                // lv1pdu.am.RF = RF;
                                lv1pdu.am.P = P;
                                lv1pdu.am.SO = pow(2, soIdx) - 1;
                                lv1pdu.am.am1DataLen = 10;
                                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                // mapping to lcid
                                lv1pdu.lcid = lcid;
                                // calculate total byte
                                lv1pdu.totalByte = calTotalByte(lv1pdu);
                                db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    }
                }
            // }
        }
    }
}

/* eIdx for AM1 (E value in the first header is 0):
*  -3: rlc PDU only has 3 bytes, but actually it should have at least 5 bytes (4 for header, 1 for payload)
*  -2: rlc PDU only has 2 bytes, but actually it should have at least 5 bytes (4 for header, 1 for payload)
*  -1: rlc PDU only has 1 byte, but actually it should have at least 5 bytes (4 for header, 1 for payload)
*   0: normal rlc pdu but mutated sn and FI
*/
void rlcFuzzer_t::mutateAM1_segment_16bitSN(int snLen,std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    const int E = 0; // E = 0 for AM1
    const int DC = 1; // DC = 1 for AM1 data pdu
    const int RF = 1; // RF = 1 for segment PDU
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    for (int eIdx = -3; eIdx < 1; eIdx++){
        if (eIdx == -1 || eIdx == -2){
            for (int FI = 0; FI < 4; FI++){
                // for (int RF = 0; RF < 1; RF++){ // for normal AMD PDU, RF = 0, 1 is segment PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAMSegment1);
                        lv1pdu.rrc_reconfig_type = RLC_16BIT_SN;
                        lv1pdu.am.snLen = snLen;
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.am.SN = (sn == -1)?0: sn;
                        lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        lv1pdu.am.DC = DC;
                        lv1pdu.am.RF = RF;
                        lv1pdu.am.P = P;
                        lv1pdu.lcid = lcid;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                // }
            }
        }
        if (eIdx == -3){
            for (int FI = 0; FI < 4; FI++){
                for (int lsf = 0; lsf < 2; lsf++){ // for normal AMD PDU, RF = 0, 1 is segment PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAMSegment1);
                        lv1pdu.rrc_reconfig_type = RLC_16BIT_SN;
                        lv1pdu.am.snLen = snLen;
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.am.SN = (sn == -1)?0: sn;
                        lv1pdu.am.LSF = lsf; // lsf mutation if there are more than 3 bytes
                        lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        lv1pdu.am.DC = DC;
                        lv1pdu.am.RF = RF;
                        lv1pdu.am.P = P;
                        lv1pdu.lcid = lcid;
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        }
        else if (eIdx == 0){
            // for (int snIdx = 0; snIdx < 1; snIdx ++){ // sn will be updated following the SN from eNB
                for (int FI = 0; FI < 4; FI++){
                    for (int lsf = 0; lsf < 2; lsf++){ // for normal AMD PDU, RF = 0, 1 is segment PDU
                        for (int P = 0; P < 2; P++){
                            for (int soIdx = 16; soIdx > 0; soIdx = soIdx - 4){
                                for (auto& sn: snList){
                                rlcPDU_t lv1pdu(rlcAMSegment1);
                                lv1pdu.rrc_reconfig_type = RLC_16BIT_SN;
                                lv1pdu.am.snLen = snLen;
                                lv1pdu.eIdx = eIdx;
                                lv1pdu.am.SN = (sn == -1)?0: sn;
                                lv1pdu.am.E = E;
                                lv1pdu.am.LSF = lsf;
                                lv1pdu.am.FI = FI;
                                lv1pdu.am.DC = DC;
                                lv1pdu.am.RF = RF;
                                lv1pdu.am.P = P;
                                lv1pdu.lcid = lcid;
                                lv1pdu.am.SO = pow(2, soIdx) - 1;
                                lv1pdu.am.am1DataLen = 10;
                                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                lv1pdu.totalByte = calTotalByte(lv1pdu);
                                db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    }
                }
            // }
        }
    }
}

/* eIdx for AM2_segment (E value in the first header is 1):
*  -3: subheader has Ex = 1 but there is no available byte behind
*  -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
*  -1: E0 = 1, but only 1 byte totally
*   0->3: the position (idx) of sub-header that L is longer than actual payload
*/
void rlcFuzzer_t::mutateAM2_segment(int snLen, int liLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    // const int E = 1;    // E = 1 for AM2
    // const int DC = 1;   // DC = 1 for AM1 data pdu
    // const int RF = 1;   // RF = 1 for segment PDU
    uint8_t config_type = (snLen == 16)? ((liLen == 15)? RLC_16BIT_SN_15BIT_LI: RLC_16BIT_SN): (liLen == 15)? RLC_15BIT_LI: RLC_NORMAL;
    if (lcid == 3 && snLen == 10 && liLen == 11){
        config_type = RLC_10BIT_SN_11BIT_LI;
    }
    rlcPDU_t initial_pdu(rlcAM2);
    generate_initial_am2_packet(snLen, liLen, initial_pdu, config_type, nofChunk, true);
    
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    std::vector<int>& liList = (liLen == 11)? LI_List11bit: LI_List15bit;
    if (nofChunk < 20){
        for (int eIdx = -3; eIdx < 0; eIdx++){
            if (eIdx == -3){       // subheader has Ex = 1 but there is no available byte behind
                if (nofChunk >=2){ // because we need at least 1 sub-header
                    for (int soIdx = 0; soIdx < 15; soIdx = soIdx+5){ // SN will be updated following the SN from eNB
                        for (int FI = 0; FI < 4; FI++){
                            for (int lsf = 0; lsf < 1; lsf++){ // fixed: RF = 0 for normal AM PDU
                                for (int P = 0; P < 2; P++){
                                    for (auto& sn: snList){
                                    rlcPDU_t lv1pdu(rlcAMSegment2);
                                    lv1pdu = initial_pdu;
                                    // packet truncation and mutation
                                    lv1pdu.eIdx = eIdx;
                                    lv1pdu.am.SO = (sn == -1)?0: sn;
                                    // lv1pdu.am.E = E;
                                    lv1pdu.am.FI = FI;
                                    // lv1pdu.am.DC = DC;
                                    // lv1pdu.am.RF = RF;
                                    lv1pdu.am.LSF = lsf;
                                    lv1pdu.am.chunk[0].E = 1;
                                    lv1pdu.am.chunk[0].L = 10;
                                    lv1pdu.am.chunk[0].dataLen = 10;
                                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                    // mapping to lcid
                                    lv1pdu.lcid = lcid;
                                    // calculate total byte
                                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                                    db.push_back(std::move(lv1pdu));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (eIdx == -2){ // E0 = 1 but all fixed+extended sub-headers, no payload
                for (int soIdx = 0; soIdx < 15; soIdx = soIdx + 5){ // SN will be updated following the SN from eNB
                    for (int FI = 0; FI < 4; FI++){
                        for (int lsf = 0; lsf < 1; lsf++){ // fixed: RF = 0 for normal AM PDU
                            for (int P = 0; P < 2; P++){
                                for (auto& sn: snList){
                                rlcPDU_t lv1pdu(rlcAMSegment2);
                                lv1pdu = initial_pdu;
                                // packet truncation and mutation
                                lv1pdu.eIdx = eIdx;
                                lv1pdu.am.SO = pow(2, soIdx) - 1;
                                // lv1pdu.am.E = E;
                                lv1pdu.am.FI = FI;
                                // lv1pdu.am.DC = DC;
                                // lv1pdu.am.RF = RF;
                                lv1pdu.am.LSF = lsf;
                                for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                    lv1pdu.am.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                                    lv1pdu.am.chunk[chunkIdx].L = (maxL)?(pow(2, snLen) -1): 10;
                                    lv1pdu.am.chunk[chunkIdx].dataLen = 0;  // no payload
                                }
                                lv1pdu.am.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                // mapping to lcid
                                lv1pdu.lcid = lcid;
                                // calculate total byte
                                lv1pdu.totalByte = calTotalByte(lv1pdu);
                                db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    }
                }
            }else if (eIdx == -1){ // -1: E0 = 1, but only 1 byte totally
                for (int FI = 0; FI < 4; FI++){
                    // for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                            rlcPDU_t lv1pdu(rlcAMSegment2);
                            lv1pdu = initial_pdu;
                            // packet truncation and mutation
                            lv1pdu.eIdx = eIdx;
                            lv1pdu.am.SN = (sn == -1)?0: sn;
                            // lv1pdu.am.E = E;            // const E = 1
                            lv1pdu.am.FI = FI;
                            //lv1pdu.am.DC = DC;
                            //lv1pdu.am.RF = RF;
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                            // mapping to lcid
                            lv1pdu.lcid = lcid;
                            // calculate total byte
                            lv1pdu.totalByte = calTotalByte(lv1pdu);
                            db.push_back(std::move(lv1pdu));
                            }
                        }
                    // }
                }
            }
        }
        for (int eIdx = 0; eIdx < nofChunk; eIdx++){        // eIdx = nofChunk - 1 is normal pdu
            for (int soIdx = 0; soIdx < 15; soIdx = soIdx + 5){
                for (int FI = 0; FI < 4; FI++){
                    for (int rsf = 0; rsf < 1; rsf++){ //
                        for (int P = 0; P < 2; P++){
                            for (auto& li: liList){
                                for (auto& sn: snList){
                                    rlcPDU_t lv1pdu(rlcAMSegment2);
                                    lv1pdu = initial_pdu;
                                    // rlcPDU_t lv1pduCase2(rlcAMSegment2);           // this is for test case with L = 0
                                    // lv1pduCase2.rrc_reconfig_type = (snLen == 16)? ((liLen == 15)? RLC_16BIT_SN_15BIT_LI: RLC_16BIT_SN): (liLen == 15)? RLC_15BIT_LI: RLC_NORMAL;
                                    // if (lcid == 3 && snLen == 10 && liLen == 11){
                                    //     lv1pduCase2.rrc_reconfig_type = RLC_10BIT_SN_11BIT_LI;
                                    // }
                                    // lv1pduCase2.am.snLen = snLen;
                                    // lv1pduCase2.am.liLen = liLen;

                                    // packet truncation and mutation
                                    lv1pdu.eIdx = eIdx;
                                    lv1pdu.am.SN = (sn == -1)?0: sn;
                                    lv1pdu.am.SO = pow(2, soIdx) - 1;
                                    // lv1pdu.am.E = E;
                                    lv1pdu.am.FI = FI;
                                    // lv1pdu.am.DC = DC;
                                    // lv1pdu.am.RF = RF;
                                    lv1pdu.am.LSF = rsf;
                                    // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                                    for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                        lv1pdu.am.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                                        lv1pdu.am.chunk[chunkIdx].L = 10;
                                    }
                                    // assign LI value in the eIdx position
                                    lv1pdu.am.chunk[eIdx].L = li;

                                    // assign legitimate values for dataLen up to eIdx
                                    for (int i = 0; i < eIdx; i++){
                                        lv1pdu.am.chunk[i].dataLen = 10;
                                    }
                                    // assign dataLen value in the eIdx position
                                    if (eIdx != nofChunk - 1){
                                        lv1pdu.am.chunk[eIdx].dataLen = (li == 0)?0: 5;  // this is position that L is longer than actual payload
                                    }else{
                                        lv1pdu.am.chunk[eIdx].dataLen = 10;
                                    }
                                    // assign dataLen value from eIdx + 1 to the end
                                    for (int i = eIdx + 1; i < nofChunk; i++){
                                        lv1pdu.am.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                                    }

                                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                    // lv1pduCase2 = lv1pdu;                   // this is for test case with L = 0
                                    // mapping to lcid
                                    lv1pdu.lcid = lcid;
                                    // calculate total byte
                                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                                    db.push_back(std::move(lv1pdu));
                                    
                                    // test cases with L = 0, only set L = 0 for the sub-header before eIdx
                                    // if (eIdx > 0){
                                    //     lv1pduCase2.am.chunk[eIdx - 1].L = 0;
                                    //     lv1pduCase2.am.chunk[eIdx - 1].dataLen = 0;
                                    //     lv1pduCase2.totalByte = calTotalByte(lv1pduCase2);
                                    //     db.push_back(std::move(lv1pduCase2));
                                    // }
                                }
                            }
                        }
                    }
                }
            }
        }
    }else {
        int eIdx = -2; // only generate test case with eIdx = -2 and 1 normal pdu
        for (int soIdx = 0; soIdx < 15; soIdx = soIdx + 5){ // SN will be updated following the SN from eNB
            for (int FI = 0; FI < 4; FI++){
                for (int lsf = 0; lsf < 1; lsf++){ // fixed: RF = 0 for normal AM PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAMSegment2);
                        lv1pdu = initial_pdu;

                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                            lv1pdu.am.SN = (sn == -1)?0: sn;
                        lv1pdu.am.SO = pow(2, soIdx) - 1;
                        // lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        // lv1pdu.am.DC = DC;
                        // lv1pdu.am.RF = RF;
                        lv1pdu.am.LSF = lsf;
                        for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                            lv1pdu.am.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                            lv1pdu.am.chunk[chunkIdx].L = (maxL)?(pow(2, liLen) - 1): 10;
                            lv1pdu.am.chunk[chunkIdx].dataLen = 0;  // no payload
                        }
                        lv1pdu.am.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        }
        eIdx = nofChunk - 1;
        int gap = nofChunk/3;
        std::vector<int> eidx_list;
        for (int index = 0; index < nofChunk; index = index + gap){
            eidx_list.push_back(index);
        }
        eidx_list.push_back(nofChunk - 1); // normal packet
        for (auto& eIndex: eidx_list){
            for (int soIdx = 0; soIdx < 15; soIdx = soIdx + 5){ // SN will be updated following the SN from eNB
                for (int FI = 0; FI < 4; FI++){
                    for (int lsf = 0; lsf < 1; lsf++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                                for (auto& li: liList){
                                    rlcPDU_t lv1pdu(rlcAMSegment2);
                                    lv1pdu = initial_pdu;

                                    // packet truncation and mutation
                                    lv1pdu.eIdx = eIndex;
                                    lv1pdu.am.SN = (sn == -1)?0: sn;
                                    lv1pdu.am.SO = pow(2, soIdx) - 1;
                                    // lv1pdu.am.E = E;
                                    lv1pdu.am.FI = FI;
                                    // lv1pdu.am.DC = DC;
                                    // lv1pdu.am.RF = RF;
                                    lv1pdu.am.LSF = lsf;
                                    // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                                    for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                        lv1pdu.am.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                                        lv1pdu.am.chunk[chunkIdx].L = 10;
                                    }
                                    // assign LI value in the eIdx position
                                    lv1pdu.am.chunk[eIndex].L = li;

                                    // assign legitimate values for dataLen up to eIdx
                                    for (int i = 0; i < eIndex; i++){
                                        lv1pdu.am.chunk[i].dataLen = 10;
                                    }
                                    if (eIndex != nofChunk - 1){
                                        lv1pdu.am.chunk[eIndex].dataLen = 5;  // this is position that L is longer than actual payload
                                    }else{
                                        lv1pdu.am.chunk[eIndex].dataLen = 10;
                                    }
                                    // assign dataLen value from eIdx + 1 to the end
                                    for (int i = eIndex + 1; i < nofChunk; i++){
                                        lv1pdu.am.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                                    }

                                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                    // mapping to lcid
                                    lv1pdu.lcid = lcid;
                                    // calculate total byte
                                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                                    // only push back test case if it is not the last chunk or the last chunk has L = 0
                                    if (eIndex < nofChunk - 1 || (eIndex == nofChunk - 1 && li == 0)){
                                        db.push_back(std::move(lv1pdu));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/* eIdx for AM2_segment (E value in the first header is 1):
*  -3: subheader has Ex = 1 but there is no available byte behind
*  -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
*  -1: E0 = 1, but only 1 byte totally
*   0->3: the position (idx) of sub-header that L is longer than actual payload
*/
void rlcFuzzer_t::mutateAM2_segment_16bitSN(int snLen, int liLen,  int nofChunk, std::vector<rlcPDU_t>& db, int lcid){ // implemented for just 10 now
    // const int E = 1;    // E = 1 for AM2
    // const int DC = 1;   // DC = 1 for AM1 data pdu
    // const int RF = 1;   // RF = 1 for segment PDU
    uint8_t config_type = (snLen == 16)? ((liLen == 15)? RLC_16BIT_SN_15BIT_LI: RLC_16BIT_SN): (liLen == 15)? RLC_15BIT_LI: RLC_NORMAL;
    rlcPDU_t initial_pdu(rlcAMSegment2);
    // generate initial pdu
    generate_initial_am2_packet(snLen, liLen, initial_pdu, config_type, nofChunk, true);

    // generate test cases
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    std::vector<int>& liList = (liLen == 11)? LI_List11bit: LI_List15bit;
    if (nofChunk < 20 ){
        for (int eIdx = -3; eIdx < 0; eIdx++){
            if (eIdx == -3){       // subheader has Ex = 1 but there is no available byte behind
                if (nofChunk >=2){ // because we need at least 1 sub-header
                    for (int soIdx = 16; soIdx > 0; soIdx = soIdx - 4){ // SN will be updated following the SN from eNB
                        for (int FI = 0; FI < 4; FI++){
                            for (int lsf = 0; lsf < 1; lsf++){ // fixed: RF = 0 for normal AM PDU
                                for (int P = 0; P < 2; P++){
                                    for (auto& sn: snList){
                                    rlcPDU_t lv1pdu(rlcAMSegment2);
                                    lv1pdu = initial_pdu;

                                    // packet truncation and mutation
                                    lv1pdu.eIdx = eIdx;
                                    lv1pdu.am.SO = pow(2, soIdx) - 1;
                                    lv1pdu.am.SN = (sn == -1)?0: sn;
                                    // lv1pdu.am.E = E;
                                    lv1pdu.am.FI = FI;
                                    // lv1pdu.am.DC = DC;
                                    // lv1pdu.am.RF = RF;
                                    lv1pdu.am.LSF = lsf;
                                    lv1pdu.am.chunk[0].E = 1;
                                    lv1pdu.am.chunk[0].L = 10;
                                    lv1pdu.am.chunk[0].dataLen = 10;
                                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                    // mapping to lcid
                                    lv1pdu.lcid = lcid;
                                    // calculate total byte
                                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                                    db.push_back(std::move(lv1pdu));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (eIdx == -2){ // E0 = 1 but all fixed+extended sub-headers, no payload
                for (int soIdx = 16; soIdx > 0; soIdx = soIdx - 4){ // SN will be updated following the SN from eNB
                    for (int FI = 0; FI < 4; FI++){
                        for (int lsf = 0; lsf < 1; lsf++){ // fixed: RF = 0 for normal AM PDU
                            for (int P = 0; P < 2; P++){
                                for (auto& sn: snList){
                                rlcPDU_t lv1pdu(rlcAMSegment2);
                                lv1pdu = initial_pdu;

                                // packet truncation and mutation
                                lv1pdu.eIdx = eIdx;
                                    lv1pdu.am.SN = (sn == -1)?0: sn;
                                lv1pdu.am.SO = pow(2, soIdx) - 1;
                                // lv1pdu.am.E = E;
                                lv1pdu.am.FI = FI;
                                // lv1pdu.am.DC = DC;
                                // lv1pdu.am.RF = RF;
                                lv1pdu.am.LSF = lsf;
                                for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                    lv1pdu.am.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                                    lv1pdu.am.chunk[chunkIdx].L = (maxL)?(pow(2, snLen) -1): 10;
                                    lv1pdu.am.chunk[chunkIdx].dataLen = 0;  // no payload
                                }
                                lv1pdu.am.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                                lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                // mapping to lcid
                                lv1pdu.lcid = lcid;
                                // calculate total byte
                                lv1pdu.totalByte = calTotalByte(lv1pdu);
                                db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    }
                }
            }else if (eIdx == -1){ // -1: E0 = 1, but only 1 byte totally
                for (int FI = 0; FI < 4; FI++){
                    // for (int RF = 0; RF < 1; RF++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                            rlcPDU_t lv1pdu(rlcAMSegment2);
                            lv1pdu = initial_pdu;

                            // packet truncation and mutation
                            lv1pdu.eIdx = eIdx;
                            lv1pdu.am.SN = (sn == -1)?0: sn;
                            // lv1pdu.am.E = E;            // const E = 1
                            lv1pdu.am.FI = FI;
                            // lv1pdu.am.DC = DC;
                            // lv1pdu.am.RF = RF;
                            lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                            // mapping to lcid
                            lv1pdu.lcid = lcid;
                            // calculate total byte
                            lv1pdu.totalByte = calTotalByte(lv1pdu);
                            db.push_back(std::move(lv1pdu));
                            }
                        }
                    // }
                }
            }
        }
        for (int eIdx = 0; eIdx < nofChunk; eIdx++){        // eIdx = nofChunk - 1 is normal pdu
            for (int soIdx = 16; soIdx > 0; soIdx = soIdx - 4){ // SN will be updated following the SN from eNB
                for (int FI = 0; FI < 4; FI++){
                    for (int rsf = 0; rsf < 1; rsf++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                                for (auto& li: liList){
                                    rlcPDU_t lv1pdu(rlcAMSegment2);
                                    lv1pdu = initial_pdu;
                                    // rlcPDU_t lv1pduCase2(rlcAMSegment2);           // this is for test case with L = 0
                                    // lv1pduCase2.rrc_reconfig_type = (snLen == 16)? ((liLen == 15)? RLC_16BIT_SN_15BIT_LI: RLC_16BIT_SN): (liLen == 15)? RLC_15BIT_LI: RLC_NORMAL;
                                    // lv1pduCase2.am.snLen = snLen;
                                    // lv1pduCase2.am.liLen = liLen;

                                    // packet truncation and mutation
                                    lv1pdu.eIdx = eIdx;
                                    lv1pdu.am.SN = (sn == -1)?0: sn;
                                    lv1pdu.am.SO = pow(2, soIdx) - 1;
                                    // lv1pdu.am.E = E;
                                    lv1pdu.am.FI = FI;
                                    // lv1pdu.am.DC = DC;
                                    // lv1pdu.am.RF = RF;
                                    lv1pdu.am.LSF = rsf;
                                    // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                                    for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                        lv1pdu.am.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                                        lv1pdu.am.chunk[chunkIdx].L = 10;
                                    }
                                    // assign LI value in the eIdx position
                                    lv1pdu.am.chunk[eIdx].L = li;

                                    // assign legitimate values for dataLen up to eIdx
                                    for (int i = 0; i < eIdx; i++){
                                        lv1pdu.am.chunk[i].dataLen = 10;
                                    }
                                    // assign dataLen value in the eIdx position
                                    if (eIdx != nofChunk - 1){
                                        lv1pdu.am.chunk[eIdx].dataLen = (li == 0)?0: 5;  // this is position that L is longer than actual payload
                                    }else{
                                        lv1pdu.am.chunk[eIdx].dataLen = 10;
                                    }
                                    // assign dataLen value from eIdx + 1 to the end
                                    for (int i = eIdx + 1; i < nofChunk; i++){
                                        lv1pdu.am.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                                    }

                                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                    // lv1pduCase2 = lv1pdu;                   // this is for test case with L = 0
                                    // mapping to lcid
                                    lv1pdu.lcid = lcid;
                                    // calculate total byte
                                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                                    db.push_back(std::move(lv1pdu));
                                    
                                    // test cases with L = 0, only set L = 0 for the sub-header before eIdx
                                    // if (eIdx > 0){
                                    //     lv1pduCase2.am.chunk[eIdx - 1].L = 0;
                                    //     lv1pduCase2.am.chunk[eIdx - 1].dataLen = 0;
                                    //     lv1pduCase2.totalByte = calTotalByte(lv1pduCase2);
                                    //     db.push_back(std::move(lv1pduCase2));
                                    // }
                                }
                            }
                        }
                    }
                }
            }
        }
    }else {
        int eIdx = -2; // only generate test case with eIdx = -2 and 1 normal pdu
        for (int soIdx = 16; soIdx > 0; soIdx = soIdx - 4){ // SN will be updated following the SN from eNB
            for (int FI = 0; FI < 4; FI++){
                for (int lsf = 0; lsf < 1; lsf++){ // fixed: RF = 0 for normal AM PDU
                    for (int P = 0; P < 2; P++){
                        for (auto& sn: snList){
                        rlcPDU_t lv1pdu(rlcAMSegment2);
                        lv1pdu = initial_pdu;

                        // packet truncation and mutation
                        lv1pdu.eIdx = eIdx;
                        lv1pdu.am.SN = (sn == -1)?0: sn;
                        lv1pdu.am.SO = pow(2, soIdx) - 1;
                        // lv1pdu.am.E = E;
                        lv1pdu.am.FI = FI;
                        // lv1pdu.am.DC = DC;
                        // lv1pdu.am.RF = RF;
                        lv1pdu.am.LSF = lsf;
                        for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                            lv1pdu.am.chunk[chunkIdx].E = 1; // all E in [E, LI] are set to 1, even the last one
                            lv1pdu.am.chunk[chunkIdx].L = (maxL)?(pow(2, liLen) - 1): 10;
                            lv1pdu.am.chunk[chunkIdx].dataLen = 0;  // no payload
                        }
                        lv1pdu.am.chunk[nofChunk - 1].dataLen = 0; // last chunk does not sub-header
                        lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                        // mapping to lcid
                        lv1pdu.lcid = lcid;
                        // calculate total byte
                        lv1pdu.totalByte = calTotalByte(lv1pdu);
                        db.push_back(std::move(lv1pdu));
                        }
                    }
                }
            }
        }
        eIdx = nofChunk - 1;
        int gap = nofChunk/3;
        std::vector<int> eidx_list;
        for (int i = 0; i < nofChunk; i = i + gap){
            eidx_list.push_back(i);
        }
        eidx_list.push_back(nofChunk - 1); // normal packet
        for (auto& eIndex: eidx_list){
            for (int soIdx = 16; soIdx > 0; soIdx = soIdx - 4){ // SN will be updated following the SN from eNB
                for (int FI = 0; FI < 4; FI++){
                    for (int lsf = 0; lsf < 1; lsf++){ // fixed: RF = 0 for normal AM PDU
                        for (int P = 0; P < 2; P++){
                            for (auto& sn: snList){
                                for (auto& li: liList){
                                    rlcPDU_t lv1pdu(rlcAMSegment2);
                                    lv1pdu = initial_pdu;

                                    // packet truncation and mutation
                                    lv1pdu.eIdx = eIndex;
                                    lv1pdu.am.SN = (sn == -1)?0: sn;
                                    lv1pdu.am.SO = pow(2, soIdx) - 1;
                                    // lv1pdu.am.E = E;
                                    lv1pdu.am.FI = FI;
                                    // lv1pdu.am.DC = DC;
                                    // lv1pdu.am.RF = RF;
                                    lv1pdu.am.LSF = lsf;
                                    // assign legitimate values for [E, LI], If we have 3 chunks, there will be 2 pairs of [E, LI], so it should be nofChunk -1, the last index is nofChunk - 2
                                    for (int chunkIdx = 0; chunkIdx < nofChunk - 1; chunkIdx++){
                                        lv1pdu.am.chunk[chunkIdx].E = (chunkIdx == nofChunk - 2)?0:1; // last subheader of chunk has E = 0
                                        lv1pdu.am.chunk[chunkIdx].L = 10;
                                    }
                                    // assign LI value in the eIdx position
                                    lv1pdu.am.chunk[eIndex].L = li;

                                    // assign legitimate values for dataLen up to eIdx
                                    for (int i = 0; i < eIndex; i++){
                                        lv1pdu.am.chunk[i].dataLen = 10;
                                    }
                                    if (eIndex != nofChunk - 1){
                                        lv1pdu.am.chunk[eIndex].dataLen = 5;  // this is position that L is longer than actual payload
                                    }else{
                                        lv1pdu.am.chunk[eIndex].dataLen = 10;
                                    }
                                    // assign dataLen value from eIdx + 1 to the end
                                    for (int i = eIndex + 1; i < nofChunk; i++){
                                        lv1pdu.am.chunk[i].dataLen = 0; // the chunks after eIdx should have dataLen = 0 to make sure it will be broken in the eIdx position
                                    }

                                    lv1pdu.isCorrectSN = (sn == -1)? true: false; // -1 is correct SN
                                    // mapping to lcid
                                    lv1pdu.lcid = lcid;
                                    // calculate total byte
                                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                                    db.push_back(std::move(lv1pdu));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


/* eIdx for Status PDU AM:
*  -3: 4 bytes, E1_0 = 1, E2_1 = 1, E1_2 = 1, E2_2 = 1, but no following byte
*  -2: 2 bytes, E1_0 = 1 but no following byte
*  -1: 1 byte only
*   0: normal status pdu, mutated CPT, ACK_SN, E1_0 = 0
*   x(1: normal status pdu, ack_sn, E1 =1, nack_sn, E1, E2, Nack_sn, E1, E2, soS, soE, nack_sn, E1, E2 (3 chunks))
*   0-> eIdx: break in the eIdx (th) chunk
*/
void rlcFuzzer_t::mutateStatusPDU_AM(int snLen, int nofChunk, std::vector<rlcPDU_t>& db, int lcid){
    const int DC = 0;   // DC = 0 for status pdu
    std::vector<int>& snList = (snLen == 5)? snList5bit: (snLen == 10)?snList10bit:snList16bit;
    std::vector<int> ack_nack_list_10bit = {0, 63, 203};
    std::vector<int> ack_nack_list_16bit = {0, 1023, 65535};
    std::vector<int> so_list_15bit = {0, 1023, 32767};
    std::vector<int> so_list_16bit = {0, 1023, 65535};

    for (int eIdx = -3; eIdx < 0; eIdx++){
        for (int cpt = 0; cpt < 8; cpt = cpt + 2){ // step 3
            rlcPDU_t lv1pdu(rlcStatus);
            lv1pdu.rrc_reconfig_type = (snLen == 16)? RLC_16BIT_SN: RLC_NORMAL;
            if (lcid == 3 && snLen == 10){
                lv1pdu.rrc_reconfig_type = RLC_10BIT_SN_11BIT_LI;
            }
            allocVectorPDU(lv1pdu, nofChunk); // allocate fixed 3 chunks
            lv1pdu.status.snLen = snLen;
            lv1pdu.totalByte = (eIdx == -1)?1:((eIdx == -2)?2:4);
            lv1pdu.eIdx = eIdx;
            lv1pdu.lcid = lcid;
            // lv1pdu.status.nofChunk = (eIdx == -1)?0:((eIdx == -2)?1:2);
            lv1pdu.status.cpt = cpt;
            lv1pdu.status.DC = DC;
            lv1pdu.status.ackSN = 0;
            lv1pdu.status.E1_0 = 1;
            if (eIdx == -3){
                lv1pdu.status.chunk[0].E1 = 1;
                lv1pdu.status.chunk[0].E2 = 1;
            }
            lv1pdu.totalByte = calTotalByte(lv1pdu);
            db.push_back(std::move(lv1pdu));
        }
    }

    int gap = nofChunk/3; // make sure that we dont generate too many test cases in case of 50/100 chunks
    std::vector<int> eidx_list;
    for (int i = 0; i < nofChunk; i = i + gap){
        eidx_list.push_back(i);
    }
    // check if eidx_list has nofChunk - 1
    if (eidx_list.back() != nofChunk - 1){
        eidx_list.push_back(nofChunk - 1);
    }
    int max_nof_ack_so = ack_nack_list_10bit.size();

    std::vector<int> ack_nack_list  = (snLen == 10)? ack_nack_list_10bit: ack_nack_list_16bit;
    std::vector<int> so_list        = (snLen == 10)? so_list_15bit      : so_list_16bit;

    for (auto eIdx: eidx_list){
        for (int cpt = 0; cpt < 8; cpt = cpt + 2){ // step 3
            for (auto& sn: snList){
                for (int nack_so_seed = 0; nack_so_seed < max_nof_ack_so; nack_so_seed++){
                    rlcPDU_t lv1pdu(rlcStatus);
                    lv1pdu.rrc_reconfig_type = (snLen == 16)? RLC_16BIT_SN: RLC_NORMAL;
                    if (lcid == 3 && snLen == 10){
                        lv1pdu.rrc_reconfig_type = RLC_10BIT_SN_11BIT_LI;
                    }
                    allocVectorPDU(lv1pdu, nofChunk);
                    lv1pdu.status.snLen = snLen;
                    // lv1pdu.totalByte = 2;
                    lv1pdu.eIdx = eIdx;
                    lv1pdu.lcid = lcid;
                    lv1pdu.status.cpt = cpt;
                    lv1pdu.status.DC = DC;
                    lv1pdu.status.ackSN = sn;
                    lv1pdu.status.E1_0 = 1;

                    // set value for [E1, E2, nack_sn, soS, soE] up to eIdx
                    for (int chunkIdx = 0; chunkIdx < eIdx + 1; chunkIdx++){
                        lv1pdu.status.chunk[chunkIdx].E1 = 1;
                        lv1pdu.status.chunk[chunkIdx].E2 = 1;
                        lv1pdu.status.chunk[chunkIdx].nackSN = ack_nack_list[nack_so_seed];
                        lv1pdu.status.chunk[chunkIdx].soStart = so_list[nack_so_seed];
                        lv1pdu.status.chunk[chunkIdx].soEnd = so_list[nack_so_seed];
                    }
                    lv1pdu.status.chunk[nofChunk - 1].E1 = 0;
                    lv1pdu.status.chunk[nofChunk - 1].E2 = 0;
                    lv1pdu.status.chunk[nofChunk - 1].nackSN = ack_nack_list[nack_so_seed];
                    lv1pdu.status.chunk[nofChunk - 1].soStart = so_list[nack_so_seed];
                    lv1pdu.status.chunk[nofChunk - 1].soEnd = so_list[nack_so_seed];
                    lv1pdu.totalByte = calTotalByte(lv1pdu);
                    db.push_back(std::move(lv1pdu));
                }
            }
        }
    }
}

void rlcFuzzer_t::generate_test_cases(){

    // initiate SN values for mutation
    snList5bit.insert(snList5bit.end(), {-1, 0, 31}); // -1 is correct SN, others are boundary values
    snList10bit.insert(snList10bit.end(), {-1, 0, 1023});
    snList16bit.insert(snList16bit.end(), {-1, 0, 65536});

    LI_List11bit.insert(LI_List11bit.end(), {0, 10, 2047});
    LI_List15bit.insert(LI_List15bit.end(), {0, 10, 32767});
    
    if (!readFromFileMode){
        //T_note: remember to change configs in srsenb/src/stack/rrc/rrc_ue.cc

        // /* UM1,2 5bits SN - Figure 6.2.1.3-1 + Figure 6.2.1.3-3 + 6.2.1.3-4 36.322*/
        mutateUM1_sn5(5, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated UM1_5, lcid 3 test cases: " << testcaseDB[state4].size() << "\n";
        mutateUM2_sn5(5, 2, testcaseDB[state4], LLFUZZ_DTCH);
        mutateUM2_sn5(5, 3, testcaseDB[state4], LLFUZZ_DTCH);
        mutateUM2_sn5(5, 100, testcaseDB[state4], LLFUZZ_DTCH); // 100 chunks of data
        // std::cout << "[MTT] Generated UM2_5, lcid 3 test cases: " << testcaseDB[state4].size() << "\n";

        // /* UM1,2 10 bits SN - Figure 6.2.1.3-2 + Figure 6.2.1.3-5 + 6.2.1.3-6 36.322*/
        mutateUM1_sn10(10, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated UM1_10, lcid 3, test case: " << testcaseDB[state4].size() << "\n";
        mutateUM2_sn10(10, 2, testcaseDB[state4], LLFUZZ_DTCH);
        mutateUM2_sn10(10, 3, testcaseDB[state4], LLFUZZ_DTCH);
        mutateUM2_sn10(10, 4, testcaseDB[state4], LLFUZZ_DTCH);
        mutateUM2_sn10(10, 100, testcaseDB[state4], LLFUZZ_DTCH); // 100 chunks of data
        // std::cout << "[MTT] Generated UM2_10, lcis 3, test case: " << testcaseDB[state4].size() << "\n";
        
        /* AM1, 2, 10 bit SN + 11 bit LI*/
        mutateAM1(10, testcaseDB[state4], LLFUZZ_DTCH); // lcid 3 is for user data with AM config
        mutateAM1(10, testcaseDB[state4], LLFUZZ_DCCH2);
        mutateAM1(10, testcaseDB[state4], LLFUZZ_DCCH1);
        // std::cout << "[MTT] Generated AM1_10 - lcid 1+2+3, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2(10, 11, 2, testcaseDB[state4], LLFUZZ_DTCH); // lcid 3 is for user data with AM config
        mutateAM2(10, 11, 3, testcaseDB[state4], LLFUZZ_DTCH); // lcid 3 is for user data with AM config
        mutateAM2(10, 11, 2, testcaseDB[state4], LLFUZZ_DCCH2);
        mutateAM2(10, 11, 3, testcaseDB[state4], LLFUZZ_DCCH2);
        mutateAM2(10, 11, 2, testcaseDB[state4], LLFUZZ_DCCH1);
        mutateAM2(10, 11, 3, testcaseDB[state4], LLFUZZ_DCCH1);
        mutateAM2(10, 11, 100, testcaseDB[state4], LLFUZZ_DCCH1);
        mutateAM2(10, 11, 100, testcaseDB[state4], LLFUZZ_DCCH2);
        mutateAM2(10, 11, 100, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated AM2 - lcid 1+2+3 test case: " << testcaseDB[state4].size() << "\n";

        // /* AM1, 2 Segment 10 bit SN + 11 bit LI*/
        mutateAM1_segment(10, testcaseDB[state4], LLFUZZ_DCCH1);
        mutateAM1_segment(10, testcaseDB[state4], LLFUZZ_DCCH2);
        mutateAM1_segment(10, testcaseDB[state4], LLFUZZ_DTCH); // lcid 3 is for user data with AM config
        // std::cout << "[MTT] Generated AM1S_10 - lcid 1+2+3 - state4, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2_segment(10, 11, 3, testcaseDB[state4], LLFUZZ_DCCH1);
        // std::cout << "[MTT] Generated AM2S - lcid 1 - state4, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2_segment(10, 11, 3, testcaseDB[state4], LLFUZZ_DCCH2);
        // std::cout << "[MTT] Generated AM2S - lcid 2 - state4, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2_segment(10, 11, 3, testcaseDB[state4], LLFUZZ_DTCH); // lcid 3 is for user data with AM config
        // std::cout << "[MTT] Generated AM2S_10_11 - lcid 3 - state4, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2_segment(10, 11, 100, testcaseDB[state4], LLFUZZ_DCCH1);
        // std::cout << "[MTT] Generated AM2S - lcid 1 - state4, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2_segment(10, 11, 100, testcaseDB[state4], LLFUZZ_DCCH2);
        // std::cout << "[MTT] Generated AM2S - lcid 2 - state4, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2_segment(10, 11, 100, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated AM2S - lcid 3 - state4, test case: " << testcaseDB[state4].size() << "\n";


        // /* AM1, 2, 16 bit SN + 11 bit LI (only user data)*/
        mutateAM1_16bitSN(16, testcaseDB[state4], LLFUZZ_DTCH); // DRB 1 (lcid 3) is configured with 16 bits SN AM
        // std::cout << "[MTT] Generated AM1_16_11 - lcid 3, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2(16, 11, 3, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated AM2_16_11 - lcid 3 test case: " << testcaseDB[state4].size() << "\n";

        // /* AM1, 2 Segment, 16 bit SN + 11 bit LI (only user data)*/
        mutateAM1_segment_16bitSN(16, testcaseDB[state4], LLFUZZ_DTCH); 
        // std::cout << "[MTT] Generated AM1S_16_11 - lcid 3 - state4, test case: " << testcaseDB[state4].size() << "\n";
        mutateAM2_segment_16bitSN(16, 11, 3, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated AM2S_16_11 - lcid 3 - state4, test case: " << testcaseDB[state4].size() << "\n";
        
        // /* AM2, 10 bit SN + 15 bit LI (only user data)*/
        mutateAM2_15bitLI(10, 15, 3, testcaseDB[state4], LLFUZZ_DTCH);
        mutateAM2_15bitLI(10, 15, 100, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated AM2_10_15 - lcid 3 test case: " << testcaseDB[state4].size() << "\n";
        
        // /* AM2 Segment, 10 bit SN + 15 bit LI (only user data)*/
        mutateAM2_segment(10, 15, 3, testcaseDB[state4], LLFUZZ_DTCH);
        mutateAM2_segment(10, 15, 100, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated AM2S_10_15 - lcid 3 - state4, test case: " << testcaseDB[state4].size() << "\n";

        // /* AM2, 16 bit SN + 15 bit LI (only user data)*/
        mutateAM2(16, 15, 3, testcaseDB[state4], LLFUZZ_DTCH);
        mutateAM2(16, 15, 100, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] lcid 3 test case: " << testcaseDB[state4].size() << "\n";

        // /* AM2 Segment, 16 bit SN + 15 bit LI (only user data)*/
        mutateAM2_segment_16bitSN(16, 15, 3, testcaseDB[state4], LLFUZZ_DTCH);
        mutateAM2_segment_16bitSN(16, 15, 100, testcaseDB[state4], LLFUZZ_DTCH);
        // std::cout << "[MTT] Generated AM2S_16_15 - lcid 3 - state4, test case: " << testcaseDB[state4].size() << "\n";

        /* Status PDU 10 bit SN*/
        /* Note that 16 bit SN configuration is only confiurable on DRB*/
        mutateStatusPDU_AM(10, 3, testcaseDB[state4], LLFUZZ_DTCH); // DRB is configured with RLC AM, 10 bit SN
        // std::cout << "[MTT] Generated Status PDU_10 - lcid 3, test case: " << testcaseDB[state4].size() << "\n";
        mutateStatusPDU_AM(10, 3, testcaseDB[state4], LLFUZZ_DCCH2);
        // std::cout << "[MTT] Generated Status PDU_10 - lcid 2, test case: " << testcaseDB[state4].size() << "\n";
        mutateStatusPDU_AM(10, 3, testcaseDB[state4], LLFUZZ_DCCH1);
        // std::cout << "[MTT] Generated Status PDU_10 - lcid 1, test case: " << testcaseDB[state4].size() << "\n";
        mutateStatusPDU_AM(10, 100, testcaseDB[state4], 1);
        // std::cout << "[MTT] Generated Status PDU_10 - lcid 1, test case: " << testcaseDB[state4].size() << "\n";
        mutateStatusPDU_AM(10, 100, testcaseDB[state4], 2);
        // std::cout << "[MTT] Generated Status PDU_10 - lcid 2, test case: " << testcaseDB[state4].size() << "\n";
        mutateStatusPDU_AM(10, 100, testcaseDB[state4], LLFUZZ_DTCH); // DRB is configured with RLC AM, 10 bit SN
        // std::cout << "[MTT] Generated Status PDU_10 - lcid 3, test case: " << testcaseDB[state4].size() << "\n";
        
        /* Status PDU 16 bit SN*/
        mutateStatusPDU_AM(16, 3, testcaseDB[state4], LLFUZZ_DTCH); // DRB is configured with RLC AM, 16 bit SN
        // std::cout << "[MTT] Generated Status PDU_16 - lcid 3, test case: " << testcaseDB[state4].size() << "\n";
        mutateStatusPDU_AM(16, 100, testcaseDB[state4], LLFUZZ_DTCH); // DRB is configured with RLC AM, 16 bit SN
        // std::cout << "[MTT] Generated Status PDU_16 - lcid 3, test case: " << testcaseDB[state4].size() << "\n";

        // state 3, only DCCH-1 is enabled
        /* AM1, 2, 10 bit SN + 11 bit LI*/
        // mutateAM1(10, testcaseDB[state3], 2);
        mutateAM1(10, testcaseDB[state3], LLFUZZ_DCCH1);
        // std::cout << "[MTT] [S3] Generated AM1_10 - lcid 1+2+3, test case: " << testcaseDB[state3].size() << "\n";
        // mutateAM2(10, 11, 2, testcaseDB[state3], 2);
        // mutateAM2(10, 11, 3, testcaseDB[state3], 2);
        mutateAM2(10, 11, 2, testcaseDB[state3], LLFUZZ_DCCH1);
        mutateAM2(10, 11, 3, testcaseDB[state3], LLFUZZ_DCCH1);
        mutateAM2(10, 11, 100, testcaseDB[state3], LLFUZZ_DCCH1);
        // mutateAM2(10, 11, 100, testcaseDB[state3], 2);
        // std::cout << "[MTT] [S3] Generated AM2 - lcid 1+2+3 test case: " << testcaseDB[state3].size() << "\n";
        mutateAM1_segment(10, testcaseDB[state3], LLFUZZ_DCCH1);
        // mutateAM1_segment(10, testcaseDB[state3], 2);
        mutateAM2_segment(10, 11, 3, testcaseDB[state3], LLFUZZ_DCCH1);
        // mutateAM2_segment(10, 11, 3, testcaseDB[state3], 2);
        // std::cout << "[MTT] [S3] Generated AM2S - lcid 1+2 - state3, test case: " << testcaseDB[state3].size() << "\n";
        mutateAM2_segment(10, 11, 100, testcaseDB[state3], LLFUZZ_DCCH1);
        // mutateAM2_segment(10, 11, 100, testcaseDB[state3], 2);
        // std::cout << "[MTT] [S3] Generated AM2S - lcid 1+2 - state3, test case: " << testcaseDB[state3].size() << "\n";
        mutateStatusPDU_AM(10, 3, testcaseDB[state3], LLFUZZ_DCCH1);
        // mutateStatusPDU_AM(10, 3, testcaseDB[state3], 2);
        mutateStatusPDU_AM(10, 100, testcaseDB[state3], LLFUZZ_DCCH1);
        // mutateStatusPDU_AM(10, 100, testcaseDB[state3], 2);
        // std::cout << "[MTT] [S3] Generated Status PDU_10 - lcid 1+2, test case: " << testcaseDB[state3].size() << "\n";

    }else{

    }

}

rlcHeaderResult_t generateUM1_1Byte(bool R1, bool R2, bool R3, int FI, int E, int SN, int snLen){
    rlcHeaderResult_t result = {};
    uint8_t temp = 0;
    if (snLen == 10){
        temp |= (R1 << 7);
        temp |= (R2 << 6);
        temp |= (R3 << 5);
        temp |= (FI << 3);
        temp |= (E << 2);
        temp |= SN;
    }else if (snLen == 5){
        temp |= (FI << 6);
        temp |= (E << 5);
        temp |= (SN & 0x1F);
    }
    result.nofByte = 1;
    result.pattern.push_back(temp);
    return result;
}

rlcHeaderResult_t generateUM1header(int snLen, bool R1, bool R2, bool R3, int FI, int E, int SN){
    rlcHeaderResult_t result = {};
    if (snLen == 10){
        result.nofByte = 2;
        uint16_t heaValue = 0;
        heaValue |= (R1 << 15);
        heaValue |= (R2 << 14);
        heaValue |= (R3 << 13);
        heaValue |= (FI << 11);
        heaValue |= (E << 10);
        heaValue |= SN;
        uint8_t firstByte = (heaValue >> 8) & 0xFF; // Get the high byte
        uint8_t secondByte = heaValue & 0xFF; // Get the low byte    
        result.pattern.push_back(firstByte);
        result.pattern.push_back(secondByte);
    }else if (snLen == 5){
        result.nofByte = 1;
        uint8_t temp = 0;
        temp |= (FI << 6);
        temp |= (E << 5);
        temp |= (SN & 0x1F);
        result.pattern.push_back(temp);
    }
    return result;
}

rlcHeaderResult_t generateSubHea2Chunk(int idx1, int idx2, std::vector<rlcChunk_t>& chunk){
    rlcHeaderResult_t result = {};
    result.nofByte = 3;
    uint32_t temp = 0;
    temp |= (chunk[idx1].E << 23);
    temp |= (chunk[idx1].L << 12);
    temp |= (chunk[idx2].E << 11);
    temp |= chunk[idx2].L;

    uint8_t firstByte = (temp >> 16) & 0xFF; // Get the first byte
    uint8_t secondByte = (temp >> 8) & 0xFF; // Get the second byte
    uint8_t thirdByte = temp & 0xFF; // Get the third byte
    result.pattern.push_back(firstByte);
    result.pattern.push_back(secondByte);
    result.pattern.push_back(thirdByte);

    return result;
}

rlcHeaderResult_t generateSubHea1Chunk(std::vector<rlcChunk_t>& chunk){
    rlcHeaderResult_t result = {};
    result.nofByte = 2;
    uint16_t temp = 0;
    if ((int)(chunk.size() - 2) >=0){ // because n chunks will result n - 1 subheaders, so the last one is chunk.size() - 2
        temp |= (chunk[chunk.size() - 2].E << 15);
        temp |= (chunk[chunk.size() - 2].L << 4); // 4 last bits are padding, 0
    }

    uint8_t firstByte = (temp >> 8) & 0xFF; // Get the first byte
    uint8_t secondByte = temp & 0xFF; // Get the second byte
    result.pattern.push_back(firstByte);
    result.pattern.push_back(secondByte);

    return result;
}

rlcHeaderResult_t generateSubHea1Chunk_15bitLI(std::vector<rlcChunk_t>& chunk, int heaIdx){
    rlcHeaderResult_t result = {};
    result.nofByte = 2;
    uint16_t temp = 0;
    temp |= (chunk[heaIdx].E << 15); // first bit is for E
    temp |= (chunk[heaIdx].L);  // 15 bits for LI

    uint8_t firstByte = (temp >> 8) & 0xFF; // Get the first byte
    uint8_t secondByte = temp & 0xFF; // Get the second byte
    result.pattern.push_back(firstByte);
    result.pattern.push_back(secondByte);

    return result;
}


rlcHeaderResult_t generateUM2header(int snLen, int eIdx, bool R1, bool R2, bool R3, int FI, int E, int SN, int nofChunk, std::vector<rlcChunk_t>& chunk){
    rlcHeaderResult_t result = {};
    if (snLen == 10){
        if (eIdx == -3 && nofChunk >= 2){
            result.nofByte = 3;
            uint16_t heaValue = 0;
            heaValue |= (R1 << 15);
            heaValue |= (R2 << 14);
            heaValue |= (R3 << 13);
            heaValue |= (FI << 11);
            heaValue |= (E << 10);
            heaValue |= SN;
            uint8_t firstByte = (heaValue >> 8) & 0xFF; // Get the high byte
            uint8_t secondByte = heaValue & 0xFF; // Get the low byte    
            result.pattern.push_back(firstByte);
            result.pattern.push_back(secondByte);
            uint8_t thirdByte = 0;
            thirdByte |= (chunk[0].E << 7);
            thirdByte = thirdByte + 10;
            result.pattern.push_back(thirdByte);
        }else{
            int nofSubhea = nofChunk - 1;
            int subHeaderByte = 0;
            if (nofSubhea % 2 == 0) {
                subHeaderByte = nofSubhea*12/8;
            }else{
                subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
            }
            result.nofByte = 2 + subHeaderByte; // 2 byte for fixed header
            rlcHeaderResult_t fixedHeader = generateUM1header(snLen, R1, R2, R3, FI, E, SN);
            result.pattern.insert(result.pattern.end(), fixedHeader.pattern.begin(), fixedHeader.pattern.end());
            int remainingSubHea = nofSubhea;
            int subHeaIdx[2] = {0, 1}; 
            while (remainingSubHea > 0){
                if (remainingSubHea == 1){
                    rlcHeaderResult_t temp = generateSubHea1Chunk(chunk);
                    result.nofByte += temp.nofByte;
                    result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                    remainingSubHea -= 1;
                }else if (remainingSubHea >= 2){
                    rlcHeaderResult_t temp = generateSubHea2Chunk(subHeaIdx[0], subHeaIdx[1], chunk);
                    result.nofByte += temp.nofByte;
                    result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                    subHeaIdx[0] += 2;
                    subHeaIdx[1] += 2;
                    remainingSubHea -= 2;
                }
            }            
        }

    }else if (snLen == 5){
        if (eIdx == -3 && nofChunk >= 2){
            result.nofByte = 2;
            uint8_t heaValue = 0;
            heaValue |= (FI << 6);
            heaValue |= (E << 5);
            heaValue |= (SN & 0x1F);
            result.pattern.push_back(heaValue);
            uint8_t secondByte = 0;
            secondByte |= (chunk[0].E << 7);
            secondByte = secondByte + 10;
            result.pattern.push_back(secondByte);
        }else{
            int nofSubhea = nofChunk - 1;
            int subHeaderByte = 0;
            if (nofSubhea % 2 == 0) {
                subHeaderByte = nofSubhea*12/8;
            }else{
                subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
            }
            result.nofByte = 1 + subHeaderByte; // 1 byte for fixed header
            rlcHeaderResult_t fixedHeader = generateUM1header(snLen, R1, R2, R3, FI, E, SN);
            result.pattern.insert(result.pattern.end(), fixedHeader.pattern.begin(), fixedHeader.pattern.end());
            int remainingSubHea = nofSubhea;
            int subHeaIdx[2] = {0, 1}; 
            while (remainingSubHea > 0){
                if (remainingSubHea == 1){
                    rlcHeaderResult_t temp = generateSubHea1Chunk(chunk);
                    result.nofByte += temp.nofByte;
                    result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                    remainingSubHea -= 1;
                }else if (remainingSubHea >= 2){
                    rlcHeaderResult_t temp = generateSubHea2Chunk(subHeaIdx[0], subHeaIdx[1], chunk);
                    result.nofByte += temp.nofByte;
                    result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                    subHeaIdx[0] += 2;
                    subHeaIdx[1] += 2;
                    remainingSubHea -= 2;
                }
            }            
        }
    }
    return result;
}

rlcHeaderResult_t generateAM1_1Byte(bool DC, bool RF, bool P, int FI, int E, int SN){
    rlcHeaderResult_t result = {};
    uint8_t temp = 0;
    temp |= (DC << 7);
    temp |= (RF << 6);
    temp |= (P << 5);
    temp |= (FI << 3);
    temp |= (E << 2);
    temp |= SN;    
    result.nofByte = 1;
    result.pattern.push_back(temp);
    return result;
}

rlcHeaderResult_t generateAM1_1Byte_16bitSN_segment(bool DC, bool RF, bool P, int FI, int E, bool lfs){
    rlcHeaderResult_t result = {};
    uint8_t temp = 0;
    bool R1_1 = 0;
    temp |= (DC << 7);
    temp |= (RF << 6);
    temp |= (P << 5);
    temp |= (FI << 3);
    temp |= (E << 2);
    temp |= (lfs << 1);
    temp |= R1_1;
    result.nofByte = 1;
    result.pattern.push_back(temp);
    return result;
}


rlcHeaderResult_t generateAM1_1Byte_16sn(bool DC, bool RF, bool P, int FI, int E, int SN){
    rlcHeaderResult_t result = {};
    bool R1_1 = 0;
    bool R1_2 = 0;
    uint8_t temp = 0;
    temp |= (DC << 7);
    temp |= (RF << 6);
    temp |= (P << 5);
    temp |= (FI << 3);
    temp |= (E << 2);
    temp |= (R1_1 << 1);
    temp |= R1_2;    
    result.nofByte = 1;
    result.pattern.push_back(temp);
    return result;
}


rlcHeaderResult_t generateAM1header(int snLen, bool DC, bool RF, bool P, int FI, int E, int SN){
    rlcHeaderResult_t result = {};
    if (snLen == 10){
        result.nofByte = 2;
        uint16_t heaValue = 0;
        heaValue |= (DC << 15);
        heaValue |= (RF << 14);
        heaValue |= (P << 13);
        heaValue |= (FI << 11);
        heaValue |= (E << 10);
        heaValue |= SN;
        uint8_t firstByte = (heaValue >> 8) & 0xFF; // Get the high byte
        uint8_t secondByte = heaValue & 0xFF; // Get the low byte    
        result.pattern.push_back(firstByte);
        result.pattern.push_back(secondByte);
    }else if (snLen == 16){
        bool R1_1 = 0;
        bool R1_2 = 0;
        result.nofByte = 3;
        uint8   firstByte = 0;
        firstByte |= (DC << 7);
        firstByte |= (RF << 6);
        firstByte |= (P << 5);
        firstByte |= (FI << 3);
        firstByte |= (E << 2);  
        firstByte |= (R1_1 << 1);
        firstByte |= R1_2;
        uint8_t secondByte = (SN >> 8) & 0xFF;
        uint8_t thirdByte = SN & 0xFF;

        result.pattern.push_back(firstByte);
        result.pattern.push_back(secondByte);
        result.pattern.push_back(thirdByte);
    }
    return result;
}

rlcHeaderResult_t generateAM1SegmentHeader(int snLen, bool DC, bool RF, bool P, int FI, int E, int SN, bool lsf, uint16_t so){
    rlcHeaderResult_t result = {};
    if (snLen == 10){
        result.nofByte = 4;
        uint32_t heaValue = 0;
        heaValue |= (DC << 31);
        heaValue |= (RF << 30);
        heaValue |= (P  << 29);
        heaValue |= (FI << 27);
        heaValue |= (E  << 26);
        heaValue |= (SN << 16);
        heaValue |= (lsf << 15);
        heaValue |= so;
        uint8_t firstByte = (heaValue >> 24) & 0xFF; // Get the high byte
        uint8_t secondByte = (heaValue >> 16) & 0xFF; // Get the second byte
        uint8_t thirdByte = (heaValue >> 8) & 0xFF; // Get the third byte
        uint8_t fourthByte = heaValue & 0xFF; // Get the fourth byte
        result.pattern.push_back(firstByte);
        result.pattern.push_back(secondByte);
        result.pattern.push_back(thirdByte);
        result.pattern.push_back(fourthByte);
    }else if (snLen == 16){
        bool R1_1 = 0;
        result.nofByte = 5;
        uint8_t firstByte = 0;
        firstByte |= (DC << 7);
        firstByte |= (RF << 6);
        firstByte |= (P << 5);
        firstByte |= (FI << 3);
        firstByte |= (E << 2);
        firstByte |= lsf<<1;
        firstByte |= R1_1;
        uint8_t secondByte = 0;
        secondByte |= (SN >> 8) & 0xFF;
        uint8_t thirdByte = SN & 0xFF;
        uint8_t fourthByte = (so >> 8) & 0xFF;
        uint8_t fifthByte = so & 0xFF;

        result.pattern.push_back(firstByte);
        result.pattern.push_back(secondByte);
        result.pattern.push_back(thirdByte);
        result.pattern.push_back(fourthByte);
        result.pattern.push_back(fifthByte);
    }
    return result;
}

rlcHeaderResult_t generateAM2header(int snLen, int liLen, int eIdx, bool DC, bool RF, bool P, int FI, int E, int SN, int nofChunk, std::vector<rlcChunk_t>& chunk){
    rlcHeaderResult_t result = {};
    if (snLen == 10){
        if (eIdx == -3 && nofChunk >= 2){
            result.nofByte = 3;
            uint16_t heaValue = 0;
            heaValue |= (DC << 15);
            heaValue |= (RF << 14);
            heaValue |= (P << 13);
            heaValue |= (FI << 11);
            heaValue |= (E << 10);
            heaValue |= SN;
            uint8_t firstByte = (heaValue >> 8) & 0xFF; // Get the high byte
            uint8_t secondByte = heaValue & 0xFF; // Get the low byte    
            result.pattern.push_back(firstByte);
            result.pattern.push_back(secondByte);
            uint8_t thirdByte = 0;
            thirdByte |= (chunk[0].E << 7);
            thirdByte = thirdByte + 10;
            result.pattern.push_back(thirdByte);
        }else{
            int nofSubhea = nofChunk - 1; // last chunk does not have subheader
            int subHeaderByte = 0;

            if (liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }

            result.nofByte = 2 + subHeaderByte; // 2 byte for fixed header
            rlcHeaderResult_t fixedHeader = generateUM1header(snLen, DC, RF, P, FI, E, SN);
            result.pattern.insert(result.pattern.end(), fixedHeader.pattern.begin(), fixedHeader.pattern.end());
            int remainingSubHea = nofSubhea;
            if (liLen == 11){
                int subHeaIdx[2] = {0, 1}; 
                while (remainingSubHea > 0){
                    if (remainingSubHea == 1){
                        rlcHeaderResult_t temp = generateSubHea1Chunk(chunk);
                        result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                        remainingSubHea -= 1;
                    }else if (remainingSubHea >= 2){
                        rlcHeaderResult_t temp = generateSubHea2Chunk(subHeaIdx[0], subHeaIdx[1], chunk);
                        result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                        subHeaIdx[0] += 2;
                        subHeaIdx[1] += 2;
                        remainingSubHea -= 2;
                    }
                }  
            }else if (liLen== 15){
                int subHeaidx = 0;
                while (remainingSubHea > 0){
                    rlcHeaderResult_t temp = generateSubHea1Chunk_15bitLI(chunk, subHeaidx);
                    result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                    subHeaidx += 1;
                    remainingSubHea -= 1;
                }
            }          
        }

    }else if (snLen == 16){
        if (eIdx == -3 && nofChunk >= 2){
            result.nofByte = 4;
            bool R1_1 = 0;
            bool R1_2 = 0;
            uint32_t heaValue = 0;
            heaValue |= (DC << 31);
            heaValue |= (RF << 30);
            heaValue |= (P  << 29);
            heaValue |= (FI << 27);
            heaValue |= (E  << 26);
            heaValue |= (R1_1 << 25);
            heaValue |= (R1_2 << 24);
            heaValue |= (SN << 8);
            heaValue |= chunk[0].E << 7;
            heaValue = heaValue + 10;
            uint8_t firstByte = (heaValue >> 24) & 0xFF; // Get the high byte
            uint8_t secondByte = (heaValue >> 16) & 0xFF; // Get the second byte
            uint8_t thirdByte = (heaValue >> 8) & 0xFF; // Get the third byte
            uint8_t fourthByte = heaValue & 0xFF; // Get the fourth byte
            result.pattern.push_back(firstByte);
            result.pattern.push_back(secondByte);
            result.pattern.push_back(thirdByte);
            result.pattern.push_back(fourthByte);
        }else{
            int nofSubhea = nofChunk - 1;
            int subHeaderByte = 0;
            if (liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            result.nofByte = 3 + subHeaderByte; // 3 byte for fixed header with 16 bits SN
            rlcHeaderResult_t fixedHeader = generateAM1header(snLen, DC, RF, P, FI, E, SN); // 3 byte for fixed header
            result.pattern.insert(result.pattern.end(), fixedHeader.pattern.begin(), fixedHeader.pattern.end());
            int remainingSubHea = nofSubhea;
            if (liLen == 11){
                int subHeaIdx[2] = {0, 1}; 
                while (remainingSubHea > 0){
                    if (remainingSubHea == 1){
                        rlcHeaderResult_t temp = generateSubHea1Chunk(chunk);
                        result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                        remainingSubHea -= 1;
                    }else if (remainingSubHea >= 2){
                        rlcHeaderResult_t temp = generateSubHea2Chunk(subHeaIdx[0], subHeaIdx[1], chunk);
                        result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                        subHeaIdx[0] += 2;
                        subHeaIdx[1] += 2;
                        remainingSubHea -= 2;
                    }
                }  
            }else if (liLen== 15){
                int subHeaidx = 0;
                while (remainingSubHea > 0){
                    rlcHeaderResult_t temp = generateSubHea1Chunk_15bitLI(chunk, subHeaidx);
                    result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                    subHeaidx += 1;
                    remainingSubHea -= 1;
                }
            }          

        }

    }
    return result;
}

/* eIdx for AM2_segment (E value in the first header is 1):
*  -3: subheader has Ex = 1 but there is no available byte behind
*  -2: E0 = 1, all Ex = 0 (chunk) but all sub-headers, no payload
*  -1: E0 = 1, but only 1 byte totally
*   0->3: the position (idx) of sub-header that L is longer than actual payload
*/
rlcHeaderResult_t generateAM2SegmentHeader(int snLen, int liLen, int eIdx, bool DC, bool RF, bool P, int FI, int E, int SN, bool lsf, uint16_t so, int nofChunk, std::vector<rlcChunk_t>& chunk){
    rlcHeaderResult_t result = {};
    if (snLen == 10){
        if (eIdx == -3 && nofChunk >= 2){
            result.nofByte = 5;
            uint32_t heaValue = 0;
            heaValue |= (DC << 31);
            heaValue |= (RF << 30);
            heaValue |= (P  << 29);
            heaValue |= (FI << 27);
            heaValue |= (E  << 26);
            heaValue |= (SN << 16);
            heaValue |= (lsf << 15);
            heaValue |= so;
            uint8_t firstByte = (heaValue >> 24) & 0xFF; // Get the high byte
            uint8_t secondByte = (heaValue >> 16) & 0xFF; // Get the second byte
            uint8_t thirdByte = (heaValue >> 8) & 0xFF; // Get the third byte
            uint8_t fourthByte = heaValue & 0xFF; // Get the fourth byte
            result.pattern.push_back(firstByte);
            result.pattern.push_back(secondByte);
            result.pattern.push_back(thirdByte);
            result.pattern.push_back(fourthByte);
            uint8_t fifthByte = 0;
            fifthByte |= (chunk[0].E << 7);
            fifthByte = fifthByte + 10;
            result.pattern.push_back(fifthByte);
        }else{
            int nofSubhea = nofChunk - 1;
            int subHeaderByte = 0;
            if (liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            result.nofByte = 4 + subHeaderByte; // 4 byte for fixed header
            rlcHeaderResult_t fixedHeader = generateAM1SegmentHeader(snLen, DC, RF, P, FI, E, SN, lsf, so); // 
            result.pattern.insert(result.pattern.end(), fixedHeader.pattern.begin(), fixedHeader.pattern.end());
            int remainingSubHea = nofSubhea;
            if (liLen == 11){
                int subHeaIdx[2] = {0, 1}; 
                while (remainingSubHea > 0){
                    if (remainingSubHea == 1){
                        rlcHeaderResult_t temp = generateSubHea1Chunk(chunk);
                        result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                        remainingSubHea -= 1;
                    }else if (remainingSubHea >= 2){
                        rlcHeaderResult_t temp = generateSubHea2Chunk(subHeaIdx[0], subHeaIdx[1], chunk);
                        result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                        subHeaIdx[0] += 2;
                        subHeaIdx[1] += 2;
                        remainingSubHea -= 2;
                    }
                }  
            }else if (liLen== 15){
                int subHeaidx = 0;
                while (remainingSubHea > 0){
                    rlcHeaderResult_t temp = generateSubHea1Chunk_15bitLI(chunk, subHeaidx);
                    result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                    subHeaidx += 1;
                    remainingSubHea -= 1;
                }
            }          
            if (result.nofByte != (int)result.pattern.size()){
                // printf("Error: AM2 segment header size mismatch, %d|%d\n", result.nofByte, (int)result.pattern.size());
            }
        }

    }else if (snLen == 16){
        if (eIdx == -3 && nofChunk >= 2){
            result.nofByte = 6;
            bool R1_1 = 0;
            uint8_t firstByte = 0;
            firstByte |= (DC << 7);
            firstByte |= (RF << 6);
            firstByte |= (P << 5);
            firstByte |= (FI << 3);
            firstByte |= (E << 2);
            firstByte |= (lsf << 1);
            firstByte |= R1_1;
            result.pattern.push_back(firstByte);
            uint8_t secondByte = 0;
            secondByte |= (SN >> 8) & 0xFF;
            result.pattern.push_back(secondByte);
            uint8_t thirdByte = SN & 0xFF;
            result.pattern.push_back(thirdByte);
            uint8_t fourthByte = 0;
            fourthByte |= (so >> 8) & 0xFF;
            result.pattern.push_back(fourthByte);
            uint8_t fifthByte = so & 0xFF;
            result.pattern.push_back(fifthByte);
            uint8_t sixthByte = 0;
            sixthByte |= (chunk[0].E << 7);
            sixthByte = sixthByte + 10;
            result.pattern.push_back(sixthByte);

        }else{
            int nofSubhea = nofChunk - 1;
            int subHeaderByte = 0;
            if (liLen == 11){
                if (nofSubhea % 2 == 0) {
                    subHeaderByte = nofSubhea*12/8;
                }else{
                    subHeaderByte = (nofSubhea*12 + 4)/8; // 4 byte padding
                }
            }else if (liLen == 15){
                subHeaderByte = nofSubhea*2; // 2 bytes for each subheader
            }
            result.nofByte = 5 + subHeaderByte; // 5 byte for fixed header with 16 bits SN
            rlcHeaderResult_t fixedHeader = generateAM1SegmentHeader(snLen, DC, RF, P, FI, E, SN, lsf, so); // 5 byte for fixed header
            result.pattern.insert(result.pattern.end(), fixedHeader.pattern.begin(), fixedHeader.pattern.end());
            int remainingSubHea = nofSubhea;
            if (liLen == 11){
                int subHeaIdx[2] = {0, 1}; 
                while (remainingSubHea > 0){
                    if (remainingSubHea == 1){
                        rlcHeaderResult_t temp = generateSubHea1Chunk(chunk);
                        result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                        remainingSubHea -= 1;
                    }else if (remainingSubHea >= 2){
                        rlcHeaderResult_t temp = generateSubHea2Chunk(subHeaIdx[0], subHeaIdx[1], chunk);
                        result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                        subHeaIdx[0] += 2;
                        subHeaIdx[1] += 2;
                        remainingSubHea -= 2;
                    }
                }  
            }else if (liLen== 15){
                int subHeaidx = 0;
                while (remainingSubHea > 0){
                    rlcHeaderResult_t temp = generateSubHea1Chunk_15bitLI(chunk, subHeaidx);
                    result.pattern.insert(result.pattern.end(), temp.pattern.begin(), temp.pattern.end());
                    subHeaidx += 1;
                    remainingSubHea -= 1;
                }
            }          
        }
    }
    return result;
}

// Helper function to add the bits of a value to a vector
void addBits(std::vector<bool>& bitPattern, uint16_t value, int bits) {
    for (int i = bits - 1; i >= 0; --i) {
        bitPattern.push_back((value >> i) & 1);
    }
}

uint32_t generateRandomNumber(int bits) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, (1 << bits) - 1);
    return dis(gen);
}

rlcHeaderResult_t generateStatusPDU(int snLen, int eIdx, int cpt, int ackSN, int E1_0, int nackSN, int nofChunk, std::vector<rlcStatusChunk_t>& chunk, int totalLen){
    const bool DC = 0; // Data/Control
    rlcHeaderResult_t result = {};
    if (snLen == 10){
        if (eIdx == -1){
            result.nofByte = 1;
            uint8_t temp = 0;
            temp |= (DC << 7);
            temp |= (cpt << 4);
            temp |= (ackSN & 0xF);
            result.pattern.push_back(temp);
        }else if (eIdx == -2){
            result.nofByte = 2;
            uint16_t temp = 0;
            temp |= (DC << 15);
            temp |= (cpt << 12);
            temp |= (ackSN << 2);
            temp |= (E1_0 << 1);
            uint8_t firstByte = (temp >> 8) & 0xFF; // Get the high byte
            uint8_t secondByte = temp & 0xFF; // Get the low byte    
            result.pattern.push_back(firstByte);
            result.pattern.push_back(secondByte);
        }else if (eIdx == -3){
            result.nofByte = 4;
            uint32_t temp = 0;
            temp |= (DC << 31);
            temp |= (cpt << 28);
            temp |= (ackSN << 18);
            temp |= (E1_0 << 17);
            temp |= (nackSN << 7);
            temp |= (chunk[0].E1 << 6);
            temp |= (chunk[0].E2 << 5);
            // temp |= (chunk[1].nackSN << 1);
            // temp |= (chunk[1].E1 << 0);
            uint8_t firstByte = (temp >> 24) & 0xFF; // Get the high byte
            uint8_t secondByte = (temp >> 16) & 0xFF; // Get the second byte
            uint8_t thirdByte = (temp >> 8) & 0xFF; // Get the third byte
            uint8_t fourthByte = temp & 0xFF; // Get the fourth byte
            result.pattern.push_back(firstByte);
            result.pattern.push_back(secondByte);
            result.pattern.push_back(thirdByte);
            result.pattern.push_back(fourthByte);
        }else if (eIdx >= 0){
            result.nofByte = totalLen;
            // int nofBits = totalLen*8;

            BitPacker statusPDUPacker;
            // Pack fixed header
            statusPDUPacker.addBits(DC, 1);
            statusPDUPacker.addBits(cpt, 3);
            statusPDUPacker.addBits(ackSN, snLen);
            statusPDUPacker.addBits(E1_0, 1);
            // Pack chunks
            for (int cIdx = 0; cIdx < eIdx + 1; cIdx++){
                statusPDUPacker.addBits(chunk[cIdx].nackSN, snLen);
                statusPDUPacker.addBits(chunk[cIdx].E1, 1);
                statusPDUPacker.addBits(chunk[cIdx].E2, 1);
                if (chunk[cIdx].E2){
                    statusPDUPacker.addBits(chunk[cIdx].soStart, 15);
                    statusPDUPacker.addBits(chunk[cIdx].soEnd, 15);
                }
            }
            std::vector<uint8_t> packer_result = statusPDUPacker.get_final_result();
            if ((int)packer_result.size() < totalLen){
                // std::cout<< "Error: Status PDU pattern size lower than actual len, " << packer_result.size() << "|" << totalLen << "\n";
            }else{
                // copy the final result based on eIdx
                result.nofByte = totalLen;
                for (int i = 0; i < totalLen; i++){
                    result.pattern.push_back(packer_result[i]);
                }

            }
        }
    }else if (snLen == 16){ // both sn and so are 16 bits
        if (eIdx == -1){
            result.nofByte = 1;
            uint8_t temp = 0;
            temp |= (DC << 7);
            temp |= (cpt << 4);
            temp |= (ackSN & 0xF);
            result.pattern.push_back(temp);
        }else if (eIdx == -2){
            result.nofByte = 3;
            uint8_t firstbyte = 0;
            firstbyte |= (DC << 7);
            firstbyte |= (cpt << 4);
            firstbyte |= 0;
            uint8_t secondByte = 0;
            secondByte |= (ackSN >> 8) & 0xFF;
            uint8_t thirdByte = 0;
            thirdByte |= E1_0 << 3;
            thirdByte |= nackSN & 0x07;

            result.pattern.push_back(firstbyte);
            result.pattern.push_back(secondByte);
            result.pattern.push_back(thirdByte);
        }else if (eIdx == -3){
            result.nofByte = 5;
            result.nofByte = 3;
            uint8_t firstbyte = 0;
            firstbyte |= (DC << 7);
            firstbyte |= (cpt << 4);
            firstbyte |= 0;
            uint8_t secondByte = 0;
            secondByte |= (ackSN >> 8) & 0xFF;
            uint8_t thirdByte = 0;
            thirdByte |= E1_0 << 3;
            thirdByte |= nackSN & 0x07;
            uint8_t fourthByte = 0;
            uint8_t fifthByte = 0;
            fifthByte |= chunk[0].E1 << 2;
            fifthByte |= chunk[0].E2 << 1;
            result.pattern.push_back(firstbyte);
            result.pattern.push_back(secondByte);
            result.pattern.push_back(thirdByte);
            result.pattern.push_back(fourthByte);
            result.pattern.push_back(fifthByte);
        }else if (eIdx >= 0){
            result.nofByte = totalLen;
            // int nofBits = totalLen*8;

            BitPacker statusPDUPacker;
            // Pack fixed header
            statusPDUPacker.addBits(DC, 1);
            statusPDUPacker.addBits(cpt, 3);
            statusPDUPacker.addBits(ackSN, snLen);
            statusPDUPacker.addBits(E1_0, 1);
            // Pack chunks
            for (int cIdx = 0; cIdx < eIdx + 1; cIdx++){
                statusPDUPacker.addBits(chunk[cIdx].nackSN, snLen);
                statusPDUPacker.addBits(chunk[cIdx].E1, 1);
                statusPDUPacker.addBits(chunk[cIdx].E2, 1);
                if (chunk[cIdx].E2){
                    statusPDUPacker.addBits(chunk[cIdx].soStart, 16);
                    statusPDUPacker.addBits(chunk[cIdx].soEnd, 16);
                }
            }
            std::vector<uint8_t> packer_result = statusPDUPacker.get_final_result();
            if ((int)packer_result.size() < totalLen){
                // std::cout<< "Error: Status PDU pattern size lower than actual len, " << packer_result.size() << "|" << totalLen << "\n";
            }else{
                // copy the final result based on eIdx
                result.nofByte = totalLen;
                for (int i = 0; i < totalLen; i++){
                    result.pattern.push_back(packer_result[i]);
                }

            }
        }

    }
    return result;
}

// void rlcFuzzer_t::switchState(){
//     fuzzingState = fuzzingMode;
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
//     case state4:
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
//       printf("[MAC] Switch Fuzzer to state %d \n", fuzzingState); 
//     }
// }


rlcPDU_t rlcFuzzer_t::getCurTestCase(){
    if (readFromFileMode){
        curTestCase = verifyDB[fuzzingState][idx[fuzzingState]];
    }else{
        curTestCase = testcaseDB[fuzzingState][idx[fuzzingState]];
    }
    return curTestCase;
}

// int rlcFuzzer_t::get_cur_testcase_idx(LLState_t state, bool isverifying){
//     if (state > 5){
//         ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
//     }
//     return idx[state];
// }

int rlcFuzzer_t::get_total_idx(LLState_t state, bool isverifying){
    if (state > 5){
        // ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
    }
    return (isverifying)?verifyDB[state].size():testcaseDB[state].size();
}

int rlcFuzzer_t::get_injecting_lcid(){
    return 0;
}

int rlcFuzzer_t::get_injecting_length(){
    int len = 0;
    getCurTestCase();
    int lcid = get_injecting_lcid();

    len = (lcid == 0)?(curTestCase.totalByte + 4 + 8 - 2):(curTestCase.totalByte + 4 + 8 - 7);
    len = (len <= 0)?1:len;

    return len;
}

void rlcFuzzer_t::generatePDU(rlcPDU_t& testCase, uint8_t* packet, int rlcIdx){
    rlcHeaderResult_t headerResult = {};
    switch (testCase.type)
    {
    case rlcUM1:
        if (testCase.eIdx == -1){
            headerResult = generateUM1_1Byte(testCase.um.R1, testCase.um.R2, testCase.um.R3, testCase.um.FI, testCase.um.E, testCase.um.SN, testCase.um.snLen);
        }
        else if (testCase.eIdx == 0){
            headerResult = generateUM1header(testCase.um.snLen, testCase.um.R1, testCase.um.R2, testCase.um.R3, testCase.um.FI, testCase.um.E, testCase.um.SN);
        }
        break;
    case rlcUM2:
        if (testCase.eIdx == -1){ // same as -1 in UM1
            headerResult = generateUM1_1Byte(testCase.um.R1, testCase.um.R2, testCase.um.R3, testCase.um.FI, testCase.um.E, testCase.um.SN, testCase.um.snLen);
        }
        else{
            headerResult = generateUM2header(testCase.um.snLen, testCase.eIdx, testCase.um.R1, testCase.um.R2, testCase.um.R3, testCase.um.FI, testCase.um.E, testCase.um.SN, testCase.um.nofChunk, testCase.um.chunk);
        }
        break;
    case rlcAM1:
        if (testCase.eIdx == -1 || testCase.eIdx == -2){
            if (testCase.am.snLen == 10){
                headerResult = generateAM1_1Byte(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
            }else {
                headerResult = generateAM1_1Byte_16sn(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
            }
            if (testCase.eIdx == -2 && testCase.am.snLen == 16){
                headerResult = generateAM1_1Byte_16sn(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
                headerResult.nofByte = 2; // -2 means 2 byte header
                headerResult.pattern.push_back(testCase.am.SN>>8); // append SN to the rest
            }
        }
        else if (testCase.eIdx == 0){ // same for 10 bits and 16 bits
            headerResult = generateAM1header(testCase.am.snLen, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
        }
        break;
    case rlcAM2:
        if (testCase.eIdx == -1){ // same as -1 in AM1
            if (testCase.am.snLen == 10){
                headerResult = generateAM1_1Byte(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
            } else{
                headerResult = generateAM1_1Byte_16sn(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
            }
            // headerResult = generateAM1_1Byte(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
        }
        else{
            headerResult = generateAM2header(testCase.am.snLen, testCase.am.liLen, testCase.eIdx, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN, testCase.am.nofChunk, testCase.am.chunk);
        }
        break;
    case rlcAMSegment1:
        if (testCase.eIdx == 0){
            headerResult = generateAM1SegmentHeader(testCase.am.snLen, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN, testCase.am.LSF, testCase.am.SO);
        }else if (testCase.eIdx == -1){
            if (testCase.am.snLen == 10){
                headerResult = generateAM1_1Byte(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
            }else if (testCase.am.snLen == 16){
                headerResult = generateAM1_1Byte_16bitSN_segment(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.LSF);
            }
            // headerResult = generateAM1_1Byte(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
        }else if (testCase.eIdx == -2){
            headerResult = generateAM1SegmentHeader(testCase.am.snLen, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN, testCase.am.LSF, testCase.am.SO);
            headerResult.nofByte = 2; // -2 means 2 byte header
        }else if (testCase.eIdx == -3){
            headerResult = generateAM1SegmentHeader(testCase.am.snLen, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN, testCase.am.LSF, testCase.am.SO);
            headerResult.nofByte = 3; // -3 means 3 byte header
        }else if (testCase.eIdx == -4){
            headerResult = generateAM1SegmentHeader(testCase.am.snLen, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN, testCase.am.LSF, testCase.am.SO);
            headerResult.nofByte = 4; // -4 means 4 byte header
        }
        break;
    case rlcAMSegment2:
        if (testCase.eIdx == -1){ // same as -1 in AM1
            if (testCase.am.snLen == 10){
                headerResult = generateAM1_1Byte(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
            } else{
                headerResult = generateAM1_1Byte_16bitSN_segment(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.LSF);
            }
            // headerResult = generateAM1_1Byte(testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN);
        }else if (testCase.eIdx == -2){
            headerResult = generateAM2SegmentHeader(testCase.am.snLen, testCase.am.liLen, testCase.eIdx, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN, testCase.am.LSF, testCase.am.SO, testCase.am.nofChunk, testCase.am.chunk);
        }else if (testCase.eIdx == -3){
            headerResult = generateAM2SegmentHeader(testCase.am.snLen, testCase.am.liLen, testCase.eIdx, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN, testCase.am.LSF, testCase.am.SO, testCase.am.nofChunk, testCase.am.chunk);
        }
        else{
            headerResult = generateAM2SegmentHeader(testCase.am.snLen, testCase.am.liLen, testCase.eIdx, testCase.am.DC, testCase.am.RF, testCase.am.P, testCase.am.FI, testCase.am.E, testCase.am.SN, testCase.am.LSF, testCase.am.SO, testCase.am.nofChunk, testCase.am.chunk);
        }
        break;
    case rlcStatus:
        headerResult = generateStatusPDU(testCase.status.snLen, testCase.eIdx, testCase.status.cpt, testCase.status.ackSN, testCase.status.E1_0, testCase.status.nackSN, testCase.status.nofChunk, testCase.status.chunk, testCase.totalByte);
        break;
    
    default:
        break;
    }

    // Copy header to packet
    for (int i = 0; i < headerResult.nofByte; i++){ // check available space in packet previously?
        packet[rlcIdx+i] = headerResult.pattern[i];
    }
}

void printPDUtestcase(rlcPDU_t& pdu, int tti, int actualLen){
    bool isAM = (pdu.type == rlcAM1 || pdu.type == rlcAM2 || pdu.type == rlcAMSegment1 || pdu.type == rlcAMSegment2);
    bool isUM = (pdu.type == rlcUM1 || pdu.type == rlcUM2);
    // bool isStatusPDU = (pdu.type == rlcStatus);

    int nofChunk = (isAM)?pdu.am.nofChunk:((isUM)?pdu.um.nofChunk:pdu.status.nofChunk);
    std::vector<rlcChunk_t> &chunk = (isAM)?(pdu.am.chunk):(pdu.um.chunk);
    // std::vector<rlcStatusChunk_t> &statusChunk = pdu.status.chunk;

    std::string pduTypeStr = "";
    if (pdu.type == rlcUM1){
        pduTypeStr = "UM1";
    }else if (pdu.type == rlcUM2){
        pduTypeStr = "UM2";
    }else if (pdu.type == rlcAM1){
        pduTypeStr = "AM1";
    }else if (pdu.type == rlcAM2){
        pduTypeStr = "AM2";
    }else if (pdu.type == rlcStatus){
        pduTypeStr = "StatusPDU";
    }else if (pdu.type == rlcAMSegment1){
        pduTypeStr = "AMS1";
    }else if (pdu.type == rlcAMSegment2){
        pduTypeStr = "AMS2";
    }
    
    std::cout << "[PDU] Type = " << pduTypeStr << " - LCID: " << pdu.lcid << " - totalByte = " << (int)pdu.totalByte \
    << " - ActualLen = " << actualLen << " - nofChunk: " << nofChunk << " - MT = " << (int)pdu.macType <<  BLUE_TEXT << " - eIdx = " << (int)pdu.eIdx << RESET_COLOR << "\n";
    // if (pdu.type == rlcUM1 || pdu.type == rlcUM2){
    //     std::cout << "[PDU] R1 = " << (int)pdu.um.R1 << " -- R2 = " << (int)pdu.um.R2 << " -- R3 = " << (int)pdu.um.R3 \
    //     << " -- FI = " << (int)pdu.um.FI << " -- E = " << (int)pdu.um.E << " -- SN = " << (int)pdu.um.SN << " -- SN_Len = " << (int)pdu.um.snLen << "\n";
    // }else if (pdu.type == rlcAM1 || pdu.type == rlcAM2){
    //     std::cout << "[PDU] DC = " << (int)pdu.am.DC << " -- RF = " << (int)pdu.am.RF << " -- P = " << (int)pdu.am.P \
    //     << " -- FI = " << (int)pdu.am.FI << " -- E = " << (int)pdu.am.E << " -- SN = " << (int)pdu.am.SN << " -- SN_Len = " << (int)pdu.am.snLen \
    //     << "LI Len = " << (int)pdu.am.liLen << "\n";
    // }else if (pdu.type  == rlcAMSegment1 || pdu.type == rlcAMSegment2){
    //     std::cout << "[PDU] DC = " << (int)pdu.am.DC << " -- RF = " << (int)pdu.am.RF << " -- P = " << (int)pdu.am.P \
    //     << " -- FI = " << (int)pdu.am.FI << " -- E = " << (int)pdu.am.E << " -- SN = " << (int)pdu.am.SN << " -- SN_Len = " << (int)pdu.am.snLen << "\n";
    //     std::cout << "LI_Len = " << (int)pdu.am.liLen << " -- LSF = " << (int)pdu.am.LSF << " -- SO = " << (int)pdu.am.SO << " -- nofChunk = " << nofChunk << "\n";
    // }else{
    //     std::cout << "[PDU] CPT = " << (int)pdu.status.cpt << " -- ACK_SN = " << (int)pdu.status.ackSN << " -- E1_0 = " << (int)pdu.status.E1_0 \
    //     << " -- NACK_SN = " << (int)pdu.status.nackSN << " -- nofChunk = " << nofChunk << "\n";
    // }
    // if (nofChunk > 1 && pdu.type != rlcStatus){ 
    //     for (int h = 0; h < 3; h++){ //nofChunk - 1
    //         std::cout << "[PDU] E_" << h << " = " << (int)chunk[h].E << " -- LI = " << (int)chunk[h].L << "\n";
    //     }
    // }else if (nofChunk > 1 && pdu.type == rlcStatus && pdu.eIdx == 2){
    //     std::cout << "[PDU] E1 = " << (int)pdu.status.chunk[0].E1 << " -- E2 = " << (int)pdu.status.chunk[0].E2 << " -- SOStart = " << (int)pdu.status.chunk[1].soStart \
    //     << " -- SOEnd = " << (int)pdu.status.chunk[1].soEnd << " -- NACK_SN = " << (int)pdu.status.chunk[1].nackSN << "\n";
    // }

    std::cout << "[PDU] --------------" << "\n";
}

void rlcFuzzer_t::send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen){
    // check if we need RRC reconfiguration complete before sending this test case
    if (curTestCase.rrc_reconfig_type != RLC_NORMAL && !receivedRRCReconfigComplete && fuzzingState == state4){
        std::cout << "[RLC] Error: Not received RRC Reconfiguration Complete, probably due to unsupported configuration by UE" << "\n";
        return;
    }

    if (curTestCase.macType == singleMAC ){
        int lcID = 1;
        if (curTestCase.type == rlcAM1|| curTestCase.type == rlcAM2){
            lcID = curTestCase.lcid;
        }else{
            lcID = curTestCase.lcid;
        }
        // update sequence number of RLC PDU
        if (lcID >= 1 && curTestCase.isCorrectSN){ // only update SN if this test case is intended for correct SN
            curTestCase.am.SN = rlcSNmap[lcID];
            curTestCase.um.SN = rlcSNmap[lcID];
        }

        macSubHeaderType_t macSubHeaderType = (curTestCase.totalByte <= 127)?typeA:typeB;
        macHeaderResult_t subHeader1 = formMacSubHeader(false, macSubHeaderType, 0, 0, 1, lcID, curTestCase.totalByte);
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
        if (remainingByte >= curTestCase.totalByte){
            generatePDU(curTestCase, payload, startIdx);
        }else{
            // std::cout << "[RLC] Error(1): actual length is not enough to contain RLC PDU" << "\n";
        }
    }else if (curTestCase.macType == ccchMAC){
        macSubHeaderType_t macSubHeaderType = (curTestCase.totalByte <= 127)?typeA:typeB;
        macHeaderResult_t ccchSubHeader = formMacSubHeader(false, typeA, 0, 0, 1, 0, 10);
        macHeaderResult_t subHeader1 = formMacSubHeader(false, macSubHeaderType, 0, 0, 1, curTestCase.lcid, curTestCase.totalByte);
        macHeaderResult_t subHeader2 = formMacSubHeader(true, typeD, 0, 0, 0, 31, 0); // 31 is padding

        int startIdx = 0;
        for (int i = 0; i < ccchSubHeader.len; i++){
            payload[i] = ccchSubHeader.pattern[i];
        }
        startIdx = startIdx + ccchSubHeader.len;
        for (int i = 0; i < subHeader1.len; i++){
            payload[i+startIdx] = subHeader1.pattern[i];
        }
        startIdx = startIdx + subHeader1.len;
        for (int i = 0; i < subHeader2.len; i++){
            payload[startIdx + i] = subHeader2.pattern[i];
        }
        startIdx = startIdx + subHeader2.len;
        startIdx = startIdx + 10; // offset 10 bytes for ccch sub-payload
        int remainingByte = actualLen - ccchSubHeader.len - subHeader1.len - subHeader2.len - 10; // bytes for MAC header
        if (remainingByte >= curTestCase.totalByte){
            generatePDU(curTestCase, payload, startIdx);
        }else{
            // std::cout << "[RLC] Error(2): actual length is not enough to contain RLC PDU" << "\n";
        }
    }

    std::vector<rlcPDU_t> &curDB = (readFromFileMode)?verifyDB[fuzzingState]:testcaseDB[fuzzingState];
    // print test case
    if (DEBUG_MODE){
        std::cout << "[RLC] SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << " -- Fuzzing State: " << (int)fuzzingState << ", RNTIState =  " \
            << fuzzingState << " -- Idx = " << idx[fuzzingState] << "/" << curDB.size() << " -- nofCrash: " << nofCrash << "\n";
        printPDUtestcase(curTestCase, tti_tx_dl, actualLen);
    }

    // save PDU to crash buffer
    rlcPDUType_t    curType = curTestCase.type;
    rlcPDU_t        savePDU(curType);
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
    //     if (verifyingState == state4 && idx[5] == (int)verifyDB[5].size()){
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

void rlcFuzzer_t::writeTCtoFile(std::ofstream& file, rlcPDU_t& pdu){
    if (file){
        int nofChunk = (pdu.type == rlcUM1 || pdu.type == rlcUM2)?pdu.um.nofChunk:pdu.am.nofChunk;
        nofChunk     = (pdu.type == rlcStatus)?pdu.status.nofChunk:nofChunk;
        std::vector<rlcChunk_t> &chunk = (pdu.type == rlcUM1 || pdu.type == rlcUM2)?pdu.um.chunk:pdu.am.chunk;
        file << "[PDU] Type = " << (int)pdu.type << " - LCID: " << pdu.lcid <<  " - totalByte = " << (int)pdu.totalByte \
        << " -- nofChunk: " << nofChunk << " - MT = " << (int)pdu.macType << " - eIdx = " << (int)pdu.eIdx << RESET_COLOR << "\n";
        if (pdu.type == rlcUM1 || pdu.type == rlcUM2){
            file << "[PDU] R1 = " << (int)pdu.um.R1 << " -- R2 = " << (int)pdu.um.R2 << " -- R3 = " << (int)pdu.um.R3 \
            << " -- FI = " << (int)pdu.um.FI << " -- E = " << (int)pdu.um.E << " -- SN = " << (int)pdu.um.SN << "\n";
        }else{
            file << "[PDU] DC = " << (int)pdu.am.DC << " -- RF = " << (int)pdu.am.RF << " -- P = " << (int)pdu.am.P \
            << " -- FI = " << (int)pdu.am.FI << " -- E = " << (int)pdu.am.E << " -- SN = " << (int)pdu.am.SN << "\n";
        }
        if (nofChunk > 1){ 
            for (int h = 0; h < nofChunk - 1; h++){
                file << "[PDU] E_" << h << " = " << (int)chunk[h].E << " -- LI = " << (int)chunk[h].L << "\n";
            }
        }

        std::cout << "\n";
    }
}

void rlcFuzzer_t::resetIndex(){
    idx[5] = startIdx; // verify crash
    idx[4] = startIdx; // verify crash
    idx[3] = startIdx;
    idx[2] = startIdx;
    
}

void rlcFuzzer_t::update_rlc_sequence_number(uint16_t lcid, uint16_t sn){
    rlcSNmap[lcid] = sn;
}

int rlcFuzzer_t::check_rrc_reconfig_type(){
    curTestCase = getCurTestCase(); // because this funtion is called before check_send_test_case
    return (int)curTestCase.rrc_reconfig_type;
}

}



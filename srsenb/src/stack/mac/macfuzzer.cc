#include "srsenb/hdr/stack/mac/macfuzzer.h"

namespace srsenb {


// void macFuzzer_t::set_fuzzing_config(LLState_t targetState_, bool verifyingMode_, int startIdx_){
//     fuzzingState = targetState_;
//     readFromFileMode = verifyingMode_;
//     startIdx = startIdx_;
// }

// allocate nofSubHea subheaders and payloads for a macPDU
void allocVectorPDU(macPDU_t& pdu, int nofSubHea){
  for (int n = 0; n < nofSubHea; n++){
    macSubHeader_t newSubHea;
    macSubPayload_t newSubPay;
    pdu.subHea.push_back(newSubHea);
    pdu.subPay.push_back(newSubPay);
  }
  pdu.nofSubHea = nofSubHea;
}

void macFuzzer_t::autoFillMacPDU(macPDU_t& pdu, int nofSubHea , int eIdx, std::vector<macSubHeader_t>& subHea, std::vector<macSubPayload_t>& subPay, int totalByte)
{
  pdu.nofSubHea = nofSubHea;
  pdu.eIdx = eIdx;
  if (nofSubHea <= 100){
    for (int h = 0; h< nofSubHea; h++){
      pdu.subHea[h] = subHea[h];
      pdu.subPay[h] = subPay[h];
    }
  }
  pdu.totalByte = totalByte;
}

void macFuzzer_t::autoFillSubHea_1(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                    bool isWrongID , int R, int lcid, int L, int eIdx, int hIdx){
    subHeader.type = type;
    subHeader.isLast = islast;
    if (islast && type != typeD){
        subHeader.type = typeD; 
        printf("[MTT] Error: last sub-header is not type D, changed it to D \n");
    }
    subHeader.isCE = (std::find(lcidCEList.begin(), lcidCEList.end(), lcid) != lcidCEList.end());
    subHeader.E = 0;
    subHeader.lcid = lcid;
    subHeader.R = R;
    subHeader.F = (type == typeB)?1:0;
    subHeader.L = L;
    subHeader.headerSize = heaSizeMap[type];
    subHeader.isWrongID = isWrongID;
    payload.size = L; // 1 subheader does not have L, this is for making payload larger than its size in specification
}

bool macFuzzer_t::check_is_CE(int lcid){
    if (lcid >= 18 && lcid < 31 && lcid != 25){ // we consider 31 as padding lcid that can have L field, 25: SC-MCCH, SC-MTCH is like a normal LCID MCCH
        return true;
    }else{
        return false;
    }
}

void macFuzzer_t::autoFillSubHea(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                    bool isWrongID , int R, int lcid, int L, int eIdx, int hIdx){
    subHeader.type = type;
    subHeader.isLast = islast;
    if (islast && type != typeD){
        subHeader.type = typeD; 
        printf("[MTT] Error: last sub-header is not type D, changed it to D \n");
    }
    subHeader.isCE = (std::find(lcidCEList.begin(), lcidCEList.end(), lcid) != lcidCEList.end());
    if (subHeader.isCE && type != typeD){
        subHeader.type = typeD;
        printf("[MTT] Error: CE sub-header is not type D, changed it to typeD \n");
    }                               
    subHeader.cePayload = check_is_CE(lcid);      // if it is ce, check size from list
    subHeader.hasID = (lcid == 28);                                                                                             // only consider UE Con Res now
    subHeader.headerSize = heaSizeMap[type];
    subHeader.isWrongID = isWrongID;
    subHeader.R = R;
    subHeader.F2 = (type == typeC)?1:0;
    subHeader.E = (islast)?0:1;
    subHeader.lcid = lcid;
    subHeader.F = (type == typeB)?1:0;
    subHeader.L = L;

    if (subHeader.cePayload){
        payload.size = cePaySize[lcid];
    }else if(subHeader.isCE && !subHeader.cePayload){
        payload.size = 0;
    }else{
        payload.size = L;
    }
    bool isChannelID = (std::find(lcidNoCEList.begin(), lcidNoCEList.end(), lcid) != lcidNoCEList.end());
    if (!subHeader.isLast && subHeader.type != typeD && isChannelID){
        subHeader.hasL = true;
    }else{
        subHeader.hasL = false;
    }

    if (!islast && hIdx == eIdx){
        payload.size =  payload.size/2;
    }else if(!islast && hIdx < eIdx){
        payload.size =  payload.size;
    }else if (!islast && hIdx > eIdx){
        payload.size = 0;
    }

}


void macFuzzer_t::autoFillSubHea_boundary(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                    bool isWrongID , int R, int lcid, int L, int eIdx, int hIdx){
    subHeader.type = type;
    subHeader.isLast = islast;
    if (islast && type != typeD){
        subHeader.type = typeD; 
        printf("[MTT] Error: last sub-header is not type D, changed it to D \n");
    }
    subHeader.isCE = (std::find(lcidCEList.begin(), lcidCEList.end(), lcid) != lcidCEList.end());
    if (subHeader.isCE && type != typeD){
        subHeader.type = typeD;
        printf("[MTT] Error: CE sub-header is not type D, changed it to typeD \n");
    }                               
    subHeader.cePayload = check_is_CE(lcid);      // if it is ce, check size from list
    subHeader.hasID = (lcid == 28);                                                                                             // only consider UE Con Res now
    subHeader.headerSize = heaSizeMap[type];
    subHeader.isWrongID = isWrongID;
    subHeader.R = R;
    subHeader.F2 = (type == typeC)?1:0;
    subHeader.E = (islast)?0:1;
    subHeader.lcid = lcid;
    subHeader.F = (type == typeB)?1:0;
    int tempL = 0;
    if (type == typeA){
        tempL = 127;
    }else if (type == typeB){
        tempL = 32767;
    }else if (type == typeC){
        tempL = 65535;
    }

    subHeader.L = tempL; // set L to maximum value

    if (subHeader.cePayload){
        payload.size = cePaySize[lcid];
    }else if(subHeader.isCE && !subHeader.cePayload){
        payload.size = 0;
    }else{
        payload.size = subHeader.L;
    }

    bool isChannelID = (std::find(lcidNoCEList.begin(), lcidNoCEList.end(), lcid) != lcidNoCEList.end());
    if (!subHeader.isLast && subHeader.type != typeD && isChannelID){
        subHeader.hasL = true;
    }else{
        subHeader.hasL = false;
    }

    if (!islast && hIdx == eIdx){
        payload.size = (type == typeB)?128:20;
    }else if(!islast && hIdx < eIdx){
        payload.size =  payload.size;
    }else if (!islast && hIdx > eIdx){
        payload.size = 0;
    }

}


void macFuzzer_t::autoFillSubHea_eLCID_1(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,
                    int elcid, int L, int eIdx, int hIdx){
    subHeader.type = type;
    subHeader.isLast = islast;
    if (islast && type != typeDe){
        subHeader.type = typeDe; 
        printf("[MTT] Error: last sub-header is not type De, changed it to De \n");
    }
    // subHeader.isCE = (std::find(lcidCEList.begin(), lcidCEList.end(), lcid) != lcidCEList.end());
    subHeader.E = 0;
    subHeader.lcid = 16; // fixed value for eLCID
    subHeader.eLCID = elcid;
    // subHeader.R = R;
    subHeader.F = (type == typeB)?1:0; // TypeBe?
    subHeader.L = L;
    subHeader.headerSize = 2;
    // subHeader.isWrongID = isWrongID;
    payload.size = L; // 1 subheader does not have L, this is for making payload larger than its size in specification
}


/* -1: last subheader has E = 0, F2 = 0, 1 byte
*  -2: last subheader has E = 1, F2 = 0, 1 byte 
*  -3: last subheader has E = 0, F2 = 1, 1 byte
*  -4: last subheader has E = 1, F2 = 1, 1 byte
*  -5: last subheader has E = 1, F2 = 0, 2 bytes
*  -6: last subheader has E = 1, F2 = 0, F = 1, 3 bytes
*  -7: last subheader has E = 1, F2 = 1, 2 bytes
*/
void macFuzzer_t::autoFillSubHea_eLCID(macSubHeader_t& subHeader, macSubPayload_t& payload, macSubHeaderType_t type, bool islast,int elcid, int L, int eIdx, int hIdx){
    subHeader.lcid = 16; // fixed value for eLCID
    subHeader.R = 0;
    subHeader.R1e = 0;
    subHeader.R2e = 0;
    subHeader.F2 = (type == typeC)?1:0;
    subHeader.type = type;
    subHeader.isLast = islast;
    if (islast && type != typeDe){
        subHeader.type = typeDe; 
        printf("[MTT] Error: last sub-header is not type De, changed it to De, idx = %d, type = %d \n", hIdx, (int)type);
    }
    subHeader.headerSize = heaSizeMap[type];
    subHeader.F2 = (type == typeCe)?1:0;
    subHeader.E = (islast)?0:1;
    subHeader.eLCID = elcid;
    subHeader.F = (type == typeBe)?1:0;
    subHeader.L = L;
    payload.size = L;

    payload.size = L; // length of test case must consider carefully because L is added here for the last subheader and subpayload
    if (islast && eIdx ==  -1){
        subHeader.E = 0;
        subHeader.F2 = 0;
        subHeader.headerSize = 1; // 1 byte
        payload.size = 0;

    }else if (islast && eIdx == -2){
        subHeader.E = 1;
        subHeader.F2 = 0;
        subHeader.headerSize = 1; // 1 byte
        payload.size = 0;
    }else if (islast && eIdx == -3){
        subHeader.E = 0;
        subHeader.F2 = 1;
        subHeader.headerSize = 1; // 1 byte
        payload.size = 0;
    }else if (islast && eIdx == -4){
        subHeader.E = 1;
        subHeader.F2 = 1;
        subHeader.headerSize = 1; // 1 byte
        payload.size = 0;
    }else if (islast && eIdx == -5){
        subHeader.E = 1;
        subHeader.F2 = 0;
        subHeader.headerSize = 2; // 2 bytes
        payload.size = 0;
    }else if (islast && eIdx == -6){
        subHeader.E = 1;
        subHeader.F2 = 0;
        subHeader.F = 1;
        subHeader.headerSize = 3; // 3 bytes
        payload.size = 0;
    }else if (islast && eIdx == -7){
        subHeader.E = 1;
        subHeader.F2 = 1;
        subHeader.headerSize = 2; // 2 byte
        payload.size = 0;
    }

    if (!islast && hIdx == eIdx){
        payload.size = L/2;
    }else if(!islast && hIdx < eIdx){
        payload.size = L;
    }else if (!islast && hIdx > eIdx){
        payload.size = 0;
    }
   
}


bool macFuzzer_t::checkGenEidx(macPDU_t& pdu, int eIdx){
  bool ret = false;
  if (eIdx <= -1 or eIdx == (pdu.nofSubHea - 1)){ // <= -1 means -1 -2 -3 -4
    ret = true;
  }else if ((eIdx > -1 and eIdx < (pdu.nofSubHea - 1)) && pdu.subHea[eIdx].L > 0){
    if (pdu.subHea[eIdx].cePayload or pdu.subHea[eIdx].hasL){
      ret = true;
    }
  }else{
    ret = false;
  }
  return ret;
}

bool macFuzzer_t::checkGenWrongID(const macPDU_t& pdu, int idIdx){
  bool ret = false;
  if (idIdx < pdu.eIdx){
    ret = true;
  }else{
    ret = false;
  }
  return ret;
}

/* -4: last subheader has E = 1 but no avialble byte behind
*  -3: last subheader has E = 1, F2 = 1 (typeC) but available bytes are not enough for F2 (1 or 2)
*  -2: last subheader has E = 1, F2 = 0, F = 1 (typeB) but available bytes are not enough for typeB (1 or 2)
*  -1: packet does not have payload
*  -5: last subheader has E = 0, F2 = 1, this indicates header is type C, but dont have any available byte behind
*/
int macFuzzer_t::calTotalByte(macPDU_t& pdu){
  int totalByte = 0;
  if (pdu.eIdx == -1 || pdu.eIdx == -4 || pdu.eIdx == -5){ // packet that does not have payload
    for (int h = 0; h< pdu.nofSubHea; h++){
      totalByte = totalByte + (int)pdu.subHea[h].headerSize;
    }
  }else if(pdu.eIdx == -2 || pdu.eIdx == -3){ 
    for (int h = 0; h< pdu.nofSubHea; h++){
      totalByte = totalByte + (int)pdu.subHea[h].headerSize;
    }
    totalByte = totalByte + 1;
  }else if (pdu.eIdx == pdu.nofSubHea - 1){ // normal packet, eIdx = -1, 0, 1, 2 if nofSubHea = 3
    for (int h = 0; h< pdu.nofSubHea; h++){
      totalByte = totalByte + (int)pdu.subHea[h].headerSize;
      totalByte = totalByte + (int)pdu.subPay[h].size;
    }
    // totalByte = totalByte - pdu.subPay[pdu.nofSubHea - 1].size/2; // injected bytes will be in the middle of last payload
  }else{
    for (int h = 0; h< pdu.nofSubHea; h++){ // include enough bytes for header first
      totalByte = totalByte + (int)pdu.subHea[h].headerSize;
    }
    for (int h = 0; h < pdu.eIdx; h++){
      totalByte = totalByte + (int)(pdu.subPay[h].size);
    }
    totalByte = totalByte + (int)(pdu.subPay[pdu.eIdx].size)/2; // injected bytes will be in the middle of eIdx payload
  }
  return totalByte;
}

/* -1: last subheader has E = 0, F2 = 0, 1 byte
*  -2: last subheader has E = 1, F2 = 0, 1 byte 
*  -3: last subheader has E = 0, F2 = 1, 1 byte
*  -4: last subheader has E = 1, F2 = 1, 1 byte
*  -5: last subheader has E = 1, F2 = 0, 2 bytes
*  -6: last subheader has E = 1, F2 = 0, F = 1, 3 bytes
*  -7: last subheader has E = 1, F2 = 1, 2 bytes
*   0->1 idx of header, final subhead does not have L, 2 is normal packet
*/
int macFuzzer_t::calTotalByte_eLCID(macPDU_t& pdu){
  int totalByte = 0;
  for (int h = 0; h < pdu.nofSubHea; h++){
    totalByte = totalByte + (int)pdu.subHea[h].headerSize;
    totalByte = totalByte + (int)pdu.subPay[h].size;
  }
  return totalByte;
}

macFuzzer_t::macFuzzer_t()
{
    // crashLog.open(logFilename);
    // if (!crashLog.is_open()) {
    //     std::cerr << "Failed to open crash log file: " << logFilename << "\n";
    // }
    tcFile.open(tcFilename);    // init test case file
    terminalLog.open(terminalFilename); // init terminal log file
    verifiedCrash.open(verifiedCrashFilename); // init verified crash file
    idx[5] = startIdx; // verify crash
    idx[4] = startIdx; // verify crash
    idx[3] = startIdx;
    idx[2] = startIdx;
    idx[1] = startIdx;
}

macFuzzer_t::~macFuzzer_t()
{
    // crashLog.close();
    tcFile.close();
    terminalLog.close();
    verifiedCrash.close();
}


void macFuzzer_t::resetIndex(){
    idx[5] = startIdx; // verify crash
    idx[4] = startIdx; // verify crash
    idx[3] = startIdx;
    idx[2] = startIdx;
    idx[1] = startIdx;
}

bool check_ce_has_payload(int lcid){
    std::vector<int> cePayloadList = {18, 19, 20, 21, 22, 24, 27, 28, 29};
    if (std::find(cePayloadList.begin(), cePayloadList.end(), lcid) != cePayloadList.end()){
        return true;
    }else{
        return false;
    }
}

// mutate general MAC CEs with 1-6 bytes of payloads
void macFuzzer_t::mutateGeneralMacCE(macPDU_t& sket, int ceSize, int ceIdx, std::vector<macPDU_t>& db){
    ceSize = ceSize * 8;
    std::vector<uint64_t> mutatingList = {0};
    int step = (ceSize <= 2)? 2: 4;
    uint64_t temp_value = 0;
    for (int i = 0; i < ceSize + 1; i = i + step){
        // if this is the final loop, modify i to ceSize to make sure boundary is covered
        if (i + step >= ceSize + 1){
            i = ceSize;
        }
        temp_value = std::pow(2, i) - 1;
        mutatingList.push_back(temp_value);
    }
    
    // check if this lcid is ce and has payload
    int LCID = sket.subHea[ceIdx].lcid; // get LCID from skeleton
    if (check_ce_has_payload(LCID)){
        for (auto& value : mutatingList){
            macPDU_t newPDU = sket;
            newPDU.subPay[ceIdx].general_ce.payload = value;
            newPDU.subPay[ceIdx].mutatingCE = true; 
            newPDU.subPay[ceIdx].lcidCE = newPDU.subHea[ceIdx].lcid;
            db.push_back(std::move(newPDU));
        }
    }

}

void macFuzzer_t::mutateRecommendedBitRate(macPDU_t& sket, int ceIdx, std::vector<macPDU_t>& db){
    //check if lcid is recommended bit rate
    int LCIDce = sket.subHea[ceIdx].lcid;
    if (LCIDce == 22 && sket.subPay[ceIdx].size == 2){

        for (int lcid = 0; lcid < 16; lcid = lcid + 2 ){ // 4 bits lcid
            for (int uldl = 0; uldl < 2; uldl++){ // 1 bit uldl
                for (int bitRate = 0; bitRate < 64; bitRate = bitRate + 5){ // 6 bit padding, 2 values step
                    //dont mutate R value now, asumme that MAC will discard all R values
                    macPDU_t newPDU = sket;
                    int firstThreeBits = (bitRate & 0b111000) >> 3;
                    int lastThreeBits = bitRate & 0b000111;
                    newPDU.subPay[ceIdx].payload[0] = (lcid << 4) + (uldl << 3) + firstThreeBits;
                    newPDU.subPay[ceIdx].payload[1] = lastThreeBits << 5; // skip R values
                    newPDU.subPay[ceIdx].bitrate_ce.bitrate = bitRate;
                    newPDU.subPay[ceIdx].bitrate_ce.ul_dl = uldl;
                    newPDU.subPay[ceIdx].bitrate_ce.lcid_bitrate = lcid;
                    newPDU.subPay[ceIdx].mutatingCE = true; 
                    newPDU.subPay[ceIdx].lcidCE = newPDU.subHea[ceIdx].lcid;
                    db.push_back(std::move(newPDU));
                }
            }

        }
    }
}

void macFuzzer_t::mutateContentionReslCE(macPDU_t& sket, int ceIdx, std::vector<macPDU_t>& db){
    // int const ceSize = 6*8;

    // std::vector<uint64_t> mutatingList = {0};
    // int step = 6;
    // uint64_t temp_value = 0;
    // for (int i = 0; i < ceSize + 1; i = i + step){
    //     temp_value = std::pow(2, i) - 1;
    //     mutatingList.push_back(temp_value);
    // }
    
    // // check if this lcid is ce and has payload
    // int LCID = sket.subHea[ceIdx].lcid; // get LCID from skeleton
    // if (check_ce_has_payload(LCID)){
    //     for (auto& value : mutatingList){
    //         macPDU_t newPDU = sket;
    //         newPDU.subPay[ceIdx].contention_ce.payload = value;
    //         newPDU.subPay[ceIdx].mutatingCE = true; 
    //         newPDU.subPay[ceIdx].lcidCE = newPDU.subHea[ceIdx].lcid;
    //         db.push_back(std::move(newPDU));
    //     }
    // }

    int ceSize = 6 * 8; // 6 bytes for Contention Resolution CE
    std::vector<uint64_t> mutatingList = {0};
    int step = (ceSize <= 2)? 2: 4;
    uint64_t temp_value = 0;
    for (int i = 0; i < ceSize + 1; i = i + step){
        // if this is the final loop, modify i to ceSize to make sure boundary is covered
        if (i + step >= ceSize + 1){
            i = ceSize;
        }
        temp_value = std::pow(2, i) - 1;
        mutatingList.push_back(temp_value);
    }
    
    // check if this lcid is ce and has payload
    int LCID = sket.subHea[ceIdx].lcid; // get LCID from skeleton
    if (check_ce_has_payload(LCID)){
        for (auto& value : mutatingList){
            macPDU_t newPDU = sket;
            newPDU.subPay[ceIdx].contention_ce.payload = value;
            newPDU.subPay[ceIdx].mutatingCE = true; 
            newPDU.subPay[ceIdx].lcidCE = newPDU.subHea[ceIdx].lcid;
            db.push_back(std::move(newPDU));
        }
    }
}

void macFuzzer_t::mutateTimingAdvanceCE(macPDU_t& sket, int ceIdx, std::vector<macPDU_t>& db){
    // int const ceSize = 6;
    // std::vector<uint8_t> mutatingList = {0};
    // int step = 1;
    // uint8_t temp_value = 0;
    // for (int i = 0; i < ceSize + 1; i = i + step){
    //     temp_value = std::pow(2, i) - 1;
    //     mutatingList.push_back(temp_value);
    // }
    // int LCID = sket.subHea[ceIdx].lcid; // get LCID from skeleton
    // if (check_ce_has_payload(LCID)){
    //     for (auto& value : mutatingList){
    //         macPDU_t newPDU = sket;
    //         newPDU.subPay[ceIdx].timing_ce.ta = value;
    //         newPDU.subPay[ceIdx].mutatingCE = true; 
    //         newPDU.subPay[ceIdx].lcidCE = newPDU.subHea[ceIdx].lcid;
    //         db.push_back(std::move(newPDU));
    //     }
    // }
    int ceSize = 1 * 8; // 6 bytes for Contention Resolution CE
    std::vector<uint64_t> mutatingList = {0};
    int step = (ceSize <= 2)? 2: 4;
    uint64_t temp_value = 0;
    for (int i = 0; i < ceSize + 1; i = i + step){
        // if this is the final loop, modify i to ceSize to make sure boundary is covered
        if (i + step >= ceSize + 1){
            i = ceSize;
        }
        temp_value = std::pow(2, i) - 1;
        mutatingList.push_back(temp_value);
    }
    
    // check if this lcid is ce and has payload
    int LCID = sket.subHea[ceIdx].lcid; // get LCID from skeleton
    if (check_ce_has_payload(LCID)){
        for (auto& value : mutatingList){
            macPDU_t newPDU = sket;
            // newPDU.subPay[ceIdx].timing_ce.ta = value;
            // // extract first bit and assign to R1
            newPDU.subPay[ceIdx].timing_ce.R1 = (value & 0b10000000) >> 7;
            // extract 2nd bit and assign to R2
            newPDU.subPay[ceIdx].timing_ce.R2 = (value & 0b01000000) >> 6;
            // extract last 6 bits and assign to ta
            newPDU.subPay[ceIdx].timing_ce.ta = value & 0b00111111;
            newPDU.subPay[ceIdx].mutatingCE = true; 
            newPDU.subPay[ceIdx].lcidCE = newPDU.subHea[ceIdx].lcid;
            db.push_back(std::move(newPDU));
        }
    }
}

// Recursive function to generate combinations
void macFuzzer_t::recursiveMutateSubHeaFormatLCID(int currentSubHeader, 
                                                 int nofSubHea, 
                                                 macPDU_t& tempPDU,
                                                 std::vector<macPDU_t>& tempDB) {
    if (currentSubHeader == nofSubHea) {
        // Base case: all sub-headers filled, create a macPDU and add to the result
        macPDU_t currentPDU = tempPDU;
        autoFillMacPDU(currentPDU, nofSubHea, 0, currentPDU.subHea, currentPDU.subPay, 0);
        tempDB.push_back(std::move(currentPDU));
    } else {
        int randomIdx = rand() % 2; // Generates 0 or 1 with equal probability
        bool isLast = (currentSubHeader == (nofSubHea - 1));

        const std::vector<macSubHeaderType_t>& typeList = (isLast)?typeListLast:typeListArr[randomIdx];
        // Recursive case: fill the current sub-header and move to the next one
        for (const auto& heaType : typeList) {
            const std::vector<int>& lcidList = (isLast)?lcidAllList234Arr[randomIdx]:((heaType == typeD)?lcidCEListArr[randomIdx]:lcidNoCEListState234Arr[randomIdx]);
            for (const auto& lcid : lcidList) {
                // Fill the current sub-header
                autoFillSubHea(tempPDU.subHea[currentSubHeader], tempPDU.subPay[currentSubHeader], heaType, isLast, false, 0, lcid, 0, 0, 0);

                // Recursively move to the next sub-header
                recursiveMutateSubHeaFormatLCID(currentSubHeader + 1, nofSubHea, tempPDU, tempDB);
            }
        }
    }
}

void macFuzzer_t::recursiveMutateSubHeaFormatLCID_boundary(int currentSubHeader, 
                                                 int nofSubHea, 
                                                 macPDU_t& tempPDU,
                                                 std::vector<macPDU_t>& tempDB) {
    if (currentSubHeader == nofSubHea) {
        // Base case: all sub-headers filled, create a macPDU and add to the result
        macPDU_t currentPDU = tempPDU;
        autoFillMacPDU(currentPDU, nofSubHea, 0, currentPDU.subHea, currentPDU.subPay, 0);
        tempDB.push_back(std::move(currentPDU));
    } else {
        int randomIdx = rand() % 2; // Generates 0 or 1 with equal probability
        bool isLast = (currentSubHeader == (nofSubHea - 1));

        const std::vector<macSubHeaderType_t>& typeList = (isLast)?typeListLast:typeListArr_boundary[randomIdx];
        // Recursive case: fill the current sub-header and move to the next one
        for (const auto& heaType : typeList) {
            const std::vector<int>& lcidList = (isLast)?lcidAllList234Arr[randomIdx]:((heaType == typeD)?lcidCEListArr[randomIdx]:lcidNoCEListState234Arr[randomIdx]);
            for (const auto& lcid : lcidList) {
                // Fill the current sub-header
                autoFillSubHea(tempPDU.subHea[currentSubHeader], tempPDU.subPay[currentSubHeader], heaType, isLast, false, 0, lcid, 0, 0, 0);

                // Recursively move to the next sub-header
                recursiveMutateSubHeaFormatLCID(currentSubHeader + 1, nofSubHea, tempPDU, tempDB);
            }
        }
    }
}

void macFuzzer_t::recursiveMutate_eLCID(int currentSubHeader, 
                                        int nofSubHea, 
                                        macPDU_t& tempPDU,
                                        std::vector<macSubHeaderType_t> heaTypes,
                                        std::vector<macPDU_t>& tempDB) {
    if (currentSubHeader == nofSubHea) {
        // Base case: all sub-headers filled, create a macPDU and add to the result
        macPDU_t currentPDU = tempPDU;
        // autoFillMacPDU(currentPDU, nofSubHea, 0, currentPDU.subHea, currentPDU.subPay, 0);
        tempDB.push_back(std::move(currentPDU));
    } else {

        // choose suitable lcid list based on the current sub-header type
        bool iseLCID = false;
        if (heaTypes[currentSubHeader] == typeAe || heaTypes[currentSubHeader] == typeBe || heaTypes[currentSubHeader] == typeCe || heaTypes[currentSubHeader] == typeDe){
            iseLCID = true;
        }
        bool islast = (currentSubHeader == (nofSubHea - 1));
        bool isTypeD = (heaTypes[currentSubHeader] == typeD);
        std::vector<int> &currentlcidList = (iseLCID)?eLCIDlist:((islast)?lcidAllList:((isTypeD)?lcidCEList:lcidNoCEList));

        for (const auto& elcid : currentlcidList) {
            if (iseLCID){
                tempPDU.subHea[currentSubHeader].eLCID = elcid;
                tempPDU.subHea[currentSubHeader].lcid = 16; // 16 is value for eLCID
            }else{
                tempPDU.subHea[currentSubHeader].lcid = elcid; // this is normal lcid 
            }

            // Recursively move to the next sub-header
            recursiveMutate_eLCID(currentSubHeader + 1, nofSubHea, tempPDU, heaTypes, tempDB);
        }
    }
}

void macFuzzer_t::mutate_1(std::vector<macPDU_t>& db){
    std::vector<int> sizeList = {10, 50, 100, 1000 }; //10000
    for (int lcid = 0; lcid < 32; lcid++){
        for (auto& size: sizeList){
            macPDU_t tempPDU;
            allocVectorPDU(tempPDU, 1);
            tempPDU.nofSubHea = 1;
            tempPDU.eIdx = 0;
            autoFillSubHea_1(tempPDU.subHea[0], tempPDU.subPay[0], typeD, true, false, 0, lcid, size, 0, 0);
            tempPDU.totalByte = 1 + size;  // type D header + payload
            db.push_back(std::move(tempPDU));
        }
    }

    for (int elcid = 0; elcid < 64; elcid = elcid + 2){
        for (auto& size: sizeList){
            macPDU_t tempPDU;
            allocVectorPDU(tempPDU, 1);
            tempPDU.nofSubHea = 1;
            tempPDU.eIdx = 0;
            tempPDU.iseLCID = true; //
            autoFillSubHea_eLCID_1(tempPDU.subHea[0], tempPDU.subPay[0], typeDe, true, elcid, size, 0, 0);
            tempPDU.totalByte = 2 + size;  // type D header + payload
            db.push_back(std::move(tempPDU));
        }
    }
}

/* 0: 1 sub-header with CE, but 0.5 payload
*/
void macFuzzer_t::mutate_1_new_typeD(std::vector<macPDU_t>& db){ // only CE
    for (auto& lcidCE: lcidCEList){
        for(auto& F2: f2List){
            macPDU_t tempPDU;
            tempPDU.nofSubHea = 1;
            tempPDU.eIdx = 0;
            allocVectorPDU(tempPDU, tempPDU.nofSubHea);
            tempPDU.subHea[0].type = typeD;
            tempPDU.subHea[0].isLast = true;
            tempPDU.subHea[0].isCE = true;
            tempPDU.subHea[0].E = 0;
            tempPDU.subHea[0].lcid = lcidCE;
            tempPDU.subHea[0].R = 0;
            tempPDU.subHea[0].F2 = F2;
            tempPDU.subPay[0].size = (cePaySize[lcidCE]/2 < 1)? 0: cePaySize[lcidCE]/2;
            tempPDU.totalByte = heaSizeMap[typeD] + tempPDU.subPay[0].size;
            tempPDU.isManualDCI = true;
            db.push_back(std::move(tempPDU));
        }
    }

}

/* 
*  -3: last subheader has E = 1, F2 = 1 (typeC) but available bytes are not enough for F2 (2)
*  -2: last subheader has E = 1, F2 = 0, F = 1 (typeB), but available bytes are not enough for typeB (2 bytes)
*  -5: last subheader has E = 0, F2 = 1, 2 bytes, this indicates header is type C, but dont have any available byte behind v
*/
void macFuzzer_t::mutate_1_new_typeABC(std::vector<macPDU_t>& db){
    // eIdx = -3
    for (auto& lcid: lcidNoCEList){
        macPDU_t tempPDU;
        tempPDU.nofSubHea = 1;
        tempPDU.eIdx = -3;
        allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        tempPDU.subHea[0].type = typeD;
        tempPDU.subHea[0].isLast = true;
        tempPDU.subHea[0].isCE = true;
        tempPDU.subHea[0].E = 1;
        tempPDU.subHea[0].lcid = lcid;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 1;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 2;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }
    // eIdx = -2
    for (auto& lcid: lcidNoCEList){
        macPDU_t tempPDU;
        tempPDU.nofSubHea = 1;
        tempPDU.eIdx = -3;
        allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        tempPDU.subHea[0].type = typeD;
        tempPDU.subHea[0].isLast = true;
        tempPDU.subHea[0].isCE = true;
        tempPDU.subHea[0].E = 1;
        tempPDU.subHea[0].lcid = lcid;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 0;
        tempPDU.subHea[0].F = 1;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 2;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }
    // eIdx = -5
    for (auto& lcid: lcidNoCEList){
        macPDU_t tempPDU;
        tempPDU.nofSubHea = 1;
        tempPDU.eIdx = -5;
        allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        tempPDU.subHea[0].type = typeD;
        tempPDU.subHea[0].isLast = true;
        tempPDU.subHea[0].isCE = true;
        tempPDU.subHea[0].E = 0;
        tempPDU.subHea[0].lcid = lcid;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 1;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 2;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }

}

void macFuzzer_t::mutate_1_new(std::vector<macPDU_t>& db, macSubHeaderType_t headerType){
    switch (headerType)
    {
    case typeD: // only generate CE
        mutate_1_new_typeD(db);
        break;
    case typeA: // CE and full LCID but no payload
        // mutate_1_new_typeA(db);
        // break;
    case typeB:
    case typeC:
        mutate_1_new_typeABC(db);
        break;
    default:
        break;
    }
}

// void fill_initial_eLCID_subheader(macSubHeader_t& subHeader, macSubHeaderType_t subheaFormat,  bool isLast){
    
//     subHeader.lcid = 16; // fixed value for eLCID
//     subHeader.L = 20; // default value, will be changed later

//     // fill F2, F based on subheader format
//     switch (subheaFormat)
//     {
//     case typeAe:
//         subHeader.F2 = 0;
//         subHeader.F = 0;
//         subHeader.headerSize = 3;
//         break;
//     case typeBe:
//         subHeader.F2 = 0;
//         subHeader.F = 1;
//         subHeader.headerSize = 4; // 4 bytes
//         break;
//     case typeCe:
//         subHeader.F2 = 1;
//         subHeader.F = 0;
//         subHeader.headerSize = 4; // 4 bytes
//         break;
//     case typeDe: // E = 0
//         subHeader.F2 = 0;
//         subHeader.F = 0;
//         subHeader.headerSize = 2; // 2 bytes
//         break;
//     default:
//         subHeader.F2 = 0; // default value
//         subHeader.F = 0; // default value
//         subHeader.headerSize = 2; // default value
//         break;
//     }

// }

void macFuzzer_t::generate_initial_eLCID_packet(macPDU_t& initial_pdu, int nofSubHea, std::vector<macSubHeaderType_t> headerTypes, bool very_short){
    initial_pdu.nofSubHea = nofSubHea;
    initial_pdu.iseLCID = true; // this is eLCID packet
    allocVectorPDU(initial_pdu, nofSubHea);
    // Fill the sub-headers 
    for (int i = 0; i < nofSubHea; i++) {
        if (i == (nofSubHea - 1)) {
            initial_pdu.subHea[i].isLast = true; // last sub-header
        } else {
            initial_pdu.subHea[i].isLast = false;
            initial_pdu.subHea[i].E = 1; // not last sub-header, E = 1
        }
        initial_pdu.subHea[i].type = headerTypes[i]; // set the type of sub-header
        initial_pdu.subHea[i].lcid = 16; // fixed value for eLCID
        // fill_initial_eLCID_subheader(initial_pdu.subHea[i], headerTypes[i], initial_pdu.subHea[i].isLast);
        assign_legitimate_subheade_and_subpayload(i, initial_pdu.subHea[i].isLast, headerTypes[i], initial_pdu.subHea[i], initial_pdu.subPay[i]);
        // if very_short, set payload size to 0
        if (very_short) {
            initial_pdu.subPay[i].size = 0; // set payload size to 0
        } 
    }
}

/* -8: 2 bytes, E = 0, F2 = 0
*  -9: 2 bytes, E = 1, F2 = 0 
*  -10: 2 bytes, E = 0, F2 = 1
*  -11: 2 bytes, E = 1, F2 = 1
*  -12: 3 bytes, E = 1, F2 = 0, F = 0
*  -13: 3 butes, E = 1, F2 = 1, F = 0
*  -14: 3 bytes, E = 1, F2 = 0, F = 1
*/
void macFuzzer_t::mutate_1_eLCID_new(std::vector<macPDU_t>& db, macSubHeaderType_t headerType){
    // eIdx = -8
    for (auto& elcid: eLCIDlist){
        macPDU_t tempPDU;
        // tempPDU.nofSubHea = 1;
        // tempPDU.iseLCID = true;
        // allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        // tempPDU.subHea[0].type = typeDe;
        // tempPDU.subHea[0].isLast = true;
        generate_initial_eLCID_packet(tempPDU, 1, {typeDe}, true);
        
        tempPDU.eIdx = -8;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 1;
        tempPDU.subHea[0].E = 0;
        tempPDU.subHea[0].lcid = 16;
        tempPDU.subHea[0].R1e = 0;
        tempPDU.subHea[0].R2e = 0;
        tempPDU.subHea[0].eLCID = elcid;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 2;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }
    // eIdx = -9
    for (auto& elcid: eLCIDlist){
        macPDU_t tempPDU;
        // tempPDU.nofSubHea = 1;
        // tempPDU.iseLCID = true;
        // allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        // tempPDU.subHea[0].type = typeDe;
        // tempPDU.subHea[0].isLast = true;
        generate_initial_eLCID_packet(tempPDU, 1, {typeDe}, true);
        tempPDU.eIdx = -9;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 0;
        tempPDU.subHea[0].E = 1;
        tempPDU.subHea[0].lcid = 16;
        tempPDU.subHea[0].R1e = 0;
        tempPDU.subHea[0].R2e = 0;
        tempPDU.subHea[0].eLCID = elcid;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 2;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }
    // eIdx = -10
    for (auto& elcid: eLCIDlist){
        macPDU_t tempPDU;
        // tempPDU.nofSubHea = 1;
        // tempPDU.iseLCID = true;
        // allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        // tempPDU.subHea[0].type = typeDe;
        // tempPDU.subHea[0].isLast = true;
        generate_initial_eLCID_packet(tempPDU, 1, {typeDe}, true);

        tempPDU.eIdx = -10;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 1;
        tempPDU.subHea[0].E = 0;
        tempPDU.subHea[0].lcid = 16;
        tempPDU.subHea[0].R1e = 0;
        tempPDU.subHea[0].R2e = 0;
        tempPDU.subHea[0].eLCID = elcid;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 2;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }
    // eIdx = -11
    for (auto& elcid: eLCIDlist){
        macPDU_t tempPDU;
        // tempPDU.nofSubHea = 1;
        // tempPDU.iseLCID = true;
        // allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        // tempPDU.subHea[0].type = typeDe;
        // tempPDU.subHea[0].isLast = true;
        generate_initial_eLCID_packet(tempPDU, 1, {typeDe}, true);
        tempPDU.eIdx = -11;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 1;
        tempPDU.subHea[0].E = 1;
        tempPDU.subHea[0].lcid = 16;
        tempPDU.subHea[0].R1e = 0;
        tempPDU.subHea[0].R2e = 0;
        tempPDU.subHea[0].eLCID = elcid;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 2;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }
    // eIdx = -12
    for (auto& elcid: eLCIDlist){
        macPDU_t tempPDU;
        // tempPDU.nofSubHea = 1;
        // tempPDU.iseLCID = true;
        // allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        // tempPDU.subHea[0].type = typeDe;
        // tempPDU.subHea[0].isLast = true;
        generate_initial_eLCID_packet(tempPDU, 1, {typeDe}, true);

        tempPDU.eIdx = -12;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 0;
        tempPDU.subHea[0].F = 0;
        tempPDU.subHea[0].E = 1;
        tempPDU.subHea[0].lcid = 16;
        tempPDU.subHea[0].R1e = 0;
        tempPDU.subHea[0].R2e = 0;
        tempPDU.subHea[0].eLCID = elcid;
        tempPDU.subHea[0].L = 0;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 3;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }
    // eIdx = -13
    for (auto& elcid: eLCIDlist){
        macPDU_t tempPDU;
        // tempPDU.nofSubHea = 1;
        // tempPDU.iseLCID = true;
        // allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        // tempPDU.subHea[0].type = typeDe;
        // tempPDU.subHea[0].isLast = true;
        generate_initial_eLCID_packet(tempPDU, 1 , {typeDe}, true);

        tempPDU.eIdx = -13;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 1;
        tempPDU.subHea[0].F = 0;
        tempPDU.subHea[0].E = 1;
        tempPDU.subHea[0].lcid = 16;
        tempPDU.subHea[0].R1e = 0;
        tempPDU.subHea[0].R2e = 0;
        tempPDU.subHea[0].eLCID = elcid;
        tempPDU.subHea[0].L = 0;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 3;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }
    // eIdx = -14
    for (auto& elcid: eLCIDlist){
        macPDU_t tempPDU;
        // tempPDU.nofSubHea = 1;
        // tempPDU.iseLCID = true;
        // allocVectorPDU(tempPDU, tempPDU.nofSubHea);
        // tempPDU.subHea[0].type = typeDe;
        // tempPDU.subHea[0].isLast = true;
        generate_initial_eLCID_packet(tempPDU, 1, {typeDe}, true);
        tempPDU.eIdx = -14;
        tempPDU.subHea[0].R = 0;
        tempPDU.subHea[0].F2 = 0;
        tempPDU.subHea[0].F = 1;
        tempPDU.subHea[0].E = 1;
        tempPDU.subHea[0].lcid = 16;
        tempPDU.subHea[0].R1e = 0;
        tempPDU.subHea[0].R2e = 0;
        tempPDU.subHea[0].eLCID = elcid;
        tempPDU.subHea[0].L = 0;
        tempPDU.subPay[0].size = 0;
        tempPDU.totalByte = 3;
        tempPDU.isManualDCI = true;
        db.push_back(std::move(tempPDU));
    }

}

void macFuzzer_t::mutate_last_subhea(int nofSubHea, std::vector<macPDU_t>& db){
    // now just implement 2 subheaders
    std::vector<int> sizeList = {50, 100, 1000 }; //10000
    for (int lcid = 0; lcid < 32; lcid++){
        for (auto& size: sizeList){
            macPDU_t tempPDU;
            tempPDU.nofSubHea = 2;
            tempPDU.isMutateLastSubHea = true;
            allocVectorPDU(tempPDU, tempPDU.nofSubHea);
            autoFillSubHea(tempPDU.subHea[0], tempPDU.subPay[0], typeA, false, false, 0, 0, 20, 1, 0); // normal CCCH sub-header with 20 bytes
            tempPDU.eIdx = 0;
            autoFillSubHea_1(tempPDU.subHea[1], tempPDU.subPay[1], typeD, true, false, 0, lcid, size, 0, 0);
            tempPDU.totalByte = 2 + 20 + 1 + size;  // 2 bytes for type A header + 20 bytes for type A payload + type D header + payload
            db.push_back(std::move(tempPDU));
        }
    }

    // for (int elcid = 0; elcid < 64; elcid = elcid + 4){
    //     for (auto& size: sizeList){
    //         macPDU_t tempPDU;
    //         allocVectorPDU(tempPDU, 1);
    //         tempPDU.nofSubHea = 1;
    //         tempPDU.eIdx = 0;
    //         tempPDU.iseLCID = true; //
    //         autoFillSubHea_eLCID_1(tempPDU.subHea[0], tempPDU.subPay[0], typeDe, true, elcid, size, 0, 0);
    //         tempPDU.totalByte = 2 + size;  // type D header + payload
    //         db.push_back(std::move(tempPDU));
    //     }
    // }
}

//TODO:
void macFuzzer_t::mutateN(int nofSubHea){
    macPDU_t tempPDU;
    allocVectorPDU(tempPDU, nofSubHea);
    recursiveMutateSubHeaFormatLCID(0, nofSubHea, tempPDU, lv1PDUtemp);

    /*Only keep packet with nof SubHeader Formats <= 2*/
    std::vector<srsenb::macPDU_t>::iterator it;
    bool nofTypeA = 0;
    bool nofTypeB = 0;
    bool nofTypeC = 0;
    bool nofTypeD = 0;
    bool del = false;
    int  totalType = 0;
    for (it = lv1PDUtemp.begin(); it != lv1PDUtemp.end(); ++it){
        nofTypeA = 0;
        nofTypeB = 0;
        nofTypeC = 0;
        nofTypeD = 0;
        del = false;
        totalType = 0;
        for (int j = 0; j < it->nofSubHea; j++){
            if (it->subHea[j].type == typeA){
                nofTypeA = true;
            }else if (it->subHea[j].type == typeB){
                nofTypeB = true;
            }else if (it->subHea[j].type == typeC){
                nofTypeC = true;
            }else if (it->subHea[j].type == typeD){
                nofTypeD = true;
            }
        }
        totalType = nofTypeA + nofTypeB + nofTypeC + nofTypeD;
        if (totalType < 2){
            del = false;
        }else if (totalType == 2 && nofTypeD){
            del = false;
        }else{
            del = true;
        }
        if (del){
            lv1PDUtemp.erase(it);
            it--;
        }
    }
    
    std::cout << "[MTT] Generated " << lv1PDUtemp.size() << " test cases lv1 " << "\n";

    for (const auto& lv1PDU: lv1PDUtemp){ // R mutation
        macPDU_t lv2PDU = lv1PDU; // all normal R =0
        lv2PDUtemp.push_back(std::move(lv2PDU));
    }
    std::cout << "[MTT] Generated " << lv2PDUtemp.size() << " test cases lv2 " << "\n";
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();

    for (const auto& lv2PDU: lv2PDUtemp){ // L mutation T_note: check mutation here
        for (int LIdx = 0; LIdx < lv2PDU.nofSubHea - 1; LIdx++ ){ // final header does not have L
            if (lv2PDU.subHea[LIdx].hasL && lv2PDU.subHea[LIdx].type != typeD && (LIdx != (lv2PDU.nofSubHea - 1))){
                std::vector<int>& LList = LListRef[lv2PDU.subHea[LIdx].type];
                for (const auto &L: LList){
                    macPDU_t lv3PDU = lv2PDU;
                    lv3PDU.subHea[LIdx].L = L;
                    lv3PDU.subPay[LIdx].size = L;
                    lv3PDUtemp.push_back(std::move(lv3PDU));
                }
            }
        }
        // macPDU_t lv3PDU = lv2PDU; // all normal L = 20Z
        // lv3PDUtemp.push_back(std::move(lv3PDU));
    }
    std::cout << "[MTT] Generated " << lv3PDUtemp.size() << " test cases lv3 " << "\n";
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();

    /*  -4: last subheader has E = 1 but no avialble byte behind
    *   -3: last subheader has E = 1, F2 = 1 (typeC) but available bytes are not enough for F2 (1 or 2)
    *   -2: last subheader has E = 1, F2 = 0, F = 1 (typeB) but available bytes are not enough for typeB (1 or 2)
    *   -1: packet does not have payload
    *   -5: last subheader has E = 0, F2 = 1, this indicates header is type C, but dont have any available byte behind
    */
    for (auto& lv3PDU: lv3PDUtemp){ //packet total size mutation
        for (int eIdx = -4; eIdx < lv3PDU.nofSubHea; eIdx++){ // -1: no payload, 0->1 idx of header, final subhead does not have L, 2 is normal packet
            if (checkGenEidx(lv3PDU, eIdx)){ // if this index can be expected crash
                macPDU_t lv4PDU = lv3PDU;
                lv4PDU.eIdx = eIdx;
                for (int i = 0; i < lv3PDU.nofSubHea; i++){
                    autoFillSubHea(lv4PDU.subHea[i], lv4PDU.subPay[i], lv4PDU.subHea[i].type, lv4PDU.subHea[i].isLast, lv4PDU.subHea[i].isWrongID, 0, lv4PDU.subHea[i].lcid, lv4PDU.subHea[i].L, eIdx, i);
                }
                lv4PDU.totalByte = calTotalByte(lv4PDU); 
                lv4PDUtemp.push_back(std::move(lv4PDU));
            }
        }
    }
    std::cout << "[MTT] Generated " << lv4PDUtemp.size() << " test cases lv4 " << "\n";
    lv3PDUtemp.clear();
    lv3PDUtemp.shrink_to_fit();

    for (const auto& lv4PDU: lv4PDUtemp){ // ID correct/incorrect mutation
        // for (int idIdx = 0; idIdx < 3; idIdx++){
        //     if (lv4PDU.subHea[idIdx].hasID && checkGenWrongID(lv4PDU, idIdx)){
        //         macPDU_t lv5PDU = lv4PDU;
        //         lv5PDU.subHea[idIdx].isWrongID = true;
        //         tcState234DB.push_back(std::move(lv5PDU));
        //     }
        // }
        macPDU_t lv5PDU = lv4PDU; // all correct ID
        tcState234DB.push_back(std::move(lv5PDU));
    }

    std::cout << "[MTT] Generated " << tcState234DB.size() << " test cases with nofSubHeaders =  " << nofSubHea << "\n";
    lv4PDUtemp.clear();
    lv4PDUtemp.shrink_to_fit();
}

// Recursive function to generate combinations of LCID given sub-header formats
void macFuzzer_t::recursiveMutateLCID_given_subhea_format(int currentSubHeader, 
                                                        int nofSubHea,
                                                        std::vector<macSubHeaderType_t>& heaTypes,
                                                        macPDU_t& tempPDU,
                                                        std::vector<macPDU_t>& tempDB, int list_idx) {
    if (currentSubHeader == nofSubHea) {
        // Base case: all sub-headers filled, create a macPDU and add to the result
        macPDU_t currentPDU = tempPDU;
        // autoFillMacPDU(currentPDU, nofSubHea, 0, currentPDU.subHea, currentPDU.subPay, 0);
        tempDB.push_back(std::move(currentPDU));
    } else {
        bool isLast = (currentSubHeader == (nofSubHea - 1));
        tempPDU.subHea[currentSubHeader].isLast = isLast;
        tempPDU.subHea[currentSubHeader].type = heaTypes[currentSubHeader];
        if (isLast && heaTypes[currentSubHeader] != typeD) {
            std::cout << "[MTT] Error: Last sub-header cannot be type D" << "\n";
            heaTypes[currentSubHeader] = typeD; // change to type D
        }
        std::vector<int> lcidList1 = (isLast)? lcidAllList: ((heaTypes[currentSubHeader] == typeD)? lcidCEList: lcidNoCEList);
        std::vector<int> lcidList2 = (isLast)? lcidAllList2: ((heaTypes[currentSubHeader] == typeD)? lcidCEList2: lcidNoCEList2);
        std::vector<int> lcidList = (list_idx == 0)? lcidList1: lcidList2;
        for (const auto& lcid : lcidList) {
            // only assign lcid
            tempPDU.subHea[currentSubHeader].lcid = lcid;

            // Recursively move to the next sub-header
            recursiveMutateLCID_given_subhea_format(currentSubHeader + 1, nofSubHea, heaTypes, tempPDU, tempDB, list_idx);
        }

        // Mutate L based on eIdx
    }
}

// assume that LCID and subheader type are already filled
void macFuzzer_t::assign_legitimate_subheade_and_subpayload(int subHeader_idx, bool isLast, macSubHeaderType_t type, macSubHeader_t& subHea, macSubPayload_t& subPay){
    subHea.type = type;
    subHea.isLast = isLast;
    subHea.isCE = check_is_CE(subHea.lcid);
    subHea.headerSize = heaSizeMap[type];
    // index?
    switch (type)
    {
    case typeA:
        subHea.R = 0;
        subHea.F2 = 0;
        subHea.E = 1; // type A always has E = 1 as the last one is always type D
        subHea.F = 0;
        subHea.L = 20; // 20 bytes
        subHea.lcid = subHea.lcid;
        subPay.size = subHea.L;
        break;
    case typeB:
        subHea.R = 0;
        subHea.F2 = 0;
        subHea.E = 1; // type A always has E = 1 as the last one is always type D
        subHea.F = 1;
        subHea.L = 200; // 200 bytes
        subHea.lcid = subHea.lcid; 
        subPay.size = subHea.L;  
        break;
    case typeC:
        subHea.R = 0;
        subHea.F2 = 1;
        subHea.E = 1; // type A always has E = 1 as the last one is always type D
        subHea.F = 0;
        subHea.L = 200; // 200 bytes
        subHea.lcid = subHea.lcid; 
        subPay.size = subHea.L;       
        break;
    case typeD:
        if (isLast){
            subHea.R = 0;
            subHea.F2 = 0;
            subHea.E = 0; 
            subHea.F = 0;
            subHea.L = 0; // 200 bytes
            subHea.lcid = subHea.lcid; 
            subPay.size = (subHea.isCE)? cePaySize[subHea.lcid]: 20;       
        }else{ // only contains CE
            subHea.R = 0;
            subHea.F2 = 0;
            subHea.E = 1; 
            subHea.F = 0;
            subHea.L = 0; // 200 bytes
            subHea.lcid = subHea.lcid; 
            subPay.size = cePaySize[subHea.lcid];       
        }
        break;
    
    // extended LCID
    case typeAe:
        subHea.R = 0;
        subHea.F2 = 0;
        subHea.E = 1; // type Ae always has E = 1 as the last one is always type De
        subHea.F = 0;
        subHea.L = 20; // 20 bytes
        subHea.lcid = subHea.lcid;
        subHea.eLCID = subHea.eLCID;
        subPay.size = subHea.L;
        break;
    case typeBe:
        subHea.R = 0;
        subHea.F2 = 0;
        subHea.E = 1; // type Be always has E = 1 as the last one is always type De
        subHea.F = 1;
        subHea.L = 200; // 200 bytes
        subHea.lcid = subHea.lcid; 
        subHea.eLCID = subHea.eLCID;
        subPay.size = subHea.L;  
        break;
    case typeCe:
        subHea.R = 0;
        subHea.F2 = 1;
        subHea.E = 1; // type Ae always has E = 1 as the last one is always type De
        subHea.F = 0;
        subHea.L = 200; // 200 bytes
        subHea.lcid = subHea.lcid; 
        subHea.eLCID = subHea.eLCID;
        subPay.size = subHea.L;       
        break;
    case typeDe: // type De must be the last one because CE cannot included in De
        if (isLast){
            subHea.R = 0;
            subHea.F2 = 0;
            subHea.E = 0; 
            subHea.F = 0;
            subHea.L = 0; // 200 bytes
            subHea.lcid = subHea.lcid; 
            subHea.eLCID = subHea.eLCID;
            subPay.size =  20;
        }else{ 
            // std::cout << "[MTT] Error: type De must be the last one" << "\n";
        }
        break;
    default:
        break;
    }
}

void macFuzzer_t::assign_legitimate_subheade_and_subpayload_numerous_subheaders(int subHeader_idx, bool isLast, macSubHeaderType_t type, macSubHeader_t& subHea, macSubPayload_t& subPay){
    subHea.type = type;
    subHea.isLast = isLast;
    subHea.isCE = check_is_CE(subHea.lcid);
    subHea.headerSize = heaSizeMap[type];
    // index?
    switch (type)
    {
    case typeA:
        subHea.R = 0;
        subHea.F2 = 0;
        subHea.E = 1; // type A always has E = 1 as the last one is always type D
        subHea.F = 0;
        subHea.L = 10; // 20 bytes
        subHea.lcid = subHea.lcid;
        subPay.size = subHea.L;
        break;
    case typeB:
        subHea.R = 0;
        subHea.F2 = 0;
        subHea.E = 1; // type A always has E = 1 as the last one is always type D
        subHea.F = 1;
        subHea.L = 10; // 200 bytes
        subHea.lcid = subHea.lcid; 
        subPay.size = subHea.L;  
        break;
    case typeC:
        subHea.R = 0;
        subHea.F2 = 1;
        subHea.E = 1; // type A always has E = 1 as the last one is always type D
        subHea.F = 0;
        subHea.L = 10; // 200 bytes
        subHea.lcid = subHea.lcid; 
        subPay.size = subHea.L;       
        break;
    case typeD:
        if (isLast){
            subHea.R = 0;
            subHea.F2 = 0;
            subHea.E = 0; 
            subHea.F = 0;
            subHea.L = 0; // 200 bytes
            subHea.lcid = subHea.lcid; 
            subPay.size = (subHea.isCE)? cePaySize[subHea.lcid]: 20;       
        }else{ // only contains CE
            subHea.R = 0;
            subHea.F2 = 0;
            subHea.E = 1; 
            subHea.F = 0;
            subHea.L = 0; // 200 bytes
            subHea.lcid = subHea.lcid; 
            subPay.size = cePaySize[subHea.lcid];       
        break;
        }
        break;
    
    default:
        break;
    }
}

// simply sum header size and payload size, assume that all sizes are already filled
int sum_header_and_payload_size(macPDU_t& pdu){
    int sum = 0;
    for (int i = 0; i < pdu.nofSubHea; i++){
        sum += pdu.subHea[i].headerSize + pdu.subPay[i].size;
    }
    return sum;
}

int get_last_subheaer_size_by_eIdx(int eIdx){
    switch (eIdx)
    {
    case -1:
        return 1; // type D
    case -2:
        return 2;
    case -3:
        return 1;
    case -4:
        return 1;
    case -5:
        return 1;
    default:
        printf("[MTT] Error: eIdx %d is not supported\n", eIdx);
        return 0;
    }
}

void fill_E_F2_F_last_subheader_by_eIdx(int eIdx, uint8_t& E, uint8_t& F2, uint8_t&F){
    switch (eIdx)
    {
    case -1:
        E = 0;
        F2 = 0;
        F = 0;
        break;
    case -2:
        E = 1;
        F2 = 0;
        F = 1;
        break;
    case -3:
        E = 1;
        F2 = 1;
        F = 0;
        break;
    case -4:
        E = 1;
        F2 = 0;
        F = 0;
        break;
    case -5:
        E = 0;
        F2 = 1;
        F = 0;
        break;
    default:
        printf("[MTT] Error: eIdx %d is not supported\n", eIdx);
        break;
    }
}

/* Only used for generating packets with not much number of subheaders (e.g < 5). Otherwire, there will be a lot of test cases
* Mutation step: 1) assign lcid based on provided subheader types, 2) assign legitimate values, including sizes of sub-headers and payloads
* 3) mutate other values based on the eIdx, this step might change the sizes of sub-headers and payloads based on eIdx
* 4) mutate MAC CE if enabled, 5) Calculate total byte based on the summary of all sizes of sub-headers and payloads
*/
void macFuzzer_t::mutate_packet_n_subheaders(int nof_subheaders, std::vector<macSubHeaderType_t> headerTypes, bool mutate_ce, int list_idx, std::vector<macPDU_t>& db){

    if ((int)headerTypes.size() != nof_subheaders){
        std::cout << "[MTT] Error: headerTypes size must be " << nof_subheaders << "\n";
        return;
    }

    // generate initial PDU with nof_subheaders, these are used for subsequent mutations
    macPDU_t tempPDU;
    allocVectorPDU(tempPDU, nof_subheaders);
    // asign legetimate values for other fields before mutation
    for (int i = 0; i < nof_subheaders; i++){
        assign_legitimate_subheade_and_subpayload(i, (i == nof_subheaders - 1), tempPDU.subHea[i].type, tempPDU.subHea[i], tempPDU.subPay[i]);
    }
    
    // mutate LCID values given sub-header formats
    recursiveMutateLCID_given_subhea_format(0, nof_subheaders, headerTypes, tempPDU, lv1PDUtemp, list_idx);

    // assign legitimate values again since many LCIDs require dedicated values:
    for (auto& pdu: lv1PDUtemp){
        for (int i = 0; i < nof_subheaders; i++){
            assign_legitimate_subheade_and_subpayload(i, (i == nof_subheaders - 1), pdu.subHea[i].type, pdu.subHea[i], pdu.subPay[i]);
        }
    }

    // eIdx: used for packet truncation or marking special mutations
    /*  -5: last subheader has E = 0, F2 = 1, this indicates header is type C, but dont have any available byte behind
    *   -4: last subheader has E = 1 but no avialble byte behind
    *   -3: last subheader has E = 1, F2 = 1 (typeC) but available bytes are not enough for F2 (1 or 2)
    *   -2: last subheader has E = 1, F2 = 0, F = 1 (typeB) but available bytes are not enough for typeB (1 or 2)
    *   -1: packet does not have payload
    *    0: break at index 0
    *    1: break at index 1
    *    2: normal packet
    *    3: break at index 2 if 3th subheader is CE (eIdx = nof_subheader)
    *    4: remaining byte is higher than last subheader - CE (eIdx = nof_subheader + 1)
    *    5: normal packet with 1 subheader has R = 1 (eIdx = nof_subheader + 2)
    */

    // mutate eIdx 5: (eIdx = nof_subheader + 2)
    for (auto& pdu: lv1PDUtemp){ // does not change anything
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = nof_subheaders + 2;
        // pick random index from 0 to nof_subheaders - 1
        int idx = rand() % nof_subheaders;
        lv2PDU.subHea[idx].R = 1;
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        if (lv2PDU.totalByte == 0){
            std::cout << "[MTT] Error: totalByte = 0 (5)" << "\n";
        }
        db.push_back(std::move(lv2PDU));
    }
    // std::cout << "[MTT] (5) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 4: nof_subheaders + 1
    for (auto& pdu: lv1PDUtemp){
        if (pdu.subHea[nof_subheaders - 1].isCE){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = nof_subheaders + 1;
            lv2PDU.subPay[nof_subheaders - 1].size = 10; // 10 bytes, always higher than CE sizes
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            if (lv2PDU.totalByte == 0){
                std::cout << "[MTT] Error: totalByte = 0 (4)" << "\n";
            }
            db.push_back(std::move(lv2PDU));
        }     
    }
    // std::cout << "[MTT] (4) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 3: nof_subheaders
    for (auto& pdu: lv1PDUtemp){
        if (pdu.subHea[nof_subheaders - 1].isCE){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = nof_subheaders;
            lv2PDU.subPay[nof_subheaders - 1].size = lv2PDU.subPay[nof_subheaders - 1].size/2; // less than CE sizes
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            if (lv2PDU.totalByte == 0){
                std::cout << "[MTT] Error: totalByte = 0 (3)" << "\n";
            }
            db.push_back(std::move(lv2PDU));
        }     
    }
    // std::cout << "[MTT] (3) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 2:
    for (auto& pdu: lv1PDUtemp){ // does not change anything
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = 2;
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        if (lv2PDU.totalByte == 0){
            std::cout << "[MTT] Error: totalByte = 0 (2)" << "\n";
        }
        macPDU_t mutateCE_pdu = lv2PDU; // to use in CE mutation if needed
        db.push_back(std::move(lv2PDU));
        // TODO:
        if (pdu.subHea[0].isCE && pdu.subHea[1].type == typeA && mutate_ce){
            mutateCE_pdu.mutatingMacCE = true;
            if (pdu.subHea[0].lcid == 22){ // recommended bitrate ce
                mutateRecommendedBitRate(mutateCE_pdu, 0, db);
            }else if (pdu.subHea[0].lcid == 29){ // timing ce
                mutateTimingAdvanceCE(mutateCE_pdu, 0, db);
            }else if (pdu.subHea[0].lcid == 28){ // contention ce
                mutateContentionReslCE(mutateCE_pdu, 0, db);
            }else{
                mutateGeneralMacCE(mutateCE_pdu, cePaySize[pdu.subHea[0].lcid], 0, db);
            }
        }
    }
    // std::cout << "[MTT] (2) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx from 0 to nof_subheaders - 2
    for (auto& pdu: lv1PDUtemp){
        for (int h_idx = 0; h_idx < nof_subheaders - 1; h_idx++){ // this is eIdx mutation
            std::vector<int>& LList = (pdu.subHea[h_idx].type == typeA)? len7bitList: (pdu.subHea[h_idx].type == typeB)? len15bitList:len16bitList;
            if (!pdu.subHea[h_idx].isCE){
                for (const auto &L: LList){
                    // std::cout << "L: " << L << "\n";
                    macPDU_t lv2PDU = pdu;
                    lv2PDU.eIdx = h_idx; // same as index of header
                    lv2PDU.subHea[h_idx].L = L;
                    lv2PDU.subPay[h_idx].size = (L == 0)? 0: lv2PDU.subPay[h_idx].size; // aready assigned size for payload 20/200
                    // set size of payload from h_idx + 1 to the last subheader to 0
                    for (int i = h_idx + 1; i < nof_subheaders; i++){
                        lv2PDU.subPay[i].size = 0;
                    }
                    lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
                    if (lv2PDU.totalByte == 0){
                        std::cout << "[MTT] Error: totalByte = 0 (0 to nof_subheaders - 2)" << "\n";
                    }
                    db.push_back(std::move(lv2PDU));
                }
            }else{ // if CE and has payload, set payload size = 1/2 CE
                int lcid_ce = pdu.subHea[h_idx].lcid;
                int ce_size = cePaySize[lcid_ce];
                if (ce_size > 0){
                    macPDU_t lv2PDU = pdu;
                    lv2PDU.eIdx = h_idx; // same as index of header
                    // lv2PDU.subHea[h_idx].L = L;                  // CE sub-header type D does not have L
                    lv2PDU.subPay[h_idx].size = ce_size/2;          // less than CE sizes
                    // set size of payload from h_idx + 1 to the last subheader to 0
                    for (int i = h_idx + 1; i < nof_subheaders; i++){
                        lv2PDU.subPay[i].size = 0;
                    }
                    lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
                    if (lv2PDU.totalByte == 0){
                        std::cout << "[MTT] Error: totalByte = 0 (0 to nof_subheaders - 2 2)" << "\n";
                    }
                    db.push_back(std::move(lv2PDU));
                }

            }
        }
    }
    // std::cout << "[MTT] (01) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx -1:
    for (auto& pdu: lv1PDUtemp){
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = -1;
        for (int i = 0; i < nof_subheaders; i++){
            lv2PDU.subPay[i].size = 0;
        }
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        if (lv2PDU.totalByte <= 9){
            lv2PDU.isManualDCI = true;
        }
        if (lv2PDU.totalByte == 0){
            std::cout << "[MTT] Error: totalByte = 0 (-1)" << "\n";
        }
        db.push_back(std::move(lv2PDU));
    }
    // std::cout << "[MTT] (-1) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx -2 to -5:
    for (auto& pdu: lv1PDUtemp){
        for (int eIdx = -5; eIdx < 0; eIdx++){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = eIdx;
            lv2PDU.subHea[nof_subheaders - 1].headerSize = get_last_subheaer_size_by_eIdx(eIdx);
            fill_E_F2_F_last_subheader_by_eIdx(eIdx, lv2PDU.subHea[nof_subheaders - 1].E, lv2PDU.subHea[nof_subheaders - 1].F2, lv2PDU.subHea[nof_subheaders - 1].F);
            //set size of all sub-payloads to 0
            for (int i = 0; i < nof_subheaders; i++){
                lv2PDU.subPay[i].size = 0;
            }
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            if (lv2PDU.totalByte <= 9){
                lv2PDU.isManualDCI = true;
            }
            db.push_back(std::move(lv2PDU));
        }
    }
    // std::cout << "[MTT] (-2-5) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // reset lv1PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
}

void macFuzzer_t::mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(int nof_subheaders, std::vector<macSubHeaderType_t> headerTypes, std::vector<macPDU_t>& db, bool is_list2){

    if ((int)headerTypes.size() != nof_subheaders){
        std::cout << "[MTT] Error: headerTypes size must be " << nof_subheaders << "\n";
        return;
    }

    // generate initial PDU with nof_subheaders, these are used for subsequent mutations
    macPDU_t tempPDU;
    allocVectorPDU(tempPDU, nof_subheaders);
    // manually assign LCID values and header types in this case
    for (int i = 0; i < nof_subheaders; i++){
        tempPDU.subHea[i].type = headerTypes[i];
    }
    // assign legitimate values for other fields before mutation
    for (int i = 0; i < nof_subheaders; i++){
        assign_legitimate_subheade_and_subpayload_numerous_subheaders(i, (i == nof_subheaders - 1), tempPDU.subHea[i].type, tempPDU.subHea[i], tempPDU.subPay[i]);
    }

    // mutate LCID values given sub-header formats, note that this is very long packets, so we cannot apply recursive function
    std::vector<int> lcidList = headerTypes[0] == typeD? lcidCEList: (is_list2)? lcidNoCEList2: lcidNoCEList;
    for (auto& lcid: lcidList){ // because this is aaaad, bbbbd, ccccd
        macPDU_t lv1PDU = tempPDU;
        for (int h_idx = 0; h_idx < nof_subheaders; h_idx++){
            lv1PDU.subHea[h_idx].lcid = lcid;
        }
        lv1PDUtemp.push_back(std::move(lv1PDU));
    }

    // assign legitimate values again since many LCIDs require dedicated values:
    for (auto& pdu: lv1PDUtemp){
        for (int i = 0; i < nof_subheaders; i++){
            assign_legitimate_subheade_and_subpayload_numerous_subheaders(i, (i == nof_subheaders - 1), pdu.subHea[i].type, pdu.subHea[i], pdu.subPay[i]);
        }
    }

    // eIdx: used for packet truncation or marking special mutations
    /*  -5: last subheader has E = 0, F2 = 1, this indicates header is type C, but dont have any available byte behind
    *   -4: last subheader has E = 1 but no avialble byte behind
    *   -3: last subheader has E = 1, F2 = 1 (typeC) but available bytes are not enough for F2 (1 or 2)
    *   -2: last subheader has E = 1, F2 = 0, F = 1 (typeB) but available bytes are not enough for typeB (1 or 2)
    *   -1: packet does not have payload
    *    0: break at index 0
    *    1: break at index 1
    *    2: normal packet
    *    3: break at index 2 if 3th subheader is CE (eIdx = nof_subheader)
    *    4: remaining byte is higher than last subheader - CE (eIdx = nof_subheader + 1)
    *    5: normal packet with 1 subheader has R = 1 (eIdx = nof_subheader + 2)
    */

    // mutate eIdx 5: (eIdx = nof_subheader + 2)
    for (auto& pdu: lv1PDUtemp){ // does not change anything
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = nof_subheaders + 2;
        // pick random index from 0 to nof_subheaders - 1
        int idx = rand() % nof_subheaders;
        lv2PDU.subHea[idx].R = 1;
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        db.push_back(std::move(lv2PDU));
    }
    // std::cout << "[MTT] (5) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 4: nof_subheaders + 1
    for (auto& pdu: lv1PDUtemp){
        if (pdu.subHea[nof_subheaders - 1].isCE){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = nof_subheaders + 1;
            lv2PDU.subPay[nof_subheaders - 1].size = 10; // 10 bytes, always higher than CE sizes
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            db.push_back(std::move(lv2PDU));
        }     
    }
    // std::cout << "[MTT] (4) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 3: nof_subheaders
    for (auto& pdu: lv1PDUtemp){
        if (pdu.subHea[nof_subheaders - 1].isCE){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = nof_subheaders;
            lv2PDU.subPay[nof_subheaders - 1].size = lv2PDU.subPay[nof_subheaders - 1].size/2; // less than CE sizes
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            db.push_back(std::move(lv2PDU));
        }     
    }
    // std::cout << "[MTT] (3) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 2:
    for (auto& pdu: lv1PDUtemp){ // does not change anything
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = 2;
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        db.push_back(std::move(lv2PDU));
    }
    // std::cout << "[MTT] (2) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx from 0 to nof_subheaders - 2
    for (auto& pdu: lv1PDUtemp){
        for (int h_idx = 0; h_idx < nof_subheaders - 1; h_idx = h_idx + 15){
            std::vector<int>& LList = (pdu.subHea[h_idx].type == typeA)? len7bitList: (pdu.subHea[h_idx].type == typeB)? len15bitList:len16bitList;
            for (const auto &L: LList){
                // std::cout << "L: " << L << "\n";
                macPDU_t lv2PDU = pdu;
                lv2PDU.eIdx = h_idx; // same as index of header
                lv2PDU.subHea[h_idx].L = L;
                lv2PDU.subPay[h_idx].size = (L == 0)? 0: lv2PDU.subPay[h_idx].size; // aready assigned size for payload 20/200
                // set size of payload from h_idx + 1 to the last subheader to 0
                for (int i = h_idx + 1; i < nof_subheaders; i++){
                    lv2PDU.subPay[i].size = 0;
                }
                lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
                db.push_back(std::move(lv2PDU));
            }
        }
    }
    // std::cout << "[MTT] (01) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx -1:
    for (auto& pdu: lv1PDUtemp){
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = -1;
        for (int i = 0; i < nof_subheaders; i++){
            lv2PDU.subPay[i].size = 0;
        }
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        // lv2PDU.isManualDCI = true;
        db.push_back(std::move(lv2PDU));
    }
    // std::cout << "[MTT] (-1) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx -2 to -5:
    for (auto& pdu: lv1PDUtemp){
        for (int eIdx = -5; eIdx < 0; eIdx++){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = eIdx;
            lv2PDU.subHea[nof_subheaders - 1].headerSize = get_last_subheaer_size_by_eIdx(eIdx);
            fill_E_F2_F_last_subheader_by_eIdx(eIdx, lv2PDU.subHea[nof_subheaders - 1].E, lv2PDU.subHea[nof_subheaders - 1].F2, lv2PDU.subHea[nof_subheaders - 1].F);
            //set size of all sub-payloads to 0
            for (int i = 0; i < nof_subheaders; i++){
                lv2PDU.subPay[i].size = 0;
            }
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            // lv2PDU.isManualDCI = true;
            db.push_back(std::move(lv2PDU));
        }
    }
    // std::cout << "[MTT] (-2-5) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // reset lv1PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
}

void macFuzzer_t::mutate_packet_numerous_subheader_DAAD(int nof_subheaders, std::vector<macSubHeaderType_t> headerTypes, std::vector<macPDU_t>& db){

    if ((int)headerTypes.size() != nof_subheaders){
        std::cout << "[MTT] Error: headerTypes size must be " << nof_subheaders << "\n";
        return;
    }

    // generate initial PDU with nof_subheaders, these are used for subsequent mutations
    macPDU_t tempPDU;
    allocVectorPDU(tempPDU, nof_subheaders);
    // manually assign LCID values and header types in this case
    for (int i = 0; i < nof_subheaders; i++){
        tempPDU.subHea[i].type = headerTypes[i];
    }

    // assign legitimate values for other fields before mutation
    for (int i = 0; i < nof_subheaders; i++){
        assign_legitimate_subheade_and_subpayload_numerous_subheaders(i, (i == nof_subheaders - 1), tempPDU.subHea[i].type, tempPDU.subHea[i], tempPDU.subPay[i]);
    }

    // mutate LCID values given sub-header formats, note that this is very long packets, so we cannot apply recursive function
    for (auto lcidCE: lcidCEList){
        for (auto lcidNoCE: lcidNoCEList){
            macPDU_t lv1PDU = tempPDU;
            lv1PDU.subHea[0].lcid = lcidCE;
            for (int h_idx = 1; h_idx < nof_subheaders; h_idx++){
                lv1PDU.subHea[h_idx].lcid = lcidNoCE;
            }
            lv1PDUtemp.push_back(std::move(lv1PDU));
        }
    }


    // eIdx: used for packet truncation or marking special mutations
    /*  -5: last subheader has E = 0, F2 = 1, this indicates header is type C, but dont have any available byte behind
    *   -4: last subheader has E = 1 but no avialble byte behind
    *   -3: last subheader has E = 1, F2 = 1 (typeC) but available bytes are not enough for F2 (1 or 2)
    *   -2: last subheader has E = 1, F2 = 0, F = 1 (typeB) but available bytes are not enough for typeB (1 or 2)
    *   -1: packet does not have payload
    *    0: break at index 0
    *    1: break at index 1
    *    2: normal packet
    *    3: break at index 2 if 3th subheader is CE (eIdx = nof_subheader)
    *    4: remaining byte is higher than last subheader - CE (eIdx = nof_subheader + 1)
    *    5: normal packet with 1 subheader has R = 1 (eIdx = nof_subheader + 2)
    */

    // mutate eIdx 5: (eIdx = nof_subheader + 2)
    for (auto& pdu: lv1PDUtemp){ // does not change anything
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = nof_subheaders + 2;
        // pick random index from 0 to nof_subheaders - 1
        int idx = rand() % nof_subheaders;
        lv2PDU.subHea[idx].R = 1;
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        db.push_back(std::move(lv2PDU));
    }
    // std::cout << "[MTT] (5) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 4: nof_subheaders + 1
    for (auto& pdu: lv1PDUtemp){
        if (pdu.subHea[nof_subheaders - 1].isCE){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = nof_subheaders + 1;
            lv2PDU.subPay[nof_subheaders - 1].size = 10; // 10 bytes, always higher than CE sizes
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            db.push_back(std::move(lv2PDU));
        }     
    }
    // std::cout << "[MTT] (4) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 3: nof_subheaders
    for (auto& pdu: lv1PDUtemp){
        if (pdu.subHea[nof_subheaders - 1].isCE){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = nof_subheaders;
            lv2PDU.subPay[nof_subheaders - 1].size = lv2PDU.subPay[nof_subheaders - 1].size/2; // less than CE sizes
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            db.push_back(std::move(lv2PDU));
        }     
    }
    // std::cout << "[MTT] (3) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx 2:
    for (auto& pdu: lv1PDUtemp){ // does not change anything
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = 2;
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        db.push_back(std::move(lv2PDU));
    }
    // std::cout << "[MTT] (2) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx from 0 to nof_subheaders - 2
    for (auto& pdu: lv1PDUtemp){
        for (int h_idx = 0; h_idx < nof_subheaders - 1; h_idx = h_idx + 15){
            std::vector<int>& LList = (pdu.subHea[h_idx].type == typeA)? len7bitList: (pdu.subHea[h_idx].type == typeB)? len15bitList:len16bitList;
            for (const auto &L: LList){
                // std::cout << "L: " << L << "\n";
                macPDU_t lv2PDU = pdu;
                lv2PDU.eIdx = h_idx; // same as index of header
                lv2PDU.subHea[h_idx].L = L;
                lv2PDU.subPay[h_idx].size = (L == 0)? 0: lv2PDU.subPay[h_idx].size; // aready assigned size for payload 20/200
                // set size of payload from h_idx + 1 to the last subheader to 0
                for (int i = h_idx + 1; i < nof_subheaders; i++){
                    lv2PDU.subPay[i].size = 0;
                }
                lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
                db.push_back(std::move(lv2PDU));
            }
        }
    }
    // std::cout << "[MTT] (01) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx -1:
    for (auto& pdu: lv1PDUtemp){
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = -1;
        for (int i = 0; i < nof_subheaders; i++){
            lv2PDU.subPay[i].size = 0;
        }
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        if (lv2PDU.totalByte <= 9){
            lv2PDU.isManualDCI = true;
        }
        db.push_back(std::move(lv2PDU));
    }
    // std::cout << "[MTT] (-1) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // mutate eIdx -2 to -5:
    for (auto& pdu: lv1PDUtemp){
        for (int eIdx = -5; eIdx < 0; eIdx++){
            macPDU_t lv2PDU = pdu;
            lv2PDU.eIdx = eIdx;
            lv2PDU.subHea[nof_subheaders - 1].headerSize = get_last_subheaer_size_by_eIdx(eIdx);
            fill_E_F2_F_last_subheader_by_eIdx(eIdx, lv2PDU.subHea[nof_subheaders - 1].E, lv2PDU.subHea[nof_subheaders - 1].F2, lv2PDU.subHea[nof_subheaders - 1].F);
            //set size of all sub-payloads to 0
            for (int i = 0; i < nof_subheaders; i++){
                lv2PDU.subPay[i].size = 0;
            }
            lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
            if (lv2PDU.totalByte <= 9){
                lv2PDU.isManualDCI = true;
            }
            db.push_back(std::move(lv2PDU));
        }
    }
    // std::cout << "[MTT] (-2-5) Generated " << db.size() << " test cases lv1 with " << nof_subheaders << " number of subheader" << "\n";

    // reset lv1PDUtemp
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
}

// TODO:
void macFuzzer_t::mutateN_boundary(int nofSubHea){
    macPDU_t tempPDU;
    allocVectorPDU(tempPDU, nofSubHea);
    recursiveMutateSubHeaFormatLCID_boundary(0, nofSubHea, tempPDU, lv1PDUtemp);

    /*Only keep packet with nof SubHeader Formats <= 2*/
    std::vector<srsenb::macPDU_t>::iterator it;
    bool nofTypeA = 0;
    bool nofTypeB = 0;
    bool nofTypeC = 0;
    bool nofTypeD = 0;
    bool del = false;
    int  totalType = 0;
    for (it = lv1PDUtemp.begin(); it != lv1PDUtemp.end(); ++it){
        nofTypeA = 0;
        nofTypeB = 0;
        nofTypeC = 0;
        nofTypeD = 0;
        del = false;
        totalType = 0;
        for (int j = 0; j < it->nofSubHea; j++){
            if (it->subHea[j].type == typeA){
                nofTypeA = true;
            }else if (it->subHea[j].type == typeB){
                nofTypeB = true;
            }else if (it->subHea[j].type == typeC){
                nofTypeC = true;
            }else if (it->subHea[j].type == typeD){
                nofTypeD = true;
            }
        }
        totalType = nofTypeA + nofTypeB + nofTypeC + nofTypeD;
        if (totalType < 2){
            del = false;
        }else if (totalType == 2 && nofTypeD){
            del = false;
        }else{
            del = true;
        }
        if (del){
            lv1PDUtemp.erase(it);
            it--;
        }
    }
    
    std::cout << "[MTT] Generated " << lv1PDUtemp.size() << " test cases lv1 " << "\n";

    for (const auto& lv1PDU: lv1PDUtemp){ // R mutation
        macPDU_t lv2PDU = lv1PDU; // all normal R =0
        lv2PDUtemp.push_back(std::move(lv2PDU));
    }
    std::cout << "[MTT] Generated " << lv2PDUtemp.size() << " test cases lv2 " << "\n";
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();

    for (const auto& lv2PDU: lv2PDUtemp){ // L mutation T_note: check mutation here
        for (int LIdx = 0; LIdx < lv2PDU.nofSubHea - 1; LIdx++ ){ // final header does not have L
            if (lv2PDU.subHea[LIdx].hasL && lv2PDU.subHea[LIdx].type != typeD && (LIdx != (lv2PDU.nofSubHea - 1))){
                std::vector<int>& LList = LListRef[lv2PDU.subHea[LIdx].type];
                for (const auto &L: LList){
                    macPDU_t lv3PDU = lv2PDU;
                    lv3PDU.subHea[LIdx].L = L;
                    lv3PDU.subPay[LIdx].size = L;
                    lv3PDUtemp.push_back(std::move(lv3PDU));
                }
            }
        }
        // macPDU_t lv3PDU = lv2PDU; // all normal L = 20Z
        // lv3PDUtemp.push_back(std::move(lv3PDU));
    }
    std::cout << "[MTT] Generated " << lv3PDUtemp.size() << " test cases lv3 " << "\n";
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();

    /*  -4: last subheader has E = 1 but no avialble byte behind
    *   -3: last subheader has E = 1, F2 = 1 (typeC) but available bytes are not enough for F2 (1 or 2)
    *   -2: last subheader has E = 1, F2 = 0, F = 1 (typeB) but available bytes are not enough for typeB (1 or 2)
    *   -1: packet does not have payload
    *   -5: last subheader has E = 0, F2 = 1, this indicates header is type C, but dont have any available byte behind
    */
    for (auto& lv3PDU: lv3PDUtemp){ //packet total size mutation
        for (int eIdx = -4; eIdx < lv3PDU.nofSubHea; eIdx++){ // -1: no payload, 0->1 idx of header, final subhead does not have L, 2 is normal packet
            if (checkGenEidx(lv3PDU, eIdx)){ // if this index can be expected crash
                macPDU_t lv4PDU = lv3PDU;
                lv4PDU.eIdx = eIdx;
                for (int i = 0; i < lv3PDU.nofSubHea; i++){
                    autoFillSubHea_boundary(lv4PDU.subHea[i], lv4PDU.subPay[i], lv4PDU.subHea[i].type, lv4PDU.subHea[i].isLast, lv4PDU.subHea[i].isWrongID, 0, lv4PDU.subHea[i].lcid, lv4PDU.subHea[i].L, eIdx, i);
                }
                lv4PDU.totalByte = calTotalByte(lv4PDU);
                if (lv4PDU.totalByte <= 8000){ 
                    lv4PDUtemp.push_back(std::move(lv4PDU));
                }else{
                    // std::cout << "[MTT] Skip packet with totalByte = " << lv4PDU.totalByte << "\n";
                }
            }
        }
    }
    std::cout << "[MTT] Generated " << lv4PDUtemp.size() << " test cases lv4 " << "\n";
    lv3PDUtemp.clear();
    lv3PDUtemp.shrink_to_fit();

    for (const auto& lv4PDU: lv4PDUtemp){ // ID correct/incorrect mutation
        // for (int idIdx = 0; idIdx < 3; idIdx++){
        //     if (lv4PDU.subHea[idIdx].hasID && checkGenWrongID(lv4PDU, idIdx)){
        //         macPDU_t lv5PDU = lv4PDU;
        //         lv5PDU.subHea[idIdx].isWrongID = true;
        //         tcState234DB.push_back(std::move(lv5PDU));
        //     }
        // }
        macPDU_t lv5PDU = lv4PDU; // all correct ID
        tcState234DB.push_back(std::move(lv5PDU));
    }

    std::cout << "[MTT] Generated " << tcState234DB.size() << " test cases with nofSubHeaders =  " << nofSubHea << "\n";
    lv4PDUtemp.clear();
    lv4PDUtemp.shrink_to_fit();
}


void macFuzzer_t::mutate_eLCID(int nofSubHea, std::vector<macSubHeaderType_t> headerTypes, std::vector<srsenb::macPDU_t>& db){

    std::vector<int> Llist[8];
    Llist[typeAe] = {0, 20};
    Llist[typeBe] = {0, 20};
    Llist[typeCe] = {0, 20};
    Llist[typeDe] = {20, 20}; // always 20 for the last subheader
    Llist[typeA] = {0, 20};
    Llist[typeB] = {0, 20};
    Llist[typeC] = {0, 20};
    Llist[typeD] = {20, 20};

    macPDU_t lv1PDU;
    allocVectorPDU(lv1PDU, nofSubHea);
    lv1PDU.nofSubHea = nofSubHea;
    lv1PDU.iseLCID   = true;
    if (nofSubHea != (int)headerTypes.size()){
        std::cout << "[MTT] Error: nofSubHea != headerTypes.size() " << "\n";
        return;
    }else{
        for (int h = 0; h < nofSubHea; h++){
            lv1PDU.subHea[h].type = headerTypes[h];
        }
    }
    
    recursiveMutate_eLCID(0, nofSubHea, lv1PDU, headerTypes, lv1PDUtemp);

    for (auto& lv1PDUt: lv1PDUtemp){ // L mutation
        for (int i = 0; i < 2; i++){
            for (int h = 0; h < nofSubHea; h++){
                bool iseLCIDtemp = (lv1PDUt.subHea[h].type == typeAe || lv1PDUt.subHea[h].type == typeBe || lv1PDUt.subHea[h].type == typeCe || lv1PDUt.subHea[h].type == typeDe);
                // bool isLasttemp = (h == nofSubHea - 1);
                bool isCE = (std::find(lcidCEList.begin(), lcidCEList.end(), lv1PDUt.subHea[h].lcid) != lcidCEList.end());
                if (iseLCIDtemp || !isCE){
                    lv1PDUt.subHea[h].L = Llist[lv1PDUt.subHea[h].type][i];
                }else if (isCE){
                    // get length of CE payload
                    lv1PDUt.subHea[h].L = cePaySize[lv1PDUt.subHea[h].lcid];
                }
            }
            macPDU_t lv2PDU = lv1PDUt;
            lv2PDUtemp.push_back(std::move(lv2PDU));  
        }
    }
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();

    /* -1: last subheader has E = 0, F2 = 0, 1 byte
    *  -2: last subheader has E = 1, F2 = 0, 1 byte 
    *  -3: last subheader has E = 0, F2 = 1, 1 byte
    *  -4: last subheader has E = 1, F2 = 1, 1 byte
    *  -5: last subheader has E = 1, F2 = 0, 2 bytes
    *  -6: last subheader has E = 1, F2 = 0, F = 1, 3 bytes
    *  -7: last subheader has E = 1, F2 = 1, 2 bytes
    */
    for (auto& lv2PDUt: lv2PDUtemp){ //packet total size mutation
        for (int eIdx = -7; eIdx < lv2PDUt.nofSubHea; eIdx++){ // -1: no payload, 0->1 idx of header, final subhead does not have L, 2 is normal packet
            lv2PDUt.eIdx = eIdx;
            for (int i = 0; i < nofSubHea; i++){
                bool iseLCIDtemp = (lv2PDUt.subHea[i].type == typeAe || lv2PDUt.subHea[i].type == typeBe || lv2PDUt.subHea[i].type == typeCe || lv2PDUt.subHea[i].type == typeDe);
                if (iseLCIDtemp){
                    autoFillSubHea_eLCID(lv2PDUt.subHea[i], lv2PDUt.subPay[i], lv2PDUt.subHea[i].type, (i == nofSubHea - 1),lv2PDUt.subHea[i].eLCID, lv2PDUt.subHea[i].L, eIdx, i);
                }else{
                    autoFillSubHea(lv2PDUt.subHea[i], lv2PDUt.subPay[i], lv2PDUt.subHea[i].type, (i == nofSubHea - 1), false, 0, lv2PDUt.subHea[i].lcid, lv2PDUt.subHea[i].L, eIdx, i);
                
                }
            }
            lv2PDUt.totalByte = calTotalByte_eLCID(lv2PDUt);
            macPDU_t lv3PDU = lv2PDUt;

            db.push_back(std::move(lv3PDU));
        }
    }
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
}

int get_last_subheaer_size_by_eIdx_eLCID(int eIdx){
    switch (eIdx)
    {
    case -1:
        return 1; 
    case -2:
        return 2;
    case -3:
        return 1;
    case -4:
        return 1;
    case -5:
        return 2;
    case -6:
        return 3;
    case -7:
        return 2;
    default:
        printf("[MTT] Error: eLCID eIdx %d is not supported\n", eIdx);
        return 0;
    }
}

void fill_E_F2_F_last_subheader_by_eIdx_eLCID(int eIdx, uint8_t& E, uint8_t& F2, uint8_t&F){
    switch (eIdx)
    {
    case -1:
        E = 0;
        F2 = 0;
        // F = 0;
        break;
    case -2:
        E = 1;
        F2 = 0;
        // F = 1;
        break;
    case -3:
        E = 0;
        F2 = 1;
        // F = 0;
        break;
    case -4:
        E = 1;
        F2 = 1;
        F = 0;
        break;
    case -5:
        E = 1;
        F2 = 0;
        // F = 0;
        break;
    case -6:
        E = 1;
        F2 = 0;
        F = 1;
        break;
    case -7:
        E = 1;
        F2 = 1;
        // F = 0;
        break;
    default:
        printf("[MTT] Error: eLCID eIdx %d is not supported\n", eIdx);
        break;
    }
}

void macFuzzer_t::mutate_eLCID_new(int nofSubHea, std::vector<macSubHeaderType_t> headerTypes, std::vector<srsenb::macPDU_t>& db){

    // generate initial PDU with nofSubHea sub-headers, these are seeds for subsequent mutations
    macPDU_t lv1PDU;
    allocVectorPDU(lv1PDU, nofSubHea);
    lv1PDU.nofSubHea = nofSubHea;
    lv1PDU.iseLCID   = true;

    // assign sub-header formats
    if (nofSubHea != (int)headerTypes.size()){
        std::cout << "[MTT] Error: nofSubHea != headerTypes.size() " << "\n";
        return;
    }else{
        for (int h = 0; h < nofSubHea; h++){
            lv1PDU.subHea[h].type = headerTypes[h];
        }
    }

    // assign legitimate values for other fields before mutation
    for (int i = 0; i < nofSubHea; i++){
        assign_legitimate_subheade_and_subpayload(i, (i == nofSubHea - 1), lv1PDU.subHea[i].type, lv1PDU.subHea[i], lv1PDU.subPay[i]);
    }

    // mutate eLCID in all sub-headers
    recursiveMutate_eLCID(0, nofSubHea, lv1PDU, headerTypes, lv1PDUtemp);

    // assign legitimate values again since many LCIDs require dedicated values:
    for (auto& pdu: lv1PDUtemp){
        for (int i = 0; i < nofSubHea; i++){
            assign_legitimate_subheade_and_subpayload(i, (i == nofSubHea - 1), pdu.subHea[i].type, pdu.subHea[i], pdu.subPay[i]);
        }
    }


    /* eIdx: index for packet truncation or error type
    *  -1: last subheader has E = 0, F2 = 0, 1 byte
    *  -2: last subheader has E = 1, F2 = 0, 1 byte 
    *  -3: last subheader has E = 0, F2 = 1, 1 byte
    *  -4: last subheader has E = 1, F2 = 1, 1 byte
    *  -5: last subheader has E = 1, F2 = 0, 2 bytes
    *  -6: last subheader has E = 1, F2 = 0, F = 1, 3 bytes
    *  -7: last subheader has E = 1, F2 = 1, 2 bytes
    */

    // mutate eIdx -7 to -1:
    for (auto& pdu: lv1PDUtemp){
        bool last_subheader_is_elcid = (pdu.subHea[nofSubHea - 1].type == typeAe || pdu.subHea[nofSubHea - 1].type == typeBe || pdu.subHea[nofSubHea - 1].type == typeCe || pdu.subHea[nofSubHea - 1].type == typeDe);
        if (last_subheader_is_elcid){
            for (int eIdx = -7; eIdx < 0; eIdx++){
                macPDU_t lv2PDU = pdu;
                lv2PDU.eIdx = eIdx;
                lv2PDU.subHea[nofSubHea - 1].headerSize = get_last_subheaer_size_by_eIdx_eLCID(eIdx);
                fill_E_F2_F_last_subheader_by_eIdx_eLCID(eIdx, lv2PDU.subHea[nofSubHea - 1].E, lv2PDU.subHea[nofSubHea - 1].F2, lv2PDU.subHea[nofSubHea - 1].F);
                for (int i = 0; i < nofSubHea; i++){
                    lv2PDU.subPay[i].size = 0;
                }
                lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
                db.push_back(std::move(lv2PDU));
            }
        }
    }

    // mutate eIdx 0 to nofSubHea - 2 (nofSubHea - 1 eIdx is the normal packet):
    for (auto& pdu: lv1PDUtemp){
        for (int eIdx = 0; eIdx < nofSubHea - 1; eIdx++){
            std::vector<int>& LList = (pdu.subHea[eIdx].type == typeA || pdu.subHea[eIdx].type == typeAe)? 
                                                                        len7bitList: (pdu.subHea[eIdx].type == typeB || pdu.subHea[eIdx].type == typeBe)? 
                                                                                                                                    len15bitList:len16bitList;
            if (!pdu.subHea[eIdx].isCE){ // if this is normal subheader, not CE, mutate L
                for (const auto &L: LList){
                    macPDU_t lv2PDU = pdu;
                    lv2PDU.eIdx = eIdx;
                    lv2PDU.subHea[eIdx].L = L;
                    lv2PDU.subPay[eIdx].size = (L == 0)? 0: lv2PDU.subPay[eIdx].size; // aready assigned size for payload 20/200
                    for (int i = eIdx + 1; i < nofSubHea; i++){
                        lv2PDU.subPay[i].size = 0;
                    }
                    lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
                    db.push_back(std::move(lv2PDU));
                }
            }else{ // if this is CE, check if it has payload, if yes, break at the middle of payload
                int lcid_ce = pdu.subHea[eIdx].lcid;
                int ce_size = cePaySize[lcid_ce];
                if (ce_size > 0){
                    macPDU_t lv2PDU = pdu;
                    lv2PDU.eIdx = eIdx;
                    lv2PDU.subPay[eIdx].size = ce_size/2;
                    for (int i = eIdx + 1; i < nofSubHea; i++){
                        lv2PDU.subPay[i].size = 0;
                    }
                    lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
                    db.push_back(std::move(lv2PDU));
                }
            }
        }
    }

    // mutate eIdx nofSubHea - 1 (normal packet)
    for (auto& pdu: lv1PDUtemp){ // does not change anything as it is normal packet
        macPDU_t lv2PDU = pdu;
        lv2PDU.eIdx = nofSubHea - 1;
        lv2PDU.totalByte = sum_header_and_payload_size(lv2PDU);
        db.push_back(std::move(lv2PDU));
    }

    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
}


/* -1: last subheader has E = 0, F2 = 0, 1 byte
*  -2: last subheader has E = 1, F2 = 0, 1 byte 
*  -3: last subheader has E = 0, F2 = 1, 1 byte
*  -4: last subheader has E = 1, F2 = 1, 1 byte
*  -5: last subheader has E = 1, F2 = 0, 2 bytes
*  -6: last subheader has E = 1, F2 = 0, F = 1, 3 bytes
*  -7: last subheader has E = 1, F2 = 1, 2 bytes
*   0->1 idx of header, final subhead does not have L, 2 is normal packet
*/
void macFuzzer_t::mutate_eLCID_long(int nofSubHea, std::vector<srsenb::macPDU_t>& db){
    std::vector<int> Llist[8];
    Llist[typeAe] = {0, 20};
    Llist[typeBe] = {0, 20};
    Llist[typeCe] = {0, 20};
    Llist[typeDe] = {20, 20}; // always 20 for the last subheader
    Llist[typeA] = {0, 20};
    Llist[typeB] = {0, 20};
    Llist[typeC] = {0, 20};
    Llist[typeD] = {20, 20};

    std::vector<macSubHeaderType_t> tempHeaTypes;
    tempHeaTypes.insert(tempHeaTypes.end(), {typeAe, typeBe, typeCe, typeDe});

    for (const auto& heaFormat  : tempHeaTypes){
        macPDU_t lv1PDU;
        // build temp subheader format vector:
        std::vector<macSubHeaderType_t> headerTypes;
        // reserve space for headerTypes
        headerTypes.reserve(nofSubHea);
        for (int h = 0; h < nofSubHea - 1; h++){
            headerTypes.push_back(heaFormat);
        }
        // last subheader is typeDe
        headerTypes.push_back(typeDe);
        // generate initial PDU with nofSubHea sub-headers, these are seeds for subsequent mutations
        generate_initial_eLCID_packet(lv1PDU, nofSubHea, headerTypes, false);

        // lv1PDU.iseLCID = true;
        // allocVectorPDU(lv1PDU, nofSubHea);
        // for (int h = 0; h < nofSubHea; h++){
        //     lv1PDU.subHea[h].type = heaFormat;
        //     if (h == nofSubHea - 1){
        //         lv1PDU.subHea[h].isLast = true;
        //         lv1PDU.subHea[h].type = typeDe;
        //     }
        // }
        lv1PDUtemp.push_back(std::move(lv1PDU));
    }

    for (auto& lv1PDU: lv1PDUtemp){ // LCID mutation
        for (auto& lcid: eLCIDlist){
            macPDU_t lv2PDU = lv1PDU;
            for (int i = 0; i < nofSubHea; i++){
                lv2PDU.subHea[i].eLCID = lcid;
            }
            lv2PDUtemp.push_back(std::move(lv2PDU));
        }

    }
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    // recursiveMutate_eLCID(0, nofSubHea, lv1PDU, headerTypes, lv1PDUtemp);

    // header0-normal type, 99 other headers: eLCID, or 99 first headers: normal LCID, last header: typeD
    // std::vector<macSubHeaderType_t> normalHeaTypes;
    // normalHeaTypes.insert(normalHeaTypes.end(), {typeA, typeB, typeC, typeD});
    // for (auto&  normaltype: normalHeaTypes){
    //     // for (auto etype: tempHeaTypes){
    //         macPDU_t lv1PDU;
    //         lv1PDU.iseLCID = true;
    //         allocVectorPDU(lv1PDU, nofSubHea);
    //         lv1PDU.subHea[0].type = normaltype;
    //         macSubHeaderType_t etype = (normaltype == typeA)?typeAe:((normaltype == typeB)?typeBe:((normaltype == typeC)?typeCe:typeDe));
    //         for (int h = 1; h < nofSubHea; h++){
    //             lv1PDU.subHea[h].type = etype;
    //             if (h == nofSubHea - 1){
    //                 lv1PDU.subHea[h].isLast = true;
    //                 lv1PDU.subHea[h].type = typeDe;
    //             }
    //         }
    //         macPDU_t lv1PDU2 = lv1PDU;
    //         lv1PDU2.subHea[0].type = lv1PDU2.subHea[1].type;
    //         lv1PDU2.subHea[nofSubHea - 1].type = typeD;
    //         lv1PDUtemp.push_back(std::move(lv1PDU));
    //         lv1PDUtemp.push_back(std::move(lv1PDU2));
    //     // }
    // }

    // std::vector<macPDU_t> lv2PDUtemptemp;
    // for (auto& lv1PDU: lv1PDUtemp){ // LCID mutation 1
    //     for (auto& lcid: eLCIDlist){
    //         macPDU_t lv2PDU = lv1PDU;
    //         for (int i = 0; i < nofSubHea; i++){
    //             lv2PDU.subHea[i].eLCID = lcid;
    //         }
    //         lv2PDUtemptemp.push_back(std::move(lv2PDU));
    //     }
    // }

    // for (auto& lv2pdutemp: lv2PDUtemptemp){ // LCID mutation 2
    //     if (lv2pdutemp.subHea[0].type == typeA || lv2pdutemp.subHea[0].type == typeB || lv2pdutemp.subHea[0].type == typeC || lv2pdutemp.subHea[0].type == typeD){
    //         std::vector<int> &normalLCIDList = (lv2pdutemp.subHea[0].type == typeD)?lcidCEListArr[1]:lcidNoCEListState234Arr[0];
    //         for (auto& normalLCID: normalLCIDList){
    //             macPDU_t lv2PDU = lv2pdutemp;
    //             lv2PDU.subHea[0].lcid = normalLCID;
    //             lv2PDUtemp.push_back(std::move(lv2PDU));
    //         }
    //     }
    //     if (lv2pdutemp.subHea[nofSubHea - 1].type == typeD){
    //         for (auto& normalLCID: lcidAllList234Arr[1]){
    //             macPDU_t lv2PDU = lv2pdutemp;
    //             lv2PDU.subHea[nofSubHea - 1].lcid = normalLCID;
    //             lv2PDUtemp.push_back(std::move(lv2PDU));
    //         }
    //     }
    // }
   

    for (auto& lv2PDUt: lv2PDUtemp){ // L mutation
        for (int i = 0; i < 2; i++){
            for (int h = 0; h < nofSubHea; h++){
                bool iseLCIDtemp = (lv2PDUt.subHea[h].type == typeAe || lv2PDUt.subHea[h].type == typeBe || lv2PDUt.subHea[h].type == typeCe || lv2PDUt.subHea[h].type == typeDe);
                // bool isLasttemp = (h == nofSubHea - 1);
                bool isCE = (std::find(lcidCEList.begin(), lcidCEList.end(), lv2PDUt.subHea[h].lcid) != lcidCEList.end());
                if (iseLCIDtemp || !isCE){
                    lv2PDUt.subHea[h].L = Llist[lv2PDUt.subHea[h].type][i];
                }else if (isCE){
                    // get length of CE payload
                    lv2PDUt.subHea[h].L = cePaySize[lv2PDUt.subHea[h].lcid];
                }
            }
            macPDU_t lv3PDU = lv2PDUt;
            lv3PDUtemp.push_back(std::move(lv3PDU));  
        }
    }
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();

    for (auto& lv3PDUt: lv3PDUtemp){ //packet total size mutation
        for (int eIdx = -7; eIdx < 1; eIdx++){ // -1: no payload, 0->1 idx of header, final subhead does not have L, 2 is normal packet
            lv3PDUt.eIdx = eIdx;
            for (int i = 0; i < nofSubHea; i++){
                bool iseLCIDtemp = (lv3PDUt.subHea[i].type == typeAe || lv3PDUt.subHea[i].type == typeBe || lv3PDUt.subHea[i].type == typeCe || lv3PDUt.subHea[i].type == typeDe);
                if (iseLCIDtemp){
                    autoFillSubHea_eLCID(lv3PDUt.subHea[i], lv3PDUt.subPay[i], lv3PDUt.subHea[i].type, (i == nofSubHea - 1),lv3PDUt.subHea[i].eLCID, lv3PDUt.subHea[i].L, eIdx, i);
                }else{
                    autoFillSubHea(lv3PDUt.subHea[i], lv3PDUt.subPay[i], lv3PDUt.subHea[i].type, (i == nofSubHea - 1), false, 0, lv3PDUt.subHea[i].lcid, lv3PDUt.subHea[i].L, eIdx, i);
                
                }
            }
            lv3PDUt.totalByte = calTotalByte_eLCID(lv3PDUt);
            macPDU_t lv4PDU = lv3PDUt;
            db.push_back(std::move(lv4PDU));
        }
    }
    lv3PDUtemp.clear();
    lv3PDUtemp.shrink_to_fit();
}

// allocate macRAR and inside containers with nof_subheaders
void allocate_rar_macPDU(macPDU_t& macpdu, int nof_subheaders){
    macpdu.nofSubHea = nof_subheaders;
    // macpdu.rar = std::make_shared<macRAR_t>();
    for (int h = 0; h < nof_subheaders; h++){
        rarSubHeader_t new_rarsubheader;
        new_rarsubheader.E      = (h == nof_subheaders - 1)? 0  : 1; // last subheader has E = 0
        new_rarsubheader.isLast = (h == nof_subheaders - 1)? true: false;
        rarSubPayload_t new_rarsubpayload;
        // std::cout << "h: " << h;
        // new_rarsubheader.print();
        macpdu.rar.subHea.push_back(new_rarsubheader);
        macpdu.rar.subPay.push_back(new_rarsubpayload);
    }
}

void assign_subheader_format(macPDU_t& macpdu, std::vector<bool>& rarHeaderTypes){
    for (int i = 0; i < macpdu.nofSubHea; i++){
        macpdu.rar.subHea[i].T = rarHeaderTypes[i];
    }
}

// this function decides the last subpayload that has grant (associated with ra subheader, not bi) for using in the mutation later
void check_last_subpayload_has_grant(macPDU_t& macpdu, std::vector<bool>& rarHeaderTypes){
    int  grant_idx = -1;
    for (int i = 0; i < macpdu.nofSubHea; i++){
        if (rarHeaderTypes[i]){
            grant_idx = i;
        }
    }
    if (grant_idx >= 0){
        macpdu.rar.subPay[grant_idx].isLastGrant = true;
    }
}   

int calculate_total_byte_rar_test_case(macPDU_t& macpdu){
    int total_byte = 0;
    int eIdx = macpdu.eIdx;
    int last_grant_idx = -1;
    int last_grant_size = 0;
    if (eIdx < 0){
        // calculate total bytes for header
        total_byte += macpdu.nofSubHea; // each subheader has 1 byte

        if (eIdx == -6){ // last subheader has E = 1 but no available byte behind
            macpdu.totalByte = total_byte;
            return total_byte;
        }

        // get last grant index
        for (int i = 0; i < macpdu.nofSubHea; i++){
            if (macpdu.rar.subPay[i].isLastGrant){
                last_grant_idx = i;
                break;
            }
        }
        for (int h = 0; h < last_grant_idx; h++){ // size of payload before the last grant
            if (macpdu.rar.subHea[h].T == 1){
                total_byte += 6; // 6 bytes for rar sub-payload
            }
        }
        last_grant_size = abs(eIdx); // eIdx is negative
        total_byte += last_grant_size;
        macpdu.totalByte = total_byte;
    }else{
        // calculate total bytes for header
        total_byte += macpdu.nofSubHea; // each subheader has 1 byte
        for (int h = 0; h < macpdu.eIdx; h++){
            if (macpdu.rar.subHea[h].T == 1){
                total_byte += 6; // 6 bytes for rar sub-payload
            }
        }
        macpdu.totalByte = total_byte;
    }
    return total_byte;
}

// these packets with eIdx < 0 only have subheaders and no payload
void macFuzzer_t::mutate_mac_rar_minus_eidx(macPDU_t& orin_rar, int eIdx, std::vector<macPDU_t>& db){
    macPDU_t lv3PDU = orin_rar;
    // assign legitimate pid and BI
    for (int i = 0; i < lv3PDU.nofSubHea; i++){
        if (lv3PDU.rar.subHea[i].T == 0){
            //assign legitimate BI subheader
            lv3PDU.rar.subHea[i].BI = 1;
        }else{
            //assign legitimate rar subheader
            lv3PDU.rar.subHea[i].pid = (lv3PDU.rar.subHea[i].is_correct_pid)?legitimate_rar_subheader.pid: legitimate_rar_subheader.pid + 1; // + 1 to avoid correct pid as the original packet from the UE
            //asign legitimate rar payload
            lv3PDU.rar.subPay[i].ta = legitimate_rar_grant.ta;
            lv3PDU.rar.subPay[i].ulGrant = legitimate_rar_grant.ulGrant;
            lv3PDU.rar.subPay[i].tcrnti = legitimate_rar_grant.tcrnti;
        }
    }

    // control the total bytes of test case based on eIdx
    calculate_total_byte_rar_test_case(lv3PDU);
    if (eIdx == -6){
        lv3PDU.rar.subHea[lv3PDU.nofSubHea - 1].E = 1; // last subheader has E = 1
    }
    // print test case
    // lv3PDU.print_general_info();
    // for (int h = 0; h < lv3PDU.nofSubHea; h++){
    //     lv3PDU.rar.subHea[h].print();
    // }
    // for (int h = 0; h < lv3PDU.nofSubHea; h++){
    //     lv3PDU.rar.subPay[h].print();
    // }
    db.push_back(std::move(lv3PDU));
}

void macFuzzer_t::mutate_rar_subheader(macPDU_t& macpdu, int subheader_idx, std::vector<macPDU_t>& db){
    if (macpdu.rar.subHea[subheader_idx].T == 0){ // BI subheader
        for (auto& bi: biList){
            macPDU_t lv4PDU = macpdu;
            lv4PDU.rar.subHea[subheader_idx].BI = bi;
            calculate_total_byte_rar_test_case(lv4PDU);
            if (lv4PDU.totalByte <= max_rar_bytes){
                // print test case
                // lv4PDU.print_general_info();
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subHea[h].print();
                // }
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subPay[h].print();
                // }
                db.push_back(std::move(lv4PDU));
            }
        }
    }else if (macpdu.rar.subHea[subheader_idx].T == 1 && !macpdu.rar.subHea[subheader_idx].is_correct_pid){ // RAR subheader, do not mutate correct pid
        for (auto& pid: pidList){
            macPDU_t lv4PDU = macpdu;
            lv4PDU.rar.subHea[subheader_idx].pid = pid;
            calculate_total_byte_rar_test_case(lv4PDU);
            if (lv4PDU.totalByte <= max_rar_bytes){
                // print test case
                // lv4PDU.print_general_info();
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subHea[h].print();
                // }
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subPay[h].print();
                // }
                db.push_back(std::move(lv4PDU));
            }
        }
    }
}

void macFuzzer_t::mutate_rar_subpayload(macPDU_t& macpdu, int subheader_idx, std::vector<macPDU_t>& db){
    if (macpdu.rar.subHea[subheader_idx].T == 1){
        for (auto& ta: taList){
            macPDU_t lv4PDU = macpdu;
            lv4PDU.rar.subPay[subheader_idx].ta = ta;
            calculate_total_byte_rar_test_case(lv4PDU);
            if (lv4PDU.totalByte <= max_rar_bytes){
                // print test case
                // lv4PDU.print_general_info();
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subHea[h].print();
                // }
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subPay[h].print();
                // }
                db.push_back(std::move(lv4PDU));
            }
        }
        for (auto& ulGrant: ulGrantList){
            macPDU_t lv4PDU = macpdu;
            lv4PDU.rar.subPay[subheader_idx].ulGrant = ulGrant;
            calculate_total_byte_rar_test_case(lv4PDU);
            if (lv4PDU.totalByte <= max_rar_bytes){
                // print test case
                // lv4PDU.print_general_info();
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subHea[h].print();
                // }
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subPay[h].print();
                // }
                db.push_back(std::move(lv4PDU));
            }
        }
        for (auto& tcrnti: tcrntiList){
            macPDU_t lv4PDU = macpdu;
            lv4PDU.rar.subPay[subheader_idx].tcrnti = tcrnti;
            calculate_total_byte_rar_test_case(lv4PDU);
            if (lv4PDU.totalByte <= max_rar_bytes){
                // print test case
                // lv4PDU.print_general_info();
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subHea[h].print();
                // }
                // for (int h = 0; h < lv4PDU.nofSubHea; h++){
                //     lv4PDU.rar.subPay[h].print();
                // }
                db.push_back(std::move(lv4PDU));
            }
        }
    }   
}
    
void macFuzzer_t::mutate_mac_rar_positive_eidx(macPDU_t& orin_rar, int eIdx, std::vector<macPDU_t>& db){
    macPDU_t lv3PDU = orin_rar;
    // assign legitimate subheaders and payloads
    for (int i = 0; i < lv3PDU.nofSubHea; i++){
        if (lv3PDU.rar.subHea[i].T == 0){
            //assign legitimate BI subheader
            lv3PDU.rar.subHea[i].BI = 1;
        }else{
            //assign legitimate rar subheader
            lv3PDU.rar.subHea[i].pid = (lv3PDU.rar.subHea[i].is_correct_pid)?legitimate_rar_subheader.pid: legitimate_rar_subheader.pid + 1; // + 1 to avoid correct pid as the original packet from the UE
            //asign legitimate rar payload
            lv3PDU.rar.subPay[i].ta = legitimate_rar_grant.ta;
            lv3PDU.rar.subPay[i].ulGrant = legitimate_rar_grant.ulGrant;
            lv3PDU.rar.subPay[i].tcrnti = legitimate_rar_grant.tcrnti;
        }
    }

    if (orin_rar.nofSubHea < 6){
        for (int h = 0; h < lv3PDU.nofSubHea; h++){
            mutate_rar_subheader(lv3PDU, h, db);
            if (lv3PDU.rar.subHea[h].T == 1 && h < lv3PDU.eIdx) { // depends on eIdx
                mutate_rar_subpayload(lv3PDU, h, db);
            } 
        }
    }else{
        // mutate numerous subheaders
        int gap = lv3PDU.nofSubHea/3;
        for (int h = 0; h < lv3PDU.nofSubHea; h = h + gap){
            mutate_rar_subheader(lv3PDU, h, db);
            if (lv3PDU.rar.subHea[h].T == 1 && h < lv3PDU.eIdx) { // depends on eIdx
                mutate_rar_subpayload(lv3PDU, h, db);
            } 
        }
    }
}

void macFuzzer_t::generate_initial_rar_packet(macPDU_t& initial_rar, int nof_subheaders, std::vector<bool>& rarHeaderTypes){
    allocate_rar_macPDU(initial_rar, nof_subheaders);            // macpdu.nofSubHea, E & isLast within subheader are also assigned here
    assign_subheader_format(initial_rar, rarHeaderTypes);        // T
    check_last_subpayload_has_grant(initial_rar, rarHeaderTypes); // isLastGrant
}

/*  -6: no payload but the last subheader has E = 1
*   -5: last payload only has 5 bytes
*   -4: last payload only has 4 bytes
*   -3: last payload only has 3 bytes
*   -2: last payload only has 2 bytes
*   -1: last payload only has 1 byte
*    0: packet does not have payload
*    1 -> nof_subheader - 1: having rar-subpayloads until (n-1) position,
*    for example, 1 means having 1 rar sub-payload (0th sub-payload index in the vector), eIdx = h: full payloads
*    nof_subheader: normal packet (nof_subheader full payloads)
*/
void macFuzzer_t::mutate_rar_n_subheaders(int nof_subheaders, std::vector<bool>& rarHeaderTypes, std::vector<macPDU_t>& db){
    
    // correct rapid mutation:
    for (int i = 0; i < nof_subheaders; i++){
        if (rarHeaderTypes[i]){ // true means rar subheader and rar grant
            macPDU_t lv1PDU;
            generate_initial_rar_packet(lv1PDU, nof_subheaders, rarHeaderTypes);
            lv1PDU.rar.subHea[i].is_correct_pid = true;
            lv1PDUtemp.push_back(std::move(lv1PDU));
        }
    }
    // add packet with no correct rapid
    macPDU_t lv1PDU_case2;
    generate_initial_rar_packet(lv1PDU_case2, nof_subheaders, rarHeaderTypes);
    lv1PDUtemp.push_back(std::move(lv1PDU_case2));

    // check if this packet has at least 1 rar grant
    bool has_rar_grant = std::find(rarHeaderTypes.begin(), rarHeaderTypes.end(), true) != rarHeaderTypes.end();

    // eIdx is used for packet truncation
    for (auto& lv1PDU: lv1PDUtemp){ // eIdx mutation (nof sub-payload mutation)
        for (int eIdx = 0; eIdx < nof_subheaders + 1; eIdx++){
            if (eIdx == 0){
                macPDU_t lv2PDU = lv1PDU;
                lv2PDU.eIdx = eIdx;
                lv2PDUtemp.push_back(std::move(lv2PDU));
            }else{                                          // only mutate eIdx for packets that have rar grant in the eIdx - 1 position`
                if (lv1PDU.rar.subHea[eIdx - 1].T == 1){
                    macPDU_t lv2PDU = lv1PDU;
                    lv2PDU.eIdx = eIdx;
                    lv2PDUtemp.push_back(std::move(lv2PDU));
                }
            }
        }
        if (has_rar_grant){
            for (int eIdx = -5; eIdx < 0; eIdx++){
                macPDU_t lv2PDU = lv1PDU;
                lv2PDU.eIdx = eIdx;
                lv2PDUtemp.push_back(std::move(lv2PDU));
            }
        }

        // idx -6
        macPDU_t lv2PDU_case6 = lv1PDU;
        lv2PDU_case6.eIdx = -6;
        lv2PDUtemp.push_back(std::move(lv2PDU_case6));
    }

    // mutate based on eIdx
    for (auto& lv2PDU: lv2PDUtemp){
        if (lv2PDU.eIdx < 0){
            mutate_mac_rar_minus_eidx(lv2PDU, lv2PDU.eIdx, db);
        }else{
            mutate_mac_rar_positive_eidx(lv2PDU, lv2PDU.eIdx, db);
        }
    }

    // clean up the temporary vector
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
    lv3PDUtemp.clear();
    lv3PDUtemp.shrink_to_fit();
    lv4PDUtemp.clear();
    lv4PDUtemp.shrink_to_fit();
}

/*  -6: no payload but the last subheader has E = 1
*   -5: last payload only has 5 bytes
*   -4: last payload only has 4 bytes
*   -3: last payload only has 3 bytes
*   -2: last payload only has 2 bytes
*   -1: last payload only has 1 byte
*    0: packet does not have payload
*    1 -> nof_subheader - 1: h full payloads
*    nof_subheader: normal packet (nof_subheader full payloads)
*/
void macFuzzer_t::mutate_rar_numerous_subheader(int nof_subheaders, std::vector<bool>& rarHeaderTypes, std::vector<macPDU_t>& db){
    // correct rapid muation:
    for (int i = 0; i < nof_subheaders - 1; i = i + 10){            // make sure that the final subheader is included
        if (rarHeaderTypes[i]){                                     // true means rar subheader and rar grant
            macPDU_t lv1PDU;
            lv1PDU.isManualDCI = true;                              // for numerous rar sub-header, we use manual dci
            generate_initial_rar_packet(lv1PDU, nof_subheaders, rarHeaderTypes);
            lv1PDU.rar.subHea[i].is_correct_pid = true;
            lv1PDUtemp.push_back(std::move(lv1PDU));
        }
    }
    if (rarHeaderTypes[nof_subheaders - 1]){                        // make sure that the final subheader is included
        macPDU_t lv1PDU_case2;
        lv1PDU_case2.isManualDCI = true;                              // for numerous rar sub-header, we use manual dci
        generate_initial_rar_packet(lv1PDU_case2, nof_subheaders, rarHeaderTypes);
        lv1PDU_case2.rar.subHea[nof_subheaders - 1].is_correct_pid = true;
        lv1PDUtemp.push_back(std::move(lv1PDU_case2));
    }
    // add packet with no correct rapid
    macPDU_t lv1PDU_case3;
    lv1PDU_case3.isManualDCI = true;                              // for numerous rar sub-header, we use manual dci
    generate_initial_rar_packet(lv1PDU_case3, nof_subheaders, rarHeaderTypes);
    lv1PDUtemp.push_back(std::move(lv1PDU_case3));

    // check if this packet has at least 1 rar grant
    bool has_rar_grant = std::find(rarHeaderTypes.begin(), rarHeaderTypes.end(), true) != rarHeaderTypes.end();

    for (auto& lv1PDU: lv1PDUtemp){ // eIdx mutation
        for (int eIdx = 0; eIdx < nof_subheaders + 1; eIdx = eIdx + 10){
            macPDU_t lv2PDU = lv1PDU;
            lv2PDU.eIdx = eIdx;
            lv2PDUtemp.push_back(std::move(lv2PDU));
        }
        if (has_rar_grant){
            for (int eIdx = -5; eIdx < 0; eIdx++){
                macPDU_t lv2PDU = lv1PDU;
                lv2PDU.eIdx = eIdx;
                lv2PDUtemp.push_back(std::move(lv2PDU));
            }
        }

        // idx -6
        macPDU_t lv2PDU_case6 = lv1PDU;
        lv2PDU_case6.eIdx = -6;
        lv2PDUtemp.push_back(std::move(lv2PDU_case6));
    }

    // mutate based on eIdx
    for (auto& lv2PDU: lv2PDUtemp){
        if (lv2PDU.eIdx < 0){
            mutate_mac_rar_minus_eidx(lv2PDU, lv2PDU.eIdx, db);
        }else{
            mutate_mac_rar_positive_eidx(lv2PDU, lv2PDU.eIdx, db);
        }
    }

    // clean up the temporary vector
    lv1PDUtemp.clear();
    lv1PDUtemp.shrink_to_fit();
    lv2PDUtemp.clear();
    lv2PDUtemp.shrink_to_fit();
    lv3PDUtemp.clear();
    lv3PDUtemp.shrink_to_fit();
    lv4PDUtemp.clear();
    lv4PDUtemp.shrink_to_fit();
}

void macFuzzer_t::initiate_mutation_values(){
    /* Init header, lcid and mapping information*/
    heaSizeMap[typeA] = 2;
    heaSizeMap[typeB] = 3;
    heaSizeMap[typeC] = 3;
    heaSizeMap[typeD] = 1;
    heaSizeMap[typeAe] = 3;
    heaSizeMap[typeBe] = 4;
    heaSizeMap[typeCe] = 4;
    heaSizeMap[typeDe] = 2;

    // for (int i=0; i< 16; i++){
    //   lcidNoCEList.push_back(i);
    // }
    lcidNoCEList.insert(lcidNoCEList.end(), {0,1,3,7,12,31}); // 6 members <---------
    lcidNoCEList2.insert(lcidNoCEList2.end(), {0,2,8,14, 25, 31}); // add 25: MCCH
    // for (int i=0; i< 5; i++){ //lcid except 
    //     lcidNoCEList.push_back(i);
    // }
    // lcidNoCEList.insert(lcidNoCEList.end(), {6, 10, 12, 15, 31}); // 31: padding | check here

    for (int i=0; i< 3; i++){ //lcid except 
        lcidNoCEListState234.push_back(i);
    }
    lcidNoCEListState234.insert(lcidNoCEListState234.end(), {4, 6, 8, 12, 15}); // 31: padding | check here

    lcidNoCEListState234Arr[0].insert(lcidNoCEListState234Arr[0].end(), {0, 2, 4, 6});
    lcidNoCEListState234Arr[1].insert(lcidNoCEListState234Arr[1].end(), {0, 1, 5, 9});


    // for (int i=18; i< 31; i++){ // CE list except padding 31
    //     lcidCEList.push_back(i);
    // }
    lcidCEList.insert(lcidCEList.end(), {18, 20, 22, 24, 26, 28, 31}); // 7 members <---------
    lcidCEList2.insert(lcidCEList2.end(), {19, 21, 23, 27, 29, 30, 31}); // 7 members <---------

    lcidCEListArr[0].insert(lcidCEListArr[0].end(), {17, 19, 21, 23, 27, 29}); // 16
    lcidCEListArr[1].insert(lcidCEListArr[1].end(), {18, 20, 22, 24, 26, 28, 30});

    lcidCEpayloadList.insert(lcidCEpayloadList.end(), {29, 28, 27, 24, 22, 21, 20, 19, 18});

    // ce_name_str
    for (int lcid = 0; lcid < 17; lcid++){
        // std::string tempStr = " ";
        ce_name_str.push_back(" "); // not ce
    }
    cePaySize[17]   = 0; // NB-IoT Downlink Channel Quality Report, fixed size of 0 bits -> 0 bytes
    ce_name_str[17] = "NB-IoT DL Channel Qua Report";
    cePaySize[18]   = 1; // 1 byte Activation/Deactivation of PDCP duplication, "1" indicates activation for corresponding DRB
    ce_name_str[18] = "PDCP Duplication";
    cePaySize[19]   = 1; // Hibernation (1 octet)
    ce_name_str[19] = "Hibernation";
    cePaySize[20]   = 4; // Hibernation 4 bytes
    ce_name_str[20] = "Hibernation(4)";
    cePaySize[21]   = 1; // Activation of CSI-RS
    ce_name_str[21] = "CSI-RS-Act";
    cePaySize[22]   = 2; // Recommended bit rate
    ce_name_str[22] = "Recmd-Bitrate";
    cePaySize[23]   = 0; // SC-PMT stop, NB-IoT, fixed size of 0 bits -> 0 bytes
    ce_name_str[23] = "SC-PMT-Stop";
    cePaySize[24]   = 4; // activation/deactivation 4 bytes
    ce_name_str[24] = "Act/Deact(4)";
    // cePaySize[25] = 1; // SC-MCCH logical channel for NB-IoT, not MAC CEs
    ce_name_str[25] = "SC-MCCH";
    cePaySize[26]   = 0; //
    ce_name_str[26] = "Long-DRX";
    cePaySize[27]   = 1; // activation/deactivation
    ce_name_str[27] = "Act/Deact";
    cePaySize[28]   = 6; // contention resolution
    ce_name_str[28] = "Cont-Res";
    cePaySize[29]   = 1; // TA command
    ce_name_str[29] = "TA-Command";
    cePaySize[30]   = 0; // drx command
    ce_name_str[30] = "DRX"; 
    cePaySize[31]   = 0; // padding
    ce_name_str[31] = "Padding";    

    // cePaySize[31] = 0; // padding
    // cePaySize[30] = 0; // drx command 
    // cePaySize[29] = 1; // TA command
    // cePaySize[28] = 6; // contention resolution
    // cePaySize[27] = 1; // activation/deactivation
    // cePaySize[26] = 0; 
    // // cePaySize[25] = 1; // SC-MCCH logical channel for NB-IoT, not MAC CE
    // cePaySize[24] = 4; // activation/deactivation 4 bytes
    // cePaySize[23] = 0; // SC-PMT stop, NB-IoT, fixed size of 0 bits -> 0 bytes
    // cePaySize[22] = 2; // Recommended bit rate
    // cePaySize[21] = 1; // Activation of CSI-RS
    // cePaySize[20] = 4; // Hibernation 4 bytes
    // cePaySize[19] = 1; // Hibernation (1 octet)
    // cePaySize[18] = 1; // 1 byte Activation/Deactivation of PDCP duplication
    // cePaySize[17] = 0; // NB-IoT Downlink Channel Quality Report, fixed size of 0 bits -> 0 bytes

    
    typeList.insert(typeList.end(), {typeA, typeB, typeC, typeD}); //typeB

    typeListArr[0].insert(typeListArr[0].end(), {typeA, typeB, typeD});
    typeListArr[1].insert(typeListArr[1].end(), {typeA, typeC, typeD});

    typeListArr_boundary[0].insert(typeListArr_boundary[0].end(), {typeB, typeD}); // for boudary value mutation
    typeListArr_boundary[1].insert(typeListArr_boundary[1].end(), {typeC, typeD});

    typeListLast.insert(typeListLast.end(), {typeD});

    rList.insert(rList.end(), {0,1}); //

    // for (int i=0; i< 32; i++){
    //     lcidAllList.push_back(i);
    // }
    // combine lcidCEList and lcidnoCEList
    lcidAllList.insert(lcidAllList.end(), lcidCEList.begin(), lcidCEList.end());
    lcidAllList.insert(lcidAllList.end(), lcidNoCEList.begin(), lcidNoCEList.end()); // 13 members <---------

    lcidAllList2.insert(lcidAllList2.end(), lcidCEList2.begin(), lcidCEList2.end());
    lcidAllList2.insert(lcidAllList2.end(), lcidNoCEList2.begin(), lcidNoCEList2.end()); // 13 members <---------

    lcidAllList234 = lcidCEList;
    lcidAllList234.insert(lcidAllList234.end(), {0, 1, 2, 4, 6, 8, 12, 15});
    lcidAllList234Arr[0].insert(lcidAllList234Arr[0].end(), {0, 2, 4, 6, 11, 16, 17, 19, 21, 23, 25, 27, 29});
    lcidAllList234Arr[1].insert(lcidAllList234Arr[1].end(), {0, 1, 5, 9, 14, 17, 18, 20, 22, 24, 26, 28, 30});

    for (int i=0; i< 11; i++){
        lcidChannelList.push_back(i);
    }

    for (int i=11; i< 16; i++){
        lcidReservedList.push_back(i);
    }
    
    idList.insert(idList.end(), {true, false});

    len7bitList.insert(len7bitList.end(), {0, 127}); 
    len15bitList.insert(len15bitList.end(), {0, 32767}); //
    len16bitList.insert(len16bitList.end(), {0, 65535}); //
    
    LListRef[typeA] = len7bitList;
    LListRef[typeB] = len15bitList;
    LListRef[typeC] = len16bitList;

    for (int i = 0; i < 7; i = i + 2){
        eLCIDlist.push_back(i);
    }
    for (int i = 7; i < 64; i = i + 20){
        eLCIDlist.push_back(i);
    }

    f2List.insert(f2List.end(), {0, 1});

    // rar mutation list
    boolList.insert(boolList.end(), {true, false});

    for (int i = 0; i < 7; i++){
        pidList.push_back(static_cast<int>(std::pow(2, i) - 1));
    }

    for (int i = 0; i < 5; i++){
        biList.push_back(static_cast<int>(std::pow(2, i) - 1));
    }

    for (int i = 0; i < 12; i = i + 2){
        taList.push_back(static_cast<int>(std::pow(2, i) - 1));
    }

    for (int i = 0; i < 21; i = i + 3){
        ulGrantList.push_back(static_cast<int>(std::pow(2, i) - 1));
    }

    for (int i = 0; i < 17; i = i + 4){
        tcrntiList.push_back(static_cast<int>(std::pow(2, i) - 1));
    }
    tcrntiList.insert(tcrntiList.end(), {2, 7, 9, 65534}); // ra-rnti and p-rnti

    // init legitimate values for rar, these values are from a real rar packet
    legitimate_rar_grant.ta = 1;
    legitimate_rar_grant.ulGrant = 52236;
    legitimate_rar_grant.tcrnti = 70;
    legitimate_rar_subheader.pid = 42;
}

void macFuzzer_t::generate_test_cases(){
    
    initiate_mutation_values();
    
    // mutate rar ------
    int nof_subheaders = 3;
    std::vector<bool> rarHeaderTypes;
    rarHeaderTypes.insert(rarHeaderTypes.end(), {1,1,1}); // 4 rar subheaders
    mutate_rar_n_subheaders(nof_subheaders, rarHeaderTypes, testcaseDB[1]);
    // std::cout << "[MTT] Generated " << testcaseDB[1].size() << " RAR test cases with nofSubHeaders = 3" << "\n";

    rarHeaderTypes.clear();
    rarHeaderTypes.insert(rarHeaderTypes.end(), {0,0,0}); // 4 bi subheaders
    mutate_rar_n_subheaders(nof_subheaders, rarHeaderTypes, testcaseDB[1]);
    // std::cout << "[MTT] Generated " << testcaseDB[1].size() << " RAR test cases with nofSubHeaders = 3" << "\n";

    rarHeaderTypes.clear();
    rarHeaderTypes.insert(rarHeaderTypes.end(), {1,1,0}); // 3 rar subheaders and 1 bi subheader
    mutate_rar_n_subheaders(nof_subheaders, rarHeaderTypes, testcaseDB[1]);
    // std::cout << "[MTT] Generated " << testcaseDB[1].size() << " RAR test cases with nofSubHeaders = 3" << "\n";

    rarHeaderTypes.clear();
    rarHeaderTypes.insert(rarHeaderTypes.end(), {0, 1, 1}); // 1 bi subheader and 3 rar subheaders
    mutate_rar_n_subheaders(nof_subheaders, rarHeaderTypes, testcaseDB[1]);
    // std::cout << "[MTT] Generated " << testcaseDB[1].size() << " RAR test cases with nofSubHeaders = 3" << "\n";

    // generate test case with numerous subheaders
    nof_subheaders = 39;
    rarHeaderTypes.clear();
    for (int i = 0; i < nof_subheaders; i++){
        rarHeaderTypes.push_back(1);
    }
    mutate_rar_numerous_subheader(nof_subheaders, rarHeaderTypes, testcaseDB[1]);
    // std::cout << "[MTT] Generated " << testcaseDB[1].size() << " RAR test cases with nofSubHeaders = 39" << "\n";

    rarHeaderTypes.clear();
    for (int i = 0; i < nof_subheaders; i++){
        rarHeaderTypes.push_back(0);
    }
    mutate_rar_numerous_subheader(nof_subheaders, rarHeaderTypes, testcaseDB[1]);
    // std::cout << "[MTT] Generated " << testcaseDB[1].size() << " RAR test cases with nofSubHeaders = 39" << "\n";

    // 19 Bi subheaders and 20 RAR subheaders
    rarHeaderTypes.clear();
    for (int i = 0; i < nof_subheaders; i++){
        if (i < 20){
            rarHeaderTypes.push_back(0);
        }else{
            rarHeaderTypes.push_back(1);
        }
    }
    mutate_rar_numerous_subheader(nof_subheaders, rarHeaderTypes, testcaseDB[1]);
    // std::cout << "[MTT] Generated " << testcaseDB[1].size() << " RAR test cases with nofSubHeaders = 39" << "\n";

    // mutate 1 subheader after manually allocating dci
    mutate_1_new(testcaseDB[state2], typeD);
    mutate_1_new(testcaseDB[state2], typeC);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 1 using new function" << "\n";

    mutate_1_eLCID_new(testcaseDB[state2], typeDe);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " eLCID test cases with nofSubHeaders = 1 using new function" << "\n";

    // generate test case for long eLCID:
    mutate_eLCID_long(100, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " eLCID test cases with nofSubHeaders = 100 using new function" << "\n";

    // generate DLSCH test cases with 3 sub-header, this is not extended LCID case --------------------
    std::vector<macSubHeaderType_t> temp_header_type_list;
    // generate typeA, TypeB, TypeD
    temp_header_type_list.insert(temp_header_type_list.end(), {typeA, typeB, typeD});
    mutate_packet_n_subheaders(3, temp_header_type_list, false, 0, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 using new function" << "\n";

    // generate typeA typeC, typeD
    temp_header_type_list.clear();
    temp_header_type_list.insert(temp_header_type_list.end(), {typeA, typeC, typeD});
    mutate_packet_n_subheaders(3, temp_header_type_list, false, 0, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 using new function" << "\n";

    // generate type. typeD, typeD, typeD
    temp_header_type_list.clear();
    temp_header_type_list.insert(temp_header_type_list.end(), {typeD, typeD, typeD});
    mutate_packet_n_subheaders(3, temp_header_type_list, false, 0, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 using new function" << "\n";

    // generate typeD typeA typeD, mutate MAC CE here
    temp_header_type_list.clear();
    temp_header_type_list.insert(temp_header_type_list.end(), {typeD, typeA, typeD});
    mutate_packet_n_subheaders(3, temp_header_type_list, true, 0, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 using new function" << "\n";

    // ------------------------------------list 2--------------------------------
    temp_header_type_list.clear();
    temp_header_type_list.insert(temp_header_type_list.end(), {typeA, typeB, typeD});
    mutate_packet_n_subheaders(3, temp_header_type_list, false, 1, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 using new function, list 2" << "\n";

    // generate type. typeC, typeD
    temp_header_type_list.clear();
    temp_header_type_list.insert(temp_header_type_list.end(), {typeA, typeC, typeD});
    mutate_packet_n_subheaders(3, temp_header_type_list, false, 1, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 using new function , list 2" << "\n";

    // generate type. typeD, typeD, typeD
    temp_header_type_list.clear();
    temp_header_type_list.insert(temp_header_type_list.end(), {typeD, typeD, typeD});
    mutate_packet_n_subheaders(3, temp_header_type_list, false, 1, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 using new function, list 2" << "\n";

    // generate typeD typeA typeD
    temp_header_type_list.clear();
    temp_header_type_list.insert(temp_header_type_list.end(), {typeD, typeA, typeD});
    mutate_packet_n_subheaders(3, temp_header_type_list, true, 1, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 using new function, list 2" << "\n";


    /*Generate test case 3 subheaders eLCID---------------*/
    mutate_eLCID_new(3, {typeAe, typeBe, typeDe}, testcaseDB[state2]);
    mutate_eLCID_new(3, {typeAe, typeCe, typeDe}, testcaseDB[state2]);
    mutate_eLCID_new(3, {typeBe, typeCe, typeDe}, testcaseDB[state2]);
    mutate_eLCID_new(3, {typeA, typeAe, typeDe}, testcaseDB[state2]);
    mutate_eLCID_new(3, {typeD, typeBe, typeDe}, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 3 eLCID" << "\n";

    // mutate packet with 50 subheaders, main steps are similar as in mutate_packet_n_subheaders ------------------
    int nofSubHea = 50;
    temp_header_type_list.clear();
    for (int i = 0; i < nofSubHea - 1; i++){
        temp_header_type_list.push_back(typeA);
    }
    temp_header_type_list.push_back(typeD);
    mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(nofSubHea, temp_header_type_list, testcaseDB[state2], false);
    mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(nofSubHea, temp_header_type_list, testcaseDB[state2], true);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 50 using new function" << "\n";

    temp_header_type_list.clear();
    for (int i = 0; i < nofSubHea - 1; i++){
        temp_header_type_list.push_back(typeB);
    }
    temp_header_type_list.push_back(typeD);
    mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(nofSubHea, temp_header_type_list, testcaseDB[state2], false);
    mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(nofSubHea, temp_header_type_list, testcaseDB[state2], true);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 50 using new function" << "\n";

    temp_header_type_list.clear();
    for (int i = 0; i < nofSubHea - 1; i++){
        temp_header_type_list.push_back(typeC);
    }
    temp_header_type_list.push_back(typeD);
    mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(nofSubHea, temp_header_type_list, testcaseDB[state2], false);
    mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(nofSubHea, temp_header_type_list, testcaseDB[state2], true);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 50 using new function" << "\n";

    temp_header_type_list.clear();
    for (int i = 0; i < nofSubHea - 1; i++){
        temp_header_type_list.push_back(typeD);
    }
    temp_header_type_list.push_back(typeD);
    mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(nofSubHea, temp_header_type_list, testcaseDB[state2], false);
    mutate_packet_numerous_subheader_AAAD_BBBD_CCCD_DDDD(nofSubHea, temp_header_type_list, testcaseDB[state2], true);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 50 using new function" << "\n";

    temp_header_type_list.clear();
    for (int i = 1; i < nofSubHea - 1; i++){
        temp_header_type_list.push_back(typeA);
    }
    // insert typeD at the first
    temp_header_type_list.insert(temp_header_type_list.begin(), typeD);
    temp_header_type_list.push_back(typeD);
    mutate_packet_numerous_subheader_DAAD(nofSubHea, temp_header_type_list, testcaseDB[state2]);
    // std::cout << "[MTT] Generated " << testcaseDB[state2].size() << " test cases with nofSubHeaders = 50 using new function" << "\n";

    testcaseDB[state3] = testcaseDB[state2];
    testcaseDB[state4] = testcaseDB[state2];
    // std::cout << "[MTT] Generated " << tcState4DB.size() << " test cases for state 4" << "\n";
    /*-----------------------------------------------------------------------------*/

    if (readFromFileMode){
        std::cout << "Read from file mode ....." << "\n";

        // previous manual test cases used to verify bugs on different devices
        load_manual_testcase();

        // std::cout << "[MTT] Finally Generated: " << verifyDB[2].size() << " " << verifyDB[3].size() << " " << verifyDB[4].size() << " " << verifyDB[5].size() << "\n";    
    
    }

}

void macFuzzer_t::load_manual_testcase(){
    // readTCfromFile(fromFile);

}

void macFuzzer_t::stopFuzzing(){
    fuzzingState = stateUnknown;
    if (DEBUG_MODE){ 
      printf("[MAC] Stop fuzzing............ \n"); 
    }
}

macPDU_t macFuzzer_t::getCurTestCase(){
    if (readFromFileMode){
        curTestCase = verifyDB[fuzzingState][idx[fuzzingState]];
    }else{
        curTestCase = testcaseDB[fuzzingState][idx[fuzzingState]];
    }
    return curTestCase;
}

// int macFuzzer_t::get_cur_testcase_idx(LLState_t state, bool isverifying){
//     if (state > 5){
//         ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
//     }
//     return idx[state];
// }

int macFuzzer_t::get_total_idx(LLState_t state, bool isverifying){
    if (state > 5){
        ERROR("[LLFuzz] Accessing out of bound state in get_cur_testcase_idx\n");
    }
    return (isverifying)?verifyDB[state].size():testcaseDB[state].size();
}

int macFuzzer_t::get_injecting_lcid(){
    // return (fuzzingState > state2)? 1: 0;
    return 0;
}

int macFuzzer_t::get_injecting_length(){
    int len = 0;
    getCurTestCase();
    int lcid = get_injecting_lcid();

    // std::cout << "[LLFuzz] Get injecting length, LCID = " << lcid << " -- Idx = " << idx[fuzzingState] << "tcByte: " << curTestCase.totalByte << "\n";
    if (curTestCase.totalByte == 0){
        printf("[LLFuzz] Error: totalByte is 0, idx = %d, fuzzingState = %d\n", idx[fuzzingState], fuzzingState);
        macPDU_t& testcasetemp = testcaseDB[fuzzingState][idx[fuzzingState]];
        printf("[LLFuzz] Error: totalByte is 0, idx = %d, fuzzingState = %d, totalByte = %d\n", idx[fuzzingState], fuzzingState, testcasetemp.totalByte);
    }

    len = (lcid == 0)?(curTestCase.totalByte - 2):(curTestCase.totalByte - 7);                           // if SRB0, subtract 2 bytes for header, else subtract 7 bytes
    if (curTestCase.verify){ len = (lcid == 0)?(curTestCase.verifyLen - 2):(curTestCase.verifyLen - 7);} // if verify, use verify length
    len = (len <= 0)?1:len;
    if (curTestCase.iseLCID){ len = len + 3;}

    return len;
}

int macFuzzer_t::get_total_byte_cur_testcase(){
    return curTestCase.totalByte;
}

bool macFuzzer_t::get_manual_dci(){
    return curTestCase.isManualDCI;
}

int macFuzzer_t::get_nof_injecting_rar(){
    if (fuzzingState == state1){
        curTestCase = testcaseDB[fuzzingState][idx[fuzzingState]];
        int totalByte = curTestCase.totalByte;
        return (totalByte/7 + 1); // 7 bytes for each RAR, 1 byte for sub-header and 6 bytes for rar grant (payload)
    }else{
        return 0;
    }
}

// TODO:
void macFuzzer_t::saveCrashtoFile(int oracle){
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
    std::deque<macPDU_t> recent_pdu = crashBuffer.getBuffer();
    crashLogFile << " Recent PDU: " << "\n";
    for (int i = 0; i < (int)recent_pdu.size(); i++){
        recent_pdu[i].print_general_info_to_file(crashLogFile);

        if (fuzzingState == state1){
            for (int h = 0; h < recent_pdu[i].nofSubHea; h++){
                recent_pdu[i].rar.subHea[h].print_to_file(crashLogFile);
            }
            for (int h = 0; h < recent_pdu[i].nofSubHea; h++){
                recent_pdu[i].rar.subPay[h].print_to_file(crashLogFile);
            }
        }else{
            for (int h = 0; h < recent_pdu[i].nofSubHea; h++){
                recent_pdu[i].subHea[h].print_to_file(crashLogFile);
            }
            for (int h = 0; h < recent_pdu[i].nofSubHea; h++){
                recent_pdu[i].subPay[h].print_to_file(crashLogFile);
            }
        }
        crashLogFile << "\n";
    }
        
    crashLogFile << "\n";
    crashLogFile << "\n";
    nofCrash++;
}

/* Supporting functions ___________________________________*/

rarResult_t formRarPayload(bool R, int ta, int grant, int rnti){
    rarResult_t result;
    uint8_t ta1     = static_cast<uint8_t>(ta >> 4); //  11 bits ta, oct1 has 7 bits, oct2 4 bits
    uint8_t ta2     = static_cast<uint8_t>(ta & 0x0f); // get final 4 bits
    uint8_t grant2  = static_cast<uint8_t>(grant >> 16); //  20 bits grant, oct2 has 4 bits, oct3,4 8 bits for each
    uint8_t grant3  = static_cast<uint8_t>((static_cast<uint8_t>(grant >> 8)) & 0xff);
    uint8_t grant4  = static_cast<uint8_t>(grant & 0xFF);
    uint8_t rnti5   = static_cast<uint8_t>(rnti >> 8);
    uint8_t rnti6   = static_cast<uint8_t>(rnti & 0xff);
    /*write result*/
    result.pattern[0] = std::pow(2, 7)*R + ta1;
    result.pattern[1] = (ta2 << 4) | (grant2 & 0x0F);
    result.pattern[2] = grant3;
    result.pattern[3] = grant4;
    result.pattern[4] = rnti5;
    result.pattern[5] = rnti6;
    result.len = 6;

  return result;
}

rarResult_t formBiHeader(bool E, bool R1, bool R2, int bi) {
    rarResult_t result;
    // uint8_t E_u8 = static_cast<uint8_t>(E);
    // uint8_t R1_u8 = static_cast<uint8_t>(R1);
    // uint8_t R2_u8 = static_cast<uint8_t>(R2);
    // uint8_t bi_u8 = static_cast<uint8_t>(bi);
    // result.pattern[0] = (E_u8 << 7) | (R1_u8 << 5) | (R2_u8 << 4) | (bi_u8 & 0x0F);
    result.pattern[0] = pow(2, 7)*E + pow(2, 5)*R1 + pow(2, 4)*R2 + bi;
    result.len = 1;
    return result;
}

rarResult_t formRarHeader(bool E, int pid) {
    rarResult_t result;
    // uint8_t pid_u8 = static_cast<uint8_t>(pid);
    // uint8_t E_u8 = static_cast<uint8_t>(E);
    uint8_t T = 1;
    // result.pattern[0] = (E_u8 << 7) | (T << 6) | (pid_u8 & 0x1F);
    result.pattern[0] = pow(2, 7)*E + pow(2, 6)*T + pid;
    result.len = 1;
    return result;
}

/*--------------------------------------------------------------------------------------------*/

bool macFuzzer_t::check_offset_rar_testcase(macPDU_t& rar, int actualLen){
    bool ret = false;
    if (rar.eIdx == rar.nofSubHea){ // this is normal rar, padding will be automatically added by PHY
        return ret;
    }

    int offsetByte = actualLen - rar.totalByte;
    int nof_rar_subhea = 0;
    int nof_bi_subhea = 0;
    for (int i = 0; i < rar.nofSubHea; i++){
        if (rar.rar.subHea[i].T == 1){
            nof_rar_subhea++;
        }else{
            nof_bi_subhea++;
        }
    }
    rar.orinByte = rar.totalByte; // save original byte for debug and crash log
    rar.orinSubH = rar.nofSubHea;
    rar.orinEIdx = rar.eIdx;
    ret = true;
    
    while (offsetByte > 0){
        if (1){ // add 1 rar sub-header until fill the remaining bytes
            // find location of the last bi subheader, if there is no bi subheader, add new subheader to the first position
            int last_bi_subhea  = -1;
            for (int i = 0; i < rar.nofSubHea; i++){
                if (rar.rar.subHea[i].T == 0){
                    last_bi_subhea = i;
                }
            }
            last_bi_subhea = (last_bi_subhea == -1)?0:last_bi_subhea;
            // make a new subheader and subpayload
            rarSubHeader_t newSubHea;
            newSubHea.T = 0;
            newSubHea.BI = 1;
            newSubHea.E = 1;
            rarSubPayload_t newSubPay; // this subpayload is just for matching number of subheaders and subpayloads
            // in this case, we all the new subheader to left of the last bi subheader
            rar.rar.subHea.insert(rar.rar.subHea.begin() + last_bi_subhea, newSubHea);
            rar.rar.subPay.insert(rar.rar.subPay.begin() + last_bi_subhea, newSubPay);
            
            rar.eIdx = (rar.eIdx > 0 && last_bi_subhea < rar.eIdx)? rar.eIdx + 1: rar.eIdx; // increase eIdx by 1 because we add 1 subpayload before expected eIdx
            rar.nofSubHea++;
            rar.totalByte = rar.totalByte + 1;
            offsetByte = offsetByte - 1;
        }
    }

    return ret;
}

void macFuzzer_t::assemble_rar_packet(macPDU_t& rar, uint8_t* payload, int len){
    int pos = 0;
    int last_rar_subhea_idx = -1;
    rarResult_t rarResult; // general result for containing all subheaders and subpayloads

    // assemble all subheaders first, all eIdx have subheaders
    for (int i = 0; i < rar.nofSubHea; i++){
        if (rar.rar.subHea[i].T == 1){
            // int pid = (rar.rar.subHea[i].is_correct_pid)?legitimate_rar_subheader.pid:rar.rar.subHea[i].pid;
            rar.rar.subHea[i].pid = (rar.rar.subHea[i].is_correct_pid)? legitimate_rar_subheader.pid : rar.rar.subHea[i].pid;
            rarResult = formRarHeader(rar.rar.subHea[i].E, rar.rar.subHea[i].pid);
        }else{
            rarResult = formBiHeader(rar.rar.subHea[i].E, rar.rar.subHea[i].R1, rar.rar.subHea[i].R2, rar.rar.subHea[i].BI);
        }
        for (int j = 0; j < rarResult.len; j++){
            if (pos < len){
                payload[pos] = rarResult.pattern[j];
                pos++;
            }else{
                std::cout << "[MTT] Assemble RAR subheader: Out of bound\n";
            }
        }
        if (rar.rar.subPay[i].isLastGrant){
            last_rar_subhea_idx = i;
        }
    }

    // assemble sub-payloads
    if (rar.eIdx < 0 && rar.eIdx > -6){ // assemble until the last rar sub-payload (grant), -6 does not have payload
        for (int i = 0; i < last_rar_subhea_idx + 1; i++){
            if (rar.rar.subHea[i].T == 1){
                // asign the last grant to the last subpayload
                rar.rar.subPay[i].ta = (rar.rar.subHea[i].is_correct_pid)? legitimate_rar_grant.ta : rar.rar.subPay[i].ta;  
                rar.rar.subPay[i].ulGrant = (rar.rar.subHea[i].is_correct_pid)? legitimate_rar_grant.ulGrant : rar.rar.subPay[i].ulGrant;
                rar.rar.subPay[i].tcrnti = (rar.rar.subHea[i].is_correct_pid)? legitimate_rar_grant.tcrnti : rar.rar.subPay[i].tcrnti;
                rarResult = formRarPayload(rar.rar.subPay[i].R, rar.rar.subPay[i].ta, rar.rar.subPay[i].ulGrant, rar.rar.subPay[i].tcrnti);
                if (rar.rar.subPay[i].isLastGrant){
                    rarResult.len = abs(rar.eIdx);
                }
            }else{
                rarResult.len = 0;
            }
            for (int j = 0; j < rarResult.len; j++){
                if (pos < len){
                    payload[pos] = rarResult.pattern[j];
                    pos++;
                }else{
                    std::cout << "[MTT] Assemble RAR subpayload: Out of bound\n";
                }
            }
        }
    }else if(rar.eIdx >= 0){ // assemble sub-payloads until eIdx
        for (int i = 0; i < rar.eIdx; i++){
            if (rar.rar.subHea[i].T == 1){
                // asign the last grant to the last subpayload
                rar.rar.subPay[i].ta = (rar.rar.subHea[i].is_correct_pid)? legitimate_rar_grant.ta : rar.rar.subPay[i].ta;  
                rar.rar.subPay[i].ulGrant = (rar.rar.subHea[i].is_correct_pid)? legitimate_rar_grant.ulGrant : rar.rar.subPay[i].ulGrant;
                rar.rar.subPay[i].tcrnti = (rar.rar.subHea[i].is_correct_pid)? legitimate_rar_grant.tcrnti : rar.rar.subPay[i].tcrnti;
                rarResult = formRarPayload(rar.rar.subPay[i].R, rar.rar.subPay[i].ta, rar.rar.subPay[i].ulGrant, rar.rar.subPay[i].tcrnti);
                for (int j = 0; j < rarResult.len; j++){
                    if (pos < len){
                        payload[pos] = rarResult.pattern[j];
                        pos++;
                    }else{
                        std::cout << "[MTT] Assemble RAR subpayload: Out of bound\n";
                    }
                }
            }
        }
    }
}

void macFuzzer_t::print_rar_testcase(macPDU_t rar, bool isOffset, int actualLen){
    std::cout << "[PDU] Nof_Sub = " << (int)rar.nofSubHea << "|" << (int)rar.orinSubH << " - OrinByte = " << (int)rar.totalByte \
    <<"|" << (int)rar.orinByte << " - ActlLen = " << actualLen << BLUE_TEXT << " - eIdx = " << (int)rar.eIdx << RESET_COLOR << "\n";

    int max_print = (rar.nofSubHea < 10) ? rar.nofSubHea: 10;
    for (int h = 0; h < max_print; h++){
        rar.rar.subHea[h].print();
    }
    for (int h = 0; h < max_print; h++){
        if (rar.rar.subHea[h].T == 1){
            rar.rar.subPay[h].print();
        }
    }

    std::cout << "\n";
}

void macFuzzer_t::send_rar_test_case(int nofGrant, int tti_tx_dl, uint8_t* payload, int len){
    if (len >= curTestCase.totalByte){
        int offset_byte = len - curTestCase.totalByte;
        bool isOffset = false;

        // print test case before offset:
        // curTestCase.print_general_info();
        // for (int i = 0; i < curTestCase.nofSubHea; i++){
        //     curTestCase.rar.subHea[i].print();
        // }
        // for (int i = 0; i < curTestCase.nofSubHea; i++){
        //     curTestCase.rar.subPay[i].print();
        // }

        if (offset_byte > 0){
            isOffset = check_offset_rar_testcase(curTestCase, len);
        }
        // assemble the rar packet
        assemble_rar_packet(curTestCase, payload, len);

        // print out the rar packet
        std::vector<macPDU_t> curDB = testcaseDB[fuzzingState];
        if (DEBUG_MODE){
            std::cout << "[MAC] SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << " -- Sending State: " << (int)fuzzingState << ", RNTIState =  " \
                << fuzzingState << " -- Idx = " << idx[fuzzingState] << "/" << curDB.size() << " -- nofCrash: " << nofCrash << "\n";
            print_rar_testcase(curTestCase, isOffset, len);
        }

        // save the recent index
        recent_testcases[fuzzingState].push(idx[fuzzingState]);

        // increase the index
        if (idx[fuzzingState] < (int)(curDB.size() - 1)){
            idx[fuzzingState]++;
        }else{
            // idx[fuzzingState] = 0;
            fuzzingState = stateUnknown;
        }
    }else{
        std::cout << "[MTT] Send RAR: Actual length is smaller than expected length. " << curTestCase.totalByte << " - " << len << "\n";
    }
    
}

/*This functions check whether the actual bytes allocated by PHY & MAC exceed the injected bytes or not
* If yes, it will return true and make a offset SubHeader to compensate for the exceeding bytes
* Note that we need to check if the actual Len exceed the position of expected crash (eIdx) or not
*/
bool macFuzzer_t::checkOffsetSubHea(macPDU_t &testcase, int actualLen){
    bool ret = false;
    int  totalHeaderLen = 0;
    for (int i = 0; i < curTestCase.nofSubHea; i++){
        totalHeaderLen += curTestCase.subHea[i].headerSize;
    }
    int offsetByte = actualLen - curTestCase.totalByte;
    int eIdx = curTestCase.eIdx;
    if (offsetByte > 0){ // save orin info for debug and crash log
        testcase.orinByte = testcase.totalByte; 
        testcase.orinSubH = testcase.nofSubHea;
    }

    /*  -4: last subheader has E = 1 but no avialble byte behind
    *   -3: last subheader has E = 1, F2 = 1 (typeC) but available bytes are not enough for F2 (1 or 2)
    *   -2: last subheader has E = 1, F2 = 0, F = 1 (typeB) but available bytes are not enough for typeB (1 or 2)
    *   -1: packet does not have payload
    *   -5: last subheader has E = 0, F2 = 1, this indicates header is type C, but dont have any available byte behind
    */
    if (eIdx <= -1 && offsetByte > 0){ // -1 means all headers, we will inject only offset subheaders
        int remainingByte = offsetByte;
        ret = true;
        int lcidOffset = testcase.subHea[testcase.nofSubHea - 1].lcid; // get lcid of last subheader to inject offset subheader
        bool isCElcid = false;
        if (testcase.subHea[testcase.nofSubHea - 1].lcid >= 16 && testcase.subHea[testcase.nofSubHea - 1].lcid <= 30){ // if last licd is CE lcid
            isCElcid = true;
        }
        while(remainingByte != 0){
            macSubHeaderType_t offsetType = typeD;
            macSubHeader_t  offSubHea; // lcid = 23, SC-PRM stop indicator that does not have payload
            macSubPayload_t offSubPay;
            if (isCElcid){ // if last lcid is CE, inject all CE subheaders
                offsetType = typeD;
                autoFillSubHea(offSubHea, offSubPay, offsetType, false, false, 0, lcidOffset, 0, testcase.eIdx, testcase.nofSubHea - 1); // subheader index is before the last subheader
            }else{
                int modByte = remainingByte % 3; // consider which subheadertype to inject
                if (modByte == 1){ // add 1 offsetSubHea
                    offsetType = typeD;
                    autoFillSubHea(offSubHea, offSubPay, offsetType, false, false, 0, 23, 0, testcase.eIdx, testcase.nofSubHea - 1);
                }else if (modByte == 2){
                    offsetType = typeA;
                    autoFillSubHea(offSubHea, offSubPay, offsetType, false, false, 0, lcidOffset, 1, testcase.eIdx, testcase.nofSubHea - 1); // 1 byte len to not making malformed packet with L = 0
                }else if (modByte == 0){ // this means remaining bytes is multple times of 3 bytes
                    offsetType = typeB; // 3 bytes
                    autoFillSubHea(offSubHea, offSubPay, offsetType, false, false, 0, lcidOffset, 1, testcase.eIdx, testcase.nofSubHea - 1);
                }
            }
            testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
            testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
            testcase.nofSubHea++;
            testcase.totalByte = testcase.totalByte + heaSizeMap[offsetType];
            remainingByte = remainingByte - heaSizeMap[offsetType];
        }
        if (testcase.totalByte != actualLen){ 
            // printf("[GEN] Total Bytes is not equal actual Bytes after adding offset\n"); 
        }
    
    }else if (offsetByte > 0 && eIdx > -1){
        int headL = totalHeaderLen;
        int tailL = totalHeaderLen; // [head,tail] is boudary of expected crash based on eIdx
        for (int j  = 0; j < curTestCase.eIdx; j ++){
            headL += curTestCase.subPay[j].size;
        }
        for (int j  = 0; j < curTestCase.eIdx + 1; j ++){
            tailL += curTestCase.subPay[j].size;
        }
        if (actualLen > headL && actualLen < tailL){ // if actual len still in the range of expected crash, we dont need to offset
            ret =   false;
        }else{
            ret = true;
            testcase.subHea[eIdx].L += offsetByte; // add offset byte to L of subheader at eIdx
            // macSubHeaderType_t offsetType;
            // macSubHeader_t  offSubHea; // lcid = 23 or 0, 23: SC-PRM stop indicator that does not have payload
            // macSubPayload_t offSubPay;
            // if (offsetByte < 2){ // only enough for 1 subheader type D
            //     offsetType = typeD;
            //     autoFillSubHea(offSubHea, offSubPay, offsetType, false, false, 0, 23, 0);
            // }else{
            //     offsetType = typeA;
            //     autoFillSubHea(offSubHea, offSubPay, offsetType, false, false, 0, 0, offsetByte - heaSizeMap[offsetType]);
            // }
            // testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
            // testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
            // testcase.nofSubHea++;
            testcase.totalByte = testcase.totalByte + offsetByte;
        }
    }

    return ret;
}

bool macFuzzer_t::checkOffsetSubHea_new(macPDU_t &testcase, int actualLen){
    bool ret = false;
    testcase.orinByte = testcase.totalByte;
    testcase.orinSubH = testcase.nofSubHea;
    testcase.orinEIdx = testcase.eIdx;

    int offsetByte = actualLen - curTestCase.totalByte;
    if (offsetByte == 0){
        // std::cout << "[GEN] No offset needed, offsetByte == 0\n";
        return false;
    }

    if (testcase.eIdx == 5 || testcase.eIdx == 4 || testcase.eIdx == 2){
        if (offsetByte > 0){
            testcase.totalByte += offsetByte; // since this is normal packet, we just add offset bytes to the final subpayload
            // std::cout << "[GEN] No offset needed, eIdx = 5, 4, 2, offsetByte --> final subpayload\n";
        }
        return false;
    }

    // int  totalHeaderLen = 0;
    // for (int i = 0; i < curTestCase.nofSubHea; i++){
    //     totalHeaderLen += curTestCase.subHea[i].headerSize;
    // }


    // if redundant bytes are not exceeding the breakpoint by eIdx
    if (testcase.eIdx >= 0 && (testcase.eIdx < (testcase.nofSubHea - 1)) && testcase.subHea[testcase.eIdx].L > testcase.subPay[testcase.eIdx].size + offsetByte){
        // addjust the subpayload size in the eIdx point
        testcase.subPay[testcase.eIdx].size += offsetByte;
        testcase.totalByte += offsetByte;
        // std::cout << "[GEN] No offset needed, eIdx < nofSubHea - 1, offsetByte --> subpayload " << testcase.eIdx << "\n";
        return false;
    }

    /* eIdx is last subheader, CE */
    if (testcase.eIdx == testcase.nofSubHea && offsetByte > 0){
        int not_type_D_subheader_idx = -1;
        for (int i = 0; i < testcase.eIdx; i++){
            if ((int)testcase.subHea[i].type < (int)typeD){
                not_type_D_subheader_idx = i;
            }
        }
        // if there is not type D front subheader, we modify the L of that subheader
        if (not_type_D_subheader_idx > -1){
            testcase.subHea[not_type_D_subheader_idx].L += offsetByte;
            testcase.totalByte += offsetByte;
            // std::cout << "[GEN] No offset needed, eIdx = last subheader CE, offsetByte --> subheader " << not_type_D_subheader_idx << "\n";
            return false;
        }else{ // if there is no not type D subheader, we add offset subheader type D with same LCID as last subheader unitl fulfill the redundant bytes
            int remainingByte = offsetByte;
            while (remainingByte > 0){
                macSubHeader_t offSubHea; 
                macSubPayload_t offSubPay;
                offSubHea.type = typeD;
                offSubHea.lcid = 30; // testcase.subHea[testcase.nofSubHea - 1].lcid; we use 30 here because DRX command does not have any payload, otherwise the new subheader requires several bytes for payload.
                assign_legitimate_subheade_and_subpayload(0, false, typeD, offSubHea, offSubPay);
                offSubPay.size = 0;
                // add offset subheader to the position before the last subheader
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                // also add offset subpayload
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.eIdx++; // because we add new subheader before the eIdx
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeD];
                remainingByte = remainingByte - heaSizeMap[typeD];
            }
            // std::cout << "[GEN] Add offset subheader type D before eIdx\n";
        }
        return true;
    }

    // if (testcase.eIdx > 0 && testcase.eIdx < testcase.nofSubHea - 1 && testcase.subHea[testcase.eIdx].L == 0 && offsetByte > 0){
    //     testcase.subHea[0].L += offsetByte;
    //     testcase.totalByte += offsetByte;
    //     return true;
    // }

    /* eIdx from 0 to nofSubHea - 2*/
    if (testcase.eIdx >= 0 && testcase.eIdx < testcase.nofSubHea - 1 && offsetByte > 0){
        // check if there is not type D front subheader, we modify the L of that subheader
        int not_type_D_subheader_idx = -1;
        for (int i = 0; i < testcase.eIdx + 1; i++){
            if ((int)testcase.subHea[i].type < (int)typeD){
                not_type_D_subheader_idx = i;
            }
        }

        if (not_type_D_subheader_idx > -1){
            testcase.subHea[not_type_D_subheader_idx].L += offsetByte;
            testcase.totalByte += offsetByte;
            // std::cout << "[GEN] No offset needed, eIdx < nofSubHea - 1, offsetByte --> subheader " << not_type_D_subheader_idx << "\n";
            return false;
        }else{ 
            // if there is no not type D subheader, we add offset subheader type D with same LCID as the eIdx subheader after eIdx subheader, 
            // as the test case expects to break at eIdx, the new subheader will not have payload (size = 0)
            int remainingByte = offsetByte;
            while (remainingByte > 0){
                macSubHeader_t offSubHea; 
                macSubPayload_t offSubPay;
                offSubHea.type = typeD;
                offSubHea.lcid = testcase.subHea[testcase.eIdx].lcid;
                assign_legitimate_subheade_and_subpayload(0, false, typeD, offSubHea, offSubPay); // because eIdx is upto nofSubHea - 2, new subheader should not be the last (false)
                offSubPay.size = 0; // because the position is after eIdx, we dont need to consider the payload size
                // add offset subheader to the position after the eIdx subheader
                testcase.subHea.insert(testcase.subHea.begin() + testcase.eIdx + 1, offSubHea);
                // also add offset subpayload
                testcase.subPay.insert(testcase.subPay.begin() + testcase.eIdx + 1, offSubPay);
                testcase.nofSubHea++;
                // we dont need to update eIdx because we add new subheader after the eIdx
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeD];
                remainingByte = remainingByte - heaSizeMap[typeD];
            }
            // std::cout << "[GEN] Add offset subheader type D after eIdx\n";
            return true;
        }
    }

    /* if eIdx < 0, test cases will be all headers, so we add offset typeD subheaders until fulfill the redundant bytes */
    if (testcase.eIdx < 0 && offsetByte > 0){
        int last_is_CE = false;
        if (check_is_CE(testcase.subHea[testcase.nofSubHea - 1].lcid)){
            last_is_CE = true;
        }
        // if (last_is_CE || offsetByte == 1){ // last_is_CE || offsetByte == 1
            int remainingByte = offsetByte;
            while (remainingByte > 0){
                macSubHeader_t offSubHea; 
                macSubPayload_t offSubPay;
                offSubHea.type = typeD;
                offSubHea.lcid = (last_is_CE)? testcase.subHea[testcase.nofSubHea - 1].lcid: 29; // 29 TA lcid is last is not CE
                assign_legitimate_subheade_and_subpayload(0, false, typeD, offSubHea, offSubPay);
                offSubPay.size = 0;
                // add offset subheader to the position before the last subheader
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                // also add offset subpayload
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                // we dont need to update eIdx because the eIdx is minus
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeD];
                remainingByte = remainingByte - heaSizeMap[typeD];
            }
            // std::cout << "[GEN] Add offset subheader type D before eIdx\n";
        // }
        // else{
        //     int remainingByte = offsetByte;
        //     while (remainingByte >= 2){
        //         // add offset subheader type A, lcid same as last subheader
        //         macSubHeader_t offSubHea;
        //         macSubPayload_t offSubPay;
        //         offSubHea.type = typeA;
        //         offSubHea.lcid = testcase.subHea[testcase.nofSubHea - 1].lcid;
        //         assign_legitimate_subheade_and_subpayload(0, false, typeA, offSubHea, offSubPay);
        //         offSubPay.size = 0;
        //         // add offset subheader to the position before the last subheader
        //         testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
        //         // also add offset subpayload
        //         testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
        //         testcase.nofSubHea++;
        //         testcase.totalByte = testcase.totalByte + heaSizeMap[typeA];
        //         remainingByte = remainingByte - heaSizeMap[typeA];
        //     }
        //     if (remainingByte == 1){
        //         // add offset subheader type D, lcid = 23
        //         macSubHeader_t offSubHea;
        //         macSubPayload_t offSubPay;
        //         offSubHea.type = typeD;
        //         offSubHea.lcid = 29;
        //         assign_legitimate_subheade_and_subpayload(0, false, typeD, offSubHea, offSubPay);
        //         offSubPay.size = 0;
        //         // add offset subheader to the position before the last subheader
        //         testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
        //         // also add offset subpayload
        //         testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
        //         testcase.nofSubHea++;
        //         testcase.totalByte = testcase.totalByte + heaSizeMap[typeD];
        //     }
        // }
        return true;
    }
    return ret;
}

int macFuzzer_t::checkOffsetSubHea_eLCID(macPDU_t &testcase, int actualLen){
    bool ret = 0;
    int  totalHeaderLen = 0;
    for (int i = 0; i < curTestCase.nofSubHea; i++){
        totalHeaderLen += curTestCase.subHea[i].headerSize;
    }
    int offsetByte = actualLen - curTestCase.totalByte;
    int eIdx = curTestCase.eIdx;

    if (offsetByte > 0){ // save orin info for debug and crash log
        testcase.orinByte = testcase.totalByte; 
        testcase.orinSubH = testcase.nofSubHea;
    }

    if (eIdx <= -1 && offsetByte > 0){ // -1 means all headers, we will inject only offset subheaders
        int remainingByte = offsetByte;
        ret = 1; // 1 means there is offset
        while(remainingByte != 0){
            if (remainingByte == 1){ // change type Ae to type Be
                int hAeIdx = 0;
                bool foundTypeAe = false;
                for (int h = 0; h < curTestCase.nofSubHea; h++){
                    if (curTestCase.subHea[h].type == typeAe){
                        hAeIdx = h;
                        foundTypeAe = true;
                        break;
                    }
                }
                if (!foundTypeAe){
                    // std::cout << "[GEN] Cannot find type Ae to change to type Be\n";
                    ret = -1; // -1 means error
                    break;
                }else{
                    testcase.subHea[hAeIdx].type = typeBe; // change type to have 1 more byte
                    testcase.subHea[hAeIdx].headerSize = heaSizeMap[typeBe];
                    testcase.subHea[hAeIdx].F = 1; // sign for type Be
                    testcase.totalByte = testcase.totalByte + 1;
                    remainingByte = remainingByte - 1;
                }
            }else if (remainingByte == 2){
                // std::cout << "[GEN] Remaining byte is 2, not implemented yet\n";
                remainingByte = 0;
                ret = -1;
                break;
            }else if (remainingByte == 3){ // add 1 more subheader type Ae before the last one, as eLCID can contain any LCID
                // int hAeIdx = 0;
                // for (int h = 0; h < curTestCase.nofSubHea; h++){
                //     if (curTestCase.subHea[h].type == typeAe){
                //         hAeIdx = h;
                //         break;
                //     }
                // }
                // macSubHeader_t offSubHea = curTestCase.subHea[hAeIdx];
                // macSubPayload_t offSubPay = curTestCase.subPay[hAeIdx];
                // testcase.nofSubHea++;
                // testcase.subHea.insert(testcase.subHea.begin(), offSubHea);
                // testcase.subPay.insert(testcase.subPay.begin(), offSubPay);
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.eLCID = testcase.subHea[testcase.nofSubHea-1].eLCID;
                offSubHea.type = typeAe;
                offSubHea.isLast = false; // remember to update hIdx of last one and this one
                offSubHea.L = testcase.subHea[testcase.nofSubHea-2].L; // get L of previous subheader as last one does not have L
                autoFillSubHea_eLCID(offSubHea, offSubPay, offSubHea.type, offSubHea.isLast, offSubHea.eLCID, offSubHea.L, testcase.eIdx, testcase.nofSubHea - 2); // hIdx = testcase.nofSubHea - 2
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeAe];
                remainingByte = remainingByte - 3;
            }else if (remainingByte == 4){ // add 1 more subheader type Be
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.eLCID = testcase.subHea[testcase.nofSubHea-1].eLCID;
                offSubHea.type = typeBe;
                offSubHea.isLast = false; // remember to update hIdx of last one and this one
                offSubHea.L = testcase.subHea[testcase.nofSubHea-2].L; // get L of previous subheader as last one does not have L
                autoFillSubHea_eLCID(offSubHea, offSubPay, offSubHea.type, offSubHea.isLast, offSubHea.eLCID, offSubHea.L, testcase.eIdx, testcase.nofSubHea - 2); // hIdx = testcase.nofSubHea - 2
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeBe];
                remainingByte = remainingByte - 4;
            }else if (remainingByte == 5){ // add 1 more subheader type Be
                // std::cout << "[GEN] Remaining byte is 5, not implemented yet\n";
                remainingByte = 0;
                ret = -1;
                break;
            }else if (remainingByte == 6 || remainingByte == 7){ // add 1 more subheader type Ae
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.eLCID = testcase.subHea[testcase.nofSubHea-1].eLCID;
                offSubHea.type = typeAe;
                offSubHea.isLast = false; // remember to update hIdx of last one and this one
                offSubHea.L = testcase.subHea[testcase.nofSubHea-2].L; // get L of previous subheader as last one does not have L
                autoFillSubHea_eLCID(offSubHea, offSubPay, offSubHea.type, offSubHea.isLast, offSubHea.eLCID, offSubHea.L, testcase.eIdx, testcase.nofSubHea - 2); // hIdx = testcase.nofSubHea - 2
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeAe];
                remainingByte = remainingByte - 3;
            }else if (remainingByte == 8){
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.eLCID = testcase.subHea[testcase.nofSubHea-1].eLCID;
                offSubHea.type = typeBe;
                offSubHea.isLast = false; // remember to update hIdx of last one and this one
                offSubHea.L = testcase.subHea[testcase.nofSubHea-2].L; // get L of previous subheader as last one does not have L
                autoFillSubHea_eLCID(offSubHea, offSubPay, offSubHea.type, offSubHea.isLast, offSubHea.eLCID, offSubHea.L, testcase.eIdx, testcase.nofSubHea - 2); // hIdx = testcase.nofSubHea - 2
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeBe];
                remainingByte = remainingByte - 4;
            }else if (remainingByte >=9){
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.eLCID = testcase.subHea[testcase.nofSubHea-1].eLCID;
                offSubHea.type = typeAe;
                offSubHea.isLast = false; // remember to update hIdx of last one and this one
                offSubHea.L = testcase.subHea[testcase.nofSubHea-2].L; // get L of previous subheader as last one does not have L
                autoFillSubHea_eLCID(offSubHea, offSubPay, offSubHea.type, offSubHea.isLast, offSubHea.eLCID, offSubHea.L, testcase.eIdx, testcase.nofSubHea - 2); // hIdx = testcase.nofSubHea - 2
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeAe];
                remainingByte = remainingByte - 3;
            }
        }
        // if (testcase.totalByte != actualLen){ printf("[GEN] Total Bytes is not equal actual Bytes after adding offset\n"); }
    
    }else if (offsetByte > 0 && eIdx > -1 && eIdx < curTestCase.nofSubHea - 1){
        ret = 1;
        testcase.subHea[eIdx].L += offsetByte; // add offset byte to L of subheader at eIdx
        testcase.subPay[eIdx].size += offsetByte;
        testcase.totalByte = testcase.totalByte + offsetByte;
    }
    if (testcase.totalByte != actualLen){ printf("[GEN] Total Bytes is not equal actual Bytes after adding offset (eLCID), %d|%d\n", testcase.totalByte, actualLen); }
    return ret;
}

int macFuzzer_t::checkOffsetSubHea_eLCID_new(macPDU_t &testcase, int actualLen){
    bool ret = 0;
    int  totalHeaderLen = 0;
    for (int i = 0; i < curTestCase.nofSubHea; i++){
        totalHeaderLen += curTestCase.subHea[i].headerSize;
    }
    int offsetByte = actualLen - curTestCase.totalByte;
    int eIdx = curTestCase.eIdx;

    if (offsetByte > 0){ // save orin info for debug and crash log
        testcase.orinByte = testcase.totalByte; 
        testcase.orinSubH = testcase.nofSubHea;
        testcase.orinEIdx = testcase.eIdx;
    }else{
        // std::cout << "[GEN] eLCID no offset needed, offsetByte == 0\n";
        return false;
    }

    if (testcase.eIdx == testcase.nofSubHea - 1){
        // std::cout << "[GEN] eLCID no offset needed, eIdx == nofSubHea - 1\n";
        return false;
    }

    if (eIdx <= -1 && offsetByte > 0){ // -1 means all headers, we will inject only offset subheaders
        int remainingByte = offsetByte;
        ret = 1; // 1 means there is offset
        while(remainingByte != 0){
            if (remainingByte == 1 || remainingByte == 2){ // add type D with lcid = 30 DRX command before the last one
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.type = typeD;
                offSubHea.lcid = 30; 
                assign_legitimate_subheade_and_subpayload(0, false, typeD, offSubHea, offSubPay);
                offSubPay.size = 0; // because this is all sub-header
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeD];
                remainingByte = remainingByte - heaSizeMap[typeD];
                // std::cout << "[GEN] Add offset subheader type D before the last one (eLCID)\n";
            }else if (remainingByte == 3 || remainingByte >= 6){ // add 1 more subheader type Ae before the last one, as eLCID can contain any LCID
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.eLCID = testcase.subHea[testcase.nofSubHea-1].eLCID;
                offSubHea.lcid = 16; // we are adding eLCID here
                offSubHea.type = typeAe;
                offSubHea.isLast = false; // remember to update hIdx of last one and this one
                assign_legitimate_subheade_and_subpayload(0, false, typeAe, offSubHea, offSubPay);
                offSubPay.size = 0; // because this is all sub-header
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeAe];
                remainingByte = remainingByte - heaSizeMap[typeAe];
                // std::cout << "[GEN] Add offset subheader type Ae before the last one (eLCID)\n";
            }else if (remainingByte == 4 || remainingByte == 5){ // add 1 more subheader type Be
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.eLCID = testcase.subHea[testcase.nofSubHea-1].eLCID;
                offSubHea.lcid = 16; // we are adding eLCID here
                offSubHea.type = typeBe;
                offSubHea.isLast = false; // remember to update hIdx of last one and this one
                assign_legitimate_subheade_and_subpayload(0, false, typeBe, offSubHea, offSubPay);
                offSubPay.size = 0; // because this is all sub-header
                testcase.subHea.insert(std::prev(testcase.subHea.end()), offSubHea);
                testcase.subPay.insert(std::prev(testcase.subPay.end()), offSubPay);
                testcase.nofSubHea++;
                testcase.totalByte = testcase.totalByte + heaSizeMap[typeBe];
                remainingByte = remainingByte - heaSizeMap[typeBe];
                // std::cout << "[GEN] Add offset subheader type Be before the last one (eLCID)\n";
            }
        }
        // if (testcase.totalByte != actualLen){ printf("[GEN] Total Bytes is not equal actual Bytes after adding offset\n"); }
    
    }else if (offsetByte > 0 && eIdx >= 0 && eIdx < curTestCase.nofSubHea - 1){
        ret = 1;
        int remainingByte = offsetByte;
        // if eIx = 0, which means the expected break point is the first sub-payload
        if (eIdx == 0){
            // if the first sub-header has L = 0, we need to add sub-header offset here (this also includes type D CE)
            if (testcase.subHea[eIdx].L == 0){
                while (remainingByte > 0){
                    if (remainingByte == 1 || remainingByte == 2){ // add type D with lcid = 30 DRX command after the first one
                        macSubHeader_t offSubHea;
                        macSubPayload_t offSubPay;
                        offSubHea.type = typeD;
                        offSubHea.lcid = 30; 
                        assign_legitimate_subheade_and_subpayload(0, false, typeD, offSubHea, offSubPay); // not the last subheader because we are considering eIdx from 0 to nofSubHea - 2
                        offSubPay.size = 0; // because this is the sub-header after eIdx
                        testcase.subHea.insert(testcase.subHea.begin() + eIdx + 1, offSubHea);
                        testcase.subPay.insert(testcase.subPay.begin() + eIdx + 1, offSubPay);
                        testcase.nofSubHea++;
                        testcase.totalByte = testcase.totalByte + heaSizeMap[typeD];
                        remainingByte = remainingByte - heaSizeMap[typeD];
                        // std::cout << "[GEN] Add offset subheader type D after eIdx\n";
                    }else if (remainingByte == 3 || remainingByte >= 6){ // add 1 more subheader type Ae (same eLCID as the first one) after the first one, as eLCID can contain any LCID
                        macSubHeader_t offSubHea;
                        macSubPayload_t offSubPay;
                        offSubHea.eLCID = testcase.subHea[eIdx].eLCID;
                        offSubHea.lcid = 16; // we are adding eLCID here
                        offSubHea.type = typeAe;
                        offSubHea.isLast = false; // remember to update hIdx of last one and this one
                        assign_legitimate_subheade_and_subpayload(0, false, typeAe, offSubHea, offSubPay); // not the last subheader because we are considering eIdx from 0 to nofSubHea - 2
                        offSubPay.size = 0; // because this is the sub-header after eIdx
                        testcase.subHea.insert(testcase.subHea.begin() + eIdx + 1, offSubHea);
                        testcase.subPay.insert(testcase.subPay.begin() + eIdx + 1, offSubPay);
                        testcase.nofSubHea++;
                        testcase.totalByte = testcase.totalByte + heaSizeMap[typeAe];
                        remainingByte = remainingByte - heaSizeMap[typeAe];
                        // std::cout << "[GEN] Add offset subheader type Ae after eIdx\n";
                    }else if (remainingByte == 4 || remainingByte == 5){ // add 1 more subheader type Be
                        macSubHeader_t offSubHea;
                        macSubPayload_t offSubPay;
                        offSubHea.eLCID = testcase.subHea[eIdx].eLCID;
                        offSubHea.lcid = 16; // we are adding eLCID here
                        offSubHea.type = typeBe;
                        offSubHea.isLast = false; // remember to update hIdx of last one and this one
                        assign_legitimate_subheade_and_subpayload(0, false, typeBe, offSubHea, offSubPay); // not the last subheader because we are considering eIdx from 0 to nofSubHea - 2
                        offSubPay.size = 0; // because this is the sub-header after eIdx
                        testcase.subHea.insert(testcase.subHea.begin() + eIdx + 1, offSubHea);
                        testcase.subPay.insert(testcase.subPay.begin() + eIdx + 1, offSubPay);
                        testcase.nofSubHea++;
                        testcase.totalByte = testcase.totalByte + heaSizeMap[typeBe];
                        remainingByte = remainingByte - heaSizeMap[typeBe];
                        // std::cout << "[GEN] Add offset subheader type Be after eIdx\n";
                    }

                }
            }else if (testcase.subHea[eIdx].L > 0){ // if the first sub-header has L > 0, it is likely the offset byte + existing payload is not exceeding L
                if (testcase.subHea[eIdx].L > testcase.subPay[eIdx].size + offsetByte){
                    ret = false;
                    testcase.subPay[eIdx].size += offsetByte;
                    testcase.totalByte = testcase.totalByte + offsetByte;
                    // std::cout << "[GEN] No offset needed, eIdx = 0, offsetByte --> subpayload " << testcase.eIdx << "\n";
                }else{
                    // std::cout << "[GEN] Offset needed for eIdx 0 but not implemented\n";
                }
            }
        }else{
            // if eIdx > 0, we can adjust L of first subheader, because it has a legitimate value and has not been mutated
            testcase.subHea[0].L += offsetByte;
            testcase.totalByte = testcase.totalByte + offsetByte;
        }
    }
    if (testcase.totalByte != actualLen){ 
        // printf("[GEN] Total Bytes is not equal actual Bytes after adding offset (eLCID), %d|%d\n", testcase.totalByte, actualLen); 
    }
    return ret;
}

int formSubHeaderTypeD(int R, int F2, int E, int lcID){
  return (std::pow(2,7)*R + std::pow(2, 6)*F2 + std::pow(2, 5)*E + lcID);
}

headerResult formSubHeaderTypeD_eLCID(int R, int F2, int E, int lcID, int R1e, int R2e, int eLCID){
    headerResult result = {};
    // // std::cout << "[GEN] Forming subheader (2): " << R << " - " << F2 << " - " << E << " - " << lcID << " - " << R1e << " - " << R2e << " - " << eLCID << "\n";
    int firstByte = std::pow(2,7)*R + std::pow(2, 6)*F2 + std::pow(2, 5)*E + lcID;
    int secondByte = std::pow(2,7)*R1e + std::pow(2, 6)*R2e + eLCID;
    result.pattern[0] = firstByte;
    result.pattern[1] = secondByte;
    result.len = 2;
    // // std::cout << "[GEN] Formed subheader: " << std::bitset<8> (result.pattern[0]) << " - " << std::bitset<8> (result.pattern[1]) << "\n";
    return result;
}

headerResult formSubHeader(bool isLast, macSubHeaderType_t type, uint8_t R, uint8_t F2, uint8_t E, int lcID, int len){
  headerResult result;
  if (isLast || type == typeD){ // E= 0 for the last header
    result.len = 1;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
  }else{
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID); //calculate 1st byte based on R F2 E LCID, all the same for all types
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

headerResult formSubHeader_eLCID(bool isLast, macSubHeaderType_t type, uint8_t R, uint8_t F2, uint8_t E, int lcID, int len, int R1e, int R2e, int eLCID){
  headerResult result;
//   // std::cout << "[GEN] Forming subheader: " << (int)type << " - " << (int)R << " - " << (int)F2 << " - " << (int)E << " - " << lcID << " - " << len << " - " << R1e << " - " << R2e << " - " << eLCID << " - " << isLast << "\n";
  if (isLast || type == typeDe){ // E= 0 for the last header
    headerResult fixedHea = formSubHeaderTypeD_eLCID(R, F2, E, lcID, R1e, R2e, eLCID);
    result.len = 2;
    result.pattern[0] = fixedHea.pattern[0];
    result.pattern[1] = fixedHea.pattern[1];
  }else{
    headerResult fixedHea = formSubHeaderTypeD_eLCID(R, F2, E, lcID, R1e, R2e, eLCID);
    result.pattern[0] = fixedHea.pattern[0]; //calculate 1st byte based on R F2 E LCID, all the same for all types
    result.pattern[1] = fixedHea.pattern[1];
    // // std::cout << "[GEN] Formed subheader (2): " << std::bitset<8> (result.pattern[0]) << " - " << std::bitset<8> (result.pattern[1]) << "\n";
    if (type == typeAe){ 
      result.len = 3;
      result.pattern[2] = len; // F = 0, so 2nd byte is equal to L
    }
    if (type == typeBe){ 
      result.len = 4; //3 bytes
      int value = std::pow(2,15)*1 + len;     // F2 = 0, F = 1, so 2 bytes length will be equal to value = ...
      result.pattern[2] = static_cast<uint8_t>(value >> 8); //value is presented to 16 bits pattern, get first 8 bits
      result.pattern[3] = static_cast<uint8_t>(value & 0xFF); // last 8 bits.
    }
    if (type == typeCe){ 
      result.len = 4;
      result.pattern[2] = static_cast<uint8_t>(len >> 8); // 16 bits for length, F2 = 1, no F, get first 8 bits
      result.pattern[3] = static_cast<uint8_t>(len & 0xFF); // last 8 bits.
    }
  }
  return result;
}

headerResult formSubHeaderFree(int eIdx, uint8_t R, uint8_t F2, uint8_t E, int lcID, uint8_t F, int len){
  headerResult result;
  if (eIdx == -4 || eIdx == -5){
    result.len = 1;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
  }else if(eIdx == -3 || eIdx == -2){
    result.len = 2;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
    result.pattern[1] = std::pow(2,7)*F + len; // 
  }
  return result;
}

headerResult formSubHeaderFree_eLCID(int eIdx, uint8_t R, uint8_t F2, uint8_t E, int lcID, uint8_t F, int len, int R1e, int R2e, int eLCID){
  headerResult result;
  if (eIdx >= -4 && eIdx <= -1){
    result.len = 1;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
  }else if(eIdx == -5 || eIdx == -7){
    result.len = 2;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
    result.pattern[1] = std::pow(2,7)*R1e + std::pow(2,6)*R2e + eLCID; // 
  }else if (eIdx == -6){
    result.len = 3;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
    result.pattern[1] = std::pow(2,7)*R1e + std::pow(2,6)*R2e + eLCID;//
    result.pattern[2] = std::pow(2,7)*F + (uint8_t)(len&0xFF);
  }else if (eIdx >= -11 && eIdx <=-8){
    result.len = 2;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
    result.pattern[1] = std::pow(2,7)*R1e + std::pow(2,6)*R2e + eLCID;
  }else if (eIdx >= -14 && eIdx <= -12){
    result.len = 3;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
    result.pattern[1] = std::pow(2,7)*R1e + std::pow(2,6)*R2e + eLCID;
    result.pattern[2] = std::pow(2,7)*F + (uint8_t)(len&0xFF);
  }
  return result;
}

void printPDUtestcase(macPDU_t& pdu, bool isOffset, macPDU_t &offsetPDU, int tti, int actualLen){
    std::cout << "[PDU] Nof_Sub = " << (int)pdu.nofSubHea << "|" << (int)offsetPDU.nofSubHea << " - OrinByte = " << (int)pdu.totalByte \
    <<"|" << (int)offsetPDU.totalByte << " - ActlLen = " << actualLen << BLUE_TEXT << " - eIdx = " << (int)pdu.eIdx << RESET_COLOR << "\n";

    for (int h = 0; h < offsetPDU.nofSubHea; h++){
        std::cout << "[PDU] LCID = " << std::setw(3) << (int)offsetPDU.subHea[h].lcid << " - eLCID = " << std::setw(3) << (int)offsetPDU.subHea[h].eLCID << " - type = " << (int)offsetPDU.subHea[h].type << " - L = " \
        << std::setw(4) << (int)offsetPDU.subHea[h].L << " - P_Sz = " << std::setw(5) << (int)offsetPDU.subPay[h].size << " -- W_ID = " << offsetPDU.subHea[h].isWrongID \
        << " -- R: " << (int)offsetPDU.subHea[h].R << " -- F2: " << (int)offsetPDU.subHea[h].F2 << " -- E: " << (int)offsetPDU.subHea[h].E << "\n";
    }

    //print CE payload
    if (pdu.mutatingMacCE){
        for (int p = 0; p < pdu.nofSubHea; p++){
            if (pdu.subHea[p].isCE && pdu.subHea[p].cePayload){ // if this subheader is CE and it has payload
                std::cout << "[PDU] CE Payload: ";
                std::cout << " LCID = " << (int)pdu.subHea[p].lcid << " -- Size = " << pdu.subPay[p].size << "\n";
                for (int id = 0; id < pdu.subPay[p].size; id++){
                    std::cout << "      Pattern " << id << ": " << std::bitset<8> (pdu.subPay[p].payload[id]) << "\n";
                }
            }
        }
    }

    std::cout << "\n";
}

void printPDUtestcase_new(macPDU_t &offsetPDU){
    offsetPDU.print_general_info();
    // for (int h = 0; h < offsetPDU.nofSubHea; h++){
    //     offsetPDU.subHea[h].print();
    // }
    // if (offsetPDU.eIdx >= 0){
    //     int max_print = std::min((int)offsetPDU.eIdx, (int)offsetPDU.nofSubHea - 1);
    //     for (int h = 0; h <= max_print; h++){
    //         offsetPDU.subPay[h].print();
    //     }
    // }
    std::cout << "\n";
}

void macFuzzer_t::generatePDU_1(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen){
    bool iseLCID = testCase.iseLCID;
    headerResult subHeaResult = {};
    if (actualLen >= testCase.totalByte && actualLen >= 2){
        if (iseLCID){
            subHeaResult = formSubHeader_eLCID(true, testCase.subHea[0].type, testCase.subHea[0].R, testCase.subHea[0].F2, testCase.subHea[0].E, testCase.subHea[0].lcid, testCase.subHea[0].L, testCase.subHea[0].R1e, testCase.subHea[0].R2e, testCase.subHea[0].eLCID);
        }else {
            subHeaResult = formSubHeader(true, testCase.subHea[0].type, testCase.subHea[0].R, testCase.subHea[0].F2, testCase.subHea[0].E, testCase.subHea[0].lcid, testCase.subHea[0].L);
        }
        for(int i = 0; i < subHeaResult.len; i++){
            if (i < actualLen){
                packet[i] = subHeaResult.pattern[i];
            }else{
                // printf("[GEN] Actual Len is smaller than expected len (test cases with  1 subheader)\n");
            }
        }
        for (int j = subHeaResult.len; j < actualLen; j++){
            packet[j] = 0;
        }
    }else{
        // printf("[GEN] Actual Len is smaller than expected len (test cases with  1 subheader)\n");
    }

}

void macFuzzer_t::generatePDU_mutateLastSubhea(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen){
    bool iseLCID = testCase.iseLCID;
    headerResult subHeaResult0 = {};
    headerResult subHeaResult1 = {};
    int startIdx = 0;
    if (actualLen >= testCase.totalByte){
        subHeaResult0 = formSubHeader(false, testCase.subHea[0].type, testCase.subHea[0].R, testCase.subHea[0].F2, testCase.subHea[0].E, testCase.subHea[0].lcid, testCase.subHea[0].L);
        for(int i = startIdx; i < subHeaResult0.len; i++){
            if (i < actualLen){
                packet[i] = subHeaResult0.pattern[i];
            }else{
                // printf("[GEN] Actual Len is smaller than expected len (test cases with  1 subheader)\n");
            }
        }
        startIdx += subHeaResult0.len;
        startIdx += testCase.subPay[0].size;
    }

    if (actualLen > startIdx){
        if (iseLCID){
            subHeaResult1 = formSubHeader_eLCID(true, testCase.subHea[1].type, testCase.subHea[1].R, testCase.subHea[1].F2, testCase.subHea[1].E, testCase.subHea[1].lcid, testCase.subHea[1].L, testCase.subHea[1].R1e, testCase.subHea[1].R2e, testCase.subHea[1].eLCID);
        }else {
            subHeaResult1 = formSubHeader(true, testCase.subHea[1].type, testCase.subHea[1].R, testCase.subHea[1].F2, testCase.subHea[1].E, testCase.subHea[1].lcid, testCase.subHea[1].L);
        }
        for(int i = startIdx; i < subHeaResult1.len; i++){
            if (i < actualLen){
                packet[i] = subHeaResult1.pattern[i];
            }else{
                // printf("[GEN] Actual Len is smaller than expected len (test cases with  1 subheader)\n");
            }
        }
        // for (int j = subHeaResult1.len; j < actualLen; j++){
        //     packet[j] = 0;
        // }
    }else{
        // printf("[GEN] Actual Len is smaller than expected len (test cases with  1 subheader)\n");
    }

}

void macFuzzer_t::generatePDU(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen){
    /*Generate subheaders first*/
    uint16_t startIdx = 0;
    for (int h = 0; h < testCase.nofSubHea; h++){
        bool isLast = (h == (testCase.nofSubHea - 1))?true:false;
        if (testCase.eIdx == -4 && isLast){
            testCase.subHea[testCase.nofSubHea - 1].E = 1;
        }else if (testCase.eIdx == -3 && isLast){
            testCase.subHea[testCase.nofSubHea - 1].E = 1;
            testCase.subHea[testCase.nofSubHea - 1].F2 = 1;
            testCase.subHea[testCase.nofSubHea - 1].F = 0;
        }else if (testCase.eIdx == -2 && isLast){
            testCase.subHea[testCase.nofSubHea - 1].E = 1;
            testCase.subHea[testCase.nofSubHea - 1].F2 = 0;
            testCase.subHea[testCase.nofSubHea - 1].F = 1;
        }else if (testCase.eIdx == -5 && isLast){
            testCase.subHea[testCase.nofSubHea - 1].E = 0;
            testCase.subHea[testCase.nofSubHea - 1].F2 = 1;
            testCase.subHea[testCase.nofSubHea - 1].F = 0;
        }
        headerResult subHeaResult = {};
        if (isLast && testCase.eIdx < -1){
            subHeaResult = formSubHeaderFree(testCase.eIdx, 
                                            testCase.subHea[h].R, 
                                            testCase.subHea[h].F2, 
                                            testCase.subHea[h].E, 
                                            testCase.subHea[h].lcid, 
                                            testCase.subHea[h].F,
                                            testCase.subHea[h].L);
        }else{
            subHeaResult = formSubHeader(isLast, 
                                        testCase.subHea[h].type, 
                                        testCase.subHea[h].R, 
                                        testCase.subHea[h].F2, 
                                        testCase.subHea[h].E, 
                                        testCase.subHea[h].lcid, 
                                        testCase.subHea[h].L);
        }
        for(int i = startIdx; i < subHeaResult.len + startIdx; i++){
            if (i < actualLen){
                packet[i] = subHeaResult.pattern[i - startIdx];
            }else{
                // printf("[GEN] Actual Len is smaller than expected len\n");
            }
        }
        startIdx += subHeaResult.len;
    }

    const int totalHeaLen = startIdx; // keep total header length
    /*Generate subPayload, only change subpayload if there is ID*/
    if (testCase.eIdx > 0){                         //packet only has a complete subpayload if eIdx > 0
        for (int p = 0; p < testCase.eIdx; p++){
            if (!testCase.subHea[p].isWrongID && testCase.subHea[p].lcid == 28){     // pass the UE Contention resolution to this subpayload
                startIdx = totalHeaLen;
                for (int j = 0; j < p; j++){        //find where is the start of ID
                    startIdx += testCase.subPay[j].size;
                }
                for (int id = startIdx; id < startIdx + 6; id++){
                    if (id < actualLen){
                        packet[id] = conResID[id - startIdx];
                    }else{
                        // printf("[GEN] Actual Len for ID is smaller than expected len\n");
                    }
                }
            }
        }
    }

    if (testCase.mutatingMacCE){ // set CE payload if it is mutated
        for (int p = 0; p < testCase.nofSubHea; p++){
            if (testCase.subHea[p].isCE && testCase.subHea[p].cePayload){ // if this subheader is CE and it has payload
                startIdx = totalHeaLen;
                for (int j = 0; j < p; j++){        //find where is the start of ID
                    startIdx += testCase.subPay[j].size;
                }
                for (int id = startIdx; id < startIdx + testCase.subPay[p].size; id++){
                    if (id < actualLen){
                        packet[id] = testCase.subPay[p].payload[id - startIdx];

                    }else{
                        // printf("[GEN] Actual Len for ID is smaller than expected len\n");
                    }
                }
            }
        }
    }
}

headerResult formSubHeader_new(bool isLast, macSubHeaderType_t type, uint8_t R, uint8_t F2, uint8_t E, uint8_t F, int lcID, int L, int eIdx, int expected_subhea_len){
  headerResult result;
  if ((isLast && !(eIdx < -1)) || (type == typeD)){ // E= 0 for the last header
    result.len = 1;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID);
  }else if (!isLast){
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID); //calculate 1st byte based on R F2 E LCID, all the same for all types
    if (type == typeA){ 
      result.len = 2;
      result.pattern[1] = L; // F = 0, so 2nd byte is equal to L
    }
    if (type == typeB){ 
      result.len = 3; //3 bytes
      int value = std::pow(2,15)*1 + L;     // F2 = 0, F = 1, so 2 bytes length will be equal to value = ...
      result.pattern[1] = static_cast<uint8_t>(value >> 8); //value is presented to 16 bits pattern, get first 8 bits
      result.pattern[2] = static_cast<uint8_t>(value & 0xFF); // last 8 bits.
    }
    if (type == typeC){ 
      result.len = 3;
      result.pattern[1] = static_cast<uint8_t>(L >> 8); // 16 bits for length, F2 = 1, no F, get first 8 bits
      result.pattern[2] = static_cast<uint8_t>(L & 0xFF); // last 8 bits.
    }
  }
  if (isLast && eIdx < -1){
    result.len = expected_subhea_len;
    result.pattern[0] = formSubHeaderTypeD(R, F2, E, lcID); // first byte is the same
    switch (eIdx)
    {
    case -2: // only this case has 2 bytes
        result.pattern[1] = std::pow(2,7)*F + 20;
        break;
    case -3:
        /* code */
        break;
    case -4:
        /* code */
        break;
    case -5:
        /* code */
        break;
    default:
        break;
    }
  }
  return result;
}

payloadResult form_mac_ce_payload_new(int size, int lcid_ce, macSubPayload_t& subpayload){
    payloadResult result;
    result.len = size;
    if (lcid_ce == 28){ // contention resolution
        for (int i = 0; i < size; i++){
            // Extract each byte from the 64-bit payload
            result.pattern[i] = (subpayload.contention_ce.payload >> (8 * i)) & 0xFF;
        }
    }else if (lcid_ce == 29){ // ta command mac ce
        if (size == 1){
            result.pattern[0] = (subpayload.timing_ce.R1 << 7) | (subpayload.timing_ce.R2 << 6) | subpayload.timing_ce.ta;
        }else{
            // std::cout << "[GEN] TA Command Mac CE has size different from 1\n";
        }
    }else if (lcid_ce == 22){
        if (size == 2){
            // first byte: 4 bits LCID, 1 bit uldl, first 3 bits out of 6 bit bitrate
            result.pattern[0] = (subpayload.bitrate_ce.lcid_bitrate << 4) | (subpayload.bitrate_ce.ul_dl << 3) | (subpayload.bitrate_ce.bitrate >> 2);
            // second byte: last 3 bits out of 6 bit bitrate, 5 bit reserved with all 0
            result.pattern[1] = ((subpayload.bitrate_ce.bitrate & 0x3) << 5) | 0x00;
        }else {
            // std::cout << "[GEN] Recommended bit rate Mac CE has size different from 2\n";
        }
    }else if (lcid_ce == 18 || lcid_ce == 19|| lcid_ce == 20 || lcid_ce == 21 || lcid_ce == 24 || lcid_ce == 27){ // general ce
        for (int i = 0; i < size; i++){
            // Extract each byte from the 64-bit payload
            result.pattern[i] = (subpayload.general_ce.payload >> (8 * i)) & 0xFF;
        }
    }else{
        // std::cout << "[GEN] Should not reach here LCIDCE = " << lcid_ce << "\n";
        result.len = 0;
    }
    return result;
}

void macFuzzer_t::generatePDU_new(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen){
    /*Generate subheaders first*/
    uint16_t startIdx = 0;
    // generate subheaders from 0 to nofSubHea - 2, usually, these subheaders are legitimate formats
    for (int h = 0; h < testCase.nofSubHea - 1; h++){
        bool isLast = (h == (testCase.nofSubHea - 1))?true:false;
        headerResult subHeaResult = formSubHeader_new(isLast, 
                                                    testCase.subHea[h].type, 
                                                    testCase.subHea[h].R, 
                                                    testCase.subHea[h].F2, 
                                                    testCase.subHea[h].E, 
                                                    testCase.subHea[h].F, 
                                                    testCase.subHea[h].lcid, 
                                                    testCase.subHea[h].L,
                                                    testCase.eIdx,
                                                    testCase.subHea[h].headerSize);
        for(int i = startIdx; i < subHeaResult.len + startIdx; i++){
            if (i < actualLen){
                packet[i] = subHeaResult.pattern[i - startIdx];
            }else{
                // printf("[GEN] Actual Len is smaller than expected len (new function)\n");
            }
        }
        startIdx += subHeaResult.len;
    }
    // geenrate the last subheader
    headerResult subHeaResult = formSubHeader_new(true, 
                                                testCase.subHea[testCase.nofSubHea - 1].type, 
                                                testCase.subHea[testCase.nofSubHea - 1].R, 
                                                testCase.subHea[testCase.nofSubHea - 1].F2, 
                                                testCase.subHea[testCase.nofSubHea - 1].E, 
                                                testCase.subHea[testCase.nofSubHea - 1].F, 
                                                testCase.subHea[testCase.nofSubHea - 1].lcid, 
                                                testCase.subHea[testCase.nofSubHea - 1].L,
                                                testCase.eIdx,
                                                testCase.subHea[testCase.nofSubHea - 1].headerSize);
    for(int i = startIdx; i < subHeaResult.len + startIdx; i++){
        if (i < actualLen){
            packet[i] = subHeaResult.pattern[i - startIdx];
        }else{
            // printf("[GEN] Actual Len is smaller than expected len (new function)\n");
        }
    }
    startIdx += subHeaResult.len;

    // generate subpayloads
    if (testCase.mutatingMacCE){
        for (int p = 0; p < testCase.nofSubHea; p++){
            if (testCase.subHea[p].isCE && testCase.subHea[p].cePayload){
                // form ce payload
                payloadResult p_result =  form_mac_ce_payload_new(testCase.subPay[p].size, testCase.subHea[p].lcid, testCase.subPay[p]);
                // copy result to packet
                for(int i = startIdx; i < p_result.len + startIdx; i++){
                    if (i < actualLen){
                        packet[i] = p_result.pattern[i - startIdx];
                    }else{
                        // printf("[GEN] Actual Len is smaller than expected len (payload mac ce), p = %d\n", p);
                    }
                }
            }else{
            
            }
            startIdx += testCase.subPay[p].size;
        }
            
    }
}

void macFuzzer_t::generatePDU_eLCID(macPDU_t& testCase, bool isOffset, uint8_t* packet, int actualLen){
    /*Generate subheaders first*/
    int startIdx = 0;
    for (int h = 0; h < testCase.nofSubHea -1 ; h++){ // form subheaders until nofSubHe - 1 first
        bool iseLCID = (testCase.subHea[h].type == typeAe || testCase.subHea[h].type == typeBe || testCase.subHea[h].type == typeCe || testCase.subHea[h].type == typeDe);
         headerResult hResult;
        if (iseLCID){
            hResult =  formSubHeader_eLCID(false, 
                                        testCase.subHea[h].type, 
                                        testCase.subHea[h].R, 
                                        testCase.subHea[h].F2, 
                                        testCase.subHea[h].E, 
                                        testCase.subHea[h].lcid, 
                                        testCase.subHea[h].L,
                                        testCase.subHea[h].R1e,
                                        testCase.subHea[h].R2e,
                                        testCase.subHea[h].eLCID);
        }else{
            hResult =  formSubHeader(false, 
                                    testCase.subHea[h].type, 
                                    testCase.subHea[h].R, 
                                    testCase.subHea[h].F2, 
                                    testCase.subHea[h].E, 
                                    testCase.subHea[h].lcid, 
                                    testCase.subHea[h].L);
        }
        for(int i = startIdx; i < hResult.len + startIdx; i++){
            if (i < actualLen){
                packet[i] = hResult.pattern[i - startIdx];
            }else{
                // printf("[GEN] Actual Len is smaller than expected len, h = %d/%d, i = %d, actualLen = %d\n", h, testCase.nofSubHea, i, actualLen);
            }
        }
        startIdx += hResult.len;
    };

    if (testCase.eIdx < 0){
        headerResult hResult =  formSubHeaderFree_eLCID(testCase.eIdx, 
                                                        testCase.subHea[testCase.nofSubHea - 1].R, 
                                                        testCase.subHea[testCase.nofSubHea - 1].F2, 
                                                        testCase.subHea[testCase.nofSubHea - 1].E, 
                                                        testCase.subHea[testCase.nofSubHea - 1].lcid, 
                                                        testCase.subHea[testCase.nofSubHea - 1].F,
                                                        testCase.subHea[testCase.nofSubHea - 1].L,
                                                        testCase.subHea[testCase.nofSubHea - 1].R1e,
                                                        testCase.subHea[testCase.nofSubHea - 1].R2e,
                                                        testCase.subHea[testCase.nofSubHea - 1].eLCID);
        for(int i = startIdx; i < hResult.len + startIdx; i++){
            if (i < actualLen){
                packet[i] = hResult.pattern[i - startIdx];
            }else{
                // printf("[GEN] Actual Len is smaller than expected len (F), i = %d\n", i);
            }
        }
        startIdx += hResult.len;

    }else {
        headerResult hResult =  formSubHeader_eLCID(true, 
                                                    testCase.subHea[testCase.nofSubHea - 1].type, 
                                                    testCase.subHea[testCase.nofSubHea - 1].R, 
                                                    testCase.subHea[testCase.nofSubHea - 1].F2, 
                                                    testCase.subHea[testCase.nofSubHea - 1].E, 
                                                    testCase.subHea[testCase.nofSubHea - 1].lcid, 
                                                    testCase.subHea[testCase.nofSubHea - 1].L,
                                                    testCase.subHea[testCase.nofSubHea - 1].R1e,
                                                    testCase.subHea[testCase.nofSubHea - 1].R2e,
                                                    testCase.subHea[testCase.nofSubHea - 1].eLCID);
        for(int i = startIdx; i < hResult.len + startIdx; i++){
            if (i < actualLen){
                packet[i] = hResult.pattern[i - startIdx];
            }else{
                // printf("[GEN] Actual Len is smaller than expected len (F), i =%d\n", i);
            }
        }
        startIdx += hResult.len;

    }
    /*No Generating payload needed */

}

void macFuzzer_t::send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen){
    if (actualLen >= (int)curTestCase.totalByte){ //rnti == curRNTI
        macPDU_t testcase = curTestCase; // testcase to insert offset subheaders and subpayloads;
        if (testcase.totalByte == 0){
            // printf("[GEN] Test case has 0 byte, idx = %d\n", idx[fuzzingState]);
        }
        bool iseLCID = testcase.iseLCID;
        int nofSubHea = testcase.nofSubHea;
        bool isAll_a  = testcase.isAll_a; // check if we are sending packet with all hex aaaa....

        if (isAll_a){
            for (int i = 0; i < actualLen; i++){
                payload[i] = 0xbb;
            }

            // printf("[GEN] Sending all hex aaaa....\n");
            std::vector<macPDU_t>& curDB = (readFromFileMode)? verifyDB[fuzzingState]:testcaseDB[fuzzingState];
            // increase test case index
            if (idx[fuzzingState] < (int)curDB.size()){
                idx[fuzzingState]++;
            }else{
                // printf("[GEN] Finish sending test cases\n");
            }
        }else{    
            // testcase.totalByte = testcase.totalByte + 10; // if read from file, we need to add 1 byte for offset subheader
            int offset = 0;
            if (nofSubHea == 1 || testcase.isMutateLastSubHea){
                offset = 0; // no offset needed for 1 subheader
            }else if (!iseLCID && nofSubHea > 1){
                offset = checkOffsetSubHea_new(testcase, actualLen);
            }else{
                offset = checkOffsetSubHea_eLCID_new(testcase, actualLen);
            }

            if (offset == -1 && (fuzzingState == state234 || fuzzingState == state4) && iseLCID){ // if offset is -1, we need to skip this testcase and add 1 subheader to test case in db
                // std::cout << "[GEN] Offset is -1, skip this testcase, adding one more subheader to testcase in DB\n" << "\n";
                std::vector<macPDU_t>& curTestcaseDB = testcaseDB[fuzzingState];
                macPDU_t &curTestcasetemp = curTestcaseDB[idx[fuzzingState]];
                macSubHeader_t offSubHea;
                macSubPayload_t offSubPay;
                offSubHea.eLCID = curTestcasetemp.subHea[curTestcasetemp.nofSubHea-1].eLCID;
                offSubHea.type = typeAe;
                offSubHea.isLast = false; // remember to update hIdx of last one and this one
                offSubHea.L = curTestcasetemp.subHea[curTestcasetemp.nofSubHea-2].L; // get L of previous subheader as last one does not have L
                autoFillSubHea_eLCID(offSubHea, offSubPay, offSubHea.type, offSubHea.isLast, offSubHea.eLCID, offSubHea.L, curTestcasetemp.eIdx, curTestcasetemp.nofSubHea - 2); // hIdx = testcase.nofSubHea - 2
                curTestcasetemp.subHea.insert(std::prev(curTestcasetemp.subHea.end()), offSubHea);
                curTestcasetemp.subPay.insert(std::prev(curTestcasetemp.subPay.end()), offSubPay);
                curTestcasetemp.nofSubHea++;
                curTestcasetemp.totalByte = curTestcasetemp.totalByte + heaSizeMap[typeAe];
            }else{
                if (nofSubHea == 1){
                    generatePDU_1(testcase, offset, payload, actualLen);
                }else if (testcase.isMutateLastSubHea){
                    generatePDU_mutateLastSubhea(testcase, offset, payload, actualLen);
                }else if (!iseLCID){
                    generatePDU_new(testcase, offset, payload, actualLen);
                }else{
                    generatePDU_eLCID(testcase, offset, payload, actualLen);
                }
                
                std::vector<macPDU_t>& curDB = (readFromFileMode)? verifyDB[fuzzingState]:testcaseDB[fuzzingState];
                // LLState_t fuzzingState = (fuzzingState == state3)?state2:curRNTIState;
                // if (readFromFileMode){
                //     fuzzingState = curRNTIState; // in verify mode, we test all states
                // }
                // fuzzingState = (fuzzingState==state4)?state4:fuzzingState;
                if (DEBUG_MODE){
                    std::cout << "[MAC] SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << " -- Sending State: " << (int)fuzzingState << ", RNTIState =  " \
                        << fuzzingState << " -- Idx = " << idx[fuzzingState] << "/" << curDB.size() << " -- nofCrash: " << nofCrash << "\n";
                    printPDUtestcase_new(testcase);
                    terminalLog << " Idx[2] = " << idx[2] << " -- Idx[4] = " << idx[4] << " -- Idx[5] = " << idx[5] << "\n"; 
                }

                macPDU_t savePDU = testcase;
                savePDU.actualLen = actualLen;
                if (readFromFileMode){
                    verifiedcrashBuffer[fuzzingState].push(std::move(savePDU));
                    recent_testcases[fuzzingState].push(idx[fuzzingState]);
                }else{
                    crashBuffer.push(std::move(savePDU));
                    recent_testcases[fuzzingState].push(idx[fuzzingState]);
                }

                /* Increase test case index*/
                if (!readFromFileMode && (idx[fuzzingState] < (int)curDB.size())){
                    idx[fuzzingState] = idx[fuzzingState] + 1;
                }else if ( readFromFileMode && (idx[fuzzingState] < (int)verifyDB[fuzzingState].size())){
                    idx[fuzzingState] = idx[fuzzingState] + 1;
                }

                /* Switch to next verifying state if idx passes max idx*/
                // if ( readFromFileMode && (idx[fuzzingState] == (int)verifyDB[fuzzingState].size())){
                //     if (verifyingState < state4){
                //         verifyingState = (LLState_t)NEXT_STATE(verifyingState);
                //         idx[verifyingState] = 0;
                //         state234Phase = state234Prepare; // start over again
                //         std::cout << "\n";
                //         std::cout << "[MAC] Switch to next verifying state = " << verifyingState << "\n";
                //         std::cout << "\n";
                //     }
                // }

                // printf("[MAC] increased idx = %d\n", idx[curRNTIState]);
                if (!readFromFileMode && (fuzzingState == state234) && (idx[fuzzingState] == (int)curDB.size())){
                    std::cout << "[MAC] Finished sending state234 test cases for State = " << fuzzingState << "\n";
                }else if (readFromFileMode && (idx[fuzzingState] == (int)verifyDB[fuzzingState].size())){
                    std::cout << "[MAC] Finished verifying test case from file state =  " << verifyingState << "\n";
                }else if (!readFromFileMode && (fuzzingState == state4) && (idx[4] == (int)testcaseDB[state4].size())){
                    std::cout << "[MAC] Finished sending state4 test cases" << "\n";
                }

                // if (idx[2] == (int)tcState234DB.size()
                // // && idx[3] == (int)tcState234DB.size()
                // && idx[4] == (int)tcState234DB.size())
                // {
                //     state234finished = true;
                //     finishingTimer.running = true;
                //     finishingTimer.activeTime = std::chrono::system_clock::now();
                //     if (DEBUG_MODE){ std::cout << "[MAC] Finished sending state234 test cases for all states" << "\n"; }
                // }
            }
        }
        // if (idx[4] == 13901){
        //     fuzzingState = stateUnknown;
        //     stopFuzzingTimer(waitingConnTimer);
        //     stopFuzzingTimer(pagingTimer);
        //     stopFuzzingTimer(finishingTimer);
        //     stopFuzzingTimer(notWorkingTimer);
        //     stopFuzzingTimer(rfLinkTimer);
        //     stopFuzzingTimer(rrcReleaseTimer);
        // }
        // notWorkingTimer.activeTime = std::chrono::system_clock::now(); // update active of fuzzer
    }else{
        if (DEBUG_MODE){
            std::cout << "[MAC] SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << " ActualLen < Requested Length, skip this sf, rnti = " \
                << rnti << " -- " << actualLen << "|" << curTestCase.totalByte <<  "\n";
        }
    }
}

void macFuzzer_t::writeTCtoFile(std::ofstream& file, macPDU_t& pdu){
    if (file){
        file << "Nof_Sub = " << std::setw(3) << (int)pdu.nofSubHea << " -- eIdx = " << std::setw(3) << (int)pdu.eIdx << " -- totalByte = " << std::setw(5) << (int)pdu.totalByte \
        << " -- iseLCID = " << std::setw(2) << (int)pdu.iseLCID << " -- OrinH = " << std::setw(3) << (int)pdu.orinSubH << " -- OrinB = " << std::setw(5) << (int)pdu.orinByte << "\n";
        for (int h = 0; h < pdu.nofSubHea; h++){
            file << "LCID = " << std::setw(3) << (int)pdu.subHea[h].lcid << " -- type = " << (int)pdu.subHea[h].type << " -- L = " \
            << std::setw(5) << (int)pdu.subHea[h].L << " -- Payl Size = " << std::setw(5) << (int)pdu.subPay[h].size << " -- W_ID = " << pdu.subHea[h].isWrongID \
            << " -- R: " << (int)pdu.subHea[h].R << " -- F2: " << (int)pdu.subHea[h].F2 << " -- E: " << (int)pdu.subHea[h].E<< " -- eLCID = " << (int)pdu.subHea[h].eLCID << "\n";
        }
        file << "\n";
    }
}

void macFuzzer_t::readTCfromFile(const std::string& filename){
    std::ifstream file(filename);
    if (file.is_open()){
        std::string line;
        int readingState = 0; // 1: detect "Detected Crash", 2: read testcase, 3: read subheader + subpayload
        int tcState = 0;
        int readIdx[5]; // plus 1 when detect Nof_sub
        for (int i = 0; i < 5; i++){
            readIdx[i] = -1;
        }
        int hIdx = 0;
        int nofSubh = 0;
        int t_lcid = 0;
        int t_type = 0;
        int t_L = 0;
        int t_size = 0;
        int t_W_ID = 0;
        int t_R = 0;
        int t_F2 = 0;
        int t_E = 0;
        int t_eIdx = 0;
        int t_totalByte = 0;
        int t_eLCID = 0;

        while (std::getline(file, line)){
            if (line.find("State:") != std::string::npos){
                tcState = std::stoi(line.substr(line.find("State:") + 7, 1));
                // std::cout << "[REA] Reading testcase for State " << tcState << "\n";
                if (tcState > 5){
                    std::cout << "[REA] Error reading testcase, tcState > 5" << "\n";
                }
            }
            if (line.find("Nof_Sub =") != std::string::npos){
                nofSubh = std::stoi(line.substr(line.find("Nof_Sub =") + 10, 4));
                // std::cout << "[REA] Nof_Sub = " << nofSubh << "\n";
                macPDU_t newTC;
                allocVectorPDU(newTC, nofSubh);
                newTC.nofSubHea = nofSubh;
                newTC.eIdx = std::stoi(line.substr(line.find("eIdx") + 6, 4));
                // std::cout << "[REA] eIdx = " << (int)newTC.eIdx << "\n";
                newTC.totalByte = std::stoi(line.substr(line.find("totalByte") + 12, 6));  // to avoid adding paddings
                // newTC.totalByte = newTC.totalByte - 10;
                // std::cout << "[REA] totalByte = " << newTC.totalByte << "\n";
                // std::string tempstr  = line.substr(line.find("iseLCID") + 9, 3);
                // std::cout << "[REA] iseLCID = " << tempstr << "\n";
                newTC.iseLCID = std::stoi(line.substr(line.find("iseLCID") + 9, 3));
                // std::cout << "[REA] iseLCID = " << newTC.iseLCID << "\n";
                // std::string tempstr = line.substr(line.find("OrinH") + 6, 4);
                // std::cout << tempstr << "\n";
                newTC.orinSubH = std::stoi(line.substr(line.find("OrinH") + 7, 4));
                // std::cout << "[REA] OrinH = " << newTC.orinSubH << "\n";
                newTC.orinByte = std::stoi(line.substr(line.find("OrinB") + 7, 6));
                // std::cout << "[REA] OrinB = " << newTC.orinByte << "\n";
                verifyDB[tcState].push_back(std::move(newTC));

                t_eIdx = newTC.eIdx;
                // t_totalByte = newTC.totalByte - 6; // to avoid adding padding
                readIdx[tcState] = readIdx[tcState] + 1;
                hIdx = 0;
            }
            if (line.find("type =") != std::string::npos){
                std::string tempstr = line.substr(line.find("LCID =") + 7, 4);
                // std::cout << tempstr << "\n";
                verifyDB[tcState][readIdx[tcState]].subHea[hIdx].lcid = (uint8_t)std::stoi(line.substr(line.find("LCID =") + 7, 4));
                // std::cout << "[REA] LCID = " << (int)verifyDB[tcState][readIdx[tcState]].subHea[hIdx].lcid << "\n";
                verifyDB[tcState][readIdx[tcState]].subHea[hIdx].type = (macSubHeaderType_t)(std::stoi(line.substr(line.find("type =") + 7, 1)) );
                // std::cout << "[REA] type = " << verifyDB[tcState][readIdx[tcState]].subHea[hIdx].type << "\n";
                verifyDB[tcState][readIdx[tcState]].subHea[hIdx].L = std::stoi(line.substr(line.find("L =") + 4, 6));
                // std::cout << "[REA] L = " << verifyDB[tcState][readIdx[tcState]].subHea[hIdx].L << "\n";
                verifyDB[tcState][readIdx[tcState]].subPay[hIdx].size = std::stoi(line.substr(line.find("Payl Size =") + 12, 6));
                // std::cout << "[REA] Payl Size = " << (int)verifyDB[tcState][readIdx[tcState]].subPay[hIdx].size << "\n";
                verifyDB[tcState][readIdx[tcState]].subHea[hIdx].isWrongID = std::stoi(line.substr(line.find("W_ID =") + 7, 1));
                // std::cout << "[REA] W_ID = " << verifyDB[tcState][readIdx[tcState]].subHea[hIdx].isWrongID << "\n";
                verifyDB[tcState][readIdx[tcState]].subHea[hIdx].R = std::stoi(line.substr(line.find("R:") + 3, 1));
                // std::cout << "[REA] R = " << verifyDB[tcState][readIdx[tcState]].subHea[hIdx].R << "\n";
                verifyDB[tcState][readIdx[tcState]].subHea[hIdx].F2 = std::stoi(line.substr(line.find("F2:") + 4, 1));
                // std::cout << "[REA] F2 = " << verifyDB[tcState][readIdx[tcState]].subHea[hIdx].F2 << "\n";
                verifyDB[tcState][readIdx[tcState]].subHea[hIdx].E = std::stoi(line.substr(line.find("E:") + 3, 1));
                // std::cout << "[REA] E = " << verifyDB[tcState][readIdx[tcState]].subHea[hIdx].E << "\n";
                // tempstr = line.substr(line.find("LCID_e =") + 9, 5);
                // std::cout << " string: " << tempstr << "\n";
                verifyDB[tcState][readIdx[tcState]].subHea[hIdx].eLCID = std::stoi(line.substr(line.find("LCID_e =") + 9, 5));
                // std::cout << "[REA] eLCID = " << (int)verifyDB[tcState][readIdx[tcState]].subHea[hIdx].eLCID << "\n";
                
                t_lcid = verifyDB[tcState][readIdx[tcState]].subHea[hIdx].lcid;
                t_type = verifyDB[tcState][readIdx[tcState]].subHea[hIdx].type;
                t_L = verifyDB[tcState][readIdx[tcState]].subHea[hIdx].L;
                t_size = verifyDB[tcState][readIdx[tcState]].subPay[hIdx].size;
                t_W_ID = verifyDB[tcState][readIdx[tcState]].subHea[hIdx].isWrongID;
                t_R = verifyDB[tcState][readIdx[tcState]].subHea[hIdx].R;
                t_F2 = verifyDB[tcState][readIdx[tcState]].subHea[hIdx].F2;
                t_E = verifyDB[tcState][readIdx[tcState]].subHea[hIdx].E;
                t_eIdx = verifyDB[tcState][readIdx[tcState]].eIdx;
                t_eLCID = verifyDB[tcState][readIdx[tcState]].subHea[hIdx].eLCID;
                bool lastSubh = (hIdx == nofSubh - 1)?true:false;

                if (!verifyDB[tcState][readIdx[tcState]].iseLCID){ // if this testcase is not eLCID
                    autoFillSubHea(verifyDB[tcState][readIdx[tcState]].subHea[hIdx], 
                                verifyDB[tcState][readIdx[tcState]].subPay[hIdx], 
                                (macSubHeaderType_t)t_type, 
                                lastSubh,
                                t_W_ID, 
                                t_R, 
                                t_lcid, 
                                t_L, t_eIdx, hIdx);
                }else{
                    autoFillSubHea_eLCID(verifyDB[tcState][readIdx[tcState]].subHea[hIdx], 
                                verifyDB[tcState][readIdx[tcState]].subPay[hIdx], 
                                (macSubHeaderType_t)t_type, 
                                lastSubh,
                                t_eLCID, 
                                t_L, 
                                t_eIdx, 
                                hIdx);
                }
                // autoFillSubHea(verifyDB[tcState][readIdx[tcState]].subHea[hIdx], 
                //                verifyDB[tcState][readIdx[tcState]].subPay[hIdx], 
                //                (macSubHeaderType_t)t_type, 
                //                lastSubh,
                //                t_W_ID, 
                //                t_R, 
                //                t_lcid, 
                //                t_L, t_eIdx, hIdx);
                hIdx++;
                if (hIdx > nofSubh){
                    std::cout << "[REA] Error reading testcase, hIdx > nofSubh" << "\n";
                }
            }
        }
        std::cout << "[REA] Finished reading testcase from file" << "\n";
        std::cout << "[REA] Verify DB size: " << verifyDB[2].size() << " " << verifyDB[3].size() << " " << verifyDB[4].size() << "\n";
        // write tc to file again to check correctness
        for (auto &tc: verifyDB[4]){
            writeTCtoFile(tcFile, tc);
        }
        file.close();
    }
}

void macFuzzer_t::update_rlc_sequence_number(uint16_t lcid, uint16_t sn){
    rlcSNmap[lcid] = sn;
}


} // namespace srsenb

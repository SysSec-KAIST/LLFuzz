#pragma once

#include <deque>
#include <ctime>
#include <atomic>
#include <fcntl.h>
#include <errno.h>
#include <stdexcept>
#include <iostream>
#include <cmath>
#include <chrono>
#include <iomanip>

#include "srsran/asn1/liblte_mme.h"
#include "srsran/asn1/rrc/dl_ccch_msg.h"
#include "srsran/asn1/rrc/dl_dcch_msg.h"
#include "srsran/asn1/rrc/ul_ccch_msg.h"
#include "srsran/asn1/rrc/ul_dcch_msg.h"
#include "srsran/asn1/asn1_utils.h"
#include "srsran/mac/pdu.h"
#include "srsran/phy/phch/dci.h"
#include "srsran/phy/phch/ra.h"

#define RAR_MAX_HEADER      101

#define NOF_HEADER_SKE_1    10
#define DEBUG_MODE true
#define RED_TEXT        "\033[31m"
#define GREEN_TEXT      "\033[32m"
#define YELLOW_TEXT     "\033[33m"
#define BLUE_TEXT       "\033[34m"
#define PINK_TEXT       "\033[35m"
#define RESET_COLOR     "\033[0m"
#define CYAN            "\033[36m"              /* Cyan */
#define WHITE           "\033[37m"              /* White */
#define BOLDRED         "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN       "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW      "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE        "\033[1m\033[34m"      /* Bold Blue */
#define BOLDWHITE       "\033[1m\033[37m"      /* Bold White */
#define SRSUE_MODE      false

using timePoint_t = std::chrono::high_resolution_clock::time_point;

#define NEXT_STATE(state) ((int)((int)(state) + 1))
#define LLFUZZ_CCCH  0
#define LLFUZZ_DCCH1 1
#define LLFUZZ_DCCH2 2
#define LLFUZZ_DTCH  3

namespace srsenb {

enum adbPhase_t: uint8_t{
  adbNoPhase = 0,
  adbTurnOnAirplane = 1,
  adbTurnOffAirplane = 2,
  adbDisableCellData = 3,
  // adbEnableCellData = 4,
};

enum toAdbCommand_t: uint8_t {
  checkADB = 0,
  switchAirplane = 1,
  monitorLogcat = 2,
  switchAirplaneCrash = 3,
  state1PrepareADB = 4,
  pingUE = 5,
  rebootUE = 6,
  enableCellData = 7,
  querryWeb = 8,
  adbSleep = 9
};

enum fromAdbCommand_t: int {
  crashDetected = 1,
  recovered = 2,
  adbConfigSuccess = 3,
  adbAirPlaneOn = 4,
  noAction = -1
};

enum pduDecodingResult_t: uint8_t {
  pduRRCConSet = 0,
  pduRRCReconfig = 1,
  pduRRCConReq = 2,
  pduRRCReestablishmentComplete = 3,
  pduRRCReconfigComplete = 4,
  pduUnknown = 5
};

enum rlcPDUType_t: uint8_t
{
    rlcUM1 = 0,
    rlcUM2,
    rlcAM1,
    rlcAM2,
    rlcStatus,
    rlcAMSegment1,
    rlcAMSegment2,
    rlcUnknown
};

struct pduInfo_t{
  pduDecodingResult_t  pduDecodingResult = pduUnknown;
  bool                 hasIP = false;
  uint8_t              ip[4] = {0};
  uint8_t              conResID[6] = {0};
  uint8_t              mmec;
  bool                 hasTMSI = false;
  uint32_t             m_tmsi = 0;
};

struct mac_packet_t{
  uint8_t packet[10000] = {0};
  int len = 0;
  uint32_t tti;
  uint16_t rnti;
};

// static int  adbStopPipe[2]     = {false};
// static int  macAdbInterface[2] = {(int)checkADB}; // 1: switch airplane mode
// static int  adbMacInterface[2] = {(int)noAction}; // 1: crash detected from ADB
// static int  pingPipe[2]; // to transfer UE ip to adb thread to ping
// static int  ttiPipe[2];  // to inform adb thread about current tti

template <typename T, size_t N>
class RingBuffer {
public:
    RingBuffer() : size_(N) {}

    void push(const T& value) {
        if (full()) {
          buffer_.pop_front(); //remove front member
          buffer_.push_back(value);
        }else{
          buffer_.push_back(value);
          count_++;
        }
    }


    size_t size() const {
        return count_;
    }

    bool empty() const {
        return count_ == 0;
    }

    bool full() const {
        return count_ == size_;
    }
    
    void cleanUp(){
      buffer_.clear();
      buffer_.shrink_to_fit();
      count_ = 0;
    }

    T getHead(){
      return buffer_.front();
    }
    T getTail(){
      return buffer_.back();
    }

    std::deque<T>& getBuffer(){
      return buffer_;
    }

    void resize(size_t new_size) {
      size_ = new_size;
      if (count_ > size_) {
          while (count_ > size_) {
              buffer_.pop_front();
              count_--;
          }
      }
    }
    
  private:
    size_t size_;
    std::deque<T> buffer_;
    size_t count_ = 0;
};

struct fuzzingTimer_t{
  bool     running = {false};
  timePoint_t activeTime;
};

struct harqFeedBack_t{
  int tti = 0; 
  enum fb: uint8_t {nack = 0, ack = 1, missing = 2} harqFb = missing; // harq feedback
};

enum macSubHeaderType_t : uint8_t {
  typeA = 0, 
  typeB = 1, 
  typeC = 2, 
  typeD = 3,
  typeAe = 4,
  typeBe = 5,
  typeCe = 6,
  typeDe = 7, 
  none = 8
};

struct macHeaderResult_t{
  uint8_t pattern[3];
  int len = 0;
};

struct rarResult_t{
  uint8_t pattern[6];
  int len = 0;
};

struct constMessage_t{
  std::vector<uint8_t>  message;
  int         len;
};

struct general_MAC_CE_t{
  uint64_t payload = 0; // 4 bytes for 1-4 byte MAC CE
  void print(){
    std::cout << " -- payload: " << (int)payload;
  }
};

struct contention_resl_CE_t{ // lcid = 28
  uint64_t payload = 0; // 6 bytes for contention resolution 
  void print(){
    std::cout << " -- Contention payload: " << (int)payload;
  }
};

struct timing_advance_CE_t{ // lcid = 29
  bool R1 = false;
  bool R2 = false;
  uint8_t ta = 0; 
  void print(){
    std::cout << " -- R1: " << (int)R1 << " -- R2: " << (int)R2 << " -- Timing Advance: " << (int)ta;
  }
};

struct recommended_bitrate_CE_t{ // lcid = 22
  uint8_t lcid_bitrate = 0;
  bool ul_dl = false;
  uint8_t bitrate = 0;
  bool x = false;
  bool r = false;
  uint8_t  payload[2] = {0};
  void print(){
    std::cout << " -- LCID_br: " << (int)lcid_bitrate << " -- ul_dl: " << (int)ul_dl << " -- bitrate: " << (int)bitrate << " -- r: " << (int)r;
  } 
};

using phyTestCase_t   = srsran_dci_dl_t;
using phyTestCaseUL_t = srsran_dci_ul_t;  

int         set_non_blocking_mode(int filedes);
bool        checkTimer(fuzzingTimer_t& checkingTimer, float thres);
void        stopFuzzingTimer(fuzzingTimer_t& fuzzingTimer);
bool        checkRFLinkIssue(RingBuffer<timePoint_t, 6>& rarVector);
int         getTXtti(uint rxtti);
uint32_t    nBitRandomGen(uint32_t n);
pduInfo_t   decodePDU(uint8_t* ptr, int len, int tti_tx_dl);
pduInfo_t   decodePDUuplink(uint8_t *pdu_ptr, int length, int tti_tx_ul);
std::string getfromADBString(fromAdbCommand_t adbMac);
bool        checkSendTCttiState2(int triggerTTI, int curTTI, int nof_test_cases_per_ss); // check if it 2 ms after trigger state
bool        checkSendTCttiState3(int triggerTTI, int curTTI, int nof_test_cases_per_ss);
bool        checkSendTCttiState4(int triggerTTI, int curTTI, int nof_test_cases_per_ss);
bool        checkSendTCttiState4VerifyMode(int triggerTTI, int curTTI);
bool        checkSendTCttiState5(int triggerTTI, int curTTI);
bool        checkSendTCttiState5Condition2(int triggerTTI, int curTTI);
bool        checkSendTCttiState2Decoy(int triggerTTI, int curTTI);
bool        checkSendTCttiState3Decoy(int triggerTTI, int curTTI);
bool        checkSendTCbyDCIState5_UL(int &nof_user_dci_ul, int reserved);
int         formMacSubHeaderTypeD(int R, int F2, int E, int lcID);
macHeaderResult_t formMacSubHeader(bool isLast, macSubHeaderType_t type, uint8_t R, uint8_t F2, uint8_t E, int lcID, int len);
void        printDCI_format1A(phyTestCase_t& pdu);
void        printDCI_format1(phyTestCase_t& pdu);
void        printDCI_format2(phyTestCase_t& pdu);
void        printDCI_format2A(phyTestCase_t& pdu);
void        printDCI_format1C(phyTestCase_t& pdu);
void        printDCI_format0(phyTestCaseUL_t& pdu);

class BitPacker {
  public:
      std::vector<uint8_t> buffer;
      int bitPos = 0; // Bit position within current byte
  
      // Adds the lower 'numBits' of 'value' into the bitstream
      void addBits(uint32_t value, int numBits) {
          while (numBits > 0) {
              if (bitPos == 0) buffer.push_back(0); // Start new byte if needed
  
              int byteIdx = buffer.size() - 1;
              int bitsLeftInByte = 8 - bitPos;
              int bitsToWrite = std::min(bitsLeftInByte, numBits);
              int shift = numBits - bitsToWrite;
  
              uint8_t bits = (value >> shift) & ((1 << bitsToWrite) - 1);
              buffer[byteIdx] |= bits << (bitsLeftInByte - bitsToWrite);
  
              bitPos = (bitPos + bitsToWrite) % 8;
              numBits -= bitsToWrite;
          }
      }
  
      // Returns the packed byte vector
      std::vector<uint8_t> get_final_result() const {
          return buffer;
      }
  
      // Optional: Print the hex representation
      void printHex() const {
          for (uint8_t byte : buffer)
              printf("%02X ", byte);
          printf("\n");
      }
};


} // namespace srsenb
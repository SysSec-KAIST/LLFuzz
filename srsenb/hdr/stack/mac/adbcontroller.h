#pragma once

#include <deque>
#include <ctime>
#include <atomic>
#include <string>
#include <future>
#include <iostream>
#include <sstream>
#include <fstream>

#include "srsran/common/threads.h"
#include "srsenb/hdr/stack/mac/utility.h"

namespace srsenb {

// /*Thread for adb control*/
// class ADBController: public srsran::thread{
// public:
//   ADBController();
//   ~ADBController();
//   int  runADBThread();
//   void stop(){ adbStop = true; }
// protected:
//   virtual void run_thread() override;
// private:
//   bool              adbStop      = {false};
//   bool              adbConnected = false;
//   std::string       adbCommand =  "adb devices";
//   std::string       adbResult;
//   const std::string airplaneOff  = "adb shell cmd connectivity airplane-mode disable";
//   const std::string airplaneOn   = "adb shell cmd connectivity airplane-mode enable";
//   const std::string CellDataOn   = "adb shell svc data enable";
//   const std::string CellDataOff  = "adb shell svc data disable";
//   const std::string wifiOff      = "adb shell svc wifi disable";
//   const std::string wifiOn       = "adb shell svc wifi enable";
//   const std::string crashString1 = "RADIO_OFF_OR_UNAVAILABLE";
//   const std::string crashString2 = "Modem Reset";
//   const std::string crashString3 = "CRASH";
//   const std::string cleanADB     = "adb logcat -c -b radio";
//   const std::string checkCellData = "adb shell settings get global mobile_data";
//   fuzzingTimer_t    adbTimer;
//   std::future<int>  adbFuture;
//   adbPhase_t        adbPhase = {adbNoPhase};
//   int               prevTTI = 0;
// };


} // namespace srsenb
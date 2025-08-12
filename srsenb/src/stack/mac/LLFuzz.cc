#include "srsenb/hdr/stack/mac/LLFuzz.h"

namespace srsenb {

/*ADB Interface*/
ADBController::ADBController(): thread("adb_controller")
{
  if (pipe(toAdbInterface) == -1 || pipe(fromAdbInterface) == -1 || pipe(pingPipe) == -1 
      || pipe(adbStopPipe) == -1 || pipe(ttiPipe) == -1){
    std::cout << "Init PIPE interface failed " << "\n";
  }

 if (set_non_blocking_mode(toAdbInterface[0]) == -1 || set_non_blocking_mode(fromAdbInterface[0]) == -1 
    || set_non_blocking_mode(pingPipe[0]) == -1 || set_non_blocking_mode(adbStopPipe[0]) == -1 || set_non_blocking_mode(ttiPipe[0]) == -1) {
    std::cout << "Init PIPE interface failed 2 " << "\n";
  }
    // int tempSignal = (int)checkADB; // check adb connection
    // ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
    // if (ret <=0){
    //     printf("[MTT] Error: cannot write to toAdbInterface pipe\n");
    // }
}

ADBController::~ADBController(){
  adbStop = true;
}

std::string toADBInterfaceGetString(toAdbCommand_t value){
  std::string ret = "unknown";
  switch (value)
  {
  case checkADB:
    ret = "checkADB";
    break;
  case switchAirplane:
    ret = "switchAirplane";
    break;
  case monitorLogcat:
    ret = "monitorLogcat";
    break;
  case switchAirplaneCrash:
    ret = "switchAirplaneCrash";
    break;
  case state1PrepareADB:
    ret = "state1PrepareADB";
    break;
  case pingUE:
    ret = "pingUE";
    break;
  case adbSleep:
    ret = "adbSleep";
    break;
  case rebootUE:
    ret = "rebootUE";
    break;
  case enableCellData:
    ret = "enableCellData";
    break;
  case querryWeb:
    ret = "querryWeb";
    break;
  default:
    break;
  }
  return ret;
}

std::string exeCmd(const char* cmd) {
  // Execute the command and redirect output to a file
  int ret = system((std::string(cmd) + " > output.txt").c_str());

  // Read the content of the output file into a string
  std::ifstream outputFile("output.txt");
  if (outputFile) {
      std::string outputContent((std::istreambuf_iterator<char>(outputFile)), std::istreambuf_iterator<char>());
      outputFile.close();

      // Clean up: delete the output file
      remove("output.txt");

      return outputContent;
  } else {
      return "Failed to open the output file.";
  }
}

void ADBController::run_thread(){
  // Store main thread id for monitoring
  // check adb connection
  adbCommand = "adb devices";
  adbResult = exeCmd(adbCommand.c_str());
  //print adb result
  std::cout << "\n";
  std::cout << adbResult;
  if ((int)adbResult.length() > 30){
    adbConnected = true;
    std::cout << GREEN_TEXT << "[ADB] Device Connected " << RESET_COLOR << "\n";
  }else{
    std::cout << RED_TEXT << "[ADB] Device Disconnected" << RESET_COLOR << "\n";
  }
  std::cout << "\n";

  if (adbConnected && enableADB_cfg){

    pid_t main_tid = getppid();  
    pid_t pid = fork();

    if (pid == 0){
      while(!adbStop){

        // Quick check if parent exists - very lightweight operation
        if (kill(main_tid, 0) != 0) {
          printf("[ADB] Main thread terminated, stopping ADB thread\n");
          adbStop = true;
          break;
        }
        
        toAdbCommand_t toADB;
        int temp;
        ssize_t ret = read(toAdbInterface[0], &temp, sizeof(temp));
        toADB = (toAdbCommand_t)temp;
        int ueIP;
        ssize_t ret2 = read(pingPipe[0], &ueIP, sizeof(ueIP));
        if (ret2 <= 0){
          ueIP = 2;
        }
        int stopSignal;
        ssize_t ret3 = read(adbStopPipe[0], &stopSignal, sizeof(stopSignal));
        if (ret3 > 0 && stopSignal == 1){
          adbStop = true;
        }
        int curTTI = 0;
        ssize_t ret4 = read(ttiPipe[0], &curTTI, sizeof(curTTI));
        if ( ret4 <= 0){ curTTI = prevTTI;}
        else { prevTTI = curTTI;} // save TTI for other phases that dont receive tti from rlc thread
        if (ret <= 0){ //no new data
          toADB = monitorLogcat;
        }else{
          if (DEBUG_MODE){ 
            printf("[ADB] SF: %d.%d Received signal: ", curTTI/10, curTTI%10); 
            std::cout << BLUE_TEXT << "[LLFuzz -> ADB] " + toADBInterfaceGetString(toADB) << RESET_COLOR << "\n";
          }
        }
        if (toADB == checkADB){
          adbCommand = adbCommand;
          const char* cmdstr = adbCommand.c_str();
          adbResult = exeCmd(cmdstr);
          std::cout << adbResult;
          //Check if there is a connected device
          if ((int)adbResult.length() > 30){
            adbConnected = true;
            std::cout << "[ADB] Device Connected " << "\n";
          }else{
            std::cout << "[ADB] Device Disconnected, L =  " << (int)adbResult.length() << "\n";
          }

          /*clean adb output*/
          adbCommand = cleanADB;
          const char* cmdstr2 = adbCommand.c_str();
          adbResult = exeCmd(cmdstr2);
          // toAdbInterface = monitorLogcat;
        
        } else if ((toADB == switchAirplane || adbPhase == adbTurnOffAirplane) and adbConnected){ // || adbPhase == adbDisableCellData
          if (!adbTimer.running){
            /*Turn on airplane mode*/
            adbCommand = airplaneOn;
            const char* cmdstr = adbCommand.c_str();
            adbResult = exeCmd(cmdstr);
            std::cout << adbResult;
            /*start timer for 2 seconds*/
            adbTimer.running = true;
            adbTimer.activeTime = std::chrono::system_clock::now();
            adbPhase = adbTurnOffAirplane; // change adb phase to continue executing without signal from pipe
            if (DEBUG_MODE){ printf("[ADB] SF: %d.%d -- State: Turned on Airplane mode, enabled timer 0 \n", curTTI/10, curTTI%10); }       
          }else if (adbTimer.running && adbPhase == adbTurnOffAirplane){
            if (checkTimer(adbTimer, 1200)){ // timer is timeout
              //Send signal to rlc to indicate that airplane mode is on, fuzzer should switch to waitingConnection phase
              int temp = (int)adbAirPlaneOn;
              ssize_t ret = write(fromAdbInterface[1], &temp, sizeof(temp));
              if (DEBUG_MODE){ printf("[ADB] SF: %d.%d Sent adbAirPlaneOn signal to rlc \n", curTTI/10, curTTI%10); }
              /*Turn off airplane mode*/
              adbCommand = airplaneOff;
              const char* cmdstr2 = adbCommand.c_str();
              adbResult = exeCmd(cmdstr2);
              std::cout << adbResult;

              /*turn off screen*/
              adbCommand = screenOff;
              const char* cmdstr3 = adbCommand.c_str();

              stopFuzzingTimer(adbTimer);
              adbPhase = adbNoPhase;
              if (DEBUG_MODE){ printf("[ADB] SF: %d.%d State: Turned off AirPlane mode 1 \n", curTTI/10, curTTI%10); }
            }
          }else{
            if (DEBUG_MODE){ printf("[ADB] Cannot enter AirPlane, timer running: %d, toADB: %d, adbPhase: %d \n", adbTimer.running, toADB, adbPhase);}
          }
        }else if (toADB == enableCellData and adbConnected) {
          adbCommand = CellDataOn;
          const char* cmdstr = adbCommand.c_str();
          adbResult = system(cmdstr);
          int temp = (int)adbConfigSuccess;
          ssize_t ret = write(fromAdbInterface[1], &temp, sizeof(temp));
          if (DEBUG_MODE){ printf("[ADB] %d.%d Enabled Cellular Data \n", curTTI/10, curTTI%10); }
        }else if (toADB == querryWeb and adbConnected) {
          adbCommand = querryWebcmd;
          const char* cmdstr = adbCommand.c_str();
          adbResult = system(cmdstr);
          std::cout << adbResult;
          if (DEBUG_MODE){ printf("[ADB] %d.%d Querried Web \n", curTTI/10, curTTI%10); }
        }else if (toADB == rebootUE and adbConnected) { // temporary using another algorithm
          /*Reboot UE*/
          adbCommand = rebootUEcmd;
          const char* cmdstr = adbCommand.c_str();
          adbResult = system(cmdstr);        
          if (DEBUG_MODE){ printf("[ADB] Rebooted UE !!!!!!! \n"); }

        } else if (toADB == state1PrepareADB && adbConnected){
          adbCommand = wifiOff; //turn off wifi on UE
          const char* cmdstr = adbCommand.c_str();
          adbResult = exeCmd(cmdstr);

          if (DEBUG_MODE){ printf("[ADB] SF: %d.%d State: state1PrepareADB --> monitorLogcat \n", curTTI/10, curTTI%10); }
          // toAdbInterface = monitorLogcat;
          int temp = (int)adbConfigSuccess;
          ssize_t ret = write(fromAdbInterface[1], &temp, sizeof(temp));
          // fromAdbInterface = adbConfigSuccess; // notify rlc thread
        }else if (toADB == pingUE && adbConnected){
          // adbCommand = "timeout 4 ping 172.16.0." + std::to_string(ueIP); //turn off wifi on UE
          adbCommand = checkCellData;
          const char* cmdstr = adbCommand.c_str();
          adbResult = exeCmd(cmdstr);
          size_t checkResult = adbResult.find("1");
          if (checkResult != std::string::npos){
            adbCommand = CellDataOff;
            printf("[ADB] SF: %d.%d Cellular is on, turning it off \n", curTTI/10, curTTI%10);
          }else if (checkResult == std::string::npos){
            adbCommand = CellDataOn;
            printf("[ADB] SF: %d.%d Cellular is off, turning it on \n", curTTI/10, curTTI%10);
          }else{
            printf("[ADB] SF: %d.%d Abnormal adb result from check cellular data \n", curTTI/10, curTTI%10);
          }
          const char* cmdstr2 = adbCommand.c_str();
          adbResult = exeCmd(cmdstr2);
          if (DEBUG_MODE){ 
            printf("[ADB] SF: %d.%d Switched cellular data \n", curTTI/10, curTTI%10);
            // std::cout << adbCommand << "\n";
          }
        }else if (toADB == monitorLogcat && adbConnected){
          /*Detect crash, inform rlc thread if there is a crash detected*/
          adbCommand = "adb logcat -b radio *:E -d | grep \"RADIO_OFF_OR_UNAVAILABLE\\|Modem Reset\\|CRASH\\|everybody panic\\|RADIO_STATE_OFF_OR_UNAVAILABLE\"";
          const char* cmdstr = adbCommand.c_str();
          adbResult = exeCmd(cmdstr);
          // std::cout << "[ADB] Result: " << adbResult << "\n";
          size_t foundCrash1 = adbResult.find(crashString1);
          size_t foundCrash2 = adbResult.find(crashString2);
          size_t foundCrash3 = adbResult.find(crashString3);
          size_t foundCrash4 = adbResult.find(crashString4);
          if (   foundCrash1 != std::string::npos 
              or foundCrash2 != std::string::npos 
              or foundCrash3 != std::string::npos
              or foundCrash4 != std::string::npos)
          {
            toADB = adbSleep;
            std::string detectedString = "";
            if (foundCrash1 != std::string::npos){detectedString = crashString1;}
            if (foundCrash2 != std::string::npos){detectedString = detectedString + " + " + crashString2;}
            if (foundCrash3 != std::string::npos){detectedString = detectedString + " + " + crashString3;}
            if (foundCrash4 != std::string::npos){detectedString = detectedString + " + " + crashString4;}
            std::cout << RED_TEXT << "[ADB] Crash detected from ADB " << RESET_COLOR << " -- Crash String: " << detectedString << "\n";
            int temp = (int)crashDetected;
            ssize_t ret = write(fromAdbInterface[1], &temp, sizeof(temp));
            adbCommand = cleanADB;
            const char* cmdstr2 = adbCommand.c_str();
            adbResult = exeCmd(cmdstr2);
          }
        }else{
          // std::cout << " [ADB] Thread not running normally, toAdbInterface = " << toAdbInterface << " , adbConnected = " << adbConnected << " *adbstopFork = " << *adbstopFork << "\n";
        }
      }
      printf("[ADB] adb stop = %d \n", (int)adbStop);
    }else if (pid < 0){
      std::cout << "Failed to fork process, pid = " << pid <<  "\n";
    }
  }else{
    std::cout << "[ADB] ADB is enabled, but no device connected or adb is not enabled in config file" << "\n";
    // exit program
    exit(0);
  }

  // while(!adbStop){
    
  // }
  // printf("[ADB] ADB Controller thread stopped \n");
}

/*-----------------------------*/

/*LLFuzz Class implementation*/

LLFuzz::LLFuzz() {
    // Constructor
}

LLFuzz::~LLFuzz() {

    adbController.stop(); // stop adb controller thread
    int adbStopSignal = 1;
    ssize_t ret = write(adbStopPipe[1], &adbStopSignal, sizeof(adbStopSignal)); // notify adb controller to stop
    // wait 100ms for the forked adb thread to stop
    
    // stop adb main thread
    if (enableADB){
      // adbController.thread_cancel();
      // adbController.wait_thread_finish();
      // usleep(100000); // 100ms
      // Check if any "adb_controller" processes are still running and kill them
      std::string kill_cmd = "ps -eo pid,comm | grep adb_controller | grep -v grep | awk '{print $1}' | xargs -r kill -9";
      int result = system(kill_cmd.c_str());
      
      // if (result == 0) {
      //     printf("[LLFuzz] Killed remaining adb_controller processes\n");
      // } else {
      //     printf("[LLFuzz] No adb_controller processes found or failed to kill them\n");
      // }
      
      // Also check for any orphaned adb processes that might have been started by the controller
      // std::string kill_adb_cmd = "ps -eo pid,comm | grep adb | grep -v grep | awk '{print $1}' | xargs -r kill -9";
      // system(kill_adb_cmd.c_str());
    }
    // check if thread "adb_controller" is still running, if so, kill it using ps and kill


    // close speedlog
    if (enableSpeedLog) speedLog.close();
    // crash_pcap.close(); // close pcap file
    fuzzer->close_crash_log_file();
}

// Helper function to trim whitespace from both ends of a string
static inline std::string trim(std::string s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
    return s;
}

LLFuzz_config_t LLFuzz::read_config_from_file(std::string& filename){

  config_file = filename; 
  std::cout << "[LLFuzz] Reading config from file: " << filename << "\n";
  std::ifstream file(filename);
  std::string line;
  std::unordered_map<std::string, std::string> configMap;

  while (std::getline(file, line)) {
      // Remove comments
      size_t commentPos = line.find('#');
      if (commentPos != std::string::npos) {
          line = line.substr(0, commentPos);
      }

      std::istringstream is_line(line);
      std::string key;
      if (std::getline(is_line, key, '=')) {
          std::string value;
          if (std::getline(is_line, value)) {
              configMap[trim(key)] = trim(value);
          }
      }  
  }

  LLFuzz_config_t config;
  config.targetLayer    = (configMap["targetLayer"] == "MAC") ? MAC : (configMap["targetLayer"] == "RLC") ? RLC : (configMap["targetLayer"] == "PDCP") ? PDCP: PHY;
  config.fuzzingState   = (configMap["fuzzingState"] == "state1") ? state1 : (configMap["fuzzingState"] == "state2") ? state2: (configMap["fuzzingState"] == "state3") ?state3: state4;
  config.enableADB      = (configMap["enableADB"] == "true");
  config.startIdx       = std::stoi(configMap["startIdx"]);
  // config.fuzzingMode    = (configMap["fuzzingMode"] == "state1") ? state1 : (configMap["fuzzingMode"] == "state234") ? state234: state4;
  config.verifyingMode  = (configMap["verifyingMode"] == "true");
  config.imsi           = std::stoll(configMap["imsi"]);
  config.sendUplinkDCI  = (configMap["sendUplinkDCI"] == "true");
  config.recoverTimerThres = std::stoi(configMap["recoverTimerThres"]);
  config.waitingConnTimerThres = std::stoi(configMap["waitingConnTimerThres"]);
  config.waitConnAfterPagingThres = std::stoi(configMap["waitConnAfterPagingThres"]);
  config.nof_test_cases_per_ss = std::stoi(configMap["NofTestCasesPerSS"]);
  config.enableNotWorkingReboot = (configMap["enableNotWorkingReboot"] == "true");
  config.nofFailedConnReboot = std::stoi(configMap["nofFailedConnReboot"]);
  config.enableSpeedLog = (configMap["enableSpeedLog"] == "true");
  config.speedLogFilename = configMap["speedLogFilename"];
  config.crashLogFilename = configMap["crashLogFilename"];
  config.enbPCAPFilename = configMap["enbPCAPFilename"];
  config.transmission_mode = std::stoi(configMap["tm"]);

  // // for PDCP layer, we only send 1 test case per SS to ensure that the test case can have appropriate RLC Sequence Number
  // if (config.targetLayer == PDCP){
  //   config.nof_test_cases_per_ss = 1;
  //   // modify configmap to print correctly:
  //   configMap["NofTestCasesPerSS"] = "1 (PDCP)";
  // }

  // print config:
  std::cout << "[LLFuzz] Configurations---------------------------------------------------------------------------" << "\n";
  std::cout << "[LLFuzz] TargetLayer              : " << configMap["targetLayer"] << "\n";
  std::cout << "[LLFuzz] FuzzingState             : " << configMap["fuzzingState"] << "\n";
  std::cout << "[LLFuzz] EnableADB                : " << configMap["enableADB"] << "\n";
  std::cout << "[LLFuzz] StartIdx                 : " << configMap["startIdx"] << "\n";
  std::cout << "[LLFuzz] NofTestCasesPerSS        : " << configMap["NofTestCasesPerSS"] << "\n";
  // std::cout << "[LLFuzz] FuzzingMode              : " << configMap["fuzzingMode"] << "\n";
  std::cout << "[LLFuzz] VerifyingMode            : " << configMap["verifyingMode"] << "\n";
  std::cout << "[LLFuzz] IMSI                     : " << configMap["imsi"] << "\n";
  std::cout << "[LLFuzz] SendUplinkDCI            : " << configMap["sendUplinkDCI"] << "\n";
  // std::cout << "[LLFuzz] TransmissionMode         : " << configMap["tm"] << "\n";
  std::cout << "[LLFuzz] RecoverTimerThres        : " << configMap["recoverTimerThres"] << "\n";
  std::cout << "[LLFuzz] WaitingConnThres         : " << configMap["waitingConnTimerThres"] << "\n";
  std::cout << "[LLFuzz] WaitConnAfterPagingThres : " << configMap["waitConnAfterPagingThres"] << "\n";
  std::cout << "[LLFuzz] EnableNotWorkingReboot   : " << configMap["enableNotWorkingReboot"] << "\n";
  std::cout << "[LLFuzz] NofFailedConnReboot      : " << configMap["nofFailedConnReboot"] << "\n";
  std::cout << "[LLFuzz] EnableSpeedLog           : " << configMap["enableSpeedLog"] << "\n";
  std::cout << "[LLFuzz] SpeedLogFilename         : " << configMap["speedLogFilename"] << "\n";
  std::cout << "[LLFuzz] CrashLogFilename         : " << configMap["crashLogFilename"] << "\n";
  std::cout << "[LLFuzz] enbPCAPFilename          : " << configMap["enbPCAPFilename"] << "\n";
  std::cout << "[LLFuzz] -------------------------------------------------------------------------------------------" << "\n";
  std::cout << "\n";

  // set configurations
  targetLayer           = config.targetLayer;
  fuzzingState          = config.fuzzingState;
  enableADB             = config.enableADB;
  startIdx              = config.startIdx;
  // fuzzingMode           = config.fuzzingMode;
  // fuzzingModeOrin       = config.fuzzingMode;
  readFromFileMode      = config.verifyingMode;
  ueid                  = config.imsi % 1024 ;  // imsi mod 1024 to send paging to UE
  sendUplinkDCI         = config.sendUplinkDCI;
  transmission_mode     = config.transmission_mode;
  recoverTimerThres     = config.recoverTimerThres;
  waitingConnTimerThres = config.waitingConnTimerThres;
  waitConnAfterPagingThres = config.waitConnAfterPagingThres;
  verifyingState        = config.fuzzingState;
  nof_test_cases_per_ss = config.nof_test_cases_per_ss;
  enableNotWorkingReboot = config.enableNotWorkingReboot;
  nofFailedConnReboot   = config.nofFailedConnReboot;
  enableSpeedLog        = config.enableSpeedLog;  
  speedFilename         = config.speedLogFilename;
  crashLogFilename      = config.crashLogFilename;
  // crash_pcap_filename   = config.crashPcapFilename;

  // automatically set fuzzingMode based on fuzzingState
  fuzzingModeOrin = (fuzzingState == state1) ? state1 : state234;

  // verify configs
  if (targetLayer == RLC || targetLayer == PDCP){
    if (fuzzingState < (int)state3){
      std::cout << RED_TEXT << "[LLFuzz] Error: FuzzingState must be state3 or state 3 for RLC and PDCP" << RESET_COLOR << "\n";
      exit(0);
    }
  }

  return config;
}

void LLFuzz::init(){
    std::unique_ptr<FuzzerBase_t> tmp_fuzzer;

    switch (targetLayer)
    {
    case MAC:
        tmp_fuzzer = std::make_unique<macFuzzer_t>();
        break;
    case RLC:
        tmp_fuzzer = std::make_unique<rlcFuzzer_t>();
        break;
    case PDCP:
        tmp_fuzzer = std::make_unique<pdcpFuzzer_t>();
        break;
    case PHY:
        tmp_fuzzer = std::make_unique<phyFuzzer_t>();
        break;    
    default:
        break;
    }

    fuzzer = std::move(tmp_fuzzer);

    if (fuzzer){
        // set fuzzer configurations (after reading config from file)
        fuzzer->set_fuzzing_config(fuzzingState, readFromFileMode, startIdx, sendUplinkDCI, crashLogFilename, nof_test_cases_per_ss, transmission_mode);
        fuzzer->resize_crash_log_buffer();
        generate_test_cases();
    }

    // get total number of test cases
    for (int i = 0; i < 6; i++){
        total_idx[i]        = fuzzer->get_total_idx((LLState_t)i, readFromFileMode);
        total_idx_phy_ul[i] = fuzzer->get_total_idx_phy_ul((LLState_t)i, readFromFileMode); // only for PHY fuzzer UL DCIs
    }

    // init speedlog
    if (enableSpeedLog) speedLog.open(speedFilename);

    // init crash pcap
    // crash_pcap.open(crash_pcap_filename); 
}


void LLFuzz::startFuzzer(){
  fuzzingMode = fuzzingModeOrin;
  
  // reset index of fuzzer
  fuzzer->set_start_fuzzing_index(startIdx);
  
  switch (fuzzingMode)
  {
  case state1:
      state1Phase = state1Prepare;
      idx[1] = startIdx;
      break;
  case state234:
      state234Phase = state234Prepare;
      idx[2] = startIdx;
      idx[3] = startIdx;
      idx[4] = startIdx;
      idx[5] = startIdx;
      std::cout << "[MAC] Switch Fuzzer to Mode 23, start_index = " << idx[3] << "\n";
      break;
  case state4:
      state4Phase = s4Prepare;
      idx[2] = startIdx;
      idx[3] = startIdx;
      idx[4] = startIdx;
      idx[5] = startIdx;
      std::cout << "[MAC] Switch Fuzzer to Mode 4, start_index = " << idx[4] << "\n";
      break;
  case stateUnknown:
      fuzzingState = stateUnknown;
      state4Phase = s4None;
      state234Phase = state234noPhase;
      break;
  default:
      break;
  }

  startnotWorkingTimer();
  
  if (DEBUG_MODE){ 
    printf("[MAC] Switch Fuzzer to Mode %d \n", fuzzingMode); 
  }
}

void LLFuzz::resetIndex(){
  idx[5] = startIdx; 
  idx[4] = startIdx; 
  idx[3] = startIdx;
  idx[2] = startIdx;
}

void LLFuzz::stopFuzzing(){
  fuzzingMode = stateUnknown;

  clearUEDB();
  rarCondition = true;
  
  // stop all timers
  stopnotWorkingTimer();
  stopTimer(recoverTimer);
  stopTimer(rrcReleaseTimer);
  stopTimer(rfLinkTimer);
  stopTimer(pagingTimer);
  stopTimer(waitingConnTimer);
  stopTimer(finishingTimer);
  stopTimer(adbDelayTimer);
  stopTimer(waitingUEidleTimer);
  stopTimer(ueRebootTimer);
  stopTimer(querryWebTimer);
  stopTimer(webDelayTimer);
  stopTimer(ueDisconnTimer);
  stopTimer(enInternetTimer);
  stopTimer(sendPagingDelayTimer);
  stopTimer(state4Timer);
  stopTimer(finishCrash);
  stopTimer(notWorkingTimer);
  
  if (DEBUG_MODE){ 
    printf("[MAC] Stopping fuzzer...\n"); 
  }
}

void LLFuzz::get_signal_from_adb(){
  int temp;
  if (enableADB){
    ssize_t ret = read(fromAdbInterface[0], &temp, sizeof(temp));
    fromADB = (fromAdbCommand_t)temp;
    if (ret <= 0){ // if no signal
      fromADB = noAction;
    }else{
      if (fromADB == adbAirPlaneOn){
          isAirPlaneOn = true;
          ueStateDB.clear();
      }
      if (DEBUG_MODE){ 
        printf("[MAC] Received signal from ADB: ");
        std::cout << BLUE_TEXT << "[ADB -> MAC] " + getfromADBString(fromADB) << RESET_COLOR << "\n";
      }
    }
  }else{
    fromADB = noAction;
  }
}

void LLFuzz::crashMonitoring(int tti_tx_dl){
  if (fuzzingMode != crashHandling && fuzzingMode != stateUnknown && fuzzingMode!= startUp){
      if ((fromADB == crashDetected)){ //|| checkCrashFromHarq() || (state234Phase == state234Send || state4Phase == s4Send)
          
          // stop ADB monitoring first
          int temp = (int)adbSleep;
          ssize_t ret = write(toAdbInterface[1], &temp, sizeof(temp));
          if (DEBUG_MODE){ printf("[MAC] SF: %d.%d Stopped ADB monitoring \n", tti_tx_dl/10, tti_tx_dl%10); }
          
          prevState   = fuzzingMode; // save previous state to recover fuzzing after crash handling
          fuzzingMode = crashHandling;

          std::string crashType = (fromADB == crashDetected)?"ADB":"RLC_ACK";
          if (DEBUG_MODE){ 
              std::cout << RED_TEXT << "[MAC] Detected Crash from " << crashType << " at SF: " << tti_tx_dl/10 << "." << tti_tx_dl%10 << RESET_COLOR << "\n";
          }
          
          startTimer(recoverTimer);
          if (finishingTimer.running){
              stopTimer(finishingTimer);
          }
          
          if (DEBUG_MODE){ printf("[MAC] SF: %d.%d Fuzzing State --> crashHandling \n", tti_tx_dl/10, tti_tx_dl%10); }
      
        }else if (!(state234Phase == state234Send || state4Phase == s4Send)){
          // rlcMaxReTX = false; // reset RLC crash flag if this is not send phase
      }
  }
}

void LLFuzz::recoverUE(){
  if (fuzzingMode == crashHandling && checkTimer(recoverTimer, 3500)){ // wait 3 secs before recover UE

      int oracle = (fromADB == crashDetected)?0:1; // 0: crash from adb, 1: crash from RLC
      // TODO:
      fuzzer->saveCrashtoFile(oracle);

      // save recent mac packets to pcap file
      // save_mac_packet_buffer_to_pcap();
      // macPacketBuffer.cleanUp();

      nofCrash++;
      if (DEBUG_MODE){ printf("[MAC] Saved recent index to file \n"); }
      
      fuzzingMode = prevState;
      switch (prevState)
      {
      case state1:
          state1Phase = state1Prepare; // set state 1 to prepare to switch airplane mode and fuzz again
          break;
      case state234:
          state234Phase = state234Prepare; // set state 234 to prepare to switch airplane mode and fuzz again
          break;
      case state4:
          state4Phase = s4Prepare; // set state 4 to prepare to switch airplane mode and fuzz again
          break;
      default:
          break;
      }
      /*set all timers to not running*/
      stopTimer(recoverTimer);
      stopTimer(rrcReleaseTimer);
      stopTimer(rfLinkTimer);
      stopTimer(pagingTimer);
      stopTimer(waitingConnTimer);
      if (DEBUG_MODE){ printf("\n[MAC] Recovered from crash, Fuzzing State --> %d \n", fuzzingMode); }
  }
}

void LLFuzz::generate_test_cases() {
  // call the generate_test_cases method of the fuzzer object (MAC/RLC/PDCP fuzzer object)
  fuzzer->generate_test_cases();
}

int LLFuzz::check_rrc_reconfig_type(){
  // only update rrc reconfig type if Fuzzer is in Sending phase
  if ((fuzzingMode == state234 && state234Phase == state234Send) || (fuzzingMode == state4 && state4Phase == s4Send)){
    rrc_reconfig_type = fuzzer->check_rrc_reconfig_type();
  }else{
    rrc_reconfig_type = 0;
  }
  return rrc_reconfig_type;
}

int LLFuzz::get_injecting_length(){
  return fuzzer->get_injecting_length();
}

int LLFuzz::get_injecting_lcid(){
  return fuzzer->get_injecting_lcid();
}

int LLFuzz::get_total_byte_cur_testcase(){
  return fuzzer->get_total_byte_cur_testcase();
}

bool LLFuzz::get_manual_dci()  {
  return fuzzer->get_manual_dci();
}

bool LLFuzz::getSendUplinkDCI(){
  return fuzzer->getSendUplinkDCI();
}

void LLFuzz::check_switch_to_next_state(){
  /*Fuzzing state control*/
  // if (fuzzingState == state1){
  //     if (rarTcIdx == (int)tcState1DB.size() && checkTimer(finishingTimer, 2000)){
  //         fuzzingState = state234;
  //         state234Phase = state234Prepare;
  //         stopTimer(finishingTimer);
  //         std::cout << "[MAC] Switched Fuzzing State 1 -> 2 " << "\n";
  //     }else if (rarTcIdx == (int)tcState1DB.size() && !finishingTimer.running){
  //         finishingTimer.running = true;
  //         finishingTimer.activeTime = std::chrono::system_clock::now();
  //     }
  // }
  // if (fuzzingState == state234){
  //     if (state234finished && checkTimer(finishingTimer, 2000)){
  //         fuzzingState = state4;
  //         stopTimer(finishingTimer);
  //         std::cout << "[MAC] Switched Fuzzing State 234 -> 5 " << "\n";
  //     }else if (state234finished && !finishingTimer.running){
  //         finishingTimer.running = true;
  //         finishingTimer.activeTime = std::chrono::system_clock::now();
  //     }
  // }
  // if (fuzzingState == state3){
  //     if (tcIdx == (int)tcState3DB.size()){
  //     fuzzingState = state4;
  //     std::cout << "[MAC] Switched Fuzzing State 4 " << "\n";
  //     }
  // }
  // if (fuzzingState == state4){
  //     if (tcIdx == (int)tcState4DB.size()){
  //     fuzzingState = state4;
  //     std::cout << "[MAC] Switched Fuzzing State 5 " << "\n";
  //     }
  // }
}

void LLFuzz::state1Control(int tti_tx_dl){    
  if (state1Phase == state1Prepare){
      int tempSignal = (int)switchAirplane;
      ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
      int curTTI = tti_tx_dl;
      ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
      state1Phase = state1PrepareWaitingUE;
      startTimer(waitingConnTimer);
      rfLinkIssue = false;
      // rarBuffer.cleanUp();
      if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 1: state1Prepare --> state1PrepareWaitingUE \n", tti_tx_dl/10, tti_tx_dl%10); }
  }else if ( state1Phase == state1PrepareWaitingUE){
      if (checkTimer(waitingConnTimer, 5000)){ // this means UE was not able to connect successfully
          state1Phase = state1Prepare;
          if (DEBUG_MODE){ 
          printf("[MAC] SF: %d.%d State 1: state1PrepareWaitingUE --> state1Prepare | ", tti_tx_dl/10, tti_tx_dl%10); 
          std::cout << YELLOW_TEXT << " waitingConnTimer timeout" << RESET_COLOR << "\n";
          }
          stopTimer(waitingConnTimer);
      }
  }else if ( state1Phase == state1PrepareWaitingADB){
      if (fromADB == adbConfigSuccess){
          if ((int)ueStateDB.size() == 0){
              state1Phase = state1Paging; // paging to switch UE from idle mode to active mode
              if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 1: state1PrepareWaitingUE --> state1Paging, DB size = 0 \n", tti_tx_dl/10, tti_tx_dl%10); }
          }else{
              rrc_h->fuzzer_release_ue(lastRNTI);
              state1Phase = state1WaitingUEIdle; // wait until all active RNTIs enter idle mode
              startTimer(rrcReleaseTimer);
              sendRRCRelease = true;
              if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 1: state1PrepareWaitingUE --> state1WaitingUEIdle, enabled rrcRelease timer \n", tti_tx_dl/10, tti_tx_dl%10); }
          }
      }
  } else if (state1Phase == state1WaitingCon){
      if (checkTimer(waitingConnTimer, 3000)){ // this means UE was not able to connect successfully
          // toAdbInterface = switchAirplane;
          int tempSignal = (int)switchAirplane;
          ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
          int curTTI = tti_tx_dl;
          ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
          state1Phase = state1WaitingCon;
          if (DEBUG_MODE){ 
          printf("[MAC] SF: %d.%d State 1: state1WaitingCon --> state1WaitingCon | ", tti_tx_dl/10, tti_tx_dl%10); 
          std::cout << YELLOW_TEXT << " waitingConnTimer timeout" << RESET_COLOR << "\n";
          }
          // waitingConnTimer.running = false;
          waitingConnTimer.activeTime = std::chrono::system_clock::now();
      }
  }else if ( state1Phase == state1Paging){        
      rrc_h->fuzzer_send_paging(ueid, mmec, m_tmsi); // send paging to wake UE up
      state1Phase = state1Send; // start sending testcase
      //enable paging timer
      startTimer(pagingTimer);
      if (DEBUG_MODE){ 
          printf(" \n[MAC] SF: %d.%d State 1: state1Paging --> state1Send \n", tti_tx_dl/10, tti_tx_dl%10);
          printf("[MAC] SF: %d.%d Send paging to IMSI = %#x%x%x%x \n", tti_tx_dl/10, tti_tx_dl%10, m_tmsi[0], m_tmsi[1], m_tmsi[2], m_tmsi[3]);
      }
  }else if (state1Phase == state1Send){
      // check timer timeout
      if (checkTimer(pagingTimer, waitConnAfterPagingThres)){ // switch airplane and set phase to waiting UE connects if paging no response
          stopTimer(pagingTimer);
          int tempSignal = (int)switchAirplane;
          ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
          state1Phase = state1WaitingCon;
          saveMacPacket = false; // disable save mac packet
          startTimer(waitingConnTimer);
          if (DEBUG_MODE){ 
              printf("[MAC] SF: %d.%d State 1: state1Send --> state1WaitingCon | ", tti_tx_dl/10, tti_tx_dl%10); 
              std::cout << YELLOW_TEXT << " pagingTimer timeout" << RESET_COLOR << "\n";
          }
      }
  }else if (state1Phase == state1WaitingUEIdle){
      if (!rfLinkIssue){
          float releaseDelay =  (readFromFileMode)?300:300; // delay 1s if read from file, 0.5s if not
          if (sendRRCRelease && checkTimer(rrcReleaseTimer, releaseDelay)) {
              rrc_h->fuzzer_release_ue(lastRNTI);
              rrc_h->fuzzer_release_ue(lastRNTI-1); // make sure that all RNTIs are released
              rrc_h->fuzzer_release_ue(lastRNTI+1);
              stopTimer(rrcReleaseTimer);
              if (DEBUG_MODE){ printf("[MAC] SF: %d.%d Sent RRC Connect Release to UE\n", tti_tx_dl/10, tti_tx_dl%10); }
              sendRRCRelease = false;
          }
      }
  }
}

void LLFuzz::state234Control(int tti_tx_dl){
  if ( enableNotWorkingReboot && checkTimer(notWorkingTimer, 180000)){ // if no test cases were sent last 3 mins (180 secs)
      // send signal to adb to reboot ue
      int tempSignal = (int)rebootUE;
      ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
      int curTTI = tti_tx_dl;
      ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
      // switch state234phase to reboot UE and wait 60 secs until UE is rebooted
      state234Phase = state234RebootUE;
      stopTimer(notWorkingTimer);
      startTimer(ueRebootTimer); // start timer to wait for UE reboot
      timeOutCnt = 0; // reset timeout counter
      // rebootCause = 0;
      if (DEBUG_MODE){ printf("\n[MAC] SF: %d.%d Inactive last 3 mins, reboot UE \n", tti_tx_dl/10, tti_tx_dl%10); }
  }else if (rfLinkIssue && !handlingRFLink){ // always restart if rflinkissue
      if (!rfLinkTimer.running){
          rfLinkTimer.running = true;
          rfLinkTimer.activeTime = std::chrono::system_clock::now();
      }else if (rfLinkTimer.running && checkTimer(rfLinkTimer, 1500)){ // wait 1.5 secs before handling RFLinkIssue 
          handlingRFLink = true;                      // to make fuzzer not going to rfLinkIssue again
          int tempSignal = (int)switchAirplane;
          ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
          int curTTI = tti_tx_dl;
          ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
          state234Phase = state234WaitingCon;
          clearUEDB(); // clear UE state buffer
          isAirPlaneOn = false;
          if (DEBUG_MODE){ 
              printf("[MAC] SF: %d.%d State 234: RF Link Issue detected, state234Phase --> state234WaitingCon", tti_tx_dl/10, tti_tx_dl%10); 
              std::cout << "\n";
          }
          // waitingConnTimer.running = false;
          startTimer(waitingConnTimer); // update waiting conn timer
          // Reset all timer
          stopTimer(pagingTimer);
          stopTimer(rfLinkTimer);
          stopTimer(finishingTimer);
          stopTimer(recoverTimer);
          stopTimer(rrcReleaseTimer);
      }
  }else{
      if ( state234Phase == state234RebootUE){ // reboot UE phase is prioritized
          // check timer to make sure that UE is rebooted
          if (checkTimer(ueRebootTimer, 60000)){
              state234Phase = state234Prepare;
              stopTimer(ueRebootTimer);
              startTimer(notWorkingTimer); // update not working timer after UE restarts
              stopTimer(sendPagingDelayTimer);
              stopTimer(waitingConnTimer);
              stopTimer(rrcReleaseTimer);
              stopTimer(pagingTimer);
              stopTimer(waitingUEidleTimer);
              stopTimer(rfLinkTimer);
              stopTimer(finishingTimer);
              stopTimer(adbDelayTimer);
              rfLinkIssue = false; // prevent rfLinkIssue after reboot
              handlingRFLink = false;

              if (DEBUG_MODE){ 
                  printf("[MAC] SF: %d.%d State 234: state234RebootUE --> state234Prepare | \n", tti_tx_dl/10, tti_tx_dl%10); 
                  std::cout << YELLOW_TEXT << "UE rebooted" << RESET_COLOR << "\n";
              }
          }
      }else if (state234Phase == state234Prepare){
          if (!adbDelayTimer.running){
              int tempSignal = (int)switchAirplane;
              ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
              int curTTI = tti_tx_dl;
              ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
              adbDelayTimer.running = true; // switch to waitingUE phase after a delay
              adbDelayTimer.activeTime = std::chrono::system_clock::now();
              clearUEDB(); // clear UE state buffer
              isAirPlaneOn = false;
          }else if (adbDelayTimer.running && checkTimer(adbDelayTimer, 100)){
              state234Phase = state234PrepareWaitingUE;
              startTimer(waitingConnTimer);
              // rfLinkIssue = false;
              // rarBuffer.cleanUp();
              stopTimer(adbDelayTimer);
              stopTimer(sendPagingDelayTimer);
              clearUEDB(); // clear UE state buffer
              // fromADB = noAction;
              if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 234: state234Prepare --> state234PrepareWaitingUE \n", tti_tx_dl/10, tti_tx_dl%10); }
          }
      }else if ( state234Phase == state234PrepareWaitingUE){
          if (checkTimer(waitingConnTimer, waitingConnTimerThres + 2500)){ // this means UE was not able to connect successfully
              if (rfLinkIssue){ 
                  rfLinkIssue = false;
                  handlingRFLink = false;
              } // reset rfLinkIssue if failed to connect
              state234Phase = state234Prepare;
              if (DEBUG_MODE){ 
              printf("[MAC] SF: %d.%d State 234: state234PrepareWaitingUE --> state234Prepare | ", tti_tx_dl/10, tti_tx_dl%10); 
              std::cout << YELLOW_TEXT << " waitingConnTimer timeout" << RESET_COLOR << "\n";
              }
              // contTimeOut = true;
              timeOutCnt++;
              stopTimer(waitingConnTimer);
              fromADB = noAction;
          }
          if (timeOutCnt >= nofFailedConnReboot){ // if timeout nofFailedConnReboot times continuously, reboot UE
              // send signal to adb to reboot ue
              int tempSignal = (int)rebootUE;
              ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
              int curTTI = tti_tx_dl;
              ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
              // switch state234phase to reboot UE and wait 60 secs until UE is rebooted
              state234Phase = state234RebootUE;
              startTimer(ueRebootTimer); // start timer to wait for UE reboot
              timeOutCnt = 0; // reset timeout counter
              stopTimer(notWorkingTimer);
              idx[2] = idx[2] + 1;
              // rebootCause = 1; // 
          }
      }else if ( state234Phase == state234PrepareWaitingADB){
          if (fromADB == adbConfigSuccess){ //fromADB == adbConfigSuccess
              if ((int)ueStateDB.size() == 0){
                  state234Phase = state234Paging; // paging to switch UE from idle mode to active mode
                  startTimer(sendPagingDelayTimer); // send paging after a duration
                  if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 234: state234PrepareWaitingUE --> state234Paging, DB size = 0 \n", tti_tx_dl/10, tti_tx_dl%10); }
              }else { // if (sendRRCRelease && checkTimer(rrcReleaseTimer, releaseDelayVerify))
                  rrc_h->fuzzer_release_ue(lastRNTI);
                  rrc_h->fuzzer_release_ue(lastRNTI-1); // make sure that all RNTIs are released
                  rrc_h->fuzzer_release_ue(lastRNTI+1);
                  rrc_h->fuzzer_release_ue(lastRNTI-2); // make sure that all RNTIs are released
                  rrc_h->fuzzer_release_ue(lastRNTI+2);
                  state234Phase = state234WaitingUEIdle; // wait until all active RNTIs enter idle mode
                  rrcReleaseTimer.running = true;
                  rrcReleaseTimer.activeTime = std::chrono::system_clock::now();
                  sendRRCRelease = true; // false?
                  stopTimer(rrcReleaseTimer);
                  if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 234: state234PrepareWaitingUE --> state234WaitingUEIdle, enabled rrcRelease timer \n", tti_tx_dl/10, tti_tx_dl%10); }
              }
          }
      } else if (state234Phase == state234WaitingCon){
          if (checkTimer(waitingConnTimer, waitingConnTimerThres + 2500)){ // this means UE was not able to connect successfully, 3s of waiting + 2s of ADB
              // toAdbInterface = switchAirplane;
              int tempSignal = (int)switchAirplane;
              ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
              int curTTI = tti_tx_dl;
              ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
              state234Phase = state234WaitingCon;
              clearUEDB(); // clear UE state buffer
              if (DEBUG_MODE){ 
                  printf("[MAC] SF: %d.%d State 234: state234WaitingCon --> state234WaitingCon | ", tti_tx_dl/10, tti_tx_dl%10); 
                  std::cout << YELLOW_TEXT << " waitingConnTimer timeout" << RESET_COLOR << "\n";
              }
              // waitingConnTimer.running = false;
              startTimer(waitingConnTimer); // update waiting conn timer
              isAirPlaneOn = false;
          }
      }else if ( state234Phase == state234Paging){
          if (checkTimer(sendPagingDelayTimer, sendPagingDelayThres)){        // send paging after 0.1s

            if (targetLayer == PHY && sendUplinkDCI){
              // reset nof_sent_dci_ul
              nof_sent_dci_ul = 0;
            } 
            // if (DEBUG_MODE){ 
            //   printf("[MAC] SF: %d.%d Start sending paging to TMSI = %#x%x%x%x...........\n", tti_tx_dl/10, tti_tx_dl%10, m_tmsi[0], m_tmsi[1], m_tmsi[2], m_tmsi[3]);
            //   // printf("\n[MAC] SF: %d.%d State 23: state234Paging --> state234Send \n", tti_tx_dl/10, tti_tx_dl%10);
            // }
            state234Phase = state234Send; // start sending testcase
              rrc_h->fuzzer_send_paging(ueid, mmec, m_tmsi); // send paging to wake UE up
              nofRARSendingPhase = 0;
              //enable paging timer
              startTimer(pagingTimer);
              stopTimer(sendPagingDelayTimer);
              nof_sent_test_cases_per_ss = 0;
              if (DEBUG_MODE){ 
                  printf("[MAC] SF: %d.%d Sent paging to TMSI = %#x%x%x%x, State 23: state234Paging --> state234Send\n", tti_tx_dl/10, tti_tx_dl%10, m_tmsi[0], m_tmsi[1], m_tmsi[2], m_tmsi[3]);
                  // printf("\n[MAC] SF: %d.%d State 23: state234Paging --> state234Send \n", tti_tx_dl/10, tti_tx_dl%10);
              }
          }
      }else if (state234Phase == state234Send){
          // check timer timeout or RF Link issue
          if (rfLinkIssue){
              state234Phase = state234Prepare;
              rfLinkIssue = false;

              // Reset all timer
              stopTimer(waitingConnTimer);
              stopTimer(pagingTimer);
              stopTimer(rfLinkTimer);
              stopTimer(finishingTimer);
              stopTimer(recoverTimer);
              if (DEBUG_MODE){ 
                  printf("[MAC] SF: %d.%d State 234: state234Send --> state234Prepare | ", tti_tx_dl/10, tti_tx_dl%10); 
                  std::cout << YELLOW_TEXT << "rfLinkIssue in Send Phase" << RESET_COLOR << "\n";
              }
          }else if (checkTimer(pagingTimer, waitConnAfterPagingThres)){ // 1200 switch airplane and set phase to waiting UE connects if paging no response
              stopTimer(pagingTimer);
              /*Disable RFLink failure signal*/
              rfLinkIssue = false;
              /*Clean rar buffer*/
              // rarBuffer.cleanUp();
              int tempSignal = (int)switchAirplane;
              ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
              int curTTI = tti_tx_dl;
              ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
              state234Phase = state234WaitingCon; // keep send phase to send TC after airplain mode
              saveMacPacket = false; // disable save mac packet
              // Reset all timer
              startTimer(waitingConnTimer);
              stopTimer(pagingTimer);
              stopTimer(rfLinkTimer);
              stopTimer(finishingTimer);
              stopTimer(recoverTimer);
              ueStateDB.clear(); //clean UE state buffer

              if (DEBUG_MODE){ 
                  printf("[MAC] SF: %d.%d State 234: state234Send --> state234WaitingCon, switched airplain mode | ", tti_tx_dl/10, tti_tx_dl%10); 
                  std::cout << YELLOW_TEXT << "pagingTimeout" << RESET_COLOR << "\n";
              }
          }else if (((readFromFileMode && verifyingState == state4) || (!readFromFileMode && fuzzingState == state4) ) && checkTimer(state4Timer, 100)){
              state234Phase = state234WaitingUEIdle;
              sendRRCRelease = true;                      // send rrc release only once
              startTimer(rrcReleaseTimer); // start rrcRelease timer to send RRC release when timeout
              stopTimer(state4Timer);
              if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 234: state234Send --> state234WaitingUEIdle after 100ms state4 \n", tti_tx_dl/10, tti_tx_dl%10); }
          }
      }else if (state234Phase == state234WaitingUEIdle){
          float releaseDelay =  (readFromFileMode)?releaseDelayVerify:releaseDelayNormal; // dont forget to change waitingUEidleTimer
          if (!rfLinkIssue){
              if (sendRRCRelease && checkTimer(rrcReleaseTimer, releaseDelay)) {
                  rrc_h->fuzzer_release_ue(lastRNTI);
                  rrc_h->fuzzer_release_ue(lastRNTI-1); // make sure that all RNTIs are released
                  rrc_h->fuzzer_release_ue(lastRNTI+1);
                  rrc_h->fuzzer_release_ue(lastRNTI-2); // make sure that all RNTIs are released
                  rrc_h->fuzzer_release_ue(lastRNTI+2);
                  stopTimer(rrcReleaseTimer);
                  startTimer(waitingUEidleTimer);  // automatic check if UE is disconnected  after 3 seconds
                  if (DEBUG_MODE){ printf("[MAC] SF: %d.%d Sent RRC Connect Release to UE %d %d %d\n", tti_tx_dl/10, tti_tx_dl%10, lastRNTI, lastRNTI -1, lastRNTI+1); }
                  sendRRCRelease = false;
              }
              if (checkTimer(waitingUEidleTimer, 4000)){ // after 2 secs, if not detect UE release, check DB and go to paging
                  if ((int)ueStateDB.size() == 0){
                      state234Phase = state234Paging;
                      startTimer(sendPagingDelayTimer); // send paging after a duration
                      stopTimer(waitingUEidleTimer);
                      sendRRCRelease = false;
                      if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 234: state234WaitingUEIdle --> state234Paging, DB size = 0 \n", tti_tx_dl/10, tti_tx_dl%10); }
                  }else { // if UE not disconnect after 2 secs, switch airplane mode
                      int tempSignal = (int)switchAirplane;
                      ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal)); 
                      int curTTI = tti_tx_dl;
                      ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
                      state234Phase = state234WaitingCon;
                      clearUEDB(); // clear UE state buffer
                      if (DEBUG_MODE){ 
                          printf("[MAC] SF: %d.%d State 234: state234WaitingUEIdle --> state234WaitingCon, switched AP | ", tti_tx_dl/10, tti_tx_dl%10); 
                          std::cout << YELLOW_TEXT << " UE not disconnect" << RESET_COLOR << "\n";
                      }
                      startTimer(waitingConnTimer); // update waiting conn timer
                      stopTimer(waitingUEidleTimer);
                      stopTimer(rrcReleaseTimer);
                      sendRRCRelease = false;
                      isAirPlaneOn = false;
                  }
              }
          }
      }
  }
}

void LLFuzz::state4Control(int tti_tx_dl){
  if (state4Phase == s4Prepare){
      int tempSignal = (int)switchAirplane;
      ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
      int curTTI = tti_tx_dl;
      ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
      startTimer(waitingConnTimer);
      state4Phase = s4WaitConn;
  }else if (state4Phase == s4WaitConn){
      if (checkTimer(waitingConnTimer, waitingConnTimerThres)){ // this means UE was not able to connect successfully
          state4Phase = s4Prepare;
          if (DEBUG_MODE){ 
              printf("[MAC] SF: %d.%d State 5: s4WaitConn --> s4Prepare | ", tti_tx_dl/10, tti_tx_dl%10); 
              std::cout << YELLOW_TEXT << " waitingConnTimer timeout" << RESET_COLOR << "\n";
          }
          stopTimer(waitingConnTimer);
      }else if (checkTimer(enInternetTimer, 300)){
          state4Phase = s4Send;
          stopTimer(enInternetTimer);
          startTimer(querryWebTimer);
          if (DEBUG_MODE){ 
              printf("[MAC] SF: %d.%d State 5: s4WaitConn --> s4Send \n", tti_tx_dl/10, tti_tx_dl%10); 
          }
      }
  
  }else if (state4Phase == s4Send){
      if (checkTimer(querryWebTimer, 10000)){ // 4000
          state4Phase = s4Web;
          stopTimer(querryWebTimer);

          if (DEBUG_MODE){ 
              printf("[MAC] SF: %d.%d State 5: s4Send --> s4Web \n", tti_tx_dl/10, tti_tx_dl%10); 
          }
      }

  }else if (state4Phase == s4Web){
      if (!webDelayTimer.running){
          int tempSignal = (int)querryWeb;
          ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
          int curTTI = tti_tx_dl;
          ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
          startTimer(webDelayTimer);
      }else if (checkTimer(webDelayTimer, 2000)){
          state4Phase = s4Send;
          stopTimer(webDelayTimer);
          startTimer(querryWebTimer);
          if (DEBUG_MODE){ 
              printf("[MAC] SF: %d.%d State 5: s4Web --> s4Send \n", tti_tx_dl/10, tti_tx_dl%10); 
          }
      }

  }else if (state4Phase == s4UEDisconn){
      if (checkTimer(ueDisconnTimer, ueDisconnTimerThres)){
          state4Phase = s4Prepare;
          stopTimer(ueDisconnTimer);
          if (DEBUG_MODE){ 
              printf("[LLFuzz] SF: %d.%d State 5: s4UEDisconn --> s4Prepare, UE Disconnect timeout \n", tti_tx_dl/10, tti_tx_dl%10); 
          }
      }
  
  }
}

void LLFuzz::handleRRCReconfig(uint16_t rnti, pduInfo_t pduInfo, int tti_tx_dl){
  /*change UE state*/
  lastRNTI    = rnti;            // save the last RNTI, this rnti belongs to target UE
  if (pduInfo.m_tmsi != 0){
      m_tmsi[0]   = (pduInfo.m_tmsi >> 24);  // save m_tmsi for paging ue later
      m_tmsi[1]   = (pduInfo.m_tmsi >> 16);
      m_tmsi[2]   = (pduInfo.m_tmsi >> 8);
      m_tmsi[3]   = (pduInfo.m_tmsi &  0xFF);
      // print m_tmsi in hex
      // std::cout << "Updated m_tmsi from RRC Reconfig: 0x" 
      //           << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)m_tmsi[0]
      //           << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)m_tmsi[1]
      //           << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)m_tmsi[2]
      //           << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)m_tmsi[3]
      //           << std::dec << "\n";
  }
  if (pduInfo.mmec != 0) { mmec     = pduInfo.mmec; }

  if (fuzzingMode == state1 && state1Phase == state1PrepareWaitingUE){
      int tempSignal = (int)state1PrepareADB;
      ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
      curTTI = tti_tx_dl;
      ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
      state1Phase = state1PrepareWaitingADB; // waiting feedback from ADB thread
      if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 1: state1PrepareWaitingUE --> state1PrepareWaitingADB \n", tti_tx_dl/10, tti_tx_dl%10); }
  }else if(fuzzingMode == state1 && state1Phase == state1WaitingCon){
      state1Phase = state1WaitingUEIdle;
      pagingTimer.running = false;                  //stop any timer is waiting for UE connection
      waitingConnTimer.running = false;
      sendRRCRelease = true;                      // send rrc release only once
      rrcReleaseTimer.running = true;
      rrcReleaseTimer.activeTime = std::chrono::system_clock::now();
      if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 1: state1WaitingCon --> state1WaitingUEIdle \n", tti_tx_dl/10, tti_tx_dl%10); }
  }

  if (fuzzingMode == state234 && state234Phase == state234PrepareWaitingUE){
      if (rfLinkIssue){
          rfLinkIssue = false;
          handlingRFLink = false;
      }
      if (isAirPlaneOn){
          isAirPlaneOn = false;
          int tempSignal = (int)state1PrepareADB; // 
          ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
          curTTI = tti_tx_dl;
          ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
          state234Phase = state234PrepareWaitingADB; // waiting feedback from ADB thread
          timeOutCnt = 0; //reset timeout counter if UE connection is detected
          stopTimer(waitingConnTimer);
          startTimer(rrcReleaseTimer);
          sendRRCRelease = true;
          if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 234: state234PrepareWaitingUE --> state234PrepareWaitingADB \n", tti_tx_dl/10, tti_tx_dl%10); }
      }
  }else if(fuzzingMode == state234 && state234Phase == state234WaitingCon){
      if (rfLinkIssue){
          rfLinkIssue = false;
          handlingRFLink = false;
      }
      if (isAirPlaneOn){
          isAirPlaneOn = false;
          state234Phase = state234WaitingUEIdle;
          stopTimer(pagingTimer);                  //stop any timer is waiting for UE connection
          stopTimer(waitingConnTimer);
          sendRRCRelease = true;                      // send rrc release only once
          startTimer(rrcReleaseTimer);
          startTimer(waitingUEidleTimer); // automatic check if UE is disconnected  after 2 seconds
          if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 234: state234WaitingCon --> state234WaitingUEIdle \n", tti_tx_dl/10, tti_tx_dl%10); }
      }
  }else if (fuzzingMode == state234 && state234Phase == state234Send){
      if ((!readFromFileMode && fuzzingState != state4) || (readFromFileMode && verifyingState != state4)){ // (!readFromFileMode && !state234Enable[state4]): state4 when state234 should be tested seperately, in fuzzingMode 5, it also should be disabled
          state234Phase = state234WaitingUEIdle;
          sendRRCRelease = true;                      // send rrc release only once
          saveMacPacket = false; // disable save mac packet
          startTimer(rrcReleaseTimer);
          // startTimer(waitingUEidleTimer); // automatic check if UE is disconnected  after 2 seconds
          if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 234: state234Send --> state234WaitingUEIdle \n", tti_tx_dl/10, tti_tx_dl%10); }
      }else if ((readFromFileMode && verifyingState == state4) || (!readFromFileMode && fuzzingState == state4 && fuzzingMode == state234)){ // (!readFromFileMode && state234Enable[state4]): this is mechanism to send TC in state 5 which utilizes state 234
          if (!state4Timer.running){
              startTimer(state4Timer); // switch to state234WaitingUEIdle after 100 miliseconds, or after finishing sending test case in state 5
          }
      }
  }else if (fuzzingMode == state234 && state234Phase == state234Paging){ // if UE suddenly performs RRC Reestablishment when waiting for paging
    state234Phase = state234WaitingUEIdle;
    stopTimer(pagingTimer);
    stopTimer(sendPagingDelayTimer);
    sendRRCRelease = true;                      // send rrc release only once
    startTimer(rrcReleaseTimer);
    startTimer(waitingUEidleTimer); // automatic check if UE is disconnected  after 2 seconds
  }

  if (fuzzingMode == state4 && state4Phase == s4WaitConn){
      stopTimer(waitingConnTimer);
      int tempSignal = (int)enableCellData; // enable cellular data
      ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
      int curTTI = tti_tx_dl;
      ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
      startTimer(enInternetTimer); // switch to send phase after 300ms
  }else if ( fuzzingMode == state4 && state4Phase == s4UEDisconn){
      state4Phase = s4Send;
      stopTimer(ueDisconnTimer);
      startTimer(querryWebTimer);
      if (DEBUG_MODE){ printf("[MAC] SF: %d.%d State 4: S5UEDisconn --> S4Send \n", tti_tx_dl/10, tti_tx_dl%10); }
        
  }

  //stop timmer:
  // stopTimer(waitingConnTimer);
}

void LLFuzz::pushRARBuffer(timePoint_t time){
  timePoint_t head = lastRARtime; // from last RAR variable
  timePoint_t tail = time;
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(tail - head).count();
  // rarCondition = (duration > 500)?true:false; // if two RARs are sent in less than 500ms, not send TC during this RAR procedure
  rarCondition = (duration > 100)?true:false; // always send

  if (DEBUG_MODE && !rarCondition){ 
    printf("[MAC] RAR condition is false {%d}, not send TC this procedure \n", (int)duration); 
  }
  lastRARtime = time;

  // if (state234Phase == state234Send){ nofRARSendingPhase++;}
}

// TODO: PHY layer, check send dci test case
bool LLFuzz::check_send_test_case_this_SF(int tti_tx_dl){
  bool ret = false;
  curTTI = tti_tx_dl;
  auto            uestate = *ueStateDB.begin();
  ueStateTTI_t ueStateTTI = uestate.second;
  curRNTI                 = uestate.first; // save rnti to use later
  curRNTIState            = ueStateTTI.state;
  int          triggerTTI = ueStateTTI.tti;
  // bool         enableState = state234Enable[(int)state];
  bool         enableState = (curRNTIState == fuzzingState);

  // check if there is still a test case to send
  idx[fuzzingState] = fuzzer->get_cur_testcase_idx(fuzzingState, readFromFileMode);
  bool hasTestCase = idx[fuzzingState] < total_idx[fuzzingState];

  switch (fuzzingMode)
  {
  case state234:
      if (!MediaTek){
          if (ueStateDB.size() == 1 && state234Phase == state234Send){ // only send TC when there is a single UE in state 2, 3, 4

              if (!readFromFileMode){                                 // tti that ue state has been changed
                  if ((enableState && curRNTIState == LLState_t::state2 && checkSendTCttiState2(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase) || 
                      (enableState && curRNTIState == LLState_t::state3 && checkSendTCttiState3(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase) ||
                      (enableState && curRNTIState == LLState_t::state4 && checkSendTCttiState4(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase)){
                      ret = true;
                      sendTCThisSF = true;
                  }else{
                      ret = false;
                      sendTCThisSF = false;   
                  }
              }else if (readFromFileMode && verifyingState == curRNTIState){ // verify test case from file
                  if ((curRNTIState == LLState_t::state2 && checkSendTCttiState2(triggerTTI, tti_tx_dl, 1) && hasTestCase) || 
                      (curRNTIState == LLState_t::state3 && checkSendTCttiState3(triggerTTI, tti_tx_dl, 1) && hasTestCase) ||
                      (curRNTIState == LLState_t::state4 && checkSendTCttiState4(triggerTTI, tti_tx_dl, 1) && hasTestCase)){
                      ret = true;
                      sendTCThisSF = true;
                  }else{
                      ret = false;
                      sendTCThisSF = false;   
                  }
              }

              /*check rar condition, if two rar happen in a short time, not send TC*/
              if (!rarCondition){  //(MediaTek) && 
                  sendTCThisSF = false;
                  ret = false;
              }

              /*In verify mode, this result will overwrite above result in verify mode*/
              // if (verifyMode && state == LLState_t::state4 &&
              //     checkSendTCttiState4VerifyMode(triggerTTI, tti_tx_dl) && (idx[4] < (int)tcstate234DB.size())){
              //     ret = true;
              //     sendTCThisSF = true;
              // }else if (verifyMode && !checkSendTCttiState4VerifyMode(triggerTTI, tti_tx_dl)){
              //     ret = false;
              //     sendTCThisSF = false;
              // }
          }else{
              ret = false;
              sendTCThisSF = false;
          }
      }else{ // this is Mediatek
          if (nofRARSendingPhase == 1 ||nofRARSendingPhase == 2){
              if ((curRNTIState == LLState_t::state3 && checkSendTCttiState3Decoy(triggerTTI, tti_tx_dl) )){
                  // std::cout << "11111111111111111" << "\n";
                  ret = true;
                  sendTCThisSF = true;
              }else{
                  // std::cout << "22222222222222222" << "\n";
                  ret = false;
                  sendTCThisSF = false;   
              }
          }else if (nofRARSendingPhase == 3){
              if (!readFromFileMode){                                 // tti that ue state has been changed
                  if ((enableState && curRNTIState == LLState_t::state2 && checkSendTCttiState2(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase) || 
                      (enableState && curRNTIState == LLState_t::state3 && checkSendTCttiState3(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase) ||
                      (enableState && curRNTIState == LLState_t::state4 && checkSendTCttiState4(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase)){
                      ret = true;
                      sendTCThisSF = true;
                  }else{
                      ret = false;
                      sendTCThisSF = false;   
                  }
              }else if (readFromFileMode && verifyingState == curRNTIState){ // verify test case from file
                  if ((curRNTIState == LLState_t::state2 && checkSendTCttiState2(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase) || 
                      (curRNTIState == LLState_t::state3 && checkSendTCttiState3(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase) ||
                      (curRNTIState == LLState_t::state4 && checkSendTCttiState4(triggerTTI, tti_tx_dl, nof_test_cases_per_ss) && hasTestCase)){
                      ret = true;
                      sendTCThisSF = true;
                  }else{
                      ret = false;
                      sendTCThisSF = false;   
                  }
              }            
          }else{
              sendTCThisSF = false;
              ret = false;
          }
      }
      break;
  case state4:
      if (curRNTIState == fuzzingState && ueStateDB.size() == 1 && checkSendTCttiState5Condition2(triggerTTI, curTTI) && hasTestCase){ // only send TC when there is a single UE in state 5
          sendTCThisSF = true;
          ret = true;
      }else{
          sendTCThisSF = false;
          ret = false;
      }
      break;
  default:
      break;
  }

  // if (ret == true){
  //     std::cout << "[LLFuzz] CheckSendTC: " << curRNTIState << " cur_idx = " << idx[fuzzingState] << "\n";
  // }
  if (ret == true){startTimer(notWorkingTimer);} // update timer if there is a test case to send to avoid restart UE
  return ret;
}

// TODO:
bool LLFuzz::checksendTC_UL(int tti_rx_ul){
    // std::unique_lock<std::mutex> FuzzerLock(fuzzerMutex);

    bool                ret = false;
    curTTI                  = tti_rx_ul;
    auto            uestate = *ueStateDB.begin(); // get the first element in the map of RNTI-state
    ueStateTTI_t ueStateTTI = uestate.second;
    curRNTI                 = uestate.first; // save rnti to use later
    curRNTIState            = ueStateTTI.state;
    int          triggerTTI = ueStateTTI.tti;
    // bool         enableState = state234Enable[(int)state];
    bool         enableState = (curRNTIState == fuzzingState);

    // check if there is still a test case to send
    idx[curRNTIState] = fuzzer->get_cur_testcase_idx(curRNTIState, readFromFileMode);
    bool hasTestCase = idx[curRNTIState] < total_idx_phy_ul[curRNTIState];

    switch (fuzzingMode)
    {
    case state234:
        if (ueStateDB.size() == 1 && state234Phase == state234Send){ // only send TC when there is a single UE in state 2, 3, 4

            if (!readFromFileMode){                                 // tti that ue state has been changed
                if ((enableState && hasTestCase && nof_sent_dci_ul < nof_ul_dci_per_ss)){
                    ret = true;
                    sendTCThisSF = true;
                }else{
                    ret = false;
                    sendTCThisSF = false;   
                }
            }else if (readFromFileMode && verifyingState == curRNTIState){ // verify test case from file
                if ((curRNTIState == LLState_t::state2 && checkSendTCttiState2(triggerTTI, tti_rx_ul, nof_test_cases_per_ss) && hasTestCase) || 
                    (curRNTIState == LLState_t::state3 && checkSendTCttiState3(triggerTTI, tti_rx_ul, nof_test_cases_per_ss) && hasTestCase) ||
                    (curRNTIState == LLState_t::state4 && checkSendTCttiState4(triggerTTI, tti_rx_ul, nof_test_cases_per_ss) && hasTestCase)){
                    ret = true;
                    sendTCThisSF = true;
                }else{
                    ret = false;
                    sendTCThisSF = false;   
                }
            }
        }else{
            ret = false;
            sendTCThisSF = false;
        }
        break;
    case state4: // TODO
        if (curRNTIState == fuzzingState && ueStateDB.size() == 1 && checkSendTCbyDCIState5_UL(nof_user_dci_ul, curTTI) && hasTestCase){ // only send TC when there is a single UE in state 5
            sendTCThisSF = true;
            ret = true;
        }else{
            sendTCThisSF = false;
            ret = false;
        }
        break;
    default:
        break;
    }

    // FuzzerLock.unlock();
    startTimer(notWorkingTimer); // update timer if there is a test case to send to avoid restart UE
    // std::cout << "[LLFuzz] CheckSendTC_UL: " << curRNTIState << " cur_idx = " << idx[curRNTIState] << " ret = " << ret << " enabled_state:" << enableState << " has TC: " << hasTestCase << "\n";
    return ret;
}


void LLFuzz::send_rar_test_case(int nofGrant, int tti_tx_dl, uint8_t *payload, int len){
  if (fuzzingState == state1 && state1Phase == state1Send && (idx[state1] < total_idx[state1])){

    fuzzer->send_rar_test_case(nofGrant, tti_tx_dl, payload, len);
    
    state1Phase = state1WaitingCon;   // wait UE to connect again
    startTimer(waitingConnTimer);
    int tempSignal = (int)monitorLogcat; // notify adb thread to monitor logcat
    ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
    int curTTI = tti_tx_dl;
    ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
    if (DEBUG_MODE){ printf("[MAC] SF: %d.%d Sent RAR test case %d, State 1: sending --> state1WaitingCon \n", tti_tx_dl/10, tti_tx_dl%10, idx[state1]); }
    
    if (idx[state1] == (total_idx[state1] - 1)){
        std::cout << "\n";
        std::cout << BOLDGREEN  << "[Fuzzer] Finished sending RAR test cases, number of crash: " << nofCrash << RESET_COLOR << "\n" << "\n";
        // finishingTimer.running = true;   //active timer to switch to state2 after 2 seconds
        // finishingTimer.activeTime = std::chrono::system_clock::now();
        fuzzingMode = stateUnknown;
        idx[state1] = startIdx;
        // if (targetLayer == PHY){
        //   fuzzingState = state234;
        //   fuzzingMode = state234;
        //   fuzzer->set_fuzzing_State(fuzzingState);
        //   state234Phase = state234Prepare;
        //   idx[fuzzingState] = 0;
        //   std::cout << BOLDGREEN << "[MAC] Switch PHY Fuzzing State " << fuzzingState << RESET_COLOR << "\n";
        // }
    }else{
        // idx[state1] = idx[state1] + 1;
    }
  }
}

void LLFuzz::send_test_case(int tti_tx_dl, uint16_t rnti, uint8_t* payload, int actualLen){
  fuzzer->send_test_case(tti_tx_dl, rnti, payload, actualLen);

  // increase the number of sent test cases per SS
  nof_sent_test_cases_per_ss++;
  
  // check if all test cases are sent
  if (idx[fuzzingState] == (total_idx[fuzzingState] - 1)){
      std::cout << "\n";
      std::cout << BOLDGREEN  << "[Fuzzer] Finished sending test cases, number of crash: " << nofCrash << RESET_COLOR << "\n" << "\n";
      // finishingTimer.running = true;   //active timer to switch to state2 after 2 seconds
      // finishingTimer.activeTime = std::chrono::system_clock::now();
      fuzzingMode = stateUnknown;
      idx[fuzzingState] = startIdx;

      // if (targetLayer == PHY && fuzzingState < 4){
      //   fuzzingState = (LLState_t)NEXT_STATE(fuzzingState);
      //   fuzzer->set_fuzzing_State(fuzzingState);
      //   fuzzingMode = state234;
      //   state234Phase = state234Prepare;
      //   idx[fuzzingState] = 0;
      //   std::cout << "[MAC] Switch PHY Fuzzing State " << fuzzingState << "\n";
      // }else if (fuzzingState == 4){
      //   fuzzingState = stateUnknown;
      //   std::cout << BOLDGREEN  << "[MAC] Finished sending test cases for state 4, Switch PHY Fuzzing State Unknown" << RESET_COLOR << "\n";
      // }
  }
}

void LLFuzz::removeUE(uint16_t rnti){
  std::unique_lock<std::mutex> bufferLock(ueStateMutex);
  ueStateDB.erase(rnti); // remove RNTI from state buffer
  bufferLock.unlock();
  // std::unique_lock<std::mutex> bufferLock2(harqBufferMutex);
  // harqFbBuffer.erase(rnti); // remove RNTI from harq buffer
  // bufferLock2.unlock();
}

void LLFuzz::addUE(uint16_t rnti, LLState_t state, int tti){
  std::unique_lock<std::mutex> bufferLock(ueStateMutex);
  ueStateTTI_t ueStateTTI;
  ueStateTTI.state = state;
  ueStateTTI.tti   = tti;
  ueStateDB.insert(std::make_pair(rnti, ueStateTTI));
  bufferLock.unlock();
}

void LLFuzz::clearUEDB(){
    std::unique_lock<std::mutex> bufferLock(ueStateMutex);
    ueStateDB.clear();
    bufferLock.unlock();
}

bool LLFuzz::updateUEState(uint16_t rnti, LLState_t state, int tti){
  bool ret = false;
  std::unique_lock<std::mutex> bufferLock(ueStateMutex);
  ueStateTTI_t ueStateTTI;
  ueStateTTI.state = state;
  ueStateTTI.tti   = tti;
  if (((int)state == NEXT_STATE(ueStateDB[rnti].state)) || 
      fuzzingMode == state1 || 
      (fuzzingMode == state234 && (state234Phase == state234Send || state234Phase == state234WaitingUEIdle || state234Phase == state234Paging))){ //|| (ueStateDB[rnti].state == stateUnknown)
      ueStateDB[rnti] = ueStateTTI;
      ret = true;
      if (state == fuzzingState){
        // clean up mac packet buffer and enable save mac packet
        saveMacPacket = true;
        // macPacketBuffer.cleanUp();
      }
  }else{
      if (DEBUG_MODE){ 
        printf("[MAC] Update UE state failed, current state %d, rejected state %d \n", ueStateDB[rnti].state, state); 
      }
  }
  sendTCThisSF = false; // not send TC in the same SF that state is changed
  /*Reset paging timer if fuzzer is in state234 and phase send*/
  if (fuzzingMode == state234 && state234Phase == state234Send){
      pagingTimer.running = true;
      pagingTimer.activeTime = std::chrono::system_clock::now(); // reset timer
  }
  bufferLock.unlock();
  return ret;
}

void LLFuzz::updateConResID(uint8_t* conResID_){
    for (int i = 0; i < 6; i++){
        conResID[i] = conResID_[i];
    }
}
//update TMSI for paging
void LLFuzz::updateTMSI(uint32_t tmsi_){
    if (tmsi_ != 0){
        m_tmsi[0]   = (tmsi_ >> 24);  // save m_tmsi for paging ue later
        m_tmsi[1]   = (tmsi_ >> 16);
        m_tmsi[2]   = (tmsi_ >> 8);
        m_tmsi[3]   = (tmsi_ &  0xFF);
        // print m_tmsi in hex
        // std::cout << "Updated m_tmsi from RRC Reconfig: 0x" 
        //           << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)m_tmsi[0]
        //           << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)m_tmsi[1]
        //           << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)m_tmsi[2]
        //           << std::hex << std::setfill('0') << std::setw(2) << (unsigned int)m_tmsi[3]
        //           << std::dec << "\n";
    }
}

void LLFuzz::update_rlc_sequence_number(uint16_t lcid, uint16_t sn){
  fuzzer->update_rlc_sequence_number(lcid, sn);
}

void LLFuzz::handleUEDisconnection() /*2 cases, RF link issue and normal connection*/
{
  if (fuzzingMode == state1 && state1Phase == state1WaitingUEIdle){
    if (rfLinkIssue){
      //run timer for 1 second
      if (!rfLinkTimer.running){
        rfLinkTimer.running = true;
        rfLinkTimer.activeTime = std::chrono::system_clock::now();
        if (DEBUG_MODE){ 
          printf("[MAC] Handling RF Link Failure \n "); 
          // std::cout << YELLOW_TEXT << " rfLinkTimer timeout" << RESET_COLOR << "\n";
        }
      }else{
        if (checkTimer(rfLinkTimer, 2000)){
          if (ueStateDB.size() == 0){
            state1Phase = state1Paging;
            if (DEBUG_MODE){ 
              printf("[MAC] State 1: state1WaitingUEIdle --> state1Paging, DB = 0 | "); 
              std::cout << YELLOW_TEXT << " rfLinkTimer timeout" << RESET_COLOR << "\n";
            }
          }else{
            int tempSignal = (int)switchAirplane;
            ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
            int curTTI = 0;
            ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
            state1Phase = state1WaitingCon;
            if (DEBUG_MODE){ 
              printf("[MAC] State 1: state1WaitingUEIdle --> state1WaitingCon, send Airplane signal, DB > 0 | "); 
              std::cout << YELLOW_TEXT << " rfLinkTimer timeout" << RESET_COLOR << "\n";
            }
          }
          stopTimer(rfLinkTimer);
          rfLinkIssue = false;
          // rarBuffer.cleanUp();
        }
      }
      // after 1 second
    }else{
      if (ueStateDB.size() == 0){
        state1Phase = state1Paging;
        stopTimer(rrcReleaseTimer);
        sendRRCRelease = false;
        if (DEBUG_MODE){ printf("[MAC] State 1: state1WaitingUEIdle --> state1Paging in rem_ue function \n"); }
      }
    }
  }else if (fuzzingMode == state234 && state234Phase == state234WaitingUEIdle){ //state234
    if (rfLinkIssue){
        // do nothing
    }else{
      if (ueStateDB.size() == 0){
        state234Phase = state234Paging;
        stopTimer(rrcReleaseTimer);
        startTimer(sendPagingDelayTimer); // send paging after a duration
        sendRRCRelease = false;
        if (DEBUG_MODE){ printf("[MAC] State 234: state234WaitingUEIdle --> state234Paging in rem_ue function \n"); }
      }
    }
  }else if (fuzzingMode == state4 && (state4Phase == s4Send || state4Phase == s4Web)){
    state4Phase = s4UEDisconn;
    stopFuzzingTimer(querryWebTimer);
    startTimer(ueDisconnTimer);
    if (DEBUG_MODE){ printf("[MAC] State 5: s4Send --> s4Prepare in rem_ue function \n"); }
  }
}

void LLFuzz::save_legitimate_rar(uint8_t* payload, int len){
  fuzzer->save_legitimate_rar(payload, len);
}

bool LLFuzz::check_inject_rar(){
  bool ret = false;
  if (targetLayer != MAC){
    return false;
  }else {
    if (fuzzingMode == state1 && state1Phase == state1Send){
      ret = true;
    }
  }
  return ret;
}

int LLFuzz::get_nof_injecting_rar(){
  return fuzzer->get_nof_injecting_rar();
}


void LLFuzz::notifyRLF(){
  // if (fuzzingState == state4 && (state5Phase == s5Send || state5Phase == s5Web || state5Phase == S5UEDisconn)){
  //     state5Phase = S5UEDisconn;
  //     stopFuzzingTimer(querryWebTimer);
  //     startTimer(ueDisconnTimer);
  //     if (DEBUG_MODE){ printf("[MAC] State 5: Notify RLF --> S5UEDisconn \n"); }
  // }
}

void LLFuzz::setCellConfig(int nofPRB_, bool isFDD){
  fuzzer->setCellConfig(nofPRB_, isFDD);
}

void LLFuzz::save_orin_dl_dci_for_reference(srsran_dci_dl_t source){
  fuzzer->save_orin_dl_dci_for_reference(source);
}

void LLFuzz::save_orin_ul_dci_for_reference(srsran_dci_ul_t source){
  fuzzer->save_orin_ul_dci_for_reference(source);
}

bool LLFuzz::send_RAR_DCI(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci){
  bool ret = false;
  ret = fuzzer->send_RAR_DCI(tti_tx_dl, rnti, orin_dci, target_dci);

  if (ret){
    state1Phase = state1WaitingCon;   // wait UE to connect again
    startTimer(waitingConnTimer);
    int tempSignal = (int)monitorLogcat; // notify adb thread to monitor logcat
    ssize_t ret = write(toAdbInterface[1], &tempSignal, sizeof(tempSignal));
    int curTTI = tti_tx_dl;
    ssize_t ret2 = write(ttiPipe[1], &curTTI, sizeof(curTTI));
    if (DEBUG_MODE){ 
      printf("\n");
      printf("[MAC] SF: %d.%d Sent RAR test case %d, State 1: sending --> state1WaitingCon \n", tti_tx_dl/10, tti_tx_dl%10, idx[state1]); 
    }
    
    if (idx[state1] == (total_idx[state1] - 1)){
        std::cout << "\n";
        std::cout << BOLDGREEN  << "[Fuzzer] Finished sending RAR DCIs, number of crash: " << nofCrash << RESET_COLOR << "\n" << "\n";
        // finishingTimer.running = true;   //active timer to switch to state2 after 2 seconds
        // finishingTimer.activeTime = std::chrono::system_clock::now();
        fuzzingMode = stateUnknown;
        idx[state1] = startIdx;
        // if (targetLayer == PHY){
        //   fuzzingState = state2;
        //   fuzzingMode = state234;
        //   fuzzer->set_fuzzing_State(fuzzingState);
        //   state234Phase = state234Prepare;
        //   idx[fuzzingState] = 0;
        //   std::cout << BOLDGREEN << "[MAC] Switch PHY Fuzzing State " << fuzzingState << RESET_COLOR << "\n";
        // }
    }else{
        idx[state1] = idx[state1] + 1;
    }
  }
  return ret;
}

bool LLFuzz::send_dl_dci_testcase(int tti_tx_dl, uint16_t rnti, srsran_dci_dl_t &orin_dci, srsran_dci_dl_t& target_dci){
  return fuzzer->send_dl_dci_testcase(tti_tx_dl, rnti, orin_dci, target_dci);
}

bool LLFuzz::send_ul_dci_testcase(int tti_tx_ul, uint16_t rnti, srsran_dci_ul_t &orin_dci, srsran_dci_ul_t& target_dci){
  bool ret = fuzzer->send_ul_dci_testcase(tti_tx_ul, rnti, orin_dci, target_dci);
  nof_sent_dci_ul = (ret) ? nof_sent_dci_ul + 1 : nof_sent_dci_ul;
  return ret;
}

void LLFuzz::save_testing_speed_log(){
  if (enableSpeedLog && checkTimer(speedLogTimer, interval*1000)){
    // get current time in format hh::mm::ss
    auto currentTime = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(currentTime);
    char timeStr[9];
    std::strftime(timeStr, sizeof(timeStr), "%H:%M:%S", std::localtime(&time));
    
    speedLog << "[" << timeStr << "] ";
    speedLog << idx[fuzzingState] << "\n";
    
    // reset timer
    speedLogTimer.activeTime = std::chrono::system_clock::now();
  }
}

std::string LLFuzz::get_cur_testcase_info(){
  return fuzzer->get_cur_testcase_info();
}

// save recent mac packet. in case of crash, these packets will be saved to pcap file
// void LLFuzz::save_mac_packet_to_buffer(uint8_t* payload, int len, uint32_t tti, uint16_t rnti){
//   if (saveMacPacket){
//     mac_packet_t packet;
//     packet.len = len;
//     packet.tti = tti;
//     packet.rnti = rnti;
//     if (len < 10000){
//       memcpy(packet.packet, payload, len);
//     }else{
//       std::cout << "[MAC] ERROR: Packet too long, not save to buffer" << "\n";
//     }
//     macPacketBuffer.push(packet);
//   }
// }

// void LLFuzz::save_mac_packet_buffer_to_pcap(){
//   std::deque<mac_packet_t> buffer = macPacketBuffer.getBuffer();

//   // First create a special marker packet with crash index
//   uint8_t marker_payload[100];
//   snprintf((char*)marker_payload, sizeof(marker_payload), "Crash Index: %d", nofCrash);
//   int marker_len = strlen((char*)marker_payload);
  
//   // Write marker packet with special RNTI (e.g., 0xFFFF) to distinguish it
//   // convert nofCrash to LTE tti:
//   int temp_tti = nofCrash * 10;
//   crash_pcap.write_dl_crnti(marker_payload, marker_len, 0xFFFF, true, temp_tti, 0);

//   // Then write actual MAC packets
//   for (int i = 0; i < (int)buffer.size(); i++){
//     if (buffer[i].rnti <= 10){
//       // this is rar packet
//       crash_pcap.write_dl_ranti(buffer[i].packet, buffer[i].len, buffer[i].rnti, true, buffer[i].tti, 0);
//     }else{
//       crash_pcap.write_dl_crnti(buffer[i].packet, buffer[i].len, buffer[i].rnti, true, buffer[i].tti, 0);
//     }
//   }
// }

} // namespace enb
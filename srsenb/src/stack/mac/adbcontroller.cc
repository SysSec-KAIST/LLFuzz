#include "srsenb/hdr/stack/mac/adbcontroller.h"

namespace srsenb {
    
// ADBController::ADBController(): thread("adbThread")
// {
//   if (pipe(macAdbInterface) == -1 || pipe(adbMacInterface) == -1 || pipe(pingPipe) == -1 
//       || pipe(adbStopPipe) == -1 || pipe(ttiPipe) == -1){
//     std::cout << "Init PIPE interface failed " << std::endl;
//   }

//  if (set_non_blocking_mode(macAdbInterface[0]) == -1 || set_non_blocking_mode(adbMacInterface[0]) == -1 
//     || set_non_blocking_mode(pingPipe[0]) == -1 || set_non_blocking_mode(adbStopPipe[0]) == -1 || set_non_blocking_mode(ttiPipe[0]) == -1) {
//     std::cout << "Init PIPE interface failed 2 " << std::endl;
//   }
//     int tempSignal = (int)checkADB; // check adb connection
//     ssize_t ret = write(macAdbInterface[1], &tempSignal, sizeof(tempSignal));
//     if (ret <=0){
//         printf("[MTT] Error: cannot write to macAdbInterface pipe\n");
//     }
// }

// ADBController::~ADBController(){
//   adbStop = true;
// }

// std::string macAdbInterfaceGetString(macAdbInterface_t value){
//   std::string ret = "unknown";
//   switch (value)
//   {
//   case checkADB:
//     ret = "checkADB";
//     break;
//   case switchAirplane:
//     ret = "switchAirplane";
//     break;
//   case monitorLogcat:
//     ret = "monitorLogcat";
//     break;
//   case switchAirplaneCrash:
//     ret = "switchAirplaneCrash";
//     break;
//   case state1PrepareADB:
//     ret = "state1PrepareADB";
//     break;
//   case pingUE:
//     ret = "pingUE";
//     break;
//   case adbSleep:
//     ret = "adbSleep";
//     break;
//   default:
//     break;
//   }
//   return ret;
// }

// std::string exeCmd(const char* cmd) {
//   // Execute the command and redirect output to a file
//   int ret = system((std::string(cmd) + " > output.txt").c_str());

//   // Read the content of the output file into a string
//   std::ifstream outputFile("output.txt");
//   if (outputFile) {
//       std::string outputContent((std::istreambuf_iterator<char>(outputFile)), std::istreambuf_iterator<char>());
//       outputFile.close();

//       // Clean up: delete the output file
//       remove("output.txt");

//       return outputContent;
//   } else {
//       return "Failed to open the output file.";
//   }
// }

// void ADBController::run_thread(){
//   pid_t pid = fork();
//   if (pid == 0){
//     while(!adbStop){
//       macAdbInterface_t macAdb;
//       int temp;
//       ssize_t ret = read(macAdbInterface[0], &temp, sizeof(temp));
//       macAdb = (macAdbInterface_t)temp;
//       int ueIP;
//       ssize_t ret2 = read(pingPipe[0], &ueIP, sizeof(ueIP));
//       if (ret2 <= 0){
//         ueIP = 2;
//       }
//       int stopSignal;
//       ssize_t ret3 = read(adbStopPipe[0], &stopSignal, sizeof(stopSignal));
//       if (ret3 > 0 && stopSignal == 1){
//         adbStop = true;
//       }
//       int curTTI = 0;
//       ssize_t ret4 = read(ttiPipe[0], &curTTI, sizeof(curTTI));
//       if ( ret4 <= 0){ curTTI = prevTTI;}
//       else { prevTTI = curTTI;} // save TTI for other phases that dont receive tti from mac thread
//       if (ret <= 0){ //no new data
//         macAdb = monitorLogcat;
//       }else{
//         if (DEBUG_MODE){ 
//           printf("[ADB] SF: %d.%d Received signal: ", curTTI/10, curTTI%10); 
//           std::cout << BLUE_TEXT << macAdbInterfaceGetString(macAdb) << RESET_COLOR << std::endl;
//         }
//       }
//     //   printf("[ADB] Debug 0 \n"); 
//       if (macAdb == checkADB){
//         adbCommand = adbCommand;
//         const char* cmdstr = adbCommand.c_str();
//         adbResult = exeCmd(cmdstr);
//         std::cout << adbResult;
//         //Check if there is a connected device
//         if ((int)adbResult.length() > 30){
//           adbConnected = true;
//           std::cout << "[ADB] Device Connected " << std::endl;
//         }else{
//           std::cout << "[ADB] Device Disconnected, L =  " << (int)adbResult.length() << std::endl;
//         }

//         /*clean adb output*/
//         adbCommand = cleanADB;
//         const char* cmdstr2 = adbCommand.c_str();
//         adbResult = exeCmd(cmdstr2);
//         // macAdbInterface = monitorLogcat;
      
//       } else if ((macAdb == switchAirplane || adbPhase == adbTurnOffAirplane) and adbConnected){ // || adbPhase == adbDisableCellData
//         if (!adbTimer.running){
//           /*Turn on airplane mode*/
//           adbCommand = airplaneOn;
//           const char* cmdstr = adbCommand.c_str();
//           adbResult = exeCmd(cmdstr);
//           std::cout << adbResult;
//           /*start timer for 2 seconds*/
//           adbTimer.running = true;
//           adbTimer.activeTime = clock();
//           adbPhase = adbTurnOffAirplane; // change adb phase to continue executing without signal from pipe
//           if (DEBUG_MODE){ printf("[ADB] SF: %d.%d -- State: Turned on Airplane mode, enabled timer 0 \n", curTTI/10, curTTI%10); }       
//         }else if (adbTimer.running && adbPhase == adbTurnOffAirplane){
//           clock_t curTime = clock();
//           long double curInterval = 0;
//           curInterval = (curTime - adbTimer.activeTime) / CLOCKS_PER_SEC;
//           if (curInterval >= 1.0){ // timer is timeout
//             /*Turn off airplane mode*/
//             adbCommand = airplaneOff;
//             const char* cmdstr2 = adbCommand.c_str();
//             adbResult = exeCmd(cmdstr2);
//             std::cout << adbResult;

//             /*clean adb output after switch airplane mode*/
//             adbCommand = cleanADB;
//             const char* cmdstr3 = adbCommand.c_str();
//             adbTimer.activeTime = 0;
//             adbTimer.running = false;
//             adbPhase = adbNoPhase;
//             if (DEBUG_MODE){ printf("[ADB] SF: %d.%d State: Turned off AirPlane mode 1 \n", curTTI/10, curTTI%10); }
//           }
//         }else{
//           if (DEBUG_MODE){ printf("[ADB] Cannot enter AirPlane, timer running: %d, macAdb: %d, adbPhase: %d \n", adbTimer.running.load(), macAdb, adbPhase);}
//         }
//         // else if (adbTimer.running && adbPhase == adbDisableCellData){
//         //   clock_t curTime = clock();
//         //   long double curInterval = 0;
//         //   curInterval = (curTime - adbTimer.activeTime) / CLOCKS_PER_SEC;
//         //   if (curInterval >= 0.5){ // timer is timeout
//         //     adbTimer.running = false;
//         //     adbTimer.activeTime = 0;
//         //     /*Turn off airplane mode*/
//         //     adbCommand = CellDataOff;
//         //     const char* cmdstr2 = adbCommand.c_str();
//         //     adbResult = exeCmd(cmdstr2);
//         //     std::cout << adbResult;

//         //     /*clean adb output after switch airplane mode*/
//         //     adbCommand = cleanADB;
//         //     const char* cmdstr3 = adbCommand.c_str();
//         //     adbPhase = adbNoPhase;
//         //     if (DEBUG_MODE){ printf("[ADB] SF: %d.%d Disabled data -- State: switchAirplane --> monitorLogcat 2 \n", curTTI/10, curTTI%10); }
//         //   }
//         // }
      
//       }else if (macAdb == switchAirplaneCrash and adbConnected) { // temporary using another algorithm
//         // /*Turn on airplane mode*/
//         // adbCommand = airplaneOn;
//         // const char* cmdstr = adbCommand.c_str();
//         // adbResult = system(cmdstr);
//         // std::cout << result;
        
//         // /*Turn off airplane mode*/
//         // adbCommand = airplaneOff;
//         // const char* cmdstr2 = adbCommand.c_str();
//         // result = system(cmdstr2);
//         // std::cout << result;

//         // /*clean adb output after switch airplane mode*/
//         // adbCommand = cleanADB;
//         // const char* cmdstr3 = adbCommand.c_str();
//         // result = system(cmdstr3);

//         // /*start timer to detect if UE is not able to connect successfully*/
//         // waitingConnTimer.running = true;
//         // waitingConnTimer.activeTime = clock();

//         // if (DEBUG_MODE){ printf("[ADB] State: switchAirplaneCrash --> monitorLogcat \n"); }

//         // adbMacInterface = noAction;
//         // macAdbInterface = monitorLogcat;

//       } else if (macAdb == state1PrepareADB && adbConnected){
//         adbCommand = wifiOff; //turn off wifi on UE
//         const char* cmdstr = adbCommand.c_str();
//         adbResult = exeCmd(cmdstr);
//         // std::cout << adbResult;
//         // int ret = system(cmdstr);
//         // /*Wait for 1 seconds*/
        
//         // adbCommand = CellDataOn; // disable cellular data on UE
//         // const char* cmdstr2 = adbCommand.c_str();
//         // adbResult = exeCmd(cmdstr2);
//         // std::cout << adbResult;
//         // ret = system(cmdstr2);


//         if (DEBUG_MODE){ printf("[ADB] SF: %d.%d State: state1PrepareADB --> monitorLogcat \n", curTTI/10, curTTI%10); }
//         // macAdbInterface = monitorLogcat;
//         int temp = (int)adbConfigSuccess;
//         ssize_t ret = write(adbMacInterface[1], &temp, sizeof(temp));
//         // adbMacInterface = adbConfigSuccess; // notify mac thread
//       }else if (macAdb == pingUE && adbConnected){
//         // adbCommand = "timeout 4 ping 172.16.0." + std::to_string(ueIP); //turn off wifi on UE
//         adbCommand = checkCellData;
//         const char* cmdstr = adbCommand.c_str();
//         adbResult = exeCmd(cmdstr);
//         size_t checkResult = adbResult.find("1");
//         if (checkResult != std::string::npos){
//           adbCommand = CellDataOff;
//           printf("[ADB] SF: %d.%d Cellular is on, turning it off \n", curTTI/10, curTTI%10);
//         }else if (checkResult == std::string::npos){
//           adbCommand = CellDataOn;
//           printf("[ADB] SF: %d.%d Cellular is off, turning it on \n", curTTI/10, curTTI%10);
//         }else{
//           printf("[ADB] SF: %d.%d Abnormal adb result from check cellular data \n", curTTI/10, curTTI%10);
//         }
//         const char* cmdstr2 = adbCommand.c_str();
//         adbResult = exeCmd(cmdstr2);
//         if (DEBUG_MODE){ 
//           printf("[ADB] SF: %d.%d Switched cellular data \n", curTTI/10, curTTI%10);
//           // std::cout << adbCommand << std::endl;
//         }
//       }else if (macAdb == monitorLogcat && adbConnected){
//         /*Detect crash, inform mac thread if there is a crash detected*/
//         adbCommand = "adb logcat -b radio *:E -d | grep \"RADIO_OFF_OR_UNAVAILABLE\\|Modem Reset\\|CRASH\"";
//         const char* cmdstr = adbCommand.c_str();
//         adbResult = exeCmd(cmdstr);
//         // std::cout << "[ADB] Result: " << adbResult << std::endl;
//         size_t foundCrash1 = adbResult.find(crashString1);
//         size_t foundCrash2 = adbResult.find(crashString2);
//         size_t foundCrash3 = adbResult.find(crashString3);
//         if (   foundCrash1 != std::string::npos 
//             or foundCrash2 != std::string::npos 
//             or foundCrash3 != std::string::npos)
//         {
//           std::cout << RED_TEXT << "[ADB] Crash detected from ADB " << RESET_COLOR << std::endl;
//           int temp = (int)crashDetected;
//           ssize_t ret = write(adbMacInterface[1], &temp, sizeof(temp));
//           adbCommand = cleanADB;
//           const char* cmdstr2 = adbCommand.c_str();
//           adbResult = exeCmd(cmdstr2);
//           macAdb = adbSleep;
//         }
//       }else{
//         // std::cout << " [ADB] Thread not running normally, macAdbInterface = " << macAdbInterface << " , adbConnected = " << adbConnected << " *adbstopFork = " << *adbstopFork << std::endl;
//       }
//     }
//     printf("[ADB] adb stop = %d \n", (int)adbStop);
//   }else if (pid < 0){
//     std::cout << "Failed to fork process, pid = " << pid <<  std::endl;
//   }
// }

} // namespace srsenb

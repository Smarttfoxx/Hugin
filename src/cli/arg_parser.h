/*
* GNU GENERAL PUBLIC LICENSE
* Version 3, 29 June 2007

* Copyright (C) 2025 Smarttfoxx

* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, 
* or any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.

* This program comes with ABSOLUTELY NO WARRANTY; This is free software, 
* and you are welcome to redistribute it under certain conditions.
*/

#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>

#include "../interfaces/visuals.h"
#include "../engine/scan_engine.h"
#include "../utilities/log_system.h"

struct ProgramConfig {
    int portScan_timeout = 1;
    int servScan_timeout = 1;
    int threadAmount = 200;
    bool isHostUp = false;
    bool enableFindService = false;
    bool enableTCPConnectScan = false;
    bool enableUDPScan = false;
    bool enableARPScan = false;
    bool enableLUA = false;
    std::string networkInterface;
    std::vector<HostInstance> HostInstances;
    std::vector<int> portsToScan;
    std::vector<std::string> luaScripts;
};

bool ParseArguments(int argc, char* argv[], ProgramConfig& config);

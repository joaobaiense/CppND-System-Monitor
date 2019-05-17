#include <algorithm>
#include <iostream>
#include <math.h>
#include <thread>
#include <chrono>
#include <iterator>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"


using namespace std;

class ProcessParser{

    private:
        ifstream stream;
    public:
        static string getCmd(string pid);
        static vector<string> getPidList();
        static string getVmSize(string pid);
        static string getCpuPercent(string pid);
        static long int getSysUpTime();
        static string getProcUpTime(string pid);
        static string getProcUser(string pid);
        static vector<string> getSysCpuPercent(string coreNumber="");
        static float getSysRamPercent();
        static string getSysKernelVersion();
        static int getTotalThreads();
        static int getTotalNumberOfProcesses();
        static int getNumberOfRunningProcesses();
        static string getOSName();
        static string PrintCpuStats(vector<string> values1, vector<string>values2);
        static bool isPidExisting(string pid);
        static int getNumberOfCores();
};


string ProcessParser::getVmSize(string pid){

    string line;

    string name = "VmData";
    string value;
    float result;

    string path = Path::basePath() + pid + Path::statusPath();
    ifstream stream;
    Util::getStream(path, stream);

    while(getline(stream, line)){

        // Search in each line
        // line.compare == 0 -> found match
        if(line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);

            istream_iterator<string> beg(buf), end;

            vector<string> values(beg, end);

            result = (stof(values[1])/float(1024));
            break;
        }
    }

    return to_string(result);
}

string ProcessParser::getCpuPercent(string pid){

    string line;
    string value;
    
    float result;
    ifstream stream;

    string path = Path::basePath() + pid + "/" + Path::statPath();
    Util::getStream(path, stream);

    // Now process the stream - only one line
    getline(stream, line);

    string str = line;
    istringstream buf(str);
    istream_iterator<string>  beg(buf), end;
    vector<string> values(beg, end);

    float uTime = stof(ProcessParser::getProcUpTime(pid));
    float sTime = stof(values[14]);
    float cuTime = stof(values[15]);
    float csTime = stof(values[16]);
    float startTime = stof(values[21]);
    float upTime = ProcessParser::getSysUpTime();
    float freq = sysconf(_SC_CLK_TCK);
    float totalTime = uTime + sTime + cuTime + csTime;
    float seconds = upTime - (startTime/freq);

    result = 100.0 * ( (totalTime/freq) / seconds );

    return to_string(result);
}

string ProcessParser::getProcUpTime(string pid){
    
    string line;
    string value;
    
    float result;
    ifstream stream;

    string path = Path::basePath() + pid + "/" + Path::statPath();
    Util::getStream(path, stream);

    // Now process the stream - only one line
    getline(stream, line);

    string str = line;
    istringstream buf(str);
    istream_iterator<string>  beg(buf), end;
    vector<string> values(beg, end);

    return to_string(float(stof(values[13])/sysconf(_SC_CLK_TCK)));
}

long int ProcessParser::getSysUpTime(){
    
    string line;
    ifstream stream;
    string path = Path::basePath() + Path::upTimePath();

    Util::getStream(path, stream);

    istringstream buf(line);

    istream_iterator<string> beg(buf), end;

    vector<string> values(beg, end);

    return stoi(values[0]);

}

string ProcessParser::getProcUser(string pid){
    string line;
    string name = "Uid:";
    string result = "";

    ifstream stream;
    string path = Path::basePath() + pid + Path::statusPath();
    Util::getStream(path, stream);

    // Search for UID
    while(getline(stream, line)){
        if(line.compare(0, name.size(), name) == 0 ){
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;

            vector<string> values(beg, end);
            result = values[1];
            break;
        }
    }

    // Search for name of user with selected UID 
    Util::getStream("/etc/passwd", stream);

    name = "x:" + result;
    while(getline(stream,line)){
        /*
        npos is a static member constant value with the greatest possible value for an element of type size_t.
            This value, when used as the value for a len (or sublen) parameter in string's member functions, means "until the end of the string".
            As a return value, it is usually used to indicate no matches.
            This constant is defined with a value of -1, which because size_t is an unsigned integral type, it is the largest possible representable value for this type.
        */
        if(line.find(name) != string::npos){
            result =line.substr(0, line.find(":"));
            return result;
        }
    }

    // edge case response
    return "";
}

vector<string> ProcessParser::getPidList(){
    DIR* dir;
    bool areDigits;
    vector<string> container;

    if(!(dir = opendir("/proc")))
        throw runtime_error(strerror(errno));
    
    while( dirent* dirp = readdir(dir)){
        
        // if this is not a directory
        if (dirp->d_type != DT_DIR)
            continue;
        
        // if this is a directory -> check if all chars are digits
        areDigits = all_of(dirp->d_name, dirp->d_name + strlen(dirp->d_name), [](char c) {
            return isdigit(c);
        });

        if (areDigits)
            container.push_back(dirp->d_name);
    }

    if (closedir(dir))
        throw runtime_error(strerror(errno));
    
    return container;
}

string ProcessParser::getCmd(string pid){

    string line;
    ifstream stream;
    string path = Path::basePath() + pid + Path::cmdPath();
    Util::getStream(path, stream);

    return line;
}

int ProcessParser::getNumberOfCores(){

    string line;
    string name = "cpu cores";
    string path = Path::basePath() + "cpuinfo";
    ifstream stream;
    Util::getStream(path, stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return stoi(values[3]);
        }
    }
    return 0;
}

vector<string> ProcessParser::getSysCpuPercent(string coreNumber){

    string line;
    string name = "cpu" + coreNumber;
    string value;
    int result;
    ifstream stream;
    string path = Path::basePath() + Path::statPath();
    Util::getStream(path, stream);
    while (getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            // set of cpu data active and idle times;
            return values;
        }
    }
    return (vector<string>());
}

float get_sys_active_cpu_time(vector<string> values)
{
    return (stof(values[S_USER]) +
            stof(values[S_NICE]) +
            stof(values[S_SYSTEM]) +
            stof(values[S_IRQ]) +
            stof(values[S_SOFTIRQ]) +
            stof(values[S_STEAL]) +
            stof(values[S_GUEST]) +
            stof(values[S_GUEST_NICE]));
}

float get_sys_idle_cpu_time(vector<string>values)
{
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}

string ProcessParser::PrintCpuStats(vector<string> values1, vector<string> values2){
    /*
    Because CPU stats can be calculated only if you take measures in two different time,
    this function has two paramaters: two vectors of relevant values.
    We use a formula to calculate overall activity of processor.
    */
    float active_time = get_sys_active_cpu_time(values2)-get_sys_active_cpu_time(values1);
    float idle_time = get_sys_idle_cpu_time(values2) - get_sys_idle_cpu_time(values1);
    float total_time = active_time + idle_time;
    float result = 100.0*(active_time / total_time);
    return to_string(result);
    
}

float ProcessParser::getSysRamPercent(){

    string line;
    string name1 = "MemAvailable:";
    string name2 = "MemFree:";
    string name3 = "Buffers:";

    string value;
    int result;
    ifstream stream;
    Util::getStream((Path::basePath() + Path::memInfoPath()), stream);

    float totalMem = 0;
    float freeMem = 0;
    float buffers = 0;

    while (std::getline(stream, line)) {
        if (totalMem != 0 && freeMem != 0)
            break;
        if (line.compare(0, name1.size(), name1) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            totalMem = stof(values[1]);
        }
        if (line.compare(0, name2.size(), name2) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            freeMem = stof(values[1]);
        }
        if (line.compare(0, name3.size(), name3) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            buffers = stof(values[1]);
        }
    }
    //calculating usage:
    return float(100.0*(1-(freeMem/(totalMem-buffers))));
}


string ProcessParser::getSysKernelVersion(){
    string line;
    string name = "Linux version ";
    ifstream stream;
    Util::getStream((Path::basePath() + Path::versionPath()), stream);
    while (getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return values[2];
        }
    }
    return "";
}

string ProcessParser::getOSName(){
    string line;
    string name = "PRETTY_NAME=";

    ifstream stream;
    
    Util::getStream(("/etc/os-release"), stream);

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
              std::size_t found = line.find("=");
              found++;
              string result = line.substr(found);
              result.erase(remove(result.begin(), result.end(), '"'), result.end());
              return result;
        }
    }
    return "";

}


int ProcessParser::getTotalThreads(){
    string line;
    int result = 0;
    string name = "Threads:";
    vector<string>_list = ProcessParser::getPidList();
    ifstream stream;

    string path;
    for (int i=0 ; i<_list.size();i++) {
        string pid = _list[i];
        //getting every process and reading their number of their threads
        path = Path::basePath() + pid + Path::statusPath();
        Util::getStream(path, stream);
        while (std::getline(stream, line)) {
            if (line.compare(0, name.size(), name) == 0) {
                istringstream buf(line);
                istream_iterator<string> beg(buf), end;
                vector<string> values(beg, end);
                result += stoi(values[1]);
                break;
            }
        }
        return result;
    }

}

int ProcessParser::getTotalNumberOfProcesses(){
    string line;
    int result = 0;
    string name = "processes";
    ifstream stream;
    Util::getStream((Path::basePath() + Path::statPath()), stream);
    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    return result;
}

int ProcessParser::getNumberOfRunningProcesses(){
    string line;
    int result = 0;
    string name = "procs_running";
    ifstream stream;
    Util::getStream((Path::basePath() + Path::statPath()), stream);
    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    return result;
}


bool ProcessParser::isPidExisting(string pid){

    vector<string> pids = ProcessParser::getPidList();

    if ( find(pids.begin(), pids.end(), pid) != pids.end()){
        return true;
    }

    return false;
}
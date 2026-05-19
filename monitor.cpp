//k213554
//usman shahid
#include <iostream>
#include <string>
using namespace std;

// class for network traffic
class nettraf {
private:
    string srcip;//src ip
    string dsturl;//dest ip
public:
    nettraf(const string& src_ip, const string& dest_url) : srcip(src_ip), dsturl(dest_url) {}

    string getsrcip() const {
        return srcip;
    }
    string getdsturl() const {
        return dsturl;
    }
};




//class for security system(secsys)
class secsys {
private:
    string suswebsite[3]; 

public:
    secsys(const string suspicious_sites[]) {
        for (int i = 0; i < 3; ++i) {
            suswebsite[i] = suspicious_sites[i];
        }
    }
    bool ifsus(const string& url) {
        for (int i = 0; i < 3; ++i) {
            if (url.find(suswebsite[i]) != string::npos) {
                return true;
            }
        }
        return false;
    }
    //monitor network traffic(checknettraf)
    void checknettraf(const nettraf traffic_data[], int size) {
        for (int i = 0; i < size; ++i) {
            if (ifsus(traffic_data[i].getdsturl())) {
                cout << "Suspicious website detected ip " << traffic_data[i].getsrcip() << ", with url " << traffic_data[i].getdsturl() << endl;
            }
        }
    }
};




int main() {
	
    string suswebsite[] = {
        "flex.com",
        "fast.net",
        "gobuster.com"
    };
    nettraf network_traffic[] = {
        nettraf("192.168.1.100", "ubl.com"),
        nettraf("192.168.1.101", "meezan.com"), 
        nettraf("192.168.1.102", "alfalh.com"),
        nettraf("192.168.1.103", "mbl.com"),
        nettraf("192.168.1.104", "gobuster.com")//suspicious 
    };
    secsys security_system(suswebsite);
    security_system.checknettraf(network_traffic, sizeof(network_traffic) / sizeof(network_traffic[0]));

    return 0;
}

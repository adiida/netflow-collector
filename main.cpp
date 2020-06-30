#include <iostream>
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <sstream>
#include <cstdlib>
#include <vector>
#include <ctime>
#include <unistd.h>
#include <mysql.h>
#include <mysql++.h>
#include <set>
#include <sstream>
#include <exception>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/lexical_cast.hpp>

// class for storage template
// ************************************************************************************************
class NetflowTemplate {
    private:
    unsigned int templateID;
    unsigned int fieldCount;
    std::vector < unsigned int > FieldTypeArray;
    std::vector < unsigned int > FieldLengthArray;
    public:
        void set_templateID(unsigned int);
    void set_fieldCount(unsigned int);
    void set_FieldTypeArray(std::vector < unsigned int > );
    void set_FieldLengthArray(std::vector < unsigned int > );
    unsigned int get_templateID() {
        return templateID;
    }
    unsigned int get_fieldCount() {
        return fieldCount;
    }
    std::vector < unsigned int > get_FieldTypeArray() {
        return FieldTypeArray;
    }
    std::vector < unsigned int > get_FieldLengthArray() {
        return FieldLengthArray;
    }
};

void NetflowTemplate::set_templateID(unsigned int templID) {
    templateID = templID;
}

void NetflowTemplate::set_fieldCount(unsigned int fieldNum) {
    fieldCount = fieldNum;
}

void NetflowTemplate::set_FieldTypeArray(std::vector < unsigned int > FTypeArray) {
    FieldTypeArray.clear();
    FieldTypeArray = FTypeArray;
}

void NetflowTemplate::set_FieldLengthArray(std::vector < unsigned int > FLengthArray) {
    FieldLengthArray.clear();
    FieldLengthArray = FLengthArray;
}

// netflow parser functions
// ************************************************************************************************
int int_to_hex(char t1) {
    int g;

    std::stringstream stream;
    stream << std::hex << int(static_cast < unsigned char > (t1));

    g = atoi(stream.str().c_str());
    return g;
}

int int_to_dec(char t1) {
    int g;

    std::stringstream stream;
    stream << std::dec << int(static_cast < unsigned char > (t1));

    g = atoi(stream.str().c_str());
    return g;
}

std::string int_to_hex_char(char t1) {
    std::stringstream stream;
    stream << std::setfill('0') << std::setw(2) << std::hex << int(static_cast < unsigned char > (t1)) + 0;
    return stream.str();
}

std::ifstream infile;

std::string parse_single_int_data(int byte_size) {
    std::string hexString = "";
    std::string decString = "";
    int decNum = 0;
    char byte_of_data;

    for (int i = 0; i < byte_size; i++) {
        infile.read( & byte_of_data, 1);
        hexString += int_to_hex_char(byte_of_data);
    }
    //std::cout << "\n" << hexString << std::endl;
    decNum = strtoul(hexString.substr(0, byte_size * 2).c_str(), NULL, 16);
    decString = boost::lexical_cast < std::string > (decNum);

    return decString;
}

std::string parse_int_data_with_delimiter(int byte_size, std::string delimiter) {
    std::string hexString = "";
    std::string decStringDelimiter = "";
    int decNum = 0;
    char byte_of_data;

    for (int i = 0; i < byte_size; i++) {
        infile.read( & byte_of_data, 1);
        hexString = int_to_hex_char(byte_of_data);
        decNum = strtoul(hexString.substr(0, 2).c_str(), NULL, 16);
        decStringDelimiter += boost::lexical_cast < std::string > (decNum);
        if (i < byte_size - 1) decStringDelimiter += delimiter;
        hexString = "";
    }

    return decStringDelimiter;
}

// mysql global variables
// ************************************************************************************************
MYSQL * conn, mysql;
MYSQL_RES * res;
MYSQL_ROW row;
int query_state;

int main() {
    try {
        infile.open("./netflow_collector_data", std::ios::binary | std::ios:: in );

        if (infile.fail()) {
            std::cerr << "Cannot open file FILENAME.EXT";
            exit(1);
        }

        infile.seekg(0, infile.end);
        unsigned int byteSizeOfFile = infile.tellg(); //Size of file in bytes (add to all variable zone later)
        infile.seekg(0, infile.beg);

        // all variables zone
        // ************************************************************************************************

        std::string stringFieldTypeArray[] = {
            "IN_BYTES",
            "IN_PKTS",
            "FLOWS",
            "PROTOCOL",
            "TOS",
            "TCP_FLAGS",
            "L4_SRC_PORT",
            "IPV4_SRC_ADDR",
            "SRC_MASK",
            "INPUT_SNMP",
            "L4_DST_PORT",
            "IPV4_DST_ADDR",
            "DST_MASK",
            "OUTPUT_SNMP",
            "IPV4_NEXT_HOP",
            "SRC_AS",
            "DST_AS",
            "BGP_IPV4_NEXT_HOP",
            "MUL_DST_PKTS",
            "MUL_DST_BYTES",
            "LAST_SWITCHED",
            "FIRST_SWITCHED",
            "OUT_BYTES",
            "OUT_PKTS",
            "IPV6_SRC_ADDR",
            "IPV6_DST_ADDR",
            "IPV6_SRC_MASK",
            "IPV6_DST_MASK",
            "IPV6_FLOW_LABEL",
            "ICMP_TYPE",
            "MUL_IGMP_TYPE",
            "SAMPLING_INTERVAL",
            "SAMPLING_ALGORITHM",
            "FLOW_ACTIVE_TIMEOUT",
            "FLOW_INACTIVE_TIMEOUT",
            "ENGINE_TYPE",
            "ENGINE_ID",
            "TOTAL_BYTES_EXP",
            "TOTAL_PKTS_EXP",
            "TOTAL_FLOWS_EXP",
            "MPLS_TOP_LABEL_TYPE",
            "MPLS_TOP_LABEL_IP_ADDR",
            "FLOW_SAMPLER_ID",
            "FLOW_SAMPLER_MODE",
            "FLOW_SAMPLER_RANDOM_INTERVAL",
            "DST_TOS",
            "SRC_MAC",
            "DST_MAC",
            "SRC_VLAN",
            "DST_VLAN",
            "IP_PROTOCOL_VERSION",
            "DIRECTION",
            "IPV6_NEXT_HOP",
            "BGP_IPV6_NEXT_HOP",
            "IPV6_OPTION_HEADERS",
            "MPLS_LABEL_1",
            "MPLS_LABEL_2",
            "MPLS_LABEL_3",
            "MPLS_LABEL_4",
            "MPLS_LABEL_5",
            "MPLS_LABEL_6",
            "MPLS_LABEL_7",
            "MPLS_LABEL_8",
            "MPLS_LABEL_9",
            "MPLS_LABEL_10"
        };

        std::string verNum = "";
        std::string numOfEntry = "";
        std::string sysUpTime = "";
        std::string unixSecs = "";
        std::string seqNum = "";
        std::string sourceID = "";

        unsigned int numOfAllEntry = 0;

        unsigned int flowSetID = 0;
        unsigned int flowSetLength = 0;
        unsigned int templateID = 0;
        unsigned int templatefFieldCount = 0;

        unsigned int numOfTemplateFields = 0;

        std::string fieldType = "";
        std::string fieldLength = "";
        std::string fieldData = "";

        std::string dataFlowSetID = "";
        std::string dataFlowSetLength = "";

        std::vector < unsigned int > FieldTypeArray;
        std::vector < unsigned int > FieldLengthArray;
        std::vector < std::string > FieldDataArray;

        unsigned int packetByteSizeOfData = 0;
        unsigned int calcSizeOfPacketData = 0;
        unsigned int paddingByteSize = 0;
        unsigned int packet = 0;
        unsigned int entry = 0;

        std::vector < NetflowTemplate > templateStorage;
        NetflowTemplate newTemplate;
        std::vector < unsigned int > templateIDArray;
        unsigned int i = 0;
        unsigned int j = 0;
        unsigned int k = 0;
        bool templateIdExist = false;
        unsigned int flowEndPosition = 0;
        unsigned int flowNumber = 0;
        unsigned int flowSetNumber = 0;
        unsigned int flow = 0;
        unsigned int numOfTotalPackets = 0;

        // variables for receive data from netflow collector (listen port 9995, 2055, etc.) and write in the file
        size_t lenReceiveData = 0;
        size_t ch = 0;
        size_t numFilePackets = 0;
        std::ofstream saveData;
        bool fileChange = false;
        boost::asio::ip::udp::endpoint remote_endpoint;
        boost::array < char, 65536 > receivedData;
        boost::asio::io_service io_service;
        std::string netflowDataFilename0 = "./netflow_collector_data_file_0";
        std::string netflowDataFilename1 = "./netflow_collector_data_file_1";

        // variables storage data for write to mysql table
        std::string mDateTime = "";
        std::string mProtocol = "";
        std::string mSourcePort = "";
        std::string mSourceAddress = "";
        std::string mDestinationPort = "";
        std::string mDestinationAddress = "";
        std::string mTotalBytes = "";
        std::string netflowEntryToMysqlTable = ""; // storage query for write netflow entry to mysql table

        // variables for connection to mysql database
        const char * server = "";
        const char * user = "";
        const char * password = "";
        const char * database = "";

        // variables for getting program options from ini file
        std::string ini_file("config.ini");
        unsigned int ini_netflow_port = 0;
        std::string ini_mysql_server = "";
        std::string ini_mysql_user = "";
        std::string ini_mysql_password = "";
        std::string ini_mysql_database = "";
        std::string ini_mysql_table = "";

        // read program options from ini file
        // ************************************************************************************************
        boost::property_tree::ptree pt;
        read_ini(ini_file, pt);

        ini_netflow_port = pt.get < unsigned int > ("netflow.port");
        ini_mysql_server = pt.get < std::string > ("mysql.server");
        ini_mysql_user = pt.get < std::string > ("mysql.user");
        ini_mysql_password = pt.get < std::string > ("mysql.password");
        ini_mysql_database = pt.get < std::string > ("mysql.database");
        ini_mysql_table = pt.get < std::string > ("mysql.table");

        server = ini_mysql_server.c_str();
        user = ini_mysql_user.c_str();
        password = ini_mysql_password.c_str();
        database = ini_mysql_database.c_str();

        verNum = "";
        numOfEntry = "";
        sysUpTime = "";
        unixSecs = "";
        seqNum = "";
        sourceID = "";
        numOfAllEntry = 0;

        flowSetID = 0;
        flowSetLength = 0;
        templateID = 0;
        templatefFieldCount = 0;
        numOfTemplateFields = 0;
        fieldType = "";
        fieldLength = "";
        fieldData = "";
        dataFlowSetID = "";
        dataFlowSetLength = "";
        FieldTypeArray.clear();
        FieldLengthArray.clear();
        FieldDataArray.clear();

        packetByteSizeOfData = 0;
        calcSizeOfPacketData = 0;
        paddingByteSize = 0;
        templateIdExist = false;
        flowSetNumber = 0;
        flow = 0;
        lenReceiveData = 0;
        ch = 0;
        numFilePackets = 0;

        // get packet header information
        // ************************************************************************************************
        verNum = parse_single_int_data(2);
        numOfEntry = parse_single_int_data(2);
        sysUpTime = parse_single_int_data(4);
        unixSecs = parse_single_int_data(4);
        seqNum = parse_single_int_data(4);
        sourceID = parse_single_int_data(4);
        numOfAllEntry = boost::lexical_cast < unsigned int > (numOfEntry);

        for (flow = 0; flow < numOfAllEntry;) {

            // get Flow Set information
            // ************************************************************************************************
            flowSetID = boost::lexical_cast < unsigned int > (parse_single_int_data(2));
            flowSetLength = boost::lexical_cast < unsigned int > (parse_single_int_data(2));
            flowEndPosition = infile.tellg() + flowSetLength - 4;

            // get template information
            // ************************************************************************************************
            if (flowSetID == 0) {
                for (entry = 0; entry < numOfAllEntry; entry++) {
                    flow++;
                    FieldTypeArray.clear();
                    FieldLengthArray.clear();
                    templateIdExist = false;
                    templateID = boost::lexical_cast < unsigned int > (parse_single_int_data(2));

                    for (i = 0; i < templateIDArray.size(); i++) {
                        if (templateIDArray[i] == templateID) {
                            templateIdExist = true;
                            break;
                        }
                    }
                    templatefFieldCount = boost::lexical_cast < unsigned int > (parse_single_int_data(2));

                    if (templateIdExist) {
                        // for each field we get type and length
                        infile.seekg(templatefFieldCount * 4, infile.cur);
                    } else {
                        // get field type and length and save in vectors
                        for (j = 0; j < templatefFieldCount; j++) {
                            fieldType = parse_single_int_data(2);
                            fieldLength = parse_single_int_data(2);
                            FieldTypeArray.push_back(boost::lexical_cast < unsigned int > (fieldType));
                            FieldLengthArray.push_back(boost::lexical_cast < unsigned int > (fieldLength));
                        }

                        newTemplate.set_templateID(templateID);
                        newTemplate.set_fieldCount(templatefFieldCount);
                        newTemplate.set_FieldTypeArray(FieldTypeArray);
                        newTemplate.set_FieldLengthArray(FieldLengthArray);
                        templateStorage.push_back(newTemplate);
                        templateIDArray.push_back(templateID);
                    }

                    if ((infile.tellg() >= flowEndPosition - 2) && (entry < numOfAllEntry)) {
                        break;
                    }

                }

                // get field data
                // ************************************************************************************************

            } else if (flowSetID > 0 && flowSetID > 1) {
                FieldTypeArray.clear();
                FieldLengthArray.clear();
                FieldDataArray.clear();
                for (i = 0; i < templateIDArray.size(); i++) {
                    if (templateIDArray[i] == flowSetID) {
                        FieldTypeArray = templateStorage[i].get_FieldTypeArray();
                        FieldLengthArray = templateStorage[i].get_FieldLengthArray();
                        break;
                    }
                }

                for (entry = 0; entry < numOfAllEntry; entry++) {
                    flow++;
                    flowNumber++;

                    // get field data and save in vector
                    for (unsigned int l = 0; l < FieldTypeArray.size(); l++) {
                        if (FieldTypeArray[l] == 8 || FieldTypeArray[l] == 12 || FieldTypeArray[l] == 15 || FieldTypeArray[l] == 40001 || FieldTypeArray[l] == 40002) {
                            fieldData = parse_int_data_with_delimiter(FieldLengthArray[l], ".");
                        } else {
                            fieldData = parse_single_int_data(FieldLengthArray[l]);
                        }
                        FieldDataArray.push_back(fieldData);;

                        calcSizeOfPacketData += FieldLengthArray[l];
                    }
                    FieldDataArray.clear();

                    // handle padding of packet's data
                    // ************************************************************************************************

                    if ((infile.tellg() >= flowEndPosition - 2) && (entry < numOfAllEntry)) {
                        flowSetNumber++;

                        // every block of data start with FlowSet ID and Length
                        calcSizeOfPacketData += 4;
                        paddingByteSize = (4 - (calcSizeOfPacketData % 4)) % 4;

                        infile.seekg(paddingByteSize, infile.cur);
                        if (infile.tellg() > byteSizeOfFile) break;
                        flowNumber = 0;
                        calcSizeOfPacketData = 0;
                        break;
                    }
                }
            }
        }
        if (numOfTotalPackets == 1) {
            infile.close();
        }

        boost::asio::ip::udp::socket socket(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), ini_netflow_port));
        saveData.open(netflowDataFilename0.c_str(), std::ios::binary);

        while (true) {
            numFilePackets++;
            lenReceiveData = socket.receive_from(boost::asio::buffer(receivedData), remote_endpoint);

            while (ch < lenReceiveData) {
                saveData << receivedData[ch];
                ch++;
                if (ch == 65535) break;
            }
            ch = 0;

            if (numFilePackets == 100) {
                saveData.close();
                numFilePackets = 0;
                //break;
                if (fileChange) {
                    saveData.open(netflowDataFilename0.c_str(), std::ios::binary);
                    infile.open(netflowDataFilename1.c_str(), std::ios::binary | std::ios:: in );
                    if (infile.fail()) {
                        std::cerr << "Cannot open file FILENAME.EXT";
                        exit(1);
                    }

                    infile.seekg(0, infile.end);
                    byteSizeOfFile = infile.tellg();
                    infile.seekg(0, infile.beg);
                    fileChange = false;
                } else {
                    saveData.open(netflowDataFilename1.c_str(), std::ios::binary);
                    infile.open(netflowDataFilename0.c_str(), std::ios::binary | std::ios:: in );
                    if (infile.fail()) {
                        std::cerr << "Cannot open file FILENAME.EXT";
                        exit(1);
                    }

                    infile.seekg(0, infile.end);
                    byteSizeOfFile = infile.tellg();
                    infile.seekg(0, infile.beg);
                    fileChange = true;
                }

                mysql_init( & mysql);
                conn = mysql_real_connect( & mysql, server, user, password, database, 0, 0, 0);
                if (conn == NULL) {
                    std::cout << mysql_error( & mysql) << std::endl << std::endl;
                    return 1;
                }

                for (packet = 0; packet < 100; packet++) {
                    numOfTotalPackets++;

                    // clear all variables
                    verNum = "";
                    numOfEntry = "";
                    sysUpTime = "";
                    unixSecs = "";
                    seqNum = "";
                    sourceID = "";

                    numOfAllEntry = 0;

                    flowSetID = 0;
                    flowSetLength = 0;
                    templateID = 0;
                    templatefFieldCount = 0;

                    numOfTemplateFields = 0;

                    fieldType = "";
                    fieldLength = "";
                    fieldData = "";

                    dataFlowSetID = "";
                    dataFlowSetLength = "";

                    FieldTypeArray.clear();
                    FieldLengthArray.clear();
                    FieldDataArray.clear();

                    packetByteSizeOfData = 0;
                    calcSizeOfPacketData = 0;
                    paddingByteSize = 0;

                    templateIdExist = false;

                    flowSetNumber = 0;

                    flow = 0;

                    mDateTime = "";
                    mProtocol = "";
                    mSourcePort = "";
                    mSourceAddress = "";
                    mDestinationPort = "";
                    mDestinationAddress = "";
                    mTotalBytes = "";
                    netflowEntryToMysqlTable = "";

                    // get packet header information
                    // ************************************************************************************************
                    verNum = parse_single_int_data(2);
                    numOfEntry = parse_single_int_data(2);
                    sysUpTime = parse_single_int_data(4);
                    unixSecs = parse_single_int_data(4);
                    seqNum = parse_single_int_data(4);
                    sourceID = parse_single_int_data(4);

                    numOfAllEntry = boost::lexical_cast < unsigned int > (numOfEntry);
                    for (flow = 0; flow < numOfAllEntry;) {

                        // get Flow Set information
                        // ************************************************************************************************
                        flowSetID = boost::lexical_cast < unsigned int > (parse_single_int_data(2));
                        flowSetLength = boost::lexical_cast < unsigned int > (parse_single_int_data(2));
                        flowEndPosition = infile.tellg() + flowSetLength - 4;

                        // get template information
                        // ************************************************************************************************
                        if (flowSetID == 0) {
                            for (entry = 0; entry < numOfAllEntry; entry++) {
                                flow++;
                                FieldTypeArray.clear();
                                FieldLengthArray.clear();
                                templateIdExist = false;
                                templateID = boost::lexical_cast < unsigned int > (parse_single_int_data(2));
                                for (i = 0; i < templateIDArray.size(); i++) {
                                    if (templateIDArray[i] == templateID) {
                                        templateIdExist = true;
                                        break;
                                    }
                                }
                                templatefFieldCount = boost::lexical_cast < unsigned int > (parse_single_int_data(2));

                                // if in template base we have template with same id we just skip else we add to the and of vector new template
                                if (templateIdExist) {
                                    // for each field we get type and length
                                    infile.seekg(templatefFieldCount * 4, infile.cur);
                                } else {
                                    // get field type and length and save in vectors
                                    for (j = 0; j < templatefFieldCount; j++) {
                                        fieldType = parse_single_int_data(2);
                                        fieldLength = parse_single_int_data(2);
                                        FieldTypeArray.push_back(boost::lexical_cast < unsigned int > (fieldType));
                                        FieldLengthArray.push_back(boost::lexical_cast < unsigned int > (fieldLength));
                                    }

                                    newTemplate.set_templateID(templateID);
                                    newTemplate.set_fieldCount(templatefFieldCount);
                                    newTemplate.set_FieldTypeArray(FieldTypeArray);
                                    newTemplate.set_FieldLengthArray(FieldLengthArray);
                                    templateStorage.push_back(newTemplate);
                                    templateIDArray.push_back(templateID);
                                }
                                if ((infile.tellg() >= flowEndPosition - 2) && (entry < numOfAllEntry)) {
                                    break;
                                }

                            }

                            // get field data
                            // ************************************************************************************************

                        } else if (flowSetID > 0 && flowSetID > 1) {
                            FieldTypeArray.clear();
                            FieldLengthArray.clear();
                            FieldDataArray.clear();
                            for (i = 0; i < templateIDArray.size(); i++) {
                                if (templateIDArray[i] == flowSetID) {
                                    FieldTypeArray = templateStorage[i].get_FieldTypeArray();
                                    FieldLengthArray = templateStorage[i].get_FieldLengthArray();
                                    break;
                                }
                            }

                            for (entry = 0; entry < numOfAllEntry; entry++) {
                                flow++;
                                flowNumber++;

                                // get field data and save in vector
                                for (unsigned int l = 0; l < FieldTypeArray.size(); l++) {
                                    if (FieldTypeArray[l] == 8 || FieldTypeArray[l] == 12 || FieldTypeArray[l] == 15 || FieldTypeArray[l] == 40001 || FieldTypeArray[l] == 40002) {
                                        fieldData = parse_int_data_with_delimiter(FieldLengthArray[l], ".");
                                    } else {
                                        fieldData = parse_single_int_data(FieldLengthArray[l]);
                                    }

                                    FieldDataArray.push_back(fieldData);
                                    calcSizeOfPacketData += FieldLengthArray[l];

                                    switch (FieldTypeArray[l]) {
                                    case 4:
                                        mProtocol = fieldData;
                                        break;
                                    case 7:
                                        mSourcePort = fieldData;
                                        break;
                                    case 8:
                                        mSourceAddress = fieldData;
                                        break;
                                    case 11:
                                        mDestinationPort = fieldData;
                                        break;
                                    case 12:
                                        mDestinationAddress = fieldData;
                                        break;
                                    case 85:
                                        mTotalBytes = fieldData;
                                        break;
                                    default:
                                        break;
                                    }
                                }

                                FieldDataArray.clear();

                                netflowEntryToMysqlTable = "INSERT INTO " + ini_mysql_table + " (DateTime, Protocol, SourcePort, SourceAddress, DestinationPort, DestinationAddress, TotalBytes) "
                                "values (NOW(), '" + mProtocol + "', '" + mSourcePort + "', '" + mSourceAddress + "', '" + mDestinationPort + "', '" + mDestinationAddress + "', '" + mTotalBytes + "')";
                                query_state = mysql_query(conn, netflowEntryToMysqlTable.c_str());

                                mDateTime = "";
                                mProtocol = "";
                                mSourcePort = "";
                                mSourceAddress = "";
                                mDestinationPort = "";
                                mDestinationAddress = "";
                                mTotalBytes = "";

                                // handle padding of packet's data
                                // ************************************************************************************************
                                if ((infile.tellg() >= flowEndPosition - 2) && (entry < numOfAllEntry)) {
                                    flowSetNumber++;

                                    // every block of data start with FlowSet ID and Length
                                    calcSizeOfPacketData += 4;
                                    paddingByteSize = (4 - (calcSizeOfPacketData % 4)) % 4;
                                    infile.seekg(paddingByteSize, infile.cur);
                                    if (infile.tellg() > byteSizeOfFile) break;
                                    flowNumber = 0;
                                    calcSizeOfPacketData = 0;
                                    break;
                                }
                            }
                        }
                    }
                    if ((packet + 1) >= 100) {
                        infile.close();
                    }
                }
            }

        }
    } catch (std::exception & e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
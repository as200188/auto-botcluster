import requests
import json
import os
import time
import pymongo
import datetime
from random import sample
import timeit
import argparse

class BotnetDataGetter:
    def __init__(self):
        self.api_key = "043773ec3264cbaad6e34e718de63598c9c33662a6a51047d6556484cb6184dd"
        self.api_key_index = 0
        self.client = pymongo.MongoClient("mongodb://localhost:27017/")
        self.botnet_db = self.client["botnet_db"]
        self.botnet_db_col = self.botnet_db["ip_info"]

        return
    
    def change_api_key(self):
        api_key_list = ["043773ec3264cbaad6e34e718de63598c9c33662a6a51047d6556484cb6184dd",
        "0299d81dc47dea8fe459649d7d13f5df39d2709b8bb3d54b5fb23503064a5559",
        "39f24d86d38a080845b882740459dbe67c68c1284c40b12c63b4924d2363ac62"]
        self.api_key_index = int((self.api_key_index+1)/len(api_key_list))
        self.api_key = api_key_list[self.api_key_index]
        if self.api_key_index == 0:
            print("Call API has reached upper limit, please wait 600 sec.")
            time.sleep(600)
    
    def get_ip_malicious_from_virustotal(self, ip):
        # IP is string. For example, check_ip_info_from_virustotal("173.189.167.21").
        # Return number of malicious tag.
        url = "https://www.virustotal.com/api/v3/ip_addresses/"+ip
        while(True):
            headers = {"accept": "application/json",
                        "x-apikey": self.api_key
                        }

            response = requests.get(url, headers=headers)
            json_obj = json.loads(response.text)
            try:
                res = json_obj["data"]["attributes"]["last_analysis_stats"]["malicious"]
                json_obj["ip"] = ip
                self.botnet_db_col.insert_one(json_obj)
                return res
            except Exception as e:
                self.change_api_key()
                
        return -1

    def get_ip_malicious_from_db(self, ip):
        ip_info = self.botnet_db_col.find_one({"ip":ip});
        if(ip_info != None):
            #print("ip:{}, has found from db".format(ip))
            return ip_info["data"]["attributes"]["last_analysis_stats"]["malicious"]
        else:
            return -1

    def get_ip_malicious(self, ip):
        # Return number of malicious tag.
        res = self.get_ip_malicious_from_db(ip)
        if(res == -1):
            #print("from virus total")
            res = self.get_ip_malicious_from_virustotal(ip)

        return res

class BotCluster():
    def __init__(self, hadoop_path, botcluster_path):
        self.hadoop_path = hadoop_path
        self.botcluster_path = botcluster_path
    def run(self, netflow_name, tcptime=21000, udptime=22000, flow_loss_ratio=0.225,
            l1Distance=3, l1MinPts=5, srcMinPts=3, dstMinPts=3, srcDistance=1.3,
            dstDistance=4, mapreduce_job=15):
        # netflow_input_file_path = /user/shino/<filename>
        # tcptime, udptime unit are micro second.
        hadoop_path = self.hadoop_path
        botcluster_path = self.botcluster_path
        
        os.system(self.hadoop_path+"bin/hdfs dfs -rm -r /user/hpds")
        # no merge, timestamp and pcapInitialTime is any.
        time_stamp = 115929039790
        pcapInitialTime = "2019-03-01_11:59:29.039"
        
        os.system(hadoop_path+"bin/hadoop jar "+botcluster_path+
        " fbicloud.botrank.MergeLog -D pcapInitialTime="+pcapInitialTime+" -D \
            netflowTime="+str(time_stamp)+" emptyfile "+netflow_name+" /user/hpds/output/merge_out")
        # filter 1
        os.system(hadoop_path+"bin/hadoop jar "+botcluster_path+
        " fbicloud.botrank.FilterPhase1MR -D filterdomain=false -D tcptime="+str(tcptime)+" -D \
            udptime="+str(udptime)+" -D mapreduce.job.reduces="+str(mapreduce_job)+" /user/hpds/output/merge_out \
                /user/hpds/output/filter1_out")

        # filter 2
        os.system(hadoop_path+"bin/hadoop jar "+botcluster_path+
        " fbicloud.botrank.FilterPhase2MR -D flowlossratio="+str(flow_loss_ratio)+" -D \
            mapreduce.job.reduces="+str(mapreduce_job)+" /user/hpds/output/filter1_out \
                /user/hpds/output/filter2_out")

        # group 1
        os.system(hadoop_path+"bin/hadoop jar "+botcluster_path+
        " ncku.hpds.botcluster.Group1MR -D l1Distance="+str(l1Distance)+" -D l1MinPts="+str(l1MinPts)+" \
            /user/hpds/output/filter2_out /user/hpds/output/group1_out")

        # group 23
        os.system(hadoop_path+"bin/hadoop jar "+botcluster_path+
              " ncku.hpds.botcluster.Group23MR -D srcMinPts="+str(srcMinPts)+" -D dstMinPts="+str(dstMinPts)+" -D \
                srcDistance="+str(srcDistance)+" -D dstDistance="+str(dstDistance)+" /user/hpds/output/group1_out \
                    /user/hpds/output/group2_out fvidmapping")
        
        # GetGroupIPs
        os.system(hadoop_path+"bin/hadoop jar "+botcluster_path+
        " fbicloud.botrank.GetGroupIPs -D mapred.reduce.tasks=1 /user/hpds/fvidmapping \
            /user/hpds/output/ip_out")

def find_malicious_ip():
    hadoop_path = "/home/shino/hadoop/hadoop-2.10.1/"
    process = os.popen(hadoop_path+"bin/hdfs dfs -cat /user/hpds/output/ip_out/part-r-00000")
    lines = process.readlines()
    print("Number of suspicious IP:{}".format(len(lines)))
    process.close()

    bdg = BotnetDataGetter()
    whitelist_updater = WhitelistUpdater(whitelist_path="/home/shino/Botnet/input/white")
    num_of_malicious_ip = 0
    for line in lines:
        ip = line.split("\n")[0]
        res = bdg.get_ip_malicious(ip)
        if(res > 0):
            num_of_malicious_ip += 1
            print("IP:{} is malicious.".format(ip))
            print("Number of malicious report:{}".format(res))
        if res == 0:
            whitelist_updater.insert(ip)
    
    whitelist_updater.save_to_file(file_path="/home/shino/Botnet/input/white")
    print("Number of malicious IP:", num_of_malicious_ip)

class WhitelistUpdater:
    def __init__(self, whitelist_path="/home/shino/Botnet/input/white"):
        self.white_set = set()
        with open(whitelist_path, "r") as f:
            lines = f.readlines()
            for line in lines:
                self.white_set.add(line.split("\n")[0])
    def insert(self, ip):
        if not ip in self.white_set:
            self.white_set.add(ip)
    def save_to_file(self, file_path="/home/shino/Botnet/input/new_white"):
        with open(file_path, "w") as f:
            for ip in self.white_set:
                f.write(ip+"\n")


def get_sample_size(total_sample, z = 1.96, p = 0.5, c = 0.034):
    #z = 1.96  value of 95% confidence level
    #p = 0.5 # probility
    #c = 0.034 # error of 3.4% confidence interval

    ss = ((z*z)*p*(1-p))/(c*c) # sample size
    new_ss = ss/(1+((ss-1)/total_sample)) # new sample size
    return (int)(new_ss+0.5)

def get_group():
    hadoop_path = "/home/shino/hadoop/hadoop-2.10.1/"
    process = os.popen(hadoop_path+"bin/hdfs dfs -cat /user/hpds/output/ip_out/part-r-00000")
    lines = process.readlines()
    print("Number of suspicious IP:{}".format(len(lines)))
    process.close()

    process = os.popen(hadoop_path+"bin/hdfs dfs -cat /user/hpds/fvidmapping/fvidIPMapping-0")
    lines = process.readlines()
    process.close()

    check_count = 0
    num_of_ip = 0
    total_ip = 0
    count = 0
    sus_ip_set = set()
    print("Number of group:{}".format(len(lines)))
    for line in lines:
        line_arr = line.split("\t")
        group_id = line_arr[0].split("-")[1]
        ip_arr = line_arr[1].split(",")
        ip_arr.pop() # remove '\n'
        sample_ip_arr = sample(ip_arr, get_sample_size(total_sample=len(ip_arr)))
        for ip in sample_ip_arr:
            if not ip in sus_ip_set:
                sus_ip_set.add(ip)
                count+=1
    print(count)
        #num_of_ip = len(ip_arr)
        #total_ip += num_of_ip
        #check_count += get_sample_size(total_sample=num_of_ip)
    #rint("total ip:{total_ip}, check count:{check_count}".format(total_ip=total_ip,
    #check_count=check_count))
def session_benign_to_dataset(clust_info, session_benign_path, dataset_dir_path):
    print("============ start session_benign_to_dataset =================")
    start = timeit.default_timer()
    feature_names = "Protocol,SrcIP,SrcPort,DstIP,DstPort,SrcToDst_NumOfPkts,"
    feature_names += "SrcToDst_NumOfBytes,SrcToDst_Byte_Max,SrcToDst_Byte_Min,SrcToDst_Byte_Mean,"
    feature_names += "DstToSrc_NumOfPkts,DstToSrc_NumOfBytes,DstToSrc_Byte_Max,DstToSrc_Byte_Min,"
    feature_names += "DstToSrc_Byte_Mean,Total_NumOfPkts,Total_NumOfBytes,Total_Byte_Max,"
    feature_names += "Total_Byte_Min,Total_Byte_Mean,Total_Byte_STD,Total_PktsRate,"
    feature_names += "Total_BytesRate,Total_BytesTransferRatio,Duration,Loss\n"

    rm_ip_set = clust_info.get_remove_ip_set()
    mal_group_list = clust_info.get_malicious_groups()

    benign_file = open(dataset_dir_path+"benign_dataset.csv", "w")
    benign_file.write(feature_names)

    benign_session_count = 0
    malicious_session_count = 0
    remove_session_count = 0

    with open(session_benign_path, "r") as session_file:
        line = session_file.readline()
        while line is not None and line != "":
            has_classification = False
            features = line.split("\t")
            ip_feature = features[2].split(">")
            src_ip = ip_feature[0].split(":")[0]
            src_port = ip_feature[0].split(":")[1]
            dst_ip = ip_feature[1].split(":")[0]
            dst_port = ip_feature[1].split(":")[1]
            write_str = features[1]+","+src_ip+","+src_port+","+dst_ip+","+dst_port
            for i in range(3, 24):
                write_str = write_str+","+features[i]

            for mal_group in mal_group_list:
                if src_ip in mal_group and dst_ip in mal_group:
                    malicious_session_count += 1
                    has_classification = True
                    break

            if not has_classification:
                if src_ip in rm_ip_set or dst_ip in rm_ip_set:
                    remove_session_count += 1
                else:
                    benign_file.write(write_str+"\n")
                    benign_session_count += 1
            line = session_file.readline()

    print("Number of malicious session:{}".format(malicious_session_count))
    print("Number of remove session:{}".format(remove_session_count))
    print("Number of benign session:{}".format(benign_session_count))
    benign_file.close()
    end = timeit.default_timer()
    print("============ end session_benign_to_dataset =================")
    print("Duration:{} sec".format(end-start))
class ClustInfo:
    def __init__(self, hadoop_path):
        process = os.popen(hadoop_path+"bin/hdfs dfs -cat /user/hpds/fvidmapping/fvidIPMapping-0")
        lines = process.readlines()
        process.close()
        print("Number of group:{}".format(len(lines)))
        self.sus_ip_set = set()
        self.rm_ip_set = set()
        self.mal_group_list = []
        bdg = BotnetDataGetter()
        ip_info_search_count = 0
        total_ip_count = 0
        malicious_group_count = 0
        for line in lines:
            cur_sus_ip_set = set()
            line_arr = line.split("\t")
            group_id = line_arr[0].split("-")[1]
            ip_arr = line_arr[1].split(",")
            ip_arr.pop() # remove '\n'
            sample_ip_arr = sample(ip_arr, get_sample_size(total_sample=len(ip_arr)))
            total_ip_count += len(ip_arr)
            ip_info_search_count += len(sample_ip_arr)
            is_malicious_group = False
            for ip in sample_ip_arr:
                res = bdg.get_ip_malicious(ip)
                if res >= 3:
                    is_malicious_group = True
                    malicious_group_count += 1
                    print("Malicious group ID: {}".format(group_id))
                    print("Malicious group size: {}".format(len(ip_arr)))
                    break
            if is_malicious_group:
                for ip in ip_arr:
                    if not ip in self.sus_ip_set:
                        self.sus_ip_set.add(ip)
                    if not ip in cur_sus_ip_set:
                        cur_sus_ip_set.add(ip)
                self.mal_group_list.append(cur_sus_ip_set)
            else:
                for ip in ip_arr:
                    if not ip in self.rm_ip_set:
                        self.rm_ip_set.add(ip)

        print("Number of malicious group:{}".format(malicious_group_count))

        # remove overlapped area
        for ip in self.sus_ip_set:
            if ip in self.rm_ip_set:
                self.rm_ip_set.remove(ip)

        print("Number of remove IP: {}".format(len(self.rm_ip_set)))
        print("Number of suspicious IP: {}".format(len(self.sus_ip_set)))
        print("Number of total IP:{}".format(total_ip_count))
        print("Number of search IP:{}".format(ip_info_search_count))

    def get_malicious_groups(self):
        return self.mal_group_list
    def get_suspicious_ip_set(self):
        return self.sus_ip_set
    def get_remove_ip_set(self):
        return self.rm_ip_set


def sessions_all_to_dataset(clust_info, session_all_path, dataset_dir_path):
    print("============ start sessions_all_to_dataset =================")
    start = timeit.default_timer()

    rm_ip_set = clust_info.get_remove_ip_set()
    mal_group_list = clust_info.get_malicious_groups()

    unknown_session_count = 0
    malicious_session_count = 0
    remove_session_count = 0
    malicious_file = open(dataset_dir_path+"malicious_dataset.csv", "w")
    unknown_file = open(dataset_dir_path+"unknown_dataset.csv", "w")
    remove_file = open(dataset_dir_path+"remove_dataset.csv", "w")
    feature_names = "Protocol,SrcIP,SrcPort,DstIP,DstPort,SrcToDst_NumOfPkts,"
    feature_names += "SrcToDst_NumOfBytes,SrcToDst_Byte_Max,SrcToDst_Byte_Min,SrcToDst_Byte_Mean,"
    feature_names += "DstToSrc_NumOfPkts,DstToSrc_NumOfBytes,DstToSrc_Byte_Max,DstToSrc_Byte_Min,"
    feature_names += "DstToSrc_Byte_Mean,Total_NumOfPkts,Total_NumOfBytes,Total_Byte_Max,"
    feature_names += "Total_Byte_Min,Total_Byte_Mean,Total_Byte_STD,Total_PktsRate,"
    feature_names += "Total_BytesRate,Total_BytesTransferRatio,Duration,Loss\n"
    malicious_file.write(feature_names)
    unknown_file.write(feature_names)
    remove_file.write(feature_names)

    with open(session_all_path, "r") as session_file:
        line = session_file.readline()
        while line is not None and line != "":
            has_classification = False
            features = line.split("\t")
            ip_feature = features[2].split(">")
            src_info = ip_feature[0].split(":")
            dst_info = ip_feature[1].split(":")
            src_ip = src_info[0]
            src_port = src_info[1]
            dst_ip = dst_info[0]
            dst_port = dst_info[1]

            write_str = features[1]+","+src_ip+","+src_port+","+dst_ip+","+dst_port
            for i in range(3, 24):
                write_str = write_str+","+features[i]

            for mal_group in mal_group_list:
                if src_ip in mal_group and dst_ip in mal_group:
                    malicious_file.write(write_str+"\n")
                    malicious_session_count += 1
                    has_classification = True
                    break
            if not has_classification:
                if src_ip in rm_ip_set or dst_ip in rm_ip_set:
                    remove_file.write(write_str+"\n")
                    remove_session_count += 1
                else:
                    unknown_file.write(write_str+"\n")
                    unknown_session_count += 1

            line = session_file.readline()

        print("Number of malicious session:{}".format(malicious_session_count))
        print("Number of remove session:{}".format(remove_session_count))
        print("Number of unknown session:{}".format(unknown_session_count))

    malicious_file.close()
    unknown_file.close()
    remove_file.close()
    end = timeit.default_timer()
    print("============  end sessions_all_to_dataset  =================")
    print("Duration:{} sec".format(end-start))

def merge_part_session_all(hadoop_path, output_file_path):
    # you must to execute run_botcluster()
    print("============ start merge_part_session_all =================")
    start = timeit.default_timer()
    os.system(hadoop_path+"bin/hdfs dfs -getmerge /user/hpds/output/filter1_out/* "+output_file_path)
    end = timeit.default_timer()
    print("============  end merge_part_session_all  =================")
    print("Duration:{} sec".format(end-start))

def merge_part_session_benign(hadoop_path, output_file_path):
    # you must to execute run_botcluster()
    print("============ start merge_part_session_benign =================")
    start = timeit.default_timer()
    os.system(hadoop_path+"bin/hdfs dfs -getmerge /user/hpds/output/filter2_out/* "+output_file_path)
    end = timeit.default_timer()
    print("============  end merge_part_session_benign  =================")
    print("Duration:{} sec".format(end-start))


if __name__ == "__main__":
    
    hadoop_path = None
    api_key = None
    botcluster_path = None
    netflow_name = None
    input_file_path = None
    output_file_path = None
    input_dir_path = None
    output_dir_path = None

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="show current version", action="store_true")
    parser.add_argument("-hp", "--hadoop_path", help="must to enter hadoop path")
    parser.add_argument("-bp", "--botcluster_path", help="must to enter botcluster path")
    parser.add_argument("-nf", "--netflow_name", help="must to enter netflow filename")
    parser.add_argument("-k", "--api_key", help="must to enter api key")
    parser.add_argument("-run", "--run_botcluster", help="exec botcluster", action="store_true")
    parser.add_argument("-i", "--input_file", help="input filename")
    parser.add_argument("-id", "--input_dir", help="input dir")
    parser.add_argument("-o", "--output_file", help="output filename")
    parser.add_argument("-od", "--output_dir", help="output dir")
    parser.add_argument("-stod", "--session_to_dataset", help="output session to dataset", action="store_true")
    parser.add_argument("-run_all", "--run_all", help="exec botcluster and get dataset", action="store_true")
    args = parser.parse_args()
    if args.verbose:
        print("version: 1.0")
    if args.hadoop_path:
        hadoop_path = args.hadoop_path
    if args.api_key:
        api_key = args.api_key
    if args.botcluster_path:
        botcluster_path = args.botcluster_path
    if args.netflow_name:
        netflow_name = args.netflow_name
    if args.output_dir:
        output_dir_path = args.output_dir

    if args.run_all:
        if hadoop_path and botcluster_path and netflow_name and output_dir_path:
            botcluster = BotCluster(hadoop_path=hadoop_path, botcluster_path=botcluster_path)
            botcluster.run(netflow_name=netflow_name)
            merge_part_session_all(hadoop_path=hadoop_path,
                                    output_file_path=output_dir_path+"session_all")
            merge_part_session_benign(hadoop_path=hadoop_path,
                                    output_file_path=output_dir_path+"session_benign")
            clust_info = ClustInfo(hadoop_path=hadoop_path)
            sessions_all_to_dataset(clust_info=clust_info,
                            session_all_path=output_dir_path+"session_all",
                            dataset_dir_path=output_dir_path)
            session_benign_to_dataset(clust_info=clust_info,
                            session_benign_path=output_dir_path+"session_benign",
                            dataset_dir_path=output_dir_path)
        else:
            print("use -hp -bp -nf to enter path and filename or use -h to get help.")

    if args.run_botcluster:
        if hadoop_path and botcluster_path and netflow_name:
            botcluster = BotCluster(hadoop_path=hadoop_path, botcluster_path=botcluster_path)
            botcluster.run(netflow_name=netflow_name)
        else:
            print("use -hp -bp -nf -od to enter path and filename or use -h to get help.")


    if args.session_to_dataset:
        if hadoop_path and output_dir_path:
            merge_part_session_all(hadoop_path=hadoop_path,
                                    output_file_path=output_dir_path+"session_all")
            merge_part_session_benign(hadoop_path=hadoop_path,
                                    output_file_path=output_dir_path+"session_benign")

            clust_info = ClustInfo(hadoop_path=hadoop_path)

            sessions_all_to_dataset(clust_info=clust_info,
                            session_all_path=output_dir_path+"session_all",
                            dataset_dir_path=output_dir_path)

            session_benign_to_dataset(clust_info=clust_info,
                            session_benign_path=output_dir_path+"session_benign",
                            dataset_dir_path=output_dir_path)
        else:
            print("use -hp -od to enter path and filename or use -h to get help.")


    print("Done.")

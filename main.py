import requests
import json
import os
import time
import pymongo
import datetime
from random import sample
import timeit
import argparse

class Tester:
    def __init__(self, mongo_ip):
        self.mongo_ip = mongo_ip
        return
    def test(self):
        self.testMongodbConnection()
    def testMongodbConnection(self):
        try:
            self.client = pymongo.MongoClient("mongodb://"+self.mongo_ip+":27017/")
            print("MongoDB:{}:27017, connection success!".format(self.mongo_ip))
        except pymongo.errors.ServerSelectionTimeoutError as err:
            print(err)


class BotnetDataGetter:
    def __init__(self, mongo_ip):
        self.api_key = "043773ec3264cbaad6e34e718de63598c9c33662a6a51047d6556484cb6184dd"
        self.api_key_index = 0
        self.mongo_ip = mongo_ip
        self.client = pymongo.MongoClient("mongodb://"+self.mongo_ip+":27017/")
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
        
        os.system(self.hadoop_path+"/bin/hdfs dfs -rm -r /user/hpds/*")

        # no merge, timestamp and pcapInitialTime is any.
        time_stamp = 115929039790
        pcapInitialTime = "2019-03-01_11:59:29.039"
        
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " fbicloud.botrank.MergeLog -D pcapInitialTime="+pcapInitialTime+" -D \
            netflowTime="+str(time_stamp)+" emptyfile "+netflow_name+" /user/hpds/output/merge_out")
        # filter 1
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " fbicloud.botrank.FilterPhase1MR -D filterdomain=false -D tcptime="+str(tcptime)+" -D \
            udptime="+str(udptime)+" -D mapreduce.job.reduces="+str(mapreduce_job)+" /user/hpds/output/merge_out \
                /user/hpds/output/filter1_out")

        # filter 2
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " fbicloud.botrank.FilterPhase2MR -D flowlossratio="+str(flow_loss_ratio)+" -D \
            mapreduce.job.reduces="+str(mapreduce_job)+" /user/hpds/output/filter1_out \
                /user/hpds/output/filter2_out")

        # group 1
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " ncku.hpds.botcluster.Group1MR -D l1Distance="+str(l1Distance)+" -D l1MinPts="+str(l1MinPts)+" \
            /user/hpds/output/filter2_out /user/hpds/output/group1_out")

        # group 23
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
              " ncku.hpds.botcluster.Group23MR -D srcMinPts="+str(srcMinPts)+" -D dstMinPts="+str(dstMinPts)+" -D \
                srcDistance="+str(srcDistance)+" -D dstDistance="+str(dstDistance)+" /user/hpds/output/group1_out \
                    /user/hpds/output/group2_out fvidmapping")
        
        # GetGroupIPs
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " fbicloud.botrank.GetGroupIPs -D mapred.reduce.tasks=1 /user/hpds/fvidmapping \
            /user/hpds/output/ip_out")

class ClustInfo:
    def __init__(self, hadoop_path, mongo_ip):
        process = os.popen(hadoop_path+"/bin/hdfs dfs -cat /user/hpds/fvidmapping/fvidIPMapping-0")
        lines = process.readlines()
        process.close()
        print("Number of group:{}".format(len(lines)))
        self.sus_ip_set = set()
        self.rm_ip_set = set()
        self.mal_group_list = []
        bdg = BotnetDataGetter(mongo_ip=mongo_ip)
        ip_info_search_count = 0
        total_ip_count = 0
        malicious_group_count = 0
        for line in lines:
            cur_sus_ip_set = set()
            line_arr = line.split("\t")
            group_id = line_arr[0].split("-")[1]
            ip_arr = line_arr[1].split(",")
            ip_arr.pop() # remove '\n'
            sample_ip_arr = sample(ip_arr, self.get_sample_size(total_sample=len(ip_arr)))
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
    def get_sample_size(self, total_sample, z = 1.96, p = 0.5, c = 0.034):
        #z = 1.96  value of 95% confidence level
        #p = 0.5 # probility
        #c = 0.034 # error of 3.4% confidence interval

        ss = ((z*z)*p*(1-p))/(c*c) # sample size
        new_ss = ss/(1+((ss-1)/total_sample)) # new sample size
        return (int)(new_ss+0.5)

def benign_session_to_dataset(clust_info, output_dir_path):
    benign_session_path=output_dir_path+"/session_benign" 
    benign_dataset_path=output_dir_path+"/benign_dataset.csv"


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

    benign_file = open(benign_dataset_path, "w")
    benign_file.write(feature_names)

    benign_session_count = 0
    malicious_session_count = 0
    remove_session_count = 0

    with open(benign_session_path, "r") as session_file:
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

def all_sessions_to_dataset(clust_info, output_dir_path):
    all_session_path=output_dir_path+"/session_all" 


    print("============ start sessions_all_to_dataset =================")
    start = timeit.default_timer()

    rm_ip_set = clust_info.get_remove_ip_set()
    mal_group_list = clust_info.get_malicious_groups()

    unknown_session_count = 0
    malicious_session_count = 0
    remove_session_count = 0
    malicious_file = open(output_dir_path+"/malicious_dataset.csv", "w")
    unknown_file = open(output_dir_path+"/unknown_dataset.csv", "w")
    remove_file = open(output_dir_path+"/remove_dataset.csv", "w")
    feature_names = "Protocol,SrcIP,SrcPort,DstIP,DstPort,SrcToDst_NumOfPkts,"
    feature_names += "SrcToDst_NumOfBytes,SrcToDst_Byte_Max,SrcToDst_Byte_Min,SrcToDst_Byte_Mean,"
    feature_names += "DstToSrc_NumOfPkts,DstToSrc_NumOfBytes,DstToSrc_Byte_Max,DstToSrc_Byte_Min,"
    feature_names += "DstToSrc_Byte_Mean,Total_NumOfPkts,Total_NumOfBytes,Total_Byte_Max,"
    feature_names += "Total_Byte_Min,Total_Byte_Mean,Total_Byte_STD,Total_PktsRate,"
    feature_names += "Total_BytesRate,Total_BytesTransferRatio,Duration,Loss\n"
    malicious_file.write(feature_names)
    unknown_file.write(feature_names)
    remove_file.write(feature_names)

    with open(all_session_path, "r") as session_file:
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
    os.system(hadoop_path+"/bin/hdfs dfs -getmerge /user/hpds/output/filter1_out/* "+output_file_path)
    end = timeit.default_timer()
    print("============  end merge_part_session_all  =================")
    print("Duration:{} sec".format(end-start))

def merge_part_session_benign(hadoop_path, output_file_path):
    # you must to execute run_botcluster()
    print("============ start merge_part_session_benign =================")
    start = timeit.default_timer()
    os.system(hadoop_path+"/bin/hdfs dfs -getmerge /user/hpds/output/filter2_out/* "+output_file_path)
    end = timeit.default_timer()
    print("============  end merge_part_session_benign  =================")
    print("Duration:{} sec".format(end-start))


if __name__ == "__main__":
    #exampe:
    #hadoop_path=/hadoop/hadoop-2.10.1
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="show current version", action="store_true")
    parser.add_argument("-hp", "--hadoop_path", help="must to enter hadoop path")
    parser.add_argument("-bp", "--botcluster_path", help="must to enter botcluster path")
    parser.add_argument("-nf", "--netflow_name", help="must to enter netflow filename")
    parser.add_argument("-k", "--api_key", help="must to enter api key")
    parser.add_argument("-run", "--run_botcluster", help="exec botcluster", action="store_true")
    parser.add_argument("-od", "--output_dir_path", help="output dir")
    parser.add_argument("-stod", "--session_to_dataset", help="output session to dataset", action="store_true")
    parser.add_argument("-run_all", "--run_all", help="exec botcluster and get dataset", action="store_true")
    parser.add_argument("--test", help="test auto botcluster", action="store_true")
    parser.add_argument("--mongo_ip", help="must to enter mongodb ip address")
    args = parser.parse_args()

    if args.test:
        if args.mongo_ip == None:
            print("Error: Need to use --mongo_ip")
        else:
            tester = Tester(mongo_ip=args.mongo_ip)
            tester.test()
    if args.verbose:
        print("version: 1.1")

    if args.run_all:
        if args.hadoop_path and args.botcluster_path and args.netflow_name and args.output_dir_path and args.mongo_ip:
            botcluster = BotCluster(hadoop_path=args.hadoop_path, botcluster_path=args.botcluster_path)
            botcluster.run(netflow_name=args.netflow_name)
            merge_part_session_all(hadoop_path=args.hadoop_path,
                                    output_file_path=args.output_dir_path+"/session_all")
            merge_part_session_benign(hadoop_path=args.hadoop_path,
                                    output_file_path=args.output_dir_path+"/session_benign")
            clust_info = ClustInfo(hadoop_path=args.hadoop_path, mongo_ip=args.mongo_ip)
            all_sessions_to_dataset(clust_info=clust_info, output_dir_path=args.output_dir_path)
            benign_session_to_dataset(clust_info=clust_info, output_dir_path=args.output_dir_path)
        else:
            print("use -hp -bp -nf to enter path and filename or use -h to get help.")

    if args.run_botcluster:
        if args.hadoop_path and args.botcluster_path and args.netflow_name:
            botcluster = BotCluster(hadoop_path=args.hadoop_path, botcluster_path=args.botcluster_path)
            botcluster.run(netflow_name=args.netflow_name)
        else:
            print("use -hp -bp -nf -od to enter path and filename or use -h to get help.")


    if args.session_to_dataset:
        if args.hadoop_path and args.output_dir_path and args.mongo_ip:
            merge_part_session_all(hadoop_path=args.hadoop_path,
                                    output_file_path=args.output_dir_path+"/session_all")
            merge_part_session_benign(hadoop_path=args.hadoop_path,
                                    output_file_path=args.output_dir_path+"/session_benign")
            clust_info = ClustInfo(hadoop_path=args.hadoop_path, mongo_ip=args.mongo_ip)
            all_sessions_to_dataset(clust_info=clust_info, output_dir_path=args.output_dir_path)
            benign_session_to_dataset(clust_info=clust_info, output_dir_path=args.output_dir_path)
        else:
            print("use -hp -od --mongo_ip to enter path and filename or use -h to get help.")


    print("Exec done.")

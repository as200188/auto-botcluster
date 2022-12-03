import requests
import json
import os
import time
import pymongo
import datetime
from random import sample
import timeit
import argparse
import pandas as pd

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
    def __init__(self):
        self.api_key = None
        self.api_key_list = []
        self.api_key_index = 0
        self.set_api_keys()
        self.mongo_ip = None
        self.set_mongo_ip()
        self.client = pymongo.MongoClient("mongodb://"+self.mongo_ip+":27017/")
        self.botnet_db = self.client["botnet_db"]
        self.botnet_db_col = self.botnet_db["ip_info"]
        self.custom_ip_info_path = None
        self.ip_info_dict = None
        self.set_custom_ip_info()
    def set_custom_ip_info(self):
        self.custom_ip_info_path = os.getenv("CUSTOM_IP_INFO_PATH")
        if self.custom_ip_info_path == None:
            raise Execption("Error, CUSTOM_IP_INFO_PATH is None.")
        df = pd.read_csv(self.custom_ip_info_path)
        self.ip_info_dict = df.set_index("IP").T.to_dict()
    def set_mongo_ip(self):
        self.mongo_ip = os.getenv("MONGO_IP")
        if self.mongo_ip == None:
            raise Execption("Error, MONGO_IP is None.")
    def set_api_keys(self):
        self.api_key_list = os.getenv("API_KEYS").split(",")
        if self.api_key_list == None:
            raise Execption("Error, API_KEYS is None.")
    def change_api_key(self):
        self.api_key_index = int((self.api_key_index+1)%len(self.api_key_list))
        self.api_key = self.api_key_list[self.api_key_index]
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
 
    def get_ip_malicious_from_dict(self, ip):
        try:
            return self.ip_info_dict[ip]["Malicious Report"]
        except Exception as e:
            return -1

    def get_ip_malicious(self, ip):
        # Return number of malicious tag.
        res = self.get_ip_malicious_from_dict(ip)
        if(res == -1):
            res = self.get_ip_malicious_from_db(ip)
        if(res == -1):
            #print("from virus total")
            res = self.get_ip_malicious_from_virustotal(ip)

        return res

class BotCluster():
    def __init__(self):
        self.hadoop_path = None
        self.set_hadoop_path()
        self.botcluster_path = None
        self.set_botcluster_path()
        self.datahome = None
        self.set_datahome()
        
    def set_datahome(self):
        self.datahome = os.getenv("DATA_HOME")
        if self.datahome == None:
            raise Execption("Error, DATA_HOME is None.")
    def set_hadoop_path(self):
        self.hadoop_path = os.getenv("HADOOP_HOME")
        if self.hadoop_path == None:
            raise Execption("Error, HADOOP_HOME is None.")
    def set_botcluster_path(self):
        botcluster2_home = os.getenv("BOTCLUSTER2_HOME")
        if botcluster2_home == None:
            raise Execption("Error, BOTCLUSTER2_HOME is None.")
        self.botcluster_path = botcluster2_home+"/target/BotCluster2-1.1.jar"

    def run(self, netflow_name, tcptime=21000, udptime=22000, flow_loss_ratio=0.225,
            l1Distance=3, l1MinPts=5, srcMinPts=3, dstMinPts=3, srcDistance=1.3,
            dstDistance=4, mapreduce_job=15):
        # netflow_input_file_path = /user/shino/<filename>
        # tcptime, udptime unit are micro second.
        
        os.system(self.hadoop_path+"/bin/hdfs dfs -rm -r /user/hpds/*")

        # no merge, timestamp and pcapInitialTime is any.
        time_stamp = 115929039790
        pcapInitialTime = "2019-03-01_11:59:29.039"
        start = timeit.default_timer()
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
        
        # Download file to datahome/output from hdfs
        os.system(self.hadoop_path+"/bin/hdfs dfs -get /user/hpds/output/ip_out/part-r-00000 "+self.datahome+"/output/botcluster_malicious_ip")
        
        end = timeit.default_timer()
        print("Botcluster Duration:{:.1f} sec".format(end-start))

class ClustInfo:
    def __init__(self):
        self.hadoop_path = None
        self.set_hadoop_path()
        
    def set_hadoop_path(self):
        self.hadoop_path = os.getenv("HADOOP_HOME")
        if self.hadoop_path == None:
            raise Execption("Error, HADOOP_HOME is None.")
        
    def run(self):
        process = os.popen(self.hadoop_path+"/bin/hdfs dfs -cat /user/hpds/fvidmapping/fvidIPMapping-0")
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
    print("Duration:{:.1f} sec".format(end-start))

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
    print("Duration:{:.1f} sec".format(end-start))

def merge_part_session_all(hadoop_path, output_file_path):
    # you must to execute run_botcluster()
    print("============ start merge_part_session_all =================")
    start = timeit.default_timer()
    os.system(hadoop_path+"/bin/hdfs dfs -getmerge /user/hpds/output/filter1_out/* "+output_file_path)
    end = timeit.default_timer()
    print("============  end merge_part_session_all  =================")
    print("Duration:{:.1f} sec".format(end-start))

def merge_part_session_benign(hadoop_path, output_file_path):
    # you must to execute run_botcluster()
    print("============ start merge_part_session_benign =================")
    start = timeit.default_timer()
    os.system(hadoop_path+"/bin/hdfs dfs -getmerge /user/hpds/output/filter2_out/* "+output_file_path)
    end = timeit.default_timer()
    print("============  end merge_part_session_benign  =================")
    print("Duration:{:.1f} sec".format(end-start))
def save_auto_botcluster_resault_to_file(clust_info):
    datahome = os.getenv("DATA_HOME")
    if datahome == None:
        raise Execption("Error, DATA_HOME is None.")
    mal_group_list = clust_info.get_malicious_groups()
    ip_set = set()
    
    for mal_group in mal_group_list:
        for ip in mal_group:
            if ip not in ip_set:
                ip_set.add(ip)
    with open(datahome+"/output/auto_botcluster_malicious_ip", "w") as file:
        for ip in ip_set:
            file.write(ip+"\n")
        

if __name__ == "__main__":
    #exampe:
    #hadoop_path=/hadoop/hadoop-2.10.1
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="show current version", action="store_true")
    parser.add_argument("-nf", "--netflow_name", help="must to enter netflow filename")
    parser.add_argument("-run", "--run_botcluster", help="exec botcluster", action="store_true")
    parser.add_argument("-od", "--output_dir_path", help="output dir")
    parser.add_argument("-stod", "--session_to_dataset", help="output session to dataset", action="store_true")
    parser.add_argument("-run_all", "--run_all", help="exec botcluster and get dataset", action="store_true")
    parser.add_argument("--test", help="test auto botcluster", action="store_true")
    args = parser.parse_args()

    if args.test:
            tester = Tester(mongo_ip=os.getenv("MONGO_IP"))
            tester.test()
    if args.verbose:
        print("version: 1.6.4")

    if args.run_all:
        if args.netflow_name and args.output_dir_path:
            botcluster = BotCluster()
            botcluster.run(netflow_name=args.netflow_name)
            merge_part_session_all(hadoop_path=os.getenv("HADOOP_HOME"),
                                    output_file_path=args.output_dir_path+"/session_all")
            merge_part_session_benign(hadoop_path=os.getenv("HADOOP_HOME"),
                                    output_file_path=args.output_dir_path+"/session_benign")
            clust_info = ClustInfo()
            clust_info.run()
            all_sessions_to_dataset(clust_info=clust_info, output_dir_path=args.output_dir_path)
            benign_session_to_dataset(clust_info=clust_info, output_dir_path=args.output_dir_path)
            save_auto_botcluster_resault_to_file(clust_info=clust_info)
        else:
            print("use -nf -od to enter path and filename or use -h to get help.")

    if args.run_botcluster:
        if args.netflow_name:
            botcluster = BotCluster()
            botcluster.run(netflow_name=args.netflow_name)
        else:
            print("use -nf or use -h to get help.")


    if args.session_to_dataset:
        if args.output_dir_path:
            merge_part_session_all(hadoop_path=os.getenv("HADOOP_HOME"),
                                    output_file_path=args.output_dir_path+"/session_all")
            merge_part_session_benign(hadoop_path=os.getenv("HADOOP_HOME"),
                                    output_file_path=args.output_dir_path+"/session_benign")
            clust_info = ClustInfo()
            clust_info.run()
            all_sessions_to_dataset(clust_info=clust_info, output_dir_path=args.output_dir_path)
            benign_session_to_dataset(clust_info=clust_info, output_dir_path=args.output_dir_path)
        else:
            print("use -od to enter path and filename or use -h to get help.")


    print("Exec done.")

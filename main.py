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
from sklearn.cluster import DBSCAN
class Tester:
    def __init__(self, mongo_ip):
        self.mongo_ip = mongo_ip
        return
    def test(self):
        bdg =  BotnetDataGetter()
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
        self.mongo_ip = None
        self.set_mongo_ip()
        self.client = pymongo.MongoClient("mongodb://"+self.mongo_ip+":27017/")
        self.botnet_db = self.client["botnet_db"]
        self.botnet_db_col = self.botnet_db["ip_info"]
        self.botnet_db_api_keys = self.botnet_db["api_kyes"]
        self.set_api_key_list_from_db()
        self.custom_ip_info_path = None
        self.ip_info_dict = None
        self.set_custom_ip_info()
        self.database_search_count = 0
        self.api_search_count = 0
        self.dict_search_count = 0
    def insert_api_key_to_db(self, api_key):
        data = {"key":api_key}
        self.botnet_db_api_keys.insert_one(data)
    def set_api_key_list_from_db(self):
        cursor = self.botnet_db_api_keys.find({})
        for data in cursor:
            self.api_key_list.append(data["key"])
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
            print("Database search count: {}".format(self.database_search_count))
            print("API search count: {}".format(self.api_search_count))
            print("Call API has reached upper limit, please wait 3600 sec.")
            time.sleep(3600)
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
            self.api_search_count += 1
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
            self.database_search_count += 1
            return ip_info["data"]["attributes"]["last_analysis_stats"]["malicious"]
        else:
            return -1

    def get_ip_malicious_from_dict(self, ip):
        try:
            self.dict_search_count += 1
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

    def get_dict_search_count(self):
        return self.dict_search_count
    def get_database_search_count(self):
        return self.database_search_count
    def get_api_search_count(self):
        return self.api_search_count

class BotCluster():
    def __init__(self):
        self.set_hadoop_path()
        self.set_botcluster_path()
        self.set_datahome()
        self.set_botcluster_conf()

    def set_botcluster_conf(self):
        conf = None
        with open(self.datahome+"/input/auto_botcluster.conf", "r") as file:
            conf = json.load(file)
        self.tcptime=conf["session"]["tcptime"]
        self.udptime=conf["session"]["udptime"]
        self.flow_loss_ratio=conf["session"]["flow_loss_ratio"]
        self.l1Distance=conf["group1"]["l1Distance"]
        self.l1MinPts=conf["group1"]["l1MinPts"]
        self.srcMinPts=conf["group23"]["srcMinPts"]
        self.dstMinPts=conf["group23"]["dstMinPts"]
        self.srcDistance=conf["group23"]["srcDistance"]
        self.dstDistance=conf["group23"]["dstDistance"]
        self.mapreduce_job=conf["hadoop"]["mapreduce_job"]
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

    def run(self, netflow_name):
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
        # filter 1, Netflows to sessions.
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " fbicloud.botrank.FilterPhase1MR -D filterdomain=false -D tcptime="+str(self.tcptime)+" -D \
            udptime="+str(self.udptime)+" -D mapreduce.job.reduces="+str(self.mapreduce_job)+" /user/hpds/output/merge_out \
                /user/hpds/output/filter1_out")
        # Download All Sessions
        os.system(self.hadoop_path+"/bin/hdfs dfs -getmerge /user/hpds/output/filter1_out/* "+self.datahome+"/output/All_Sessions.txt")
        # filter 2
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " fbicloud.botrank.FilterPhase2MR -D flowlossratio="+str(self.flow_loss_ratio)+" -D \
            mapreduce.job.reduces="+str(self.mapreduce_job)+" /user/hpds/output/filter1_out \
                /user/hpds/output/filter2_out")
        # Download FLR_IPs
        os.system(self.hadoop_path+"/bin/hdfs dfs -getmerge /user/hpds/output/filter2_out_job2_FLR/LowFLR/* "+self.datahome+"/output/Low_FLR_IPs.txt")
        os.system(self.hadoop_path+"/bin/hdfs dfs -getmerge /user/hpds/output/filter2_out_job2_FLR/HighFLR/* "+self.datahome+"/output/High_FLR_IPs.txt")

        # group 1
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " ncku.hpds.botcluster.Group1MR -D l1Distance="+str(self.l1Distance)+" -D l1MinPts="+str(self.l1MinPts)+" \
            /user/hpds/output/filter2_out /user/hpds/output/group1_out")

        # group 23
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
              " ncku.hpds.botcluster.Group23MR -D srcMinPts="+str(self.srcMinPts)+" -D dstMinPts="+str(self.dstMinPts)+" -D \
                srcDistance="+str(self.srcDistance)+" -D dstDistance="+str(self.dstDistance)+" /user/hpds/output/group1_out \
                    /user/hpds/output/group2_out fvidmapping")
        # GetGroupIPs
        os.system(self.hadoop_path+"/bin/hadoop jar "+self.botcluster_path+
        " fbicloud.botrank.GetGroupIPs -D mapred.reduce.tasks=1 /user/hpds/fvidmapping \
            /user/hpds/output/ip_out")
        # Download file to datahome/output from hdfs
        os.system(self.hadoop_path+"/bin/hdfs dfs -get -f /user/hpds/output/ip_out/part-r-00000 "+self.datahome+"/output/botcluster_malicious_ip.txt")
        end = timeit.default_timer()
        print("Botcluster Duration:{:.1f} sec".format(end-start))

class Auto_BotCluster:
    def __init__(self):
        self.hadoop_path = None
        self.set_hadoop_path()
        self.sample_size = None
        self.malicious_report_threshold = None
        self.eps = None
        self.min_samples = None
        self.algorithm = None
        self.leaf_size = None
        self.set_conf()
        self.mal_ip_set = set()
        self.rm_ip_set = set()
        self.mal_group_list = []
        self.bdg = BotnetDataGetter()
        self.set_mal_ip_set_and_rm_ip_set_and_mal_group_list()
        self.high_flr_ip_set = set()
        self.set_high_flr_ip_set()
        self.feature_names = None
# ================         process malicious and benign session         ===============
    def run(self):
        self.output_all_session_to_all_dataset()
        self.output_all_dataset_to_high_and_low_flr_dataset()
        self.output_malicious_dataset()
        self.output_benign_dataset()
        self.output_malicious_dataset_cleaned()
    def output_malicious_dataset_cleaned(self):
        print("============== Clean Malicious Dataset ===================")
        chunk_size = self.sample_size
        loop_done = False
        reader = pd.read_csv("data/output/malicious_dataset.csv", chunksize=chunk_size)
        malicious_session_cleaned_file = open("data/output/malicious_dataset_cleaned.csv", "w")
        malicious_session_cleaned_file.write(self.feature_names)
        feature_names = ["Protocol", "SrcIP", "SrcPort", "DstIP", "DstPort", "SrcToDst_NumOfPkts", "SrcToDst_NumOfBytes", "SrcToDst_Byte_Max",
                "SrcToDst_Byte_Min", "SrcToDst_Byte_Mean", "DstToSrc_NumOfPkts", "DstToSrc_NumOfBytes", "DstToSrc_Byte_Max",
                "DstToSrc_Byte_Min", "DstToSrc_Byte_Mean", "Total_NumOfPkts", "Total_NumOfBytes", "Total_Byte_Max",
                "Total_Byte_Min", "Total_Byte_Mean", "Total_Byte_STD", "Total_PktsRate", "Total_BytesRate",
                "Total_BytesTransferRatio", "Duration", "Loss"]
        sel_feature_names = ["Protocol", "SrcPort", "DstPort", "SrcToDst_NumOfPkts", "SrcToDst_NumOfBytes", "SrcToDst_Byte_Max",
                "SrcToDst_Byte_Min", "SrcToDst_Byte_Mean", "DstToSrc_NumOfPkts", "DstToSrc_NumOfBytes", "DstToSrc_Byte_Max",
                "DstToSrc_Byte_Min", "DstToSrc_Byte_Mean", "Total_NumOfPkts", "Total_NumOfBytes", "Total_Byte_Max",
                "Total_Byte_Min", "Total_Byte_Mean", "Total_Byte_STD", "Total_PktsRate", "Total_BytesRate",
                "Total_BytesTransferRatio", "Duration", "Loss"]

        while(not loop_done):
            all_session = pd.DataFrame(reader.get_chunk(), columns=feature_names)
            all_session_processed = all_session[sel_feature_names]
            subset_sessions = pd.DataFrame(all_session_processed, columns=all_session_processed.columns)
            try:
                db = DBSCAN(eps=self.eps, min_samples=self.min_samples, algorithm=self.algorithm, leaf_size=self.leaf_size, n_jobs=-1).fit(subset_sessions.values)

                if len(all_session_processed) < chunk_size:
                    loop_done = True

                labels = db.labels_
                n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
                n_noise = list(labels).count(-1)
                print("Number of clusters:{}".format(n_clusters))
                print("Number of noise:{}".format(n_noise))
                subset_sessions.insert(1, "SrcIP", all_session.loc[subset_sessions.index, "SrcIP"])
                subset_sessions.insert(3, "DstIP", all_session.loc[subset_sessions.index, "DstIP"])
                subset_sessions.insert(len(subset_sessions.columns), "Label", labels)
                subset_sessions_rm_noise = subset_sessions[subset_sessions.Label != -1]
                subset_sessions_sorted = subset_sessions_rm_noise.sort_values(by=["Label"])
                for session in subset_sessions_sorted.values:
                    write_str = ""
                    src_ip = session[1]
                    dst_ip = session[3]
                    write_str = str(session[0])
                    for i in range(1, len(session)-1):
                        write_str = write_str+","+str(session[i])
                    malicious_session_cleaned_file.write(write_str+"\n")
            except:
               break
        malicious_session_cleaned_file.close()
    def output_benign_dataset(self):
        chunk_size = 10000
        reader = pd.read_csv("data/output/low_flr_session_dataset.csv", chunksize=chunk_size)
        loop_done = False
        benign_session_file = open("data/output/benign_dataset.csv", "w")
        benign_session_file.write(self.feature_names)

        while(not loop_done):
            all_session = pd.DataFrame(reader.get_chunk())
            if len(all_session) < chunk_size:
                loop_done = True
            for session in all_session.values:
                write_str = ""
                src_ip = session[1]
                dst_ip = session[3]
                write_str = str(session[0])
                for i in range(1, len(session)):
                    write_str = write_str+","+str(session[i])
                if src_ip not in self.mal_ip_set and dst_ip not in self.mal_ip_set:
                    if src_ip not in self.rm_ip_set and dst_ip not in self.rm_ip_set:
                        benign_session_file.write(write_str+"\n")
        benign_session_file.close()
    def output_malicious_dataset(self):
        chunk_size = 10000
        reader = pd.read_csv("data/output/high_flr_session_dataset.csv", chunksize=chunk_size)
        loop_done = False
        malicious_session_file = open("data/output/malicious_dataset.csv", "w")
        malicious_session_file.write(self.feature_names)

        while(not loop_done):
            all_session = pd.DataFrame(reader.get_chunk())
            if len(all_session) < chunk_size:
                loop_done = True
            for session in all_session.values:
                write_str = ""
                src_ip = session[1]
                dst_ip = session[3]
                write_str = str(session[0])
                for i in range(1, len(session)):
                    write_str = write_str+","+str(session[i])
                for mal_group in self.mal_group_list:
                    if len(mal_group) == 1:
                       if src_ip in mal_group or dst_ip in mal_group:
                           malicious_session_file.write(write_str+"\n")
                           break
                    elif src_ip in mal_group and dst_ip in mal_group:
                        malicious_session_file.write(write_str+"\n")
                        break
        malicious_session_file.close()
    def output_all_session_to_all_dataset(self):
        self.feature_names = "Protocol,SrcIP,SrcPort,DstIP,DstPort,SrcToDst_NumOfPkts,"
        self.feature_names += "SrcToDst_NumOfBytes,SrcToDst_Byte_Max,SrcToDst_Byte_Min,SrcToDst_Byte_Mean,"
        self.feature_names += "DstToSrc_NumOfPkts,DstToSrc_NumOfBytes,DstToSrc_Byte_Max,DstToSrc_Byte_Min,"
        self.feature_names += "DstToSrc_Byte_Mean,Total_NumOfPkts,Total_NumOfBytes,Total_Byte_Max,"
        self.feature_names += "Total_Byte_Min,Total_Byte_Mean,Total_Byte_STD,Total_PktsRate,"
        self.feature_names += "Total_BytesRate,Total_BytesTransferRatio,Duration,Loss\n"
        all_session_file = open("data/output/all_session_dataset.csv", "w")
        all_session_file.write(self.feature_names)
        with open("data/output/All_Sessions.txt", "r") as session_file:
            line = session_file.readline()
            while line is not None and line != "":
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

                all_session_file.write(write_str+"\n")
                line = session_file.readline()
        all_session_file.close()
    def output_all_dataset_to_high_and_low_flr_dataset(self):
        chunk_size = 10000
        reader = pd.read_csv("data/output/all_session_dataset.csv", chunksize=chunk_size)
        loop_done = False
        high_flr_session_file = open("data/output/high_flr_session_dataset.csv", "w")
        high_flr_session_file.write(self.feature_names)
        low_flr_session_file = open("data/output/low_flr_session_dataset.csv", "w")
        low_flr_session_file.write(self.feature_names)
        while(not loop_done):
            all_session = pd.DataFrame(reader.get_chunk())
            if len(all_session) < chunk_size:
                loop_done = True
            for session in all_session.values:
                write_str = ""
                src_ip = session[1]
                dst_ip = session[3]
                write_str = str(session[0])
                for i in range(1, len(session)):
                    write_str = write_str+","+str(session[i])
                if src_ip in self.high_flr_ip_set or dst_ip in self.high_flr_ip_set:
                    high_flr_session_file.write(write_str+"\n")
                else:
                    low_flr_session_file.write(write_str+"\n")
        high_flr_session_file.close()
        low_flr_session_file.close()
# ================         set self.variable                            ===============
    def set_high_flr_ip_set(self):
        with open("data/output/High_FLR_IPs.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                data = line.split()
                ip = data[0]
                if ip not in self.high_flr_ip_set:
                    self.high_flr_ip_set.add(ip)
    def set_conf(self):
        with open("data/input/auto_botcluster.conf", "r") as file:
            conf = json.load(file)
        self.sample_size = conf["auto_botcluster"]["sample_size"]
        self.malicious_report_threshold = conf["auto_botcluster"]["malicious_report_threshold"]
        self.eps = conf["auto_botcluster"]["DBSCAN"]["eps"]
        self.min_samples = conf["auto_botcluster"]["DBSCAN"]["min_samples"]
        self.algorithm = conf["auto_botcluster"]["DBSCAN"]["algorithm"]
        self.leaf_size = conf["auto_botcluster"]["DBSCAN"]["leaf_size"]

    def set_hadoop_path(self):
        self.hadoop_path = os.getenv("HADOOP_HOME")
        if self.hadoop_path == None:
            raise Execption("Error, HADOOP_HOME is None.")
    def set_mal_ip_set_and_rm_ip_set_and_mal_group_list(self):
        print("=============   Check Malicious Group Using Database and Virustotal API  ===============")
        process = os.popen(self.hadoop_path+"/bin/hdfs dfs -cat /user/hpds/fvidmapping/fvidIPMapping-0")
        lines = process.readlines()
        process.close()
        print("Number of group:{}".format(len(lines)))
        bdg = self.bdg
        ip_info_search_count = 0
        total_ip_count = 0
        malicious_group_count = 0
        for line in lines:
            cur_mal_ip_set = set()
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
                if res >= self.malicious_report_threshold:
                    is_malicious_group = True
                    malicious_group_count += 1
                    print("Malicious group ID: {}".format(group_id))
                    print("Malicious group size: {}".format(len(ip_arr)))
                    break
            if is_malicious_group:
                for ip in ip_arr:
                    if not ip in self.mal_ip_set:
                        self.mal_ip_set.add(ip)
                    if not ip in cur_mal_ip_set:
                        cur_mal_ip_set.add(ip)
                self.mal_group_list.append(cur_mal_ip_set)
            else:
                for ip in ip_arr:
                    if not ip in self.rm_ip_set:
                        self.rm_ip_set.add(ip)

        print("Number of malicious group:{}".format(malicious_group_count))

        # remove overlapped area
        for ip in self.mal_ip_set:
            if ip in self.rm_ip_set:
                self.rm_ip_set.remove(ip)

        print("Number of remove IP: {}".format(len(self.rm_ip_set)))
        print("Number of malicious IP: {}".format(len(self.mal_ip_set)))
        print("Number of total IP:{}".format(total_ip_count))
        print("Number of search IP:{}".format(ip_info_search_count))
        print("Number of API search:{}".format(bdg.get_api_search_count()))
        print("Number of database search:{}".format(bdg.get_database_search_count()))
        print("Number of dictionary search:{}".format(bdg.get_dict_search_count()))
    def get_malicious_groups(self):
        return self.mal_group_list
    def get_malicious_ip_set(self):
        return self.mal_ip_set
    def get_remove_ip_set(self):
        return self.rm_ip_set
    def get_sample_size(self, total_sample, z = 1.96, p = 0.5, c = 0.034):
        #z = 1.96  value of 95% confidence level
        #p = 0.5 # probility
        #c = 0.034 # error of 3.4% confidence interval
        if total_sample == 0:
            return 0
        ss = ((z*z)*p*(1-p))/(c*c) # sample size
        new_ss = ss/(1+((ss-1)/total_sample)) # new sample size
        return (int)(new_ss+0.5)

def save_auto_botcluster_resault_to_file(clust_info):
    datahome = os.getenv("DATA_HOME")
    if datahome == None:
        raise Execption("Error, DATA_HOME is None.")
    mal_ip_set = clust_info.get_malicious_ip_set()
    benign_ip_set = clust_info.get_benign_ip_set()
    #mal_exp_set = clust_info.get_mal_exp_set()
    #p2p_mal_exp_set = clust_info.get_p2p_mal_exp_set()
    with open(datahome+"/output/auto_botcluster_malicious_ip.txt", "w") as file:
        for ip in mal_ip_set:
            file.write(ip+"\n")
    with open(datahome+"/output/auto_botcluster_benign_ip.txt", "w") as file:
        for ip in benign_ip_set:
            file.write(ip+"\n")
    #with open(datahome+"/output/auto_botcluster_p2p_malicious_exp_ip.txt", "w") as file:
    #    for ip in p2p_mal_exp_set:
    #        file.write(ip+"\n")

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
        print("version: 1.7.4")

    if args.run_all:
        if args.netflow_name and args.output_dir_path:
            botcluster = BotCluster()
            botcluster.run(netflow_name=args.netflow_name)
            auto_botcluster = Auto_BotCluster()
            auto_botcluster.run()
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

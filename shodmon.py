#! /usr/bin/env python
# coding=UTF-8
# Shodan Monitoring Tool V2
# By NGrovyer
# Revived by SierraUniformSierra
# Discord code ripped from https://gist.github.com/Bilka2/5dd2ca2b6e9f3573e0c2defe5d3031b2

url = "WEBHOOKURLHERE" # webhook url for discord
SHODAN_API_KEY = "SHODANKEYHERE" #Your Shodan Key
shodan_query_expression='ASN:11111' #Your Shodan Query expression

import sys
import ast
import json
import time
import sqlite3
import schedule                                 #pip install schedule
import requests 
import datetime
from io import StringIO
from shodan import Shodan                       #pip install shodan
import dateutil.parser as dp
from shodan import exception as Shodan_exception

conn = sqlite3.connect('shodan_db.sqlite')

# Create a connection to the Shodan API
api = Shodan(SHODAN_API_KEY)

#Queries Shodan for a search term and then stores results in a list of dictionaries
def query_Shodan(term, callback):
    print("Runing Shodan Query")
    templist = []
    previous_ip=""
    while True:
        try:
            #Search Shodan and get bunch of IP Addresses (limit 100, you can increase it even more as per the number of servers you are planning to monitor)
            results = api.search(term,page=1,limit=100)
            #Construct a temp dictionary to store details of each of IP Address
            
            for result in results['matches']:

                #Shodan repeat IP entries for each port Open on an IP, the below code is for that
                if  previous_ip==result['ip_str']:
                    continue
                else:
                    previous_ip=result['ip_str']
                
                #print "Reached here"
                #print result
                temp = {}
                temp["Query"] = term
                time.sleep(1)
                #Fetch details of each  of IP one by one
                try:
                    host = api.host('%s' %result['ip'])
                except Shodan_exception.APIError as e:
                    #No results found, print no 'matches'
                    
                    print("No "+result['ip_str']+' %s\r' %e)
                    continue
                
                ip = '%s' %host.get('ip_str', None)
                #IP Stored as string
                temp["IP"] = ip.encode('ascii', 'replace')
                
                #Hostname also as string
                hostnames = s = ''.join(host.get('hostnames', None))
                temp["Hostnames"] = hostnames.encode('ascii', 'replace')

                #String as array of ports
                ports = '%s' %host.get('ports', None)
                temp["Ports"] = ports.encode('ascii', 'replace')

                #Last update time as string
                last_update = '%s' %host.get('last_update', None)
                temp["last_update"] = last_update.encode('ascii', 'replace')

                #ASN unique to a company
                asn = '%s' %host.get('asn', None)
                temp["ASN"] = asn.encode('ascii', 'replace')
                
                #Empty dictionary for
                port_dict=dict()
                
                # Ensure temp["Ports"] is a string
                ports = temp["Ports"]
                if isinstance(ports, bytes):
                    ports = ports.decode('utf-8')

                #Convert Ports to array list
                port_list=ports.strip("[").strip("]").split(",")
                                
                #Get hash data from data row
                hash_data = host.get('data')

                i=0
                #For each port, create dictionary with port=>Hash
                for portname in port_list:
                    port_dict[hash_data[i]['port']]=str(hash_data[i]['hash'])
                    i=i+1
                #Convert that dictonary into string for processing in next function
                temp["hash_data"] = str(port_dict)
                #Create mega list consisting of each of nested list
                templist.append(temp)
                callback(temp)
            break
        except Exception as e:
            #No results found, print no 'matches'
            print("Exception!")
            print('%s\r' %e)
            
    #Returns a list of dictionary objects. Each dictionary is a result
    return templist

count_var=0
def print_result(info):
    global count_var
    count_var=count_var+1
    #This function exist for existance purpose, cause I dont want to screw up the code LOL

def run_shodan_query():
    global know_ip_dns_mapping, shodan_query_expression
    #Variable that flips as soon as one change is detected, changes subject line of mail
    is_changed=False
    message_body=""     #Variable which will create mail body of your email
    list = query_Shodan(shodan_query_expression,print_result) #This is main query, could be done on basis of ASN or anything else, based on shodan format
    print("Processing")

    list_length=len(list)   #Number of results fetched from shodan

    #Code to find out new IPs and revoked IPs
    select_rec = conn.execute("SELECT sno,ip_address,open_ports FROM shodan_db where past_exist=0 order by sno DESC")
    old_ip_address = select_rec.fetchall()

    #How many IPs we saw last time, and how many are there now
    message_body=message_body+"Total IPs Yesterday" + str(len(old_ip_address))+"\r\n"   
    message_body=message_body+"Total IPs Today"+ str(list_length)+"\r\n"

    #Now begins the loop of checking whether any IP is gone from shodan or what?
    for x in old_ip_address:
        is_found=False
        for y in list:
            if x[1]==y['IP']:
                is_found=True
                break
        if is_found==False:
            select_rec = conn.execute("SELECT sno,ip_address,unix_scan_timestamp FROM shodan_db where ip_address='"+x[1]+"' order by sno DESC limit 0,1")
            get_last_date=select_rec.fetchall()
            if len(get_last_date)==0:
                last_scan_date="NONE"
            else:  
                last_scan_date=datetime.datetime.utcfromtimestamp(int(get_last_date[0][2])).strftime('%d-%m-%Y')
            is_changed=True
            message_body=message_body+"Old IP: "+x[1]+" ("+know_ip_dns_mapping.get(x[1],"")+") ::"+x[2]+" is not found today, last appeared on: "+str(last_scan_date)+"\r\n"

    #Now 2nd loop is to check whether a new IP had popped up in Shodan (or what)
    for y in list:
        is_found=False
        for x in old_ip_address:
            if x[1]==y['IP']:
                is_found=True
                break
        if is_found==False:
            # Ensure y['IP'] is a string
            ip_address = y['IP']
            if isinstance(ip_address, bytes):
                ip_address = ip_address.decode('utf-8')

            # Construct the SQL query
            query = f"SELECT sno, ip_address, unix_scan_timestamp FROM shodan_db WHERE ip_address='{ip_address}' ORDER BY sno DESC LIMIT 0,1"
            select_rec = conn.execute(query)

            get_last_date=select_rec.fetchall()
            if len(get_last_date)==0:
                last_scan_date="NONE"
            else:            
                last_scan_date=datetime.datetime.utcfromtimestamp(int(get_last_date[0][2])).strftime('%d-%m-%Y')
            is_changed=True

            ports = y['Ports']
            if isinstance(ports, bytes):
                ports = ports.decode('utf-8')

            message_body=message_body+"New IP: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"")+") ::"+ports+" is found today, last appeared on: "+str(last_scan_date)+"\r\n"

    #Update all past_exist to 1 as we are getting new records
    conn.execute("update shodan_db set past_exist=1")
    
    #Start processing each item in the live list        
    for match in list:
        #Screwit, we will just apply decode utf right here.
        ip_address=match['IP'].decode('utf-8')
        last_update=match['last_update']
        hostnames=match['Hostnames']
        hash_data=match['hash_data']
        query_term=match['Query']
        asn_num=match['ASN']
        ports=match['Ports'].decode('utf-8')
        
        parsed_t = dp.parse(last_update)
        parsed_date = parsed_t.strftime('%Y-%m-%d')
        unix_timestamp = time.time()
        
        #Code to check change, select query
        select_rec = conn.execute("SELECT sno,hash_data,open_ports FROM shodan_db where ip_address='"+ip_address+"' order by sno DESC limit 0,1")
        q = select_rec.fetchall()
        
        #If IP Already exist in database, check if changes
        if len(q) != 0:

            #Convert ports into a list
            live_new_ports=[]
            ports_list =ports.strip("[").strip("]").split(",")
            for port_live in ports_list:
                live_new_ports.append(int(port_live))
            ports_list=live_new_ports
                        
            #Convert both strings into dictionaries
            hash_live_dict=ast.literal_eval(hash_data)
            db_hash_dict=ast.literal_eval(q[0][1])
            
            #Check if the length is matching, if not, some new port is there!
            if len(hash_live_dict) == len(db_hash_dict):
                for key in hash_live_dict:
                    
                    #Check if key not in dictionary, means one port got closed, other got opened
                    #below statement means, if key not in dictionary, for some reason below is true
                    if str(key) in db_hash_dict:
                        is_changed=True
                        message_body=message_body+"New Port Found: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"")+") "+" | Old:"+str(db_hash_dict) +" AND New: "+str(hash_live_dict) +"\r\n"
                        
                    #If key already exist, check if Hash is same, if hash not equal, something changed, and we need to check
                    else:   
                        if hash_live_dict[key]!=db_hash_dict[key]:
                            is_changed=True
                            message_body=message_body+"HASH CHANGED: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"")+") "+" | Old:"+str(key)+" --> "+ str(db_hash_dict[key]) +" AND New: "+str(key)+" --> "+ str(hash_live_dict[key]) +"\r\n"
            else:
                is_changed=True
                message_body=message_body+"HASH & PORTS CHANGED: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"")+") "+" | Old:"+ str(db_hash_dict) +" AND New:"+ str(hash_live_dict) +"\r\n"
                
	    #Breaking Port string into a list
            db_ports_list=q[0][2].strip("[").strip("]").split(",")
            db_new_ports=[]
            for db_port in db_ports_list:
                db_new_ports.append(int(db_port))
            db_ports_list=db_new_ports
            
            #First check if length is equal, if not clearly port has changed
            
            if len(ports_list) == len(db_ports_list):
                #Iterate over each live port and see if they are same as what we have in DB
                for port_check in ports_list:
                    if port_check not in db_ports_list:
                        is_changed=True
                        message_body=message_body+"PORT CHANGED: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"")+") "+" | Old:"+ str(db_ports_list) +" AND New:"+ str(ports_list) +"\r\n"

            #If number of ports before and after are not equal, thats definitely a port change!                        
            else:
                is_changed=True
                message_body=message_body+"PORT CHANGED: "+ip_address+" ("+know_ip_dns_mapping.get(ip_address,"")+") "+" | Old:"+ str(db_ports_list) +" AND New:"+ str(ports_list) +"\r\n"

        else:
	    #if net new IP, append to changes along with comparision
            is_changed=True
            
        #Code to insert the new data into DB
        conn.execute('insert into shodan_db (ip_address,hostname,query_term,ASN_number,hash_data,open_ports,last_update_date,unix_scan_timestamp,past_exist) values (?,?,?,?,?,?,?,?,?)', (ip_address,hostnames,query_term,asn_num,hash_data,ports,parsed_date,unix_timestamp,"0"))

    conn.commit()
    #conn.close()
    message_starter="***Total IP Scanned: "+ str(list_length)+"*** \r\n"

    #If anywhere the change flag is raised
    if is_changed:
        subject="[Changes]Shodan-Monitoring"
    else:
        subject="[No Change]Shodan Monitoring"

    #This part of mail body is for record keeping in our mailbox, rather than looking in your Sqlite DB, you can quickly use your mailbox to pin point first appearance of IP
    message_body=message_body+"\n***Total IPs found today***\r\n"
    for match in list:
        message_body=message_body+match['IP'].decode('utf-8')+" ("+know_ip_dns_mapping.get(match['IP'].decode('utf-8'),"")+") "+" - Ports - "+match['Ports'].decode('utf-8')+"\r\n"

    print("finished")

    #If you want to see how our mail body will look like, uncomment below line
    print (message_starter+message_body)

    #Processing finished, lets mail it!
    #mail_status=send_mail(message_starter+message_body,subject)
    message_body = "*Unless otherwise specified, dates are formatted as DD-MM-YYYY*\n\n"+message_body
    send_discord(message_body,subject)




def send_discord(msg_to_send,Subject):
    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook


    # leave this out if you dont want an embed
    # for all params, see https://discordapp.com/developers/docs/resources/channel#embed-object

    data = {
        "content" : "DATA",
        "username" : "Shodan Monitor"
    }
    data["embeds"] = [
        {
            "description" : msg_to_send,
            "title" : Subject
        }
    ]
    result = requests.post(url, json = data)

    try:
        result.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
    else:
        print(f"Message delivered successfully, code {result.status_code}.")
	


#The below is dictionary mapping, for known exposed servers and their domain names (or whatever that can make you understand IP)
#If something unknown Pop up, that either needs to be mapped, or needs to be investigated
#
know_ip_dns_mapping={
  "209.133.79.64": "SSO Tesla",       #This is Just an Example

}

#Run the script first time to immediately gather data.
run_shodan_query()

#The scheduler, you can schedule it in mins, or days, or at specific time.
#Read more about it here
#https://github.com/dbader/schedule

#schedule.every(120).minutes.do(run_shodan_query)
schedule.every().day.at("10:30").do(run_shodan_query)

while True:
    schedule.run_pending()
    time.sleep(1)
    

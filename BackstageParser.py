#####
# Backstage Parser
# Thanks to David Cowen for his blog post --  http://www.hecfblog.com/2018/10/daily-blog-510-office-2016-backstage.html
#     _                              _   ____
#    / \   _ __ ___  ___ _ __   __ _| | |  _ \ ___  ___ ___  _ __
#   / _ \ | '__/ __|/ _ \ '_ \ / _` | | | |_) / _ \/ __/ _ \| '_ \
#  / ___ \| |  \__ \  __/ | | | (_| | | |  _ <  __/ (_| (_) | | | |
# /_/   \_\_|  |___/\___|_| |_|\__,_|_| |_| \_\___|\___\___/|_| |_|
#
#
# To learn more about Arsenal's digital forensics software and training,
# please visit https://ArsenalRecon.com and follow us on Twitter @ArsenalRecon (https://twitter.com/ArsenalRecon).
#
# To learn more about Arsenal's digital forensics consulting services,
# please visit https://ArsenalExperts.com and follow us on Twitter @ArsenalArmed (https://twitter.com/ArsenalArmed).
#
#
### Change Log ###
#
# 1.3.1 -- Fixed indentation issues
# 1.3 -- Fixed code related to JSON processing
# 1.2 -- Adding argument parser, ignoring unicode chars to avoid crashes, fixed bug with wrong key name (UTC Human) - hadar0x
# 1.1 -- Added JSON support
# 1.0 -- Original implementation
#
#####

import os
import re
import sys
import json
import codecs
import argparse

from datetime import datetime, timedelta


__description__ = "Backstage Parser"
__version__ = "1.3.1"
__updated__ = "2018-12-27"
__author__ = "Arsenal Recon"

######

def twos_comp(val, bits):
	#https://stackoverflow.com/questions/1604464/twos-complement-in-python
    mask = '0x'+'f'*bits
    val = val ^ int(mask,16)-1
    if hex(val)[-1:] == "L":
    	return '0x'+hex(val)[-9:-1]
    else:
        return '0x'+hex(val)[-8:]
    return val


def filetime_to_dt(ft):
	#https://stackoverflow.com/questions/38878647/python-convert-filetime-to-datetime-for-dates-before-1970/38878860#38878860
	EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
	HUNDREDS_OF_NANOSECONDS = 10000000
	us = (ft - EPOCH_AS_FILETIME) // 10
	return (datetime(1970, 1, 1) + timedelta(microseconds = us)).strftime("%Y-%m-%d %H:%M:%S")


def strToFileTime(val):

    dates = val.split(':')
    if len(dates) != 2:
        print ("More information expected with dates %s" % str(dates))
        exit(0)
    dates[0] = twos_comp(int(dates[0]), 32)
    if dates[0][0] == "-":
        dates[0] = dates[0][3:]
    else:
        dates[0] = dates[0][2:]
    dates[1] = hex(int(dates[1]))
    fileTime = '0x'+dates[1][2:]+dates[0]
    return fileTime


def getDirs(f):

    dirs = []
    i = 0
    currentLine = f.readline().strip('\r\n')
	##loop on folders until we hit "[Files]"
    while currentLine.strip('\r\n') != "[Files]" and currentLine.strip('\r\n') != '':
        line = currentLine.split('|')
        path = line[0]
        foldername = line[1]
        fileTimeDate = strToFileTime(line[-1])
        humanTime = filetime_to_dt(int(fileTimeDate, 16))
        dirs.append(i)
        dirs[i] = {"Path": path, "FolderName":foldername, "Modified Time(Hex)":fileTimeDate, "Modified Time(Human-UTC)":humanTime}
        i = i + 1
        currentLine = f.readline().strip('\r\n')
    return dirs

def getFiles(f):

    files = []
    i = 0
    currentLine = f.readline().strip('\r\n')
    while currentLine != '':
        line = currentLine.split('|')
        path = line[0]
        filename = line[1]
        fileTimeDate = strToFileTime(line[-1])
        humanTime = filetime_to_dt(int(fileTimeDate, 16))
        files.append(i)
        files[i] = {"Path": path, "FolderName":filename, "Modified Time(Hex)":fileTimeDate, "Modified Time(Human-UTC)":humanTime}
        i = i + 1
        currentLine = f.readline().strip('\r\n')
    return files

def main(arguments):

    if arguments.INPUT_FILE.endswith(".json"):
        try:
            fIn = codecs.open(arguments.INPUT_FILE, 'r', encoding='utf-16le')
            fOut = codecs.open(arguments.INPUT_FILE+".tsv", 'w', encoding='utf-8')
        except Exception as e:
            print (e)
            exit(0)
            
        try:
            json_string = fIn.read()
        except Exception as e:
            print (e)
            exit(0)

        try:
            parsed_json = json.loads(json_string)
        except Exception as e:
            print(e)
            exit(0)

        print ("Type\tURL\tDisplayName\tLastModified(Integer)\tLastModified (UTC)\tAuthor\tResourceId\tSharingLevelDescription")
        fOut.write("Type\tURL\tDisplayName\tLastModified(Integer)\tLastModified (UTC)\tAuthor\tResourceId\tSharingLevelDescription\n")

        for items in parsed_json['Folders']:
            date = filetime_to_dt(items['LastModified'])
            print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % ("Folder", items['Url'], items['DisplayName'], items['LastModified'], date, items['Author'], items['ResourceId'], items['SharingLevelDescription']))
            fOut.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % ("Folder", items['Url'], items['DisplayName'], items['LastModified'], date, items['Author'], items['ResourceId'], items['SharingLevelDescription']))

        for items in parsed_json['Files']:
            date = filetime_to_dt(items['LastModified'])
            print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % ("File", items['Url'], items['DisplayName'], items['LastModified'], date, items['Author'], items['ResourceId'], items['SharingLevelDescription']))
            fOut.write("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % ("File", items['Url'], items['DisplayName'], items['LastModified'], date, items['Author'], items['ResourceId'], items['SharingLevelDescription']))
        
    else:
	try:
            fIn = codecs.open(arguments.INPUT_FILE, 'r', encoding='utf-8')
	except Exception as e:
            print ("%s" % e)
            exit(0)
	try:
            fOut = codecs.open(arguments.INPUT_FILE+".tsv", 'w', encoding='utf-8')
	except Exception as e:
            print ("%s" % e)
            exit(0)
                

## non-JSON files
##First line of file is the master directory
        currentLine = fIn.readline()
        masterFolder=currentLine.encode("ascii", errors="replace")
        print ("%s" % masterFolder)
        fOut.write("%s" % masterFolder)
        print ("Type\tPath\tName\tModified Time(Hex)\tModified Time (UTC)")
        fOut.write("Type\tPath\tName\tModified Time(Hex)\tModified Time (UTC)\n")

##Second line of file is "[Folders]"
        currentLine = fIn.readline()
        if currentLine.strip('\r\n') == "[Folders]":
            dirs = getDirs(fIn)
            noFolders = False
#currentLine = f.readline().strip('\r\n')
            for d in dirs:
                print ("%s\t%s\t%s\t%s\t%s" % ("Folder", d["Path"], d["FolderName"],d["Modified Time(Hex)"], d["Modified Time(Human-UTC)"]))
                fOut.write("%s\t%s\t%s\t%s\t%s\n" % ("Folder", d["Path"], d["FolderName"],d["Modified Time(Hex)"], d["Modified Time(Human-UTC)"]))
        else:
            noFolders = True            
## Files
            if currentLine.strip('\r\n') == "[Files]" or noFolders == False:
                files = getFiles(fIn)
                for f in files:
                    print ("%s\t%s\t%s\t%s\t%s" % ("File", f["Path"], f["FolderName"],f["Modified Time(Hex)"], f["Modified Time(Human-UTC)"]))
                    fOut.write("%s\t%s\t%s\t%s\t%s\n" % ("File", f["Path"], f["FolderName"],f["Modified Time(Hex)"], f["Modified Time(Human-UTC)"]))

    fIn.close()
    fOut.close()

if __name__ == "__main__":
    # execute only if run as a script
    parser = argparse.ArgumentParser(description=__description__, version=__version__)
    parser.add_argument("INPUT_FILE", help="Backstage File to Parse")
    args = parser.parse_args()
    main(args)

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
### ToDo ###
# Add carving functionality
#
###
#
#
### Change Log ###
#
# 1.11  -- minor updates
# 1.10  -- changed file output format to utf-16
# 1.9   -- added "|" as option option
# 1.8   -- added output to files
# 1.7.1 -- added output summary
# 1.7   -- added simple logging
# 1.6.1 -- Fixed output/record logic
# 1.6   -- Added carving (experimental)
# 1.5   -- Restructured some of the code, added support for processing all files in a directory
# 1.4   -- Account for corrupted date field
# 1.3.2 -- More indentation issues
# 1.3.1 -- Fixed indentation issues
# 1.3   -- Fixed code related to JSON processing
# 1.2   -- Adding argument parser, ignoring unicode chars to avoid crashes, fixed bug with wrong key name (UTC Human) - hadar0x
# 1.1   -- Added JSON support
# 1.0   -- Original implementation
#
#####

import os
import re
import sys
import json
import codecs
import argparse
import os
from datetime import datetime, timedelta


__description__ = "Backstage Parser"
__version__ = "1.10"
__updated__ = "2019-07-17"
__author__ = "Arsenal Recon"

######

def getFilesInDirectory(directory):

    fileList = []
    for root, dirnames, filenames in os.walk(directory):
        for file in filenames:
            fileList.append(os.path.join(root, file))
    return fileList

def processJSON(currentFile,logFile):

    try:
        fIn = codecs.open(currentFile, 'r', encoding='utf-16le')
    except Exception as e:
        logFile.write("Error (processJSON): %s\n" % e)
    
    try:
        json_string = fIn.read()
    except Exception as e:
        logFile.write("Error (processJSON): %s\n" % e)

    try:
        parsed_json = json.loads(json_string)
    except Exception as e:
        logFile.write("Error (processJSON): %s\n" % e)
        return None

    records = {}
    for items in parsed_json['Folders']:
        date = filetime_to_dt(items['LastModified'])

        records[items["Url"]] = {}
        records[items["Url"]]['Source'] = currentFile
        records[items["Url"]]['Type'] = "Folder"
        records[items["Url"]]['Path'] = items["Url"]
        records[items["Url"]]['Name'] = items["DisplayName"]
        records[items["Url"]]['ModifiedTime'] = date  
    
    for items in parsed_json['Files']:
        date = filetime_to_dt(items['LastModified'])

        records[items["Url"]] = {}
        records[items["Url"]]['Source'] = currentFile  
        records[items["Url"]]['Type'] = "Folder"
        records[items["Url"]]['Path'] = items["Url"]
        records[items["Url"]]['Name'] = items["DisplayName"]
        records[items["Url"]]['ModifiedTime'] = date  
    return records
    
def processFile(currentFile,logFile):
    try:
        fIn = codecs.open(currentFile, 'r', encoding='utf-8')
    except Exception as e:
        logFile.write("Error (processFile): %s\n" % e)
        return None


    ## non-JSON files
    ##First line of file is the master directory
    try:
        currentLine = fIn.readline()
        masterFolder=currentLine#.encode("ascii", errors="replace")
    except:
        return None

    records = {}
    ##Second line of file is "[Folders]"
    try:
        currentLine = fIn.readline()
    except:
        return None

    if currentLine.strip('\r\n') == "[Folders]":
        dirs = getDirs(fIn)
        noFolders = False
    #currentLine = f.readline().strip('\r\n')
        for d in dirs:
            records[d["Path"]] = {}
            records[d["Path"]]['Source'] = currentFile
            records[d["Path"]]['Type'] = "Folder"
            records[d["Path"]]['Path'] = d["Path"]
            records[d["Path"]]['Name'] = d["FolderName"]
            records[d["Path"]]['ModifiedTime'] = d["Modified Time(Human-UTC)"]           
    else:
        noFolders = True            
    ## Files
    if currentLine.strip('\r\n') == "[Files]" or noFolders == False:
        files = getFiles(fIn)
        for f in files:
            records[f["Path"]] = {}
            records[f["Path"]]['Source'] = currentFile
            records[f["Path"]]['Type'] = "File"
            records[f["Path"]]['Path'] = f["Path"]
            records[f["Path"]]['Name'] = f["FolderName"]
            records[f["Path"]]['ModifiedTime'] = f["Modified Time(Human-UTC)"]

    return records

def processRawFile(currentFile,logFile):
    csvPattern = re.compile('(?:\\\\\\\\|[A-Z]:\\\\).+\|*\|.*\|[-]*[0-9]{8,10}:[0-9]{8}')
    jsonPattern = re.compile('\{"Url": "(?:\\\\\\\\|[A-Z]:\\\\).+?", "DisplayName": ".*?", "Author": ".*?", "ResourceId": ".*?", "RootResourceId": ".*?", "LastModified": [0-9]+?, "SharingLevelDescription": ".*?"\}')
    fIn = open(currentFile, 'rb')
    bufferLen = 4096

    try:
        buffer = fIn.read(bufferLen)
    except Exception as e:
        logFile.write("Error (processRawFile): %s\n" % e)

    records = {}
    while buffer != None and buffer != b'':
        try:
            csvMatch = re.findall(csvPattern, buffer.decode('utf-8'))
        except Exception as e:
            logFile.write("Error (processRawFile): %s\n" % e)
            pass
        try:
            jsonMatch = re.findall(jsonPattern, buffer.decode('utf-16'))
        except Exception as e:
            logFile.write("Error (processRawFile): %s\n" % e)
            pass
        import pdb; pdb.set_trace()
        if csvMatch:
            for match in csvMatch:
                try:
                    records[match.split('|')[0]] = {}
                    records[match.split('|')[0]]['Source'] = currentFile
                    records[match.split('|')[0]]['Type'] = 'CarvedRecord'
                    records[match.split('|')[0]]['Path'] = match.split('|')[0]
                    records[match.split('|')[0]]['Name'] = match.split('|')[1]
                    fileTimeDate = strToFileTime(match.split('|')[4])
                    if fileTimeDate != "N/A":
                        humanTime = filetime_to_dt(int(fileTimeDate, 16))
                    else:
                        humanTime = "N/A"
                    records[match.split('|')[0]]['ModifiedTime'] = humanTime  
                except Exception as e:
                    logFile.write("Error (processRawFile): %s\n" % e) 
                    pass
        if jsonMatch:
            for match in jsonMatch:
                try:
                    thisMatch = re.match('.+?"Url": (".+?"), "DisplayName": (".+?"), "Author": (".*?"), "ResourceId": (".*?"), "RootResourceId": (".*?"), "LastModified": ([0-9]+), "SharingLevelDescription": (".*?").*', match)
                    if thisMatch:
                        records[thisMatch.group(1)] = {}
                        records[thisMatch.group(1)]['Source'] = currentFile
                        records[thisMatch.group(1)]['Type'] = 'CarvedRecord'
                        records[thisMatch.group(1)]['Path'] = thisMatch.group(1)
                        records[thisMatch.group(1)]['Name'] = thisMatch.group(2)
                        date = filetime_to_dt(int(thisMatch.group(6)))
                        records[thisMatch.group(1)]['ModifiedTime'] = date  
                except Exception as e:
                    logFile.write("Error (processRawFile): %s\n" % e) 
                    pass            
            print ("JSON Hit")
        try:
            buffer = fIn.read(bufferLen)
        except Exception as e:
            logFile.write("Error (processRawFile): %s\n" % e)
            buffer = None
    return records


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
    try:
        dates[1] = hex(int(dates[1]))
    except:
        return "N/A"

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
        if fileTimeDate != "N/A":
            humanTime = filetime_to_dt(int(fileTimeDate, 16))
        else:
            humanTime = "N/A"
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
        if fileTimeDate != "N/A":
            humanTime = filetime_to_dt(int(fileTimeDate, 16))
        else:
            humanTime = "N/A"
        files.append(i)
        files[i] = {"Path": path, "FolderName":filename, "Modified Time(Hex)":fileTimeDate, "Modified Time(Human-UTC)":humanTime}
        i = i + 1
        currentLine = f.readline().strip('\r\n')
    return files




def main(arguments):

    fileList = []
    now = datetime.now().strftime("%Y%m%d%H%M%S")
    logFileName = 'backstage-'+now+'.log'
    logFile = open(logFileName, 'w')
    start = datetime.now()

    if arguments.debug == True:
        import pdb; pdb.set_trace()
    if arguments.f:
        fileList.append(arguments.f)
    elif arguments.d:
        fileList = getFilesInDirectory(arguments.d)

    masterList = {}
    for currentFile in fileList:

        logFile.write("Processing file: %s\n" % currentFile)
        if arguments.r:
            output = processRawFile(currentFile,logFile)
        else:
            if currentFile.endswith(".json"):
                output = processJSON(currentFile,logFile)
            else:
                output = processFile(currentFile,logFile)
        if output != None:
            masterList.update(output)


    if masterList == None or len(masterList) == 0:
        print ("No records found")
        exit(0)

    fOut = None
    if arguments.o:
        try:
            fOut = open(arguments.o, 'w', encoding='utf-16')
        except Exception as e:
            logFile.write("Error opening output file: %s\n" % str(e))
            arguments.o = None

    if arguments.oj:
        j = json.dumps(masterList)
        print (j)
        if arguments.o: fOut.write(j) 
    elif arguments.ot:
        print ("Type\tPath\tName\tModifiedTime(UTC)\tSoure")
        for row in masterList:
            print ("%s\t%s\t%s\t%s\t%s" % (masterList[row]['Type'], masterList[row]['Path'], masterList[row]['Name'],masterList[row]['ModifiedTime'],masterList[row]['Source']))
            if arguments.o: fOut.write("%s\t%s\t%s\t%s\t%s\n" % (masterList[row]['Type'], masterList[row]['Path'], masterList[row]['Name'],masterList[row]['ModifiedTime'],masterList[row]['Source']))
    elif arguments.op:
        print ("Type|Path|Name|ModifiedTime(UTC)|Soure")
        for row in masterList:
            print ("%s|%s|%s|%s|%s" % (masterList[row]['Type'], masterList[row]['Path'], masterList[row]['Name'],masterList[row]['ModifiedTime'],masterList[row]['Source']))
            if arguments.o: fOut.write("%s|%s|%s|%s|%s\n" % (masterList[row]['Type'], masterList[row]['Path'], masterList[row]['Name'],masterList[row]['ModifiedTime'],masterList[row]['Source']))
    else:
        print ("Type,Path,Name,ModifiedTime(UTC),Source")
        for row in masterList:
            print ("'%s','%s','%s','%s','%s'" % (masterList[row]['Type'], masterList[row]['Path'], masterList[row]['Name'],masterList[row]['ModifiedTime'],masterList[row]['Source']))
            if arguments.o: fOut.write ("'%s','%s','%s','%s','%s'\n" % (masterList[row]['Type'], masterList[row]['Path'], masterList[row]['Name'],masterList[row]['ModifiedTime'],masterList[row]['Source']))

    end = datetime.now()
    print ("%d files processed, %d records found, %s elapsed time" % (len(fileList), len(masterList), str(end-start)))
    logFile.write("%d files processed, %d records found, %s elapsed time\n" % (len(fileList), len(masterList), str(end-start)))
    
    if arguments.o: fOut.close()
        
    logFile.close()

if __name__ == "__main__":
    # execute only if run as a script
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument("-f",  help="Individual Backstage file to parse")
    parser.add_argument("-d",  help="Directory containing Backstage file(s)")
    parser.add_argument("-o",  help="Output filename")
    parser.add_argument("-r", action='store_true', help="Flag: Carve Backstage records from raw file - experimental!")

    parser.add_argument("-oj", action='store_true', help="Flag: Output as JSON")
    parser.add_argument("-ot", action='store_true', help="Flag: Output as TSV")
    parser.add_argument("-oc", action='store_true', help="Flag: Output as CSV")
    parser.add_argument("-op", action='store_true', help="Flag: Output as PSV")
   
    parser.add_argument("--debug", action='store_true', help="Flag: debug")
    
    args = parser.parse_args()

    if args.f and args.d:
        print ("Choose file OR directory")
        exit(0)


    if sys.version_info <= (3,0):
        print("Sorry, requires Python 3.x, not Python 2.x")
        sys.exit(1)

    main(args)

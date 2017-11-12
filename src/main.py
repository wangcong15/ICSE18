# -*- coding: utf-8 -*-  
import os
import getopt
import sys
import defect_match_CWE134
import defect_match_CWE195
import defect_match_CWE674
import defect_match_CWE690
import defect_match_CWE789
import defect_match_CWE835
from common_lib import write_new_file

def handle_dir(dir_path):
	if dir_path.find("linux-master") > 0:
		return
	files = os.listdir(dir_path)
	for file in files:
		file_path = os.path.join(dir_path, file)
		if os.path.isdir(file_path):
			handle_dir(file_path)
		elif os.path.isfile(file_path) and (file_path.endswith(".c") or file_path.endswith(".cpp")) and not file_path.endswith(".bak.c"):
			handle_file(file_path)


def handle_file(file_path):
	if os.path.exists(file_path + ".bak.c"):
		return

	insert_array = []
	if '134' in weakList:
		insert_array += defect_match_CWE134.handle_file(file_path)
	if '195' in weakList:
		insert_array += defect_match_CWE195.handle_file(file_path)
	if '674' in weakList:
		insert_array += defect_match_CWE674.handle_file(file_path)
	if '690' in weakList:
		insert_array += defect_match_CWE690.handle_file(file_path)
	if '789' in weakList:
		insert_array += defect_match_CWE789.handle_file(file_path)
	if '835' in weakList:
		insert_array += defect_match_CWE835.handle_file(file_path)

	new_file_path = ""
	if len(insert_array) > 0:
		print file_path
		new_file_path = file_path + ".bak.c"
		write_result = write_new_file(file_path, new_file_path, insert_array, False)
	# if os.path.isfile(new_file_path):
	# 	verify_result = smack_verification(new_file_path)
	# 	verify_result = -1
	# 	if verify_result == 0:
	# 		global assert_false_count
	# 		assert_false_count += 1
	# 	elif verify_result == -1:
	# 		global file_parse_error
	# 		file_parse_error += 1



opts, args = getopt.getopt(sys.argv[1:], "d:f:w:v")
dirPath = ""
filePath = ""
weakList = []
needVerify = False

for op, value in opts:
    if op == "-d":
        dirPath = value
    elif op == "-f":
        filePath = value
    elif op == "-w":
        weakList = value.split(",")
    elif op == "-v":
    	needVerify = True

if dirPath == "" and filePath == "":
	print "Lack Parameters"
	sys.exit(0)
elif len(weakList) == 0:
	print "Lack Weakness Parameters"
	sys.exit(0)
elif dirPath != "" and not os.path.isdir(dirPath):
	print "Illegal Directory Path"
	sys.exit(0)
elif dirPath != "" and filePath != "":
	print "Need Directory either File"
	sys.exit(0)
elif filePath != "" and not os.path.isfile(filePath):
	print "Illegal File Path"
	sys.exit(0)

print dirPath, filePath, weakList, needVerify

if dirPath != "":
	handle_dir(dirPath)

if filePath != "":
	handle_file(filePath)
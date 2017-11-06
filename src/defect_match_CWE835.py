# -*- coding: utf-8 -*-  

# 这里主要是匹配代码缺陷的类型，定位需要插入assertion的位置和类型
# 主要是针对CWE835的缺陷类型

import clang.cindex
import os
from common_lib import get_src_from_sr, write_new_file, smack_verification, get_length
import time	

# 得到for语句的位置
def find_for(new_cursor):
	result = []
	if new_cursor.kind == clang.cindex.CursorKind.FOR_STMT or new_cursor.kind == clang.cindex.CursorKind.DO_STMT or new_cursor.kind == clang.cindex.CursorKind.WHILE_STMT:
		result.append(new_cursor.location.line)
	new_cursor_stmts = new_cursor.get_children()
	for new_cursor_stmt in new_cursor_stmts:
		result += find_for(new_cursor_stmt)
	return result

# 获得该函数中for语句的参数
def get_for_param(func_cursor):
	for_array = find_for(func_cursor)
	return_result = []
	for for_a in for_array:
		temp_result = [for_a, "int iterator_tempvalue = 0;\n"]
		return_result.append(temp_result)
		temp_result = [for_a + 2, "iterator_tempvalue += 1; assert(iterator_tempvalue <= 100000);\n"]
		return_result.append(temp_result)
	return return_result

# 处理单个文件
def handle_file(file_path):
	global file_number
	file_number += 1
	print "----[", file_number, "]----"
	print file_path

	# for
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	insert_array = []
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_for_param(child)
	
	new_file_path = ""
	if len(insert_array) > 0:
		global assert_file_number
		assert_file_number += 1
		new_file_path = file_path + ".bak.c"
		write_result = write_new_file(file_path, new_file_path, insert_array)
	if os.path.isfile(new_file_path):
		# verify_result = smack_verification(new_file_path)
		verify_result = -1
		# print verify_result
		if verify_result == 0:
			global assert_false_count
			assert_false_count += 1
		elif verify_result == -1:
			global file_parse_error
			file_parse_error += 1
	# print insert_array
	# print write_result

# 处理文件夹
def handle_dir(dir_path):
	files = os.listdir(dir_path)
	for file in files:
		file_path = os.path.join(dir_path, file)
		if os.path.isdir(file_path):
			handle_dir(file_path)
		elif os.path.isfile(file_path) and (file_path.endswith(".c") or file_path.endswith(".cpp")) and not file_path.endswith(".bak.c"):
			handle_file(file_path)

if __name__ == "__main__":
	global file_number
	file_number = 0
	global assert_file_number
	assert_file_number = 0
	global assert_false_count
	assert_false_count = 0
	global file_parse_error
	file_parse_error = 0
	# 处理文件夹
	handle_dir("/home/wangcong/Documents/ETAPS/training_sets/training_set_835/")
	# handle_file("/home/wangcong/Documents/ETAPS/training_sets/training_set_835/CWE835_Infinite_Loop__for_01.c")
	print "-------------------"
	print "TOTAL NUMBER OF FILE:", file_number
	print "ASSERTION-INSERTED FILES:", assert_file_number
	print "VERIFIED-FALSE:", assert_false_count
	print "PARSE-ERROR:", file_parse_error
	print "-------------------"
	# handle_file("/home/ubuntu/Document/ETAPS/training_set/CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_01.c")
# END Author Cong Wang 




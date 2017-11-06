# -*- coding: utf-8 -*-  

# 这里主要是匹配代码缺陷的类型，定位需要插入assertion的位置和类型
# 主要是针对CWE195的缺陷类型

import clang.cindex
import os
from common_lib import get_src_from_sr, write_new_file, smack_verification, get_length
import time	

parent_stack = []
mms = ["memcpy", "memmove", "strncpy"]

# 得到memcpy／memmove／strncpy的位置
def find_mms(new_cursor):
	global parent_stack
	parent_stack.append(new_cursor)
	result = []
	if new_cursor.displayname in mms and new_cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR and new_cursor.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
		parent_node = parent_stack[-3]
		temp_node = parent_node.get_children()
		param_node = temp_node.next()
		param_node = temp_node.next()
		param_node = temp_node.next()
		param_node = temp_node.next()
		result.append([new_cursor.location.line, get_src_from_sr(param_node.extent)])
	new_cursor_stmts = new_cursor.get_children()
	# temp_void = True
	for new_cursor_stmt in new_cursor_stmts:
		# temp_void = False
		result += find_mms(new_cursor_stmt)
	parent_stack.pop()
	return result

# 得到malloc语句的位置
def find_malloc(new_cursor):
	global parent_stack
	parent_stack.append(new_cursor)
	result = []
	if new_cursor.displayname == "malloc" and new_cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR and new_cursor.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
		parent_node = parent_stack[-3]
		temp_node = parent_node.get_children()
		param_node = temp_node.next()
		param_node = temp_node.next()
		result.append([new_cursor.location.line, get_src_from_sr(param_node.extent)])
	new_cursor_stmts = new_cursor.get_children()
	# temp_void = True
	for new_cursor_stmt in new_cursor_stmts:
		# temp_void = False
		result += find_malloc(new_cursor_stmt)
	parent_stack.pop()
	return result

# 获得该函数中malloc语句的参数
def get_malloc_param(func_cursor):
	malloc_array = find_malloc(func_cursor)
	return_result = []
	for malloc_a in malloc_array:
		temp_result = [malloc_a[0], "assert("+ malloc_a[1] +" >= 0);\n"]
		return_result.append(temp_result)
	return return_result

# 获得该函数中mms语句的参数
def get_mms_param(func_cursor):
	mms_array = find_mms(func_cursor)
	return_result = []
	for mms_a in mms_array:
		temp_result = [mms_a[0], "assert("+ mms_a[1] +" >= 0);\n"]
		return_result.append(temp_result)
	return return_result

# 处理单个文件
def handle_file(file_path):
	global file_number
	file_number += 1
	print "----[", file_number, "]----"
	print file_path
	# malloc
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	insert_array = []
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_malloc_param(child)
	# mms
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_mms_param(child)
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
	handle_dir("/home/ubuntu/Document/ETAPS/C_Only")
	# handle_file("/home/ubuntu/Document/ETAPS/demos/demo195.c")
	print "-------------------"
	print "TOTAL NUMBER OF FILE:", file_number
	print "ASSERTION-INSERTED FILES:", assert_file_number
	print "VERIFIED-FALSE:", assert_false_count
	print "PARSE-ERROR:", file_parse_error
	print "-------------------"
	# handle_file("/home/ubuntu/Document/ETAPS/training_set/CWE195_Signed_to_Unsigned_Conversion_Error__connect_socket_memcpy_01.c")
# END Author Cong Wang 




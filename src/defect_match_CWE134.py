# -*- coding: utf-8 -*-  

# 这里主要是匹配代码缺陷的类型，定位需要插入assertion的位置和类型
# 主要是针对CWE134的缺陷类型

import clang.cindex
import os
from common_lib import get_src_from_sr, write_new_file, smack_verification, get_length

parent_stack = []

fprintf_array = ["fwprintf", "fprintf"]
printf_array = ["wprintf", "printf"]
vfprintf_array = ["vfprintf", "vfwprintf"]
vprintf_array = ["vwprintf", "vprintf"]
vsnprintf_array = ["vsnprintf"]

# 1.1 得到fprintf语句的位置
def find_fprintf(new_cursor):
	global parent_stack
	parent_stack.append(new_cursor)
	result = []
	if new_cursor.displayname in fprintf_array  and new_cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR and new_cursor.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
		parent_node = parent_stack[-3]
		num_of_children = get_length(parent_node)
		if num_of_children == 3:
			temp_node = parent_node.get_children()
			param_node = temp_node.next()
			param_node = temp_node.next()
			param_node = temp_node.next()
			result.append([new_cursor.location.line, get_src_from_sr(param_node.extent)])
	new_cursor_stmts = new_cursor.get_children()
	# temp_void = True
	for new_cursor_stmt in new_cursor_stmts:
		# temp_void = False
		result += find_fprintf(new_cursor_stmt)
	parent_stack.pop()
	return result

# 1.2 获得该函数中fprintf语句的参数
def get_fprintf_param(func_cursor):
	fprintf_array = find_fprintf(func_cursor)
	return_result = []
	for fprintf_a in fprintf_array:
		temp_result = [fprintf_a[0], "for(int temp_iterator = 0; temp_iterator < strlen(" + fprintf_a[1] + "); temp_iterator++)\nassert(" + fprintf_a[1] + "[temp_iterator] != '%');\n"]
		return_result.append(temp_result)
	return return_result

# 2.1 得到printf语句的位置
def find_printf(new_cursor):
	global parent_stack
	parent_stack.append(new_cursor)
	result = []
	if new_cursor.displayname in printf_array and new_cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR and new_cursor.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
		parent_node = parent_stack[-3]
		num_of_children = get_length(parent_node)
		if num_of_children == 2:
			temp_node = parent_node.get_children()
			param_node = temp_node.next()
			param_node = temp_node.next()
			result.append([new_cursor.location.line, get_src_from_sr(param_node.extent)])
	new_cursor_stmts = new_cursor.get_children()
	# temp_void = True
	for new_cursor_stmt in new_cursor_stmts:
		# temp_void = False
		result += find_printf(new_cursor_stmt)
	parent_stack.pop()
	return result

# 2.2 获得该函数中printf语句的参数
def get_printf_param(func_cursor):
	printf_array = find_printf(func_cursor)
	return_result = []
	for printf_a in printf_array:
		temp_result = [printf_a[0], "for(int temp_iterator = 0; temp_iterator < strlen(" + printf_a[1] + "); temp_iterator++)\nassert(" + printf_a[1] + "[temp_iterator] != '%');\n"]
		return_result.append(temp_result)
	return return_result

# 3.1 得到SNPRINTF语句的位置
def find_SNPRINTF(new_cursor):
	global parent_stack
	parent_stack.append(new_cursor)
	result = []
	if new_cursor.displayname == "snprintf" and new_cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR and new_cursor.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
		parent_node = parent_stack[-3]
		num_of_children = get_length(parent_node)
		if num_of_children == 4:
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
		result += find_SNPRINTF(new_cursor_stmt)
	parent_stack.pop()
	return result

# 3.2 获得该函数中SNPRINTF语句的参数
def get_SNPRINTF_param(func_cursor):
	SNPRINTF_array = find_SNPRINTF(func_cursor)
	return_result = []
	for SNPRINTF_a in SNPRINTF_array:
		temp_result = [SNPRINTF_a[0], "for(int temp_iterator = 0; temp_iterator < strlen(" + SNPRINTF_a[1] + "); temp_iterator++)\nassert(" + SNPRINTF_a[1] + "[temp_iterator] != '%');\n"]
		return_result.append(temp_result)
	return return_result

# 4.1 得到vfprint语句的位置
def find_vfprint(new_cursor):
	global parent_stack
	parent_stack.append(new_cursor)
	result = []
	if new_cursor.displayname in vfprintf_array and new_cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR and new_cursor.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
		parent_node = parent_stack[-3]
		num_of_children = get_length(parent_node)
		if num_of_children == 4:
			temp_node = parent_node.get_children()
			param_node = temp_node.next()
			param_node = temp_node.next()
			param_node = temp_node.next()
			if get_src_from_sr(param_node.extent) != "%s":
				param_node = temp_node.next()
				result.append([new_cursor.location.line, get_src_from_sr(param_node.extent)])
	new_cursor_stmts = new_cursor.get_children()
	# temp_void = True
	for new_cursor_stmt in new_cursor_stmts:
		# temp_void = False
		result += find_vfprint(new_cursor_stmt)
	parent_stack.pop()
	return result

# 4.2 获得该函数中vfprint语句的参数
def get_vfprint_param(func_cursor):
	vfprint_array = find_vfprint(func_cursor)
	return_result = []
	for vfprint_a in vfprint_array:
		temp_result = [vfprint_a[0], "for(int temp_iterator = 0; temp_iterator < strlen(" + vfprint_a[1] + "); temp_iterator++)\nassert(" + vfprint_a[1] + "[temp_iterator] != '%');\n"]
		return_result.append(temp_result)
	return return_result

# 5.1 得到vprintf语句的位置
def find_vprintf(new_cursor):
	global parent_stack
	parent_stack.append(new_cursor)
	result = []
	if new_cursor.displayname in vprintf_array and new_cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR and new_cursor.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
		parent_node = parent_stack[-3]
		num_of_children = get_length(parent_node)
		if num_of_children == 3:
			temp_node = parent_node.get_children()
			param_node = temp_node.next()
			param_node = temp_node.next()
			if get_src_from_sr(param_node.extent) != "%s":
				param_node = temp_node.next()
				result.append([new_cursor.location.line, get_src_from_sr(param_node.extent)])
	new_cursor_stmts = new_cursor.get_children()
	# temp_void = True
	for new_cursor_stmt in new_cursor_stmts:
		# temp_void = False
		result += find_vprintf(new_cursor_stmt)
	parent_stack.pop()
	return result

# 5.2 获得该函数中vprintf语句的参数
def get_vprintf_param(func_cursor):
	vprintf_array = find_vprintf(func_cursor)
	return_result = []
	for vprintf_a in vprintf_array:
		temp_result = [vprintf_a[0], "for(int temp_iterator = 0; temp_iterator < strlen(" + vprintf_a[1] + "); temp_iterator++)\nassert(" + vprintf_a[1] + "[temp_iterator] != '%');\n"]
		return_result.append(temp_result)
	return return_result

# 6.1 得到vsnprintf语句的位置
def find_vsnprintf(new_cursor):
	global parent_stack
	parent_stack.append(new_cursor)
	result = []
	if new_cursor.displayname in vsnprintf_array and new_cursor.kind == clang.cindex.CursorKind.DECL_REF_EXPR and new_cursor.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
		parent_node = parent_stack[-3]
		num_of_children = get_length(parent_node)
		if num_of_children == 5:
			temp_node = parent_node.get_children()
			param_node = temp_node.next()
			param_node = temp_node.next()
			param_node = temp_node.next()
			param_node = temp_node.next()
			if get_src_from_sr(param_node.extent) != "%s":
				param_node = temp_node.next()
				result.append([new_cursor.location.line, get_src_from_sr(param_node.extent)])
	new_cursor_stmts = new_cursor.get_children()
	# temp_void = True
	for new_cursor_stmt in new_cursor_stmts:
		# temp_void = False
		result += find_vsnprintf(new_cursor_stmt)
	parent_stack.pop()
	return result

# 6.2 获得该函数中vsnprintf语句的参数
def get_vsnprintf_param(func_cursor):
	vsnprintf_array = find_vsnprintf(func_cursor)
	return_result = []
	for vsnprintf_a in vsnprintf_array:
		temp_result = [vsnprintf_a[0], "for(int temp_iterator = 0; temp_iterator < strlen(" + vsnprintf_a[1] + "); temp_iterator++)\nassert(" + vsnprintf_a[1] + "[temp_iterator] != '%');\n"]
		return_result.append(temp_result)
	return return_result

# 处理单个文件
def handle_file(file_path):
	# global file_number
	# file_number += 1
	# print "----[", file_number, "]----"
	# print file_path

	# 1. fprintf
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	insert_array = []
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_fprintf_param(child)

	# 2. printf
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_printf_param(child)

	# 3. SNPRINTF
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_SNPRINTF_param(child)

	# 4. vfprint
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_vfprint_param(child)

	# 5. vprintf
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_vprintf_param(child)

	# 6. vsnprintf
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	for child in children:
		if file_path != child.location.file.name:
			continue
		insert_array += get_vsnprintf_param(child)

	# IMPORTANT: combine arrays 
	return insert_array 

	new_file_path = ""
	if len(insert_array) > 0:
		global assert_file_number
		assert_file_number += 1
		new_file_path = file_path + ".bak.c"
		write_result = write_new_file(file_path, new_file_path, insert_array, False)
	if os.path.isfile(new_file_path):
		# verify_result = smack_verification(new_file_path)
		verify_result = -1
		if verify_result == 0:
			global assert_false_count
			assert_false_count += 1
		elif verify_result == -1:
			global file_parse_error
			file_parse_error += 1

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
	# handle_file("/home/ubuntu/Document/ETAPS/demos/demo134.c")
	print "-------------------"
	print "TOTAL NUMBER OF FILE:", file_number
	print "ASSERTION-INSERTED FILES:", assert_file_number
	print "VERIFIED-FALSE:", assert_false_count
	print "PARSE-ERROR:", file_parse_error
	print "-------------------"
	
# END Author Cong Wang 




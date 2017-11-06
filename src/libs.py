# -*- coding: utf-8 -*-  
import clang.cindex

from common_lib import get_src_from_sr, check_pycparser_passed, write_new_file, get_case_value

# 得到赋值语句的位置
def find_assign(if_expr):
	if_expr_stmts = if_expr.get_children()
	for if_expr_stmt in if_expr_stmts:
		if if_expr_stmt.kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
			print get_src_from_sr(if_expr_stmt.extent)
			print if_expr_stmt.kind, if_expr_stmt.type.kind
			if_expr_bin = if_expr_stmt.get_children()
			while True:
				val = if_expr_bin.next()	
				if val.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
					if_expr_bin = val
					break
				else:
					if_expr_bin = val.get_children()
			if type(if_expr_bin) == clang.cindex.Cursor and if_expr_bin.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
				if_expr_bin_nodes = if_expr_bin.get_children()
				return if_expr_bin_nodes
			else:
				return ""
		else:
			# print get_src_from_sr(if_expr_stmt.extent)
			# print if_expr_stmt.kind, if_expr_stmt.type.kind
			temp_result = find_assign(if_expr_stmt)
			if temp_result != "":
				return temp_result
	return ""

# 对481代码缺陷进行assertion插入
def insert_assert_cwe481(file_path, line):
	print "#input#", file_path, line
	new_file_path = file_path + ".bak"
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	# 利用广度优先策略找到对应行数所在的条件分支语句
	save_path_stack = []
	while True:
		for child in children:
			if file_path != child.location.file.name:
				continue
			if child.location.line <= line:
				save_child = child
			else:
				break
		save_path_stack.append(save_child)
		# get_src_from_sr(save_child.extent)
		# print save_child.location.line, save_child.extent, save_child.kind, save_child.type.kind
		child_length = sum(1 for new_child in save_child.get_children())
		if save_child.location.line == line and child_length == 0:
			break
		else:
			children = save_child.get_children()
	final_var_name = final_line_if = final_var_type = final_line_then = ""
	# 对save_path_stack中保存的语句路径，找到对应的行数
	for save_child in save_path_stack[::-1]:
		if save_child.kind == clang.cindex.CursorKind.IF_STMT:
			# IF语句所在行
			final_line_if = save_child.location.line
			# 定位到赋值表达式
			if_children = save_child.get_children()
			if_expr = if_children.next()
			then_expr = if_children.next()
			final_line_then = then_expr.location.line + 1
			if_expr_bin_nodes = find_assign(if_expr)
			# 变量名与变量类型
			variable = if_expr_bin_nodes.next()
			final_var_name = get_src_from_sr(variable.extent)
			final_var_type = variable.type.kind
			# print final_var_type
			if final_var_type == clang.cindex.TypeKind.INT:
				final_var_type = "int"
			elif final_var_type == clang.cindex.TypeKind.FLOAT:
				final_var_type = "float"
			elif final_var_type == clang.cindex.TypeKind.CHAR_S:
				final_var_type = "char"
			elif final_var_type == clang.cindex.TypeKind.BOOL:
				final_var_type = "bool"
			break
	# 插入的代码信息
	insert_array = []
	insert_init = final_var_type + " tempValue = " + final_var_name  + ";\n"
	insert_array.append([final_line_if, insert_init])
	insert_assert = "assert(" + final_var_name + " == tempValue);\n"
	insert_array.append([final_line_then, insert_assert])
	write_result = write_new_file(file_path, new_file_path, insert_array)
	print write_result
	return new_file_path

# 对195代码缺陷进行assertion插入
def insert_assert_cwe195(file_path, line):
	print "#input#", file_path, line
	new_file_path = file_path + ".bak"
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	save_path_stack = []
	# 利用广度优先策略找到对应行数所在的MALLOC语句
	while True:
		for child in children:
			if file_path != child.location.file.name:
				continue
			if child.location.line <= line:
				save_child = child
			else:
				break
		save_path_stack.append(save_child)
		child_length = sum(1 for new_child in save_child.get_children())
		if save_child.location.line == line and child_length == 0:
			break
		else:
			children = save_child.get_children()
	for save_child in save_path_stack[::-1]:
		if save_child.displayname == "malloc":
			final_line_malloc = save_child.location.line
			malloc_children = save_child.get_children()
			final_var_name = malloc_children.next()
			final_var_name = malloc_children.next()
			final_var_name = final_var_name.displayname
			break
	# 插入的代码信息
	insert_array = []
	insert_assert = "assert(" + final_var_name + " > 0);\n"
	insert_array.append([final_line_malloc, insert_assert])
	write_result = write_new_file(file_path, new_file_path, insert_array)
	print write_result
	return new_file_path

# 对478代码缺陷进行assertion插入
def insert_assert_cwe478(file_path, line):
	print "#input#", file_path, line
	new_file_path = file_path + ".bak"
	index = clang.cindex.Index.create()
	translation_unit = index.parse(file_path, ['-x', 'c++', '-std=c++11'])
	temp_cursor = translation_unit.cursor
	children = temp_cursor.get_children()
	save_path_stack = []
	# 利用广度优先策略找到对应行数所在的SWITCH语句
	while True:
		for child in children:
			if file_path != child.location.file.name:
				continue
			if child.location.line <= line:
				save_child = child
			else:
				break
		save_path_stack.append(save_child)
		child_length = sum(1 for new_child in save_child.get_children())
		if save_child.location.line == line and child_length == 0:
			break
		else:
			children = save_child.get_children()
	for save_child in save_path_stack[::-1]:
		if save_child.kind == clang.cindex.CursorKind.SWITCH_STMT:
			final_line_switch = save_child.location.line
			switch_children = save_child.get_children()
			final_var_name, case_value_array = get_case_value(switch_children)
			# final_var_name = final_var_name.displayname
			break
	# 插入的代码信息
	insert_array = []
	insert_assert = []
	for case_value in case_value_array:
		insert_assert.append(final_var_name + " == " + case_value)
	insert_assert = " || ".join(insert_assert)
	insert_assert = "assert(" + insert_assert + ");\n"
	insert_array.append([final_line_switch, insert_assert])
	write_result = write_new_file(file_path, new_file_path, insert_array)
	print write_result
	return new_file_path

# 进行assertion插入的程序入口
def insert_assert_template(file_path, line, defect_type):
	# 481代码缺陷
	if defect_type == "CWE481":
		new_file_path = insert_assert_cwe481(file_path, line)
	elif defect_type == "CWE195":
		new_file_path = insert_assert_cwe195(file_path, line)
	elif defect_type == "CWE478":
		new_file_path = insert_assert_cwe478(file_path, line)
	return new_file_path

if __name__ == "__main__":
	# print check_pycparser_passed("/home/ubuntu/Download/Juliet_Template_Support")
	new_file_path = insert_assert_template("/home/ubuntu/Download/test/CWE478_Missing_Default_Case_in_Switch__basic_01.c", 33, "CWE478")
	print "#output#", new_file_path

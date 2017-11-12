# -*- coding: utf-8 -*-  
import sys
import clang.cindex
import os
import commands

# 将插入的assertion写入新的文件
def write_new_file(file_path, new_file_path, insert_asserts, need_smack=False):
	file_input = open(file_path, 'r')
	file_output = open(new_file_path, 'wb')
	try:
		list_of_all_the_lines = file_input.readlines()
		now_line = 0
		if need_smack:
			file_output.write('#include "smack.h"\n')
		else:
			file_output.write('#include <assert.h>\n#include <string.h>\n')
		file_output.write('#define INCLUDEMAIN\n')
		# 以assert作为断点，写入新的文件
		for insert_assert in insert_asserts:
			temp_line = insert_assert[0] - 1
			while now_line < temp_line:
				file_output.write(list_of_all_the_lines[now_line].replace('\r\n', os.linesep))
				now_line += 1
			file_output.write(insert_assert[1].replace('\r\n', os.linesep))
		total_length = len(list_of_all_the_lines)
		while now_line < total_length:
			file_output.write(list_of_all_the_lines[now_line].replace('\r\n', os.linesep))
			now_line += 1
	except Exception, e:
		return "Fail"
	finally:
		file_input.close()
		file_output.close()
	return "Succeed", new_file_path


# 根据SourceRange变量获得源码
def get_src_from_sr(sr):
	if type(sr) == clang.cindex.SourceRange:
		try:
			start_pos = sr.start.offset
			end_pos = sr.end.offset
			text_file = sr.start.file.name
			try:
				f = open(text_file, "r")
				f.seek(start_pos, 0)  
				text_read = f.read(end_pos - start_pos)  
				f.close()  
			except Exception, e:
				return ""
			return text_read
		except Exception as e:
			return ""
	else:
		return ""

# 用来检查dir目录下的c文件是否可以通过libclang的转化
def check_pycparser_passed(tmp_dir):
	result = 0
	curr_dir = tmp_dir
	files = os.listdir(tmp_dir)
	parse_true = 0
	parse_false = 0
	for tmp_file in files:
		new_file = os.path.join(curr_dir, tmp_file)
		if os.path.isfile(new_file) and (tmp_file.endswith(".c") or tmp_file.endswith(".cpp")):
			try:
				index = clang.cindex.Index.create()
				tu = index.parse(new_file)
				sys.stdout.flush()
				parse_true += 1
			except Exception, e:
				sys.stdout.flush()
				parse_false += 1
		elif os.path.isdir(new_file):
			new_true, new_false = check_pycparser_passed(new_file)
			parse_true += new_true
			parse_false += new_false
	return parse_true, parse_false

# 获得switch语句中case的数值
def get_case_value(switch_children):
	values = []
	temp_variable = switch_children.next()
	variable = get_src_from_sr(temp_variable.extent)

	case_stmts = switch_children.next().get_children()
	for case_stmt in case_stmts:
		case_children = case_stmt.get_children()
		temp_void = True
		for case_child in case_children:
			temp_void = False
			temp_value = get_src_from_sr(case_child.extent)
			break
		if not temp_void:
			values.append(temp_value) 
	return variable, values

# 获得验证的结果
def smack_verification(new_file_path):
	# print 'smack ' + new_file_path
	(status, output) = commands.getstatusoutput('smack ' + new_file_path)
	output_array = output.split("\n")  
	last_line_output = output_array[-1]
	# print last_line_output
	if last_line_output == "SMACK found an error.":
		return 0
	elif last_line_output == "SMACK found no errors with unroll bound 1.":
		return 1
	else:
		return -1

# 得到node子结点的数量
def get_length(node):
	node_children = node.get_children()
	result = 0
	for node_child in node_children:
		result += 1
	return result

# END Author Cong Wang 


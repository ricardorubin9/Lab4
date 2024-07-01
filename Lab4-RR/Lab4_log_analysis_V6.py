import pandas as pd
import re
import os
import sys 

def main():
    # Get the log file path from the command line
    log_path= get_file_path_from_cmd_line(1)
    
    if os.path.isfile(log_path):
        print(f"The input file {log_path} exists")
    else:
        print(f"The path is not found!")    
        sys.exit(1)

   ## log_path="gateway.log" 
    print (f"The file to analyze is: {log_path}")

    regex='message'  #STEP 4 message records
    filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=False)
    regex='sshd'  #STEP 5a the gateway firewall log
    filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=False)
    regex='invalid'  #STEP 5b invalid records
    filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=False)
    regex='Invalid.*220.195.35.40'  #STEP 5c invalid and ip=220.195.35.40 records
    filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=False)
    regex='error'  #STEP 5d error records
    filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=False)
    regex='pam'  #STEP 5e pam records
    filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=False)
    regex='src=.*?.*dst=.*?'  #STEP 7 records
    filter_log_by_regexT(log_path, regex, ignore_case=True, print_summary=True, print_records=False)
    regex='dpt=.*?'  #STEP 8 records
    Count_record_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=False) 
    regex='src=.*?.*dst=.*?.*spt=.*?.*dpt='  #STEP 9 report
    report_log_by_regexT(log_path, regex, ignore_case=True, print_summary=True, print_records=True)
    regex='invalid'  #STEP 11 report
    reportInvalid_log_by_regexT(log_path, regex, ignore_case=True, print_summary=True, print_records=True)
    regex='Invalid.*220.195.35.40'  #STEP 12 invalid records
    Report_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=True)
    
    return


def get_file_path_from_cmd_line(param_num=1):
    """Gets a file path from a command line parameter.

    Exits script execution if no file path is specified as a command 
    line parameter or the specified path is not for an existing file.

    Args:
        param_num (int): Parameter number from which to look for file path. Defaults to 1.

    Returns:
        str: File path
    """
    # TODO: Implement the function body per Step 3

    print(f"Número de argumentos recibidos: {len(sys.argv)}")
    print(f"Argumentos recibidos: {sys.argv}")

    if len(sys.argv) <= param_num: 
        print(f"No file path specified in command line")
        file_path=sys.argv [param_num]

    file_path = sys.argv[param_num]

    if not os.path.isfile(file_path): 
        print(f"The file is not found:")
        sys.exit(1)

    return file_path  
#return

def filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=True):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')
        
    # Print summary of results, if enabled
    if print_summary is True:
        print("SUMMARY:\n")
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')

    return (filtered_records, captured_data)

#Filter records and generate file_out
def filter_log_by_regexT(log_path, regex, ignore_case=True, print_summary=True, print_records=True):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')

    # Print summary of results, if enabled
    if print_summary is True:
        print("SUMMARY:\n")
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')
   
    campos_T = [["SRC", "DST", "LEN"]]
    list_campos= []
    for record in filtered_records:
        record_div=re.split(r'\sSRC=|DST=|LEN=|TOS=+',record)    
        for j in range(1,4):
                 list_campos.append(record_div[j])   
        campos_T.append(list_campos)
        list_campos= []
    print(campos_T)
    list_C_df=pd.DataFrame(campos_T)
    list_C_df.to_csv("Step7.csv",index=False, header=False)       
    return (filtered_records, captured_data)

def Report_log_by_regex(log_path, regex, ignore_case=True, print_summary=True, print_records=True):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    ##print(f"Se encuentra en la funcion filter_log_by_regex log_path={log_path} regex={regex}\n")
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')

    # Print summary of results, if enabled
    if print_summary is True:
        print("SUMMARY:\n")
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')
   
    df=pd.DataFrame(filtered_records)
    df.to_csv("Step12_InvalidUser.txt",index=False, header=False)       
    return (filtered_records, captured_data)


#Step 8. Count DPT
def Count_record_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0
    
    Info_DPT={
           "DPT": []
    }
    
    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')

    # Print summary of results, if enabled
    if print_summary is True:
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')
    
    for record in filtered_records:
        record_div=re.split(r'\sDPT=|LEN=|WINDOW=|TOS=',record) 
        Info_DPT["DPT"].append (record_div[3])
    
    df=pd.DataFrame(Info_DPT)
    df.sort_values(by='DPT', inplace=True)
    df_group_grantot =df.groupby("DPT")
    df_grantotal=df_group_grantot["DPT"].count()
    df_grantotal.sort_values()
    sorted_final=dict(sorted(df_grantotal.items(), key=lambda item:item[1], reverse=True))
    print("Count DPTs")
    print(df_grantotal)
    df_grantotal.to_csv("Step8_countDPT.txt")
    print("\nTOTAL BY DTP sorted largest to smallest\n")
    print(sorted_final)

    return (filtered_records, captured_data)


# STEP 9. Report of DPT
def report_log_by_regexT(log_path, regex, ignore_case=True, print_summary=True, print_records=True):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')

    # Print summary of results, if enabled
    if print_summary is True:
        print("SUMMARRY:\n")
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')
   
    campos_T = [["DATE", "TIME", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port"]]
    list_campos= []
    v_date=[]
    v_day=""
    v_month=""
    v_time=""
    v_guion="-"
   ## df_list=pd.DataFrame(filtered_records)    
   ## print(f"dataFrame formado: {df_list}")
    for record in filtered_records:      
        record_div=re.split(r'myth|SRC=|DST=|LEN=|TOS=|SPT=|DPT=|WINDOW=+',record) 
        v_date=re.split(r'\s+',record_div[0])
        v_month=v_date[0]
        v_day=v_date[1]+v_guion+v_month
        v_time=v_date[2]
        list_campos.append(v_day)
        list_campos.append(v_time)
        list_campos.append(record_div[2])
        list_campos.append(record_div[3])
        list_campos.append(record_div[6])
        list_campos.append(record_div[7])  
        campos_T.append(list_campos)
        list_campos= []
        
    list_C_df=pd.DataFrame(campos_T)
    list_C_df.to_csv("Step9Report.csv",index=False, header=False)       
    return (filtered_records, captured_data)


# STEP 11. Report of Invalid user
def reportInvalid_log_by_regexT(log_path, regex, ignore_case=True, print_summary=True, print_records=True):
    """Gets a list of records in a log file that match a specified regex.

    Args:
        log_file (str): Path of the log file
        regex (str): Regex filter
        ignore_case (bool, optional): Enable case insensitive regex matching. Defaults to True.
        print_summary (bool, optional): Enable printing summary of results. Defaults to False.
        print_records (bool, optional): Enable printing all records that match the regex. Defaults to False.

    Returns:
        (list, list): List of records that match regex, List of tuples of captured data
    """
    # Initalize lists returned by function
    filtered_records = []
    captured_data = []

    # Set the regex search flag for case sensitivity
    search_flags = re.IGNORECASE if ignore_case else 0

    # Iterate the log file line by line
    with open(log_path, 'r') as file:
        for record in file:
            # Check each line for regex match
            match = re.search(regex, record, search_flags)
            i+=1
            if match:
                # Add lines that match to list of filtered records
                filtered_records.append(record[:-1]) # Remove the trailing new line
                # Check if regex match contains any capture groups
                if match.lastindex:
                    # Add tuple of captured data to captured data list
                    captured_data.append(match.groups())

    # Print all records, if enabled
    if print_records is True:
        print(*filtered_records, sep='\n', end='\n')

    # Print summary of results, if enabled
    if print_summary is True:
        print("SUMMARY:\n")
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')
   
    campos_T = [["DATE", "TIME", "Username", "IP Address"]]
    list_campos= []
    v_date=[]
    v_day=""
    v_month=""
    v_time=""
    v_guion="-"
    for record in filtered_records:      
        record_div=re.split(r'user\s|from\s+',record) 
        v_date=re.split(r'\s+',record_div[0])
        v_month=v_date[0]
        v_day=v_date[1]+v_guion+v_month
        v_time=v_date[2]
        list_campos.append(v_day)
        list_campos.append(v_time)
        list_campos.append(record_div[1])
        list_campos.append(record_div[2])  
        campos_T.append(list_campos)
        list_campos= []
    list_C_df=pd.DataFrame(campos_T)
    list_C_df.to_csv("Step11Report.csv",index=False, header=False)      
    return (filtered_records, captured_data)

if __name__ == '__main__':
    main()      
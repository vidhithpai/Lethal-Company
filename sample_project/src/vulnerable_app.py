import os

def execute_query(query):
    os.system(query)

def process_data(data):
    clean_data = data.strip()
    execute_query(clean_data)

def input_handler():
    user_input = input("Enter command: ")
    process_data(user_input)

import os
DB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_NAME = os.path.join(DB_DIR, 'members.db')
print(f'DB_DIR: {DB_DIR}')
print(f'DB_NAME: {DB_NAME}')
print(f'Current dir: {os.getcwd()}')
print(f'Files in current dir: {os.listdir(".")}')
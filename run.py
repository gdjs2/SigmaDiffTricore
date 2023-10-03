import argparse
import os
import subprocess

GRAPHS_DIR = './graphs'
GRAPHS_IMAGE_1 = os.path.join(GRAPHS_DIR, 'graph_image1.txt')
GRAPHS_IMAGE_2 = os.path.join(GRAPHS_DIR, 'graph_image2.txt')

def check_env():
    if not os.path.exists(GRAPHS_DIR):
        os.makedirs(GRAPHS_DIR)
        print('Create directory: {}'.format(GRAPHS_DIR))

def init_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--ghidra_home', type=str, required=True, help='The home path to ghidra')
    parser.add_argument('-p', '--project_path', type=str, required=True, help='The path to the project')
    parser.add_argument('--image1', type=str, required=True, help='The path to the first image')
    parser.add_argument('--image2', type=str, required=True, help='The path to the second image')

    args = parser.parse_args()
    return args.ghidra_home, args.project_path, args.image1, args.image2

def execute_scripts():
    # Analyzer path
    analyzer = os.path.join(GHIDRA_HOME, 'support', 'analyzeHeadless')    
    # Define the commands
    command = [analyzer, PROJECT_PATH, PROJECT_NAME, 
               '-processor', 'tricore:LE:32:default', 
               '-scriptPath', SCRIPT_PATH, 
               '-preScript', 'DisassembleAll',  
               '-deleteProject', '-overwrite']
    
    command_image1 = command + ['-import', IMAGE1, '-postScript', 'SigmadiffTricore', GRAPHS_IMAGE_1]
    command_image2 = command + ['-import', IMAGE2, '-postScript', 'SigmadiffTricore', GRAPHS_IMAGE_2]
    subprocess.run(command_image1)
    subprocess.run(command_image2)

if __name__ == '__main__':

    # Predefine some constants
    GHIDRA_HOME, PROJECT_PATH, IMAGE1, IMAGE2 = init_args()
    PROJECT_NAME = 'SigmadiffTricore'
    SCRIPT_PATH = './'

    # Print some information
    print('GHIDRA_HOME: {}'.format(GHIDRA_HOME))
    print('PROJECT_PATH: {}'.format(PROJECT_PATH))
    print('IMAGE1: {}'.format(IMAGE1))
    print('IMAGE2: {}'.format(IMAGE2))
    print('PROJECT_NAME: {}'.format(PROJECT_NAME))

    # Check the environment
    check_env()
    # Execute the scripts
    execute_scripts()
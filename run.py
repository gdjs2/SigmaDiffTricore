import argparse
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--ghidra_home', type=str, required=True, help='The home path to ghidra')
    parser.add_argument('-p', '--project_path', type=str, required=True, help='The path to the project')
    parser.add_argument('--image1', type=str, required=True, help='The path to the first image')
    parser.add_argument('--image2', type=str, required=True, help='The path to the second image')

    args = parser.parse_args()
    GHIDRA_HOME = args.ghidra_home
    PROJECT_PATH = args.project_path
    IMAGE1 = args.image1
    IMAGE2 = args.image2
    PROJECT_NAME = 'SigmadiffTricore'
    SCRIPT_PATH = './'


    print('GHIDRA_HOME: {}'.format(GHIDRA_HOME))
    print('PROJECT_PATH: {}'.format(PROJECT_PATH))
    print('IMAGE1: {}'.format(IMAGE1))
    print('IMAGE2: {}'.format(IMAGE2))
    print('PROJECT_NAME: {}'.format(PROJECT_NAME))

    analyzer = os.path.join(GHIDRA_HOME, 'support', 'analyzeHeadless');
    
    command = [analyzer, PROJECT_PATH, PROJECT_NAME, 
               '-processor', 'tricore:LE:32:default', 
               '-scriptPath', SCRIPT_PATH, 
               '-preScript', 'DisassembleAll', 
               '-postScript', 'SigmadiffTricore', 
               '-deleteProject', 'overwrite']
    
    



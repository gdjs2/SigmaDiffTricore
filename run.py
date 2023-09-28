import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ghidra_home', type=str, required=True, help='The home path to ghidra')
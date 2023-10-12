import argparse
from collections import defaultdict
import os
import subprocess

import torch
import pickle

import numpy as np
from loguru import logger
from rich.console import Console
from rich.progress import track

GRAPHS_DIR = "./tmp/graphs"
SIGMADIFF_OUT_DIR = "./tmp/sigmadiff_out"
PROJECT_NAME = "SigmadiffTricore"
SCRIPT_PATH = "./ghidra_scripts/tricore;./ghidra_scripts/sigmadiff"
DOC2VEC_PATH = "./doc2vec"
DOC2VEC_MODEL = "Doc2Vec_Model.pkl"

def init_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-g", "--ghidra_home", type=str, required=True, help="The home path to ghidra"
    )
    parser.add_argument(
        "-p", "--project_path", type=str, required=True, help="The path to the project"
    )
    parser.add_argument(
        "--image1", type=str, required=True, help="The path to the first image"
    )
    parser.add_argument(
        "--image2", type=str, required=True, help="The path to the second image"
    )

    args = parser.parse_args()
    return args.ghidra_home, args.project_path, args.image1, args.image2


def execute_graph_generation_scripts(image1_path, image2_path):
    analyzer = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")
    pre_command = [
        analyzer,
        PROJECT_PATH,
        PROJECT_NAME,
        "-processor",
        "tricore:LE:32:default",
        "-preScript",
        "DisassembleAll",
        "-scriptPath",
        SCRIPT_PATH,
        "-deleteProject",
        "-overwrite",
    ]

    def execute_single(image_path):
        image_name = os.path.basename(image_path)
        image_graph = os.path.join(GRAPHS_DIR, image_name, "graph.json")
        image_sigmadiff_out = os.path.join(SIGMADIFF_OUT_DIR, image_name)
        image_log_dir = os.path.join(image_sigmadiff_out, "logs")
        image_ghidra_log = os.path.join(image_log_dir, "application.log")
        image_script_log = os.path.join(image_log_dir, "script.log")

        command = pre_command + [
            "-log",
            image_ghidra_log,
            "-scriptLog",
            image_script_log,
            "-import",
            image_path,
            "-postScript",
            "SigmadiffTricore",
            image_graph,
            "-postScript",
            "VSAPCode",
            image_sigmadiff_out,
        ]

        logger.info("Executing the command: {}".format(command))
        with console.status(
            "[bold green]Generating the graphs & Preparing for embedding generation for {}(It may take a while) ...".format(image_name)
        ) as status:
            proc = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status.update("[bold green]Finish generating the graphs & Preparing for embedding generation for {}!".format(image_name))

        if proc.returncode != 0:
            logger.error("Failed to execute the command: {}. Please check log files under: {}".format(command, image_log_dir))
            exit(1)

    execute_single(image1_path)
    execute_single(image2_path)


def generate_embeddings(image1_path, image2_path):
    MODEL_PATH = os.path.join(DOC2VEC_PATH, DOC2VEC_MODEL)

    def generate_single_embedding(image_path):

        image_name = os.path.basename(image_path)
        image_sigmadiff_out = os.path.join(SIGMADIFF_OUT_DIR, image_name)
        image_embedding = os.path.join(image_sigmadiff_out, "embedding.pkl")

        node_label_file = os.path.join(
            image_sigmadiff_out, image_name + "_nodelabel.txt"
        )
        edge_file = os.path.join(image_sigmadiff_out, image_name + "_edges.txt")

        model = pickle.load(open(MODEL_PATH, "rb"))

        last_node_seq = 0
        func_dict = {}
        func_node_list = defaultdict(list)
        this_func = ""

        label_file = open(node_label_file, "r")
        lines = label_file.readlines()
        for each_line in lines:
            if each_line.startswith("#"):
                this_func = each_line.strip().strip("#")
                continue
            records = each_line.strip().split("|&|")

            node_seq = int(records[0])
            func_dict[node_seq] = this_func
            func_node_list[this_func].append(node_seq)

            if node_seq > last_node_seq:
                last_node_seq = node_seq

        embedding_seq_1 = [0.0 for x in range(0, last_node_seq + 1)]
        type_list = {}
        lineNum_list = {}
        value_dict = {}
        decompile_dict = {}

        label_file = open(node_label_file, "r")
        lines = label_file.readlines()

        for each_line in track(lines):
            records = each_line.strip().split(", ")

            if each_line.startswith("#"):
                continue
            records = each_line.strip().split("|&|")

            node_seq = int(records[0])

            token = records[1]
            token_type = records[2]

            token_list = token.split(" ")
            this_embedding = model.infer_vector(token_list)
            embedding_seq_1[node_seq] = this_embedding

            if token_type == "null":
                this_line_type = set()
                type_list[node_seq] = this_line_type
            else:
                this_line_type = set()
                types = token_type.split("##")
                for each_type in types:
                    if not each_type == "":
                        this_line_type.add(each_type)
                type_list[node_seq] = this_line_type

            token_value = records[3]
            if token_value == "null":
                this_line_type = set()
                value_dict[node_seq] = this_line_type
            else:
                this_line_type = set()
                types = token_value.split("##")
                for each_type in types:
                    if not each_type == "":
                        this_line_type.add(each_type)
                value_dict[node_seq] = this_line_type

            decompile_code = records[4]
            decompile_dict[node_seq] = decompile_code

            lineNum = records[5]
            lineNum_list[node_seq] = lineNum

        edges = []
        edges_dict = defaultdict(list)
        graph_edge_file = open(edge_file, "r")
        lines = graph_edge_file.readlines()
        for each_line in lines:
            records = each_line.strip().split(", ")
            float_list = list(map(float, [records[0], records[1]]))
            ndarray = np.array(float_list)
            ndarray = ndarray.astype(int)
            edges.append(ndarray)
            edges_dict[int(records[0])].append(int(records[1]))
        
        embedding = torch.tensor(embedding_seq_1)
        all_func_emb = []
        for func in func_node_list.keys():
            node_ids = func_node_list[func]
            embs = embedding[node_ids]
            func_emb = torch.mean(embs, dim=0)
            all_func_emb.append(func_emb)
        with open(image_embedding, "wb") as f:
            pickle.dump(torch.stack(all_func_emb), f, protocol=4)

    generate_single_embedding(image1_path)
    generate_single_embedding(image2_path)

if __name__ == "__main__":
    console = Console()
    logger.remove()
    logger.add(console.log)
    
    # Predefine some constants
    GHIDRA_HOME, PROJECT_PATH, IMAGE1, IMAGE2 = init_args()

    # Print some information
    logger.info("GHIDRA_HOME: {}".format(GHIDRA_HOME))
    logger.info("PROJECT_PATH: {}".format(PROJECT_PATH))
    logger.info("IMAGE1: {}".format(IMAGE1))
    logger.info("IMAGE2: {}".format(IMAGE2))
    logger.info("PROJECT_NAME: {}".format(PROJECT_NAME))

    # Execute the scripts
    execute_graph_generation_scripts(IMAGE1, IMAGE2)
    # Generate embeddings
    generate_embeddings(IMAGE1, IMAGE2)

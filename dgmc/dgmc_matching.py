from collections import defaultdict
import json
import pickle
import torch

def build_graph(image_graph, embedding):

    with open(image_graph, 'r') as f:
        graph = json.load(f)
    
    id2node = []
    emb_list = []
    node2id = {}
    for function_node in graph['functionNodes']:
        id2node.append(function_node)
        node2id[function_node] = len(id2node)-1
        emb_list.append(embedding[function_node])
        emb = embedding[function_node]
    for var_node in graph['variableNodes']:
        id2node.append(var_node)
        node2id[var_node] = len(id2node)-1

    edges = []
    for edge_type in ['f2fEdges', 'f2vEdges', 'v2fEdges', 'v2vEdges']:
        for edge in graph[edge_type]:
            src, dst = edge['from'], edge['to']
            edges.append((node2id[src], node2id[dst]))

    edges = torch.as_tensor(edges, dtype=torch.int64).t()
    





# if __name__ == "__main__":
#     build_graph('/Users/gdjs2/Desktop/sigmadiff/script/SigmaDiffTricore/tmp/graphs/D1711A05C000_MY13B6.bin/graph.json', '/Users/gdjs2/Desktop/sigmadiff/script/SigmaDiffTricore/tmp/sigmadiff_out/D1711A05C000_MY13B6.bin/embedding.pkl')
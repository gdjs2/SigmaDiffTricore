# Edge feature: read, write, call, call_rev, adjacency_next, adjacency_prev
import pickle
from collections import defaultdict, Counter

import torch
from dgmc import DGMC
from dgmc.models import SplineCNN, RelCNN
from torch import nn
import torch.nn.functional as F


class GraphModel(nn.Module):
    def __init__(self, in_channels, out_channels):
        super().__init__()
        # SplineCNN
        psi_1 = RelCNN(in_channels, out_channels, num_layers=3, dropout=0.2)
        psi_2 = RelCNN(64, 64, num_layers=3, dropout=0)
        self.dgmc = DGMC(psi_1, psi_2, num_steps=None, k=25)
        # self.emb = nn.Embedding(6, 2)
        self.loss = self.dgmc.loss
        self.acc = self.dgmc.acc
        self.hits_at_k = self.dgmc.hits_at_k

    def forward(self, x1, x2, edge1, edge2, y):
        # w = self.emb.weight
        # attr1 = []
        # for idx, e in enumerate(edge1):
        #     attr1.extend([idx] * e.size(1))
        # attr1 = w[attr1]
        # attr2 = []
        # for idx, e in enumerate(edge2):
        #     attr2.extend([idx] * e.size(1))
        # attr2 = w[attr2]
        edge1 = torch.cat(edge1, dim=1)
        edge2 = torch.cat(edge2, dim=1)

        # assert torch.all(edge1 < len(x1))
        # assert torch.all(edge2 < len(x2))
        # assert torch.all(y < max(len(x1), len(x2)))

        # _, S_L = self.dgmc(x1, edge1, attr1, None, x2, edge2, attr2, None, y)
        _, S_L = self.dgmc(x1, edge1, None, None, x2, edge2, None, None, y)
        return S_L


def add_base(name):
    return name[:4] + '8' + name[5:]


def read_graph(edge_path):
    with open(edge_path, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()
    func_cnt = int(lines[0])
    func_names = lines[1:func_cnt+1]
    var_cnt = int(lines[func_cnt+1])
    idx = func_cnt+1
    var_names = list(map(int, lines[idx+1:idx+1+var_cnt]))
    var_names.sort()
    idx = idx+1+var_cnt
    cg_edge_cnt = int(lines[idx])
    cg_edges = lines[idx+1:idx+1+cg_edge_cnt]
    idx = idx+1+cg_edge_cnt
    write_cnt = int(lines[idx+1])
    write_edges = lines[idx+2:idx+2+write_cnt]
    idx = idx+2+write_cnt
    read_cnt = int(lines[idx+1])
    read_edges = lines[idx+2:idx+2+read_cnt]
    idx = idx+2+read_cnt
    var_var_cnt = int(lines[idx+1])
    var_edges = lines[idx+2:idx+2+var_var_cnt]

    callgraph = defaultdict(set)
    for edge in cg_edges:
        f0, f1 = edge.split(' ')
        if f0.startswith('thunk') and f1.startswith('thunk'):
            print(f0, f1)
            continue
        callgraph[f0].add(f1)

    # Remove thunk
    thunk_to_remove = set()
    for k, v in callgraph.items():
        if k.startswith('thunk'):
            thunk_to_remove.add(k)
            continue
        to_remove = []
        to_add = []
        for vv in v:
            if not vv.startswith('thunk'):
                continue
            callee_set = callgraph[vv]
            assert len(callee_set) == 1
            callee = next(iter(callee_set))
            assert not callee.startswith('thunk')
            to_add.append(callee)
            to_remove.append(vv)
        for vv in to_remove:
            v.remove(vv)
        v.update(to_add)
    for v in thunk_to_remove:
        del callgraph[v]

    def parse_edges(edges):
        output = defaultdict(list)
        for edge in edges:
            e0, e1 = edge.split(' ')
            try:
                e0 = int(e0)
                output[e1].append(e0)
                continue
            except ValueError:
                pass
            try:
                e1 = int(e1)
                output[e0].append(e1)
                continue
            except ValueError:
                pass
            assert False
        return output

    read_edges = parse_edges(read_edges)
    write_edges = parse_edges(write_edges)

    var_name_to_id = {}
    for name in var_names:
        var_name_to_id[name] = len(var_name_to_id)

    return callgraph, read_edges, write_edges, var_name_to_id


def read_emb(emb_path, name_list):
    with open(emb_path, 'rb') as f:
        emb = pickle.load(f)
    with open(name_list, 'r', encoding='utf-8') as f:
        name_list = f.read().splitlines()
    name_to_id = {}
    for name in name_list:
        name = add_base(name)
        name_to_id[name] = len(name_to_id)
    return emb, name_to_id


def convert_cnt_to_list(edges):
    d = defaultdict(list)
    for name, l in edges.items():
        d[len(l)].append(name)
    return d


class RestrictedDict(dict):
    def __setitem__(self, key, value):
        if key not in self:
            return super().__setitem__(key, value)
        val = self[key]
        assert val == value


def build_graph():
    emb_dir = './firmware_image1.bin_vs_firmware_image2.bin'
    edge_dir = './graphs'

    def load(idx):
        emb, name_to_id = read_emb(f'{emb_dir}/funcemb{idx}.pkl', f'{emb_dir}/funcname{idx}.txt')
        callgraph, read_edges, write_edges, var_name_to_id = read_graph(f'{edge_dir}\\graph_image{idx}.txt')

        for k, v in var_name_to_id.items():
            var_name_to_id[k] = v + len(name_to_id)

        # node list
        # [func0, func1, ... funcN, var0, var1, .., varN]
        # edge list: 2-D list [2, N]
        # [[0, 1, 2, 3], [1, 2, 3, 4]]
        cg_edges = []
        for caller, callee_list in callgraph.items():
            if not (caller_id := name_to_id.get(caller)):
                print('caller', caller)
                continue
            for callee in callee_list:
                if not (callee_id := name_to_id.get(callee)):
                    print('callee', callee)
                    continue
                cg_edges.append((caller_id, callee_id))
        # [[0, 1], [1,2], [2,3]]
        cg_edges = torch.as_tensor(cg_edges, dtype=torch.int64).t()
        cg_edges_rev = cg_edges[[1, 0]]

        var_edges = [[], []]
        for idx, edges in enumerate([read_edges, write_edges]):
            for func, var_list in edges.items():
                if not (func_id := name_to_id.get(func)):
                    print(func)
                    continue
                for v in var_list:
                    vid = var_name_to_id[v]
                    var_edges[idx].append((func_id, vid))
        var_read_edges, var_write_edges = var_edges
        var_read_edges = torch.as_tensor(var_read_edges, dtype=torch.int64).t()
        var_write_edges = torch.as_tensor(var_write_edges, dtype=torch.int64).t()

        # e.g. from: [0, 1, 2, 3]
        adj_edges_from = torch.arange(len(name_to_id), len(name_to_id) + len(var_name_to_id) - 1, dtype=torch.int64)
        # e.g. [1, 2, 3, 4]
        adj_edges_to = adj_edges_from + 1
        # e.g. [[0, 1, 2, 3], [1, 2, 3, 4]]
        adj_edges = torch.stack((adj_edges_from, adj_edges_to), dim=0)
        adj_edges_rev = adj_edges[[1, 0]]

        var_nodes = torch.randn(len(var_name_to_id), emb.size(1), dtype=emb.dtype)
        nodes = torch.cat((emb, var_nodes), dim=0)

        return cg_edges, cg_edges_rev, var_read_edges, var_write_edges, adj_edges, adj_edges_rev, nodes, name_to_id, var_name_to_id, read_edges, write_edges

    *edges1, nodes1, name_to_id1, var_name_to_id1, read_edge1, write_edge1 = load(1)
    *edges2, nodes2, name_to_id2, var_name_to_id2, read_edge2, write_edge2 = load(2)

    # in-deg, out-deg: funcA read 2 var, write 3 var -> (2, 3)
    # cnt -> tuple list
    # 1 -> [(2,3)]
    # 15 -> [(1,0), (0,1)]

    # firmware 1: funca, b, c: (2,3)
    # a: read 1, 2, write 1, 2, 3 -> 56567
    # b: read 2, 3, write 4, 5, 6
    # firmware 2: func d, e, f: (2, 3)
    # d: read 5, 6, write 567
    # e: 56567
    read_cnt1 = convert_cnt_to_list(read_edge1)
    read_cnt2 = convert_cnt_to_list(read_edge2)
    write_cnt1 = convert_cnt_to_list(write_edge1)
    write_cnt2 = convert_cnt_to_list(write_edge2)

    matched_funcs = RestrictedDict()
    matched_vars = RestrictedDict()

    def refine(cnt1, cnt2, edge1, edge2):
        k = list(cnt1.keys() & cnt2.keys())
        k.sort(reverse=True)
        for kk in k:
            v1 = cnt1[kk]
            v2 = cnt2[kk]
            if len(v1) == 1 and len(v2) == 1:
                f1 = v1[0]
                f2 = v2[0]
                matched_funcs[f1] = f2
                e1 = edge1[f1]
                e2 = edge2[f2]
                assert len(e1) == len(e2)
                for i in range(len(e1)):
                    matched_vars[e1[i]] = e2[i]
            else:
                edge_list_list1 = [edge1[v] for v in v1]
                edge_list_list2 = [edge2[v] for v in v2]
                for i, el in enumerate(edge_list_list1):
                    for idx, e in enumerate(el):
                        if e in matched_vars:
                            el[idx] = matched_vars[e]
                    matched = []
                    for j, el2 in enumerate(edge_list_list2):
                        if el == el2:
                            matched.append((i, j))
                    if len(matched) == 1:
                        for i, j in matched:
                            matched_funcs[v1[i]] = v2[j]
    refine(read_cnt1, read_cnt2, read_edge1, read_edge2)
    refine(write_cnt1, write_cnt2, write_edge1, write_edge2)

    # TODO: plus embedding almost same func, callgraph in-degree, out-degree
    y = []
    for k, v in matched_funcs.items():
        if not (id1 := name_to_id1.get(k)):
            print(k)
            continue
        if not (id2 := name_to_id2.get(v)):
            print(v)
            continue
        y.append((id1, id2))
    for k, v in matched_vars.items():
        id1 = var_name_to_id1[k]
        id2 = var_name_to_id2[v]
        y.append((id1, id2))
    y = torch.as_tensor(y, dtype=torch.int64).t()
    return nodes1, nodes2, edges1, edges2, y


def train_model():
    # x1: [N x 128]
    x1, x2, edge1, edge2, y = build_graph()
    device = torch.device('cpu')
    model = GraphModel(x1.size(1), 64).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    x1 = x1.to(device)
    x2 = x2.to(device)
    edge1 = [e.to(device) for e in edge1]
    edge2 = [e.to(device) for e in edge2]
    y = y.to(device)
    x1 = F.normalize(x1)
    x2 = F.normalize(x2)

    def train():
        model.train()
        optimizer.zero_grad()
        S_L = model(x1, x2, edge1, edge2, y)
        loss = model.loss(S_L, y)
        loss.backward()
        optimizer.step()
        return loss

    @torch.no_grad()
    def test():
        model.eval()
        S_L = model(x1, x2, edge1, edge2, None)
        #
        hits1 = model.acc(S_L, y)
        hits10 = model.hits_at_k(10, S_L, y)
        return hits1, hits10, S_L

    print('Optimize initial feature matching...')
    model.dgmc.num_steps = 0
    for epoch in range(1, 1201):
        if epoch == 901:
            print('Refine correspondence matrix...')
            model.dgmc.num_steps = 10
            model.dgmc.detach = True

        loss = train()

        if epoch % 100 == 0:
            hits1, hits10, _ = test()
            print((f'{epoch:03d}: Loss: {loss:.4f}, Hits@1: {hits1:.4f}, Hits@10: {hits10:.4f}'))

    _, _, S_L = test()
    # 10000x10000
    # sparse matrix: indices: [[0, 1, 2], [3,4,5]], values[3,4,5]
    S_L = S_L.to_dense()
    print()


if __name__ == '__main__':
    train_model()
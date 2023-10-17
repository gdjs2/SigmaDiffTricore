import torch

from torch import nn
from dgmc.models import RelCNN
from dgmc import DGMC

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
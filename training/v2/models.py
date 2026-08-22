"""Detector-v2 challenger models (CPU-first).

Sequence encoders consume the shared masked per-packet tensor; the aggregate branch
reuses the portable Schema-A matrix. Embeddings are exposed for OOD scoring and the
dataset-origin diagnostic.
"""

from __future__ import annotations

from typing import Any

import torch
from torch import Tensor, nn


class MaskedFlatten(nn.Module):
    def forward(self, sequence: Tensor, mask: Tensor) -> Tensor:
        flat: Tensor = sequence * mask.unsqueeze(-1)
        output: Tensor = flat.reshape(flat.shape[0], -1)
        return output


class GradientReversal(torch.autograd.Function):
    """Identity forward, negated backward: the domain-adversarial core."""

    @staticmethod
    def forward(ctx: Any, x: Tensor, lambd: float) -> Tensor:
        ctx.lambd = lambd
        return x.clone()

    @staticmethod
    def backward(ctx: Any, grad_output: Tensor) -> tuple[Tensor, None]:
        return -ctx.lambd * grad_output, None


def gradient_reversal(embedding: Tensor, lambd: float) -> Tensor:
    reversed_embedding: Tensor = GradientReversal.apply(embedding, lambd)  # type: ignore[no-untyped-call]
    return reversed_embedding


class SequenceMLP(nn.Module):
    """Baseline A: flattened masked sequence plus compact MLP."""

    def __init__(
        self,
        *,
        max_length: int,
        features_per_packet: int,
        embedding_dim: int = 32,
    ) -> None:
        super().__init__()
        input_dim = max_length * features_per_packet
        self.flatten = MaskedFlatten()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, embedding_dim),
            nn.ReLU(),
        )
        self.head = nn.Linear(embedding_dim, 1)

    def embed(self, sequence: Tensor, mask: Tensor) -> Tensor:
        embedding: Tensor = self.encoder(self.flatten(sequence, mask))
        return embedding

    def forward(self, sequence: Tensor, mask: Tensor) -> Tensor:
        logit: Tensor = self.head(self.embed(sequence, mask)).squeeze(-1)
        return logit


class MaskedConvPool(nn.Module):
    """Mask-aware mean pooling after causal-free temporal convolution."""

    def __init__(self, channels: int, kernel_size: int = 3) -> None:
        super().__init__()
        padding = kernel_size // 2
        self.conv = nn.Sequential(
            nn.Conv1d(channels, 32, kernel_size=kernel_size, padding=padding),
            nn.ReLU(),
            nn.Conv1d(32, 64, kernel_size=kernel_size, padding=padding),
            nn.ReLU(),
        )

    def forward(self, sequence: Tensor, mask: Tensor) -> Tensor:
        hidden: Tensor = self.conv(sequence.transpose(1, 2))
        weights = mask.unsqueeze(1)
        pooled: Tensor = (hidden * weights).sum(dim=-1) / weights.sum(dim=-1).clamp(min=1.0)
        return pooled


class SequenceCNN(nn.Module):
    """Baseline B: small temporal CNN over the packet sequence."""

    def __init__(self, *, features_per_packet: int, embedding_dim: int = 32) -> None:
        super().__init__()
        self.pool = MaskedConvPool(features_per_packet)
        self.encoder = nn.Sequential(
            nn.Linear(64, embedding_dim),
            nn.ReLU(),
        )
        self.head = nn.Linear(embedding_dim, 1)

    def embed(self, sequence: Tensor, mask: Tensor) -> Tensor:
        embedding: Tensor = self.encoder(self.pool(sequence, mask))
        return embedding

    def forward(self, sequence: Tensor, mask: Tensor) -> Tensor:
        logit: Tensor = self.head(self.embed(sequence, mask)).squeeze(-1)
        return logit


class AggregateEncoder(nn.Module):
    def __init__(self, aggregate_dim: int, embedding_dim: int = 16) -> None:
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(aggregate_dim, 48),
            nn.ReLU(),
            nn.Linear(48, embedding_dim),
            nn.ReLU(),
        )

    def forward(self, aggregate: Tensor) -> Tensor:
        embedding: Tensor = self.network(aggregate)
        return embedding


class FusionNet(nn.Module):
    """Sequence + aggregate + connection-state fusion."""

    def __init__(
        self,
        *,
        max_length: int,
        features_per_packet: int,
        aggregate_dim: int,
        encoder: str = "mlp",
        embedding_dim: int = 32,
    ) -> None:
        super().__init__()
        if encoder not in {"mlp", "cnn"}:
            raise ValueError("fusion encoder must be 'mlp' or 'cnn'")
        if encoder == "mlp":
            self.sequence_encoder: nn.Module = SequenceMLP(
                max_length=max_length,
                features_per_packet=features_per_packet,
                embedding_dim=embedding_dim,
            )
            seq_dim = embedding_dim
        else:
            self.sequence_encoder = SequenceCNN(
                features_per_packet=features_per_packet,
                embedding_dim=embedding_dim,
            )
            seq_dim = embedding_dim
        self.aggregate_encoder = AggregateEncoder(aggregate_dim)
        combined = seq_dim + 16
        self.head = nn.Sequential(
            nn.Linear(combined, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
        )

    def embed(self, sequence: Tensor, mask: Tensor, aggregate: Tensor) -> Tensor:
        if isinstance(self.sequence_encoder, SequenceMLP | SequenceCNN):
            sequence_embedding = self.sequence_encoder.embed(sequence, mask)
        else:  # pragma: no cover - defensive
            raise TypeError("unsupported sequence encoder")
        combined: Tensor = torch.cat(
            (sequence_embedding, self.aggregate_encoder(aggregate)), dim=1
        )
        return combined

    def forward(self, sequence: Tensor, mask: Tensor, aggregate: Tensor) -> Tensor:
        logit: Tensor = self.head(self.embed(sequence, mask, aggregate)).squeeze(-1)
        return logit

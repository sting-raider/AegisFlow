from __future__ import annotations

from typing import Any, cast

import numpy as np
import torch
from torch import nn


class DenoisingAutoencoder(nn.Module):
    """Compact CPU autoencoder used only as one open-set signal."""

    def __init__(self, input_dim: int, hidden_dim: int = 12, bottleneck_dim: int = 5) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.bottleneck_dim = bottleneck_dim
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, bottleneck_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )

    def forward(self, values: torch.Tensor) -> torch.Tensor:
        return cast(torch.Tensor, self.decoder(self.encoder(values)))

    def artifact(self) -> dict[str, Any]:
        return {
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "bottleneck_dim": self.bottleneck_dim,
            "state_dict": self.state_dict(),
        }

    @classmethod
    def from_artifact(cls, artifact: dict[str, Any]) -> DenoisingAutoencoder:
        model = cls(
            int(artifact["input_dim"]),
            int(artifact["hidden_dim"]),
            int(artifact["bottleneck_dim"]),
        )
        model.load_state_dict(artifact["state_dict"])
        model.eval()
        return model


@torch.inference_mode()
def reconstruction_errors(model: DenoisingAutoencoder, values: np.ndarray) -> np.ndarray:
    tensor = torch.as_tensor(values, dtype=torch.float32, device="cpu")
    reconstructed = model(tensor)
    return torch.mean((reconstructed - tensor) ** 2, dim=1).cpu().numpy()

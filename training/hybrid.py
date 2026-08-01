from __future__ import annotations

import numpy as np
import torch

from packages.detection.autoencoder import DenoisingAutoencoder
from packages.features.registry import FEATURE_NAMES


def train_autoencoder(
    benign_train: np.ndarray,
    *,
    seed: int = 431,
    epochs: int = 120,
    noise_std: float = 0.06,
) -> DenoisingAutoencoder:
    """Train the CPU denoising autoencoder shared by bundle and dataset workflows."""

    values = np.asarray(benign_train, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != len(FEATURE_NAMES) or len(values) < 2:
        raise ValueError("autoencoder training requires at least two canonical benign rows")
    if not np.all(np.isfinite(values)):
        raise ValueError("autoencoder training refuses non-finite features")
    if epochs < 1 or noise_std < 0:
        raise ValueError("autoencoder training parameters are invalid")
    torch.manual_seed(seed)
    torch.set_num_threads(1)
    model = DenoisingAutoencoder(len(FEATURE_NAMES))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.004, weight_decay=1e-5)
    clean = torch.as_tensor(values, dtype=torch.float32)
    generator = torch.Generator(device="cpu").manual_seed(seed)
    model.train()
    for _ in range(epochs):
        noisy = clean + torch.randn(clean.shape, generator=generator) * noise_std
        optimizer.zero_grad(set_to_none=True)
        loss = torch.mean((model(noisy) - clean) ** 2)
        loss.backward()  # type: ignore[no-untyped-call]
        optimizer.step()
    model.eval()
    return model

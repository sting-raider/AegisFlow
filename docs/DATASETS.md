# Dataset policy

Supported adapter targets are CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, user-provided
flow CSV, and bundled synthetic smoke data. Full datasets are never committed.

Each imported dataset needs a manifest containing source URL, retrieval time, license,
expected filename/size/checksum, capture boundaries, label mapping, and transformation
history. A download must resume or fail clearly and must never substitute a different
file.

Quality reports must cover duplicates, constants, missing/infinite values, labels,
identifier leakage, train/test overlap, class distribution, suspicious predictors,
and feature drift. Raw endpoint identifiers are removed from the model vector.

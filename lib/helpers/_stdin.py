import sys


def read_batches_from_stdin(batch_size, num_fields):

  batch = []

  for line in sys.stdin:
    line = line.strip()
    if not line:
      continue

    parts = line.split()
    if len(parts) != num_fields:
      print(f"Invalid line: {line}", file=sys.stderr)
      continue

    batch.append(parts)
    if len(batch) >= batch_size:
      yield batch
      batch = []

  if batch:
    yield batch


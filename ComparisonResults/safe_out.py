"""Resolve a runner's output path without ever silently overwriting a deposited record.

A deposited runner has to write the record the manuscript names, or a reader on a clean
clone cannot reproduce it. But a runner re-run during development, or run with a changed
flag, must not quietly replace the deposit that the manifest and the paper are pinned to.

resolve() keeps the documented name and directory, and refuses to overwrite an existing
file unless the caller says so. Refusal is not an error: the run proceeds and writes to
reproduction/ beside results/, where the output can be diffed against the deposit.

  ANTIDDOS_OVERWRITE=1   write over the deposited record on purpose
  <PREFIX>_OUTDIR        send output elsewhere entirely
  <PREFIX>_OUT           change the file name
"""
import os


def resolve(results_dir, filename, prefix):
    outdir = os.environ.get(f'{prefix}_OUTDIR')
    name = os.environ.get(f'{prefix}_OUT', filename)
    if outdir:
        os.makedirs(outdir, exist_ok=True)
        return os.path.join(outdir, name)
    target = os.path.join(results_dir, name)
    if not os.path.exists(target) or os.environ.get('ANTIDDOS_OVERWRITE') == '1':
        return target
    repro = os.path.join(os.path.dirname(results_dir.rstrip(os.sep)), 'reproduction')
    os.makedirs(repro, exist_ok=True)
    alt = os.path.join(repro, name)
    print(f'[safe_out] {target} exists; writing {alt} instead.\n'
          f'[safe_out] diff it against the deposit, or set ANTIDDOS_OVERWRITE=1 to replace it.',
          flush=True)
    return alt

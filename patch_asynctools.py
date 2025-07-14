# patch_asynctools.py
from itertools import chain
from asynctools import __all__ as original_all
from asynctools import *

async_chain_from_iterable = chain

if 'async_chain_from_iterable' not in original_all:
    original_all.append('async_chain_from_iterable')

# -*- coding: utf-8 -*-
import random

__author__ = 'pahaz'
ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
digits = '0123456789'
asciis = ascii_lowercase + ascii_uppercase + digits


def get_random_string(length=12):
    """
    >>> r = get_random_string(1)
    >>> r in asciis
    True
    >>> r = get_random_string(2)
    >>> [r[0] in asciis, r[1] in asciis]
    [True, True]
    """
    return ''.join([random.choice(asciis) for _ in range(length)])

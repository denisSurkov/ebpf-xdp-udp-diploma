import os
from os import closerange

REDIRECT_TO = getattr(os, 'devnull', '/dev/null')


def daemonize(enable_stdio_inheritance=False):
    """
    http://www.faqs.org/faqs/unix-faq/programmer/faq/
    1.7 How do I get my program to act like a daemon?
    """
    if os.fork():
        os._exit(0)
    os.setsid()

    if os.fork():
        os._exit(0)

    # rwxr-xr-x
    os.umask(0o22)

    closerange(0, 3)

    fd_null = os.open(REDIRECT_TO, os.O_RDWR)
    # PEP 446, make fd for /dev/null inheritable
    os.set_inheritable(fd_null, True)

    if fd_null != 0:
        os.dup2(fd_null, 0)

    os.dup2(fd_null, 1)
    os.dup2(fd_null, 2)

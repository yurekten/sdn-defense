#!/usr/bin/env python3
import os
import sys

from ryu.base.app_manager import AppManager
from ryu.cmd import manager

from configuration import CONTROLLER_PORT

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))


def main():
    sys.path.append(CURRENT_PATH)
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append(str(CONTROLLER_PORT))
    sys.argv.append('--enable-debugger')
    sys.argv.append('--observe-links')
    sys.argv.append('sdn_defense')

    manager.main()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as err:
        print("closing kindly")
    finally:
        app_mgr = AppManager.get_instance()
        app_mgr.close()

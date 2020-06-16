#!/usr/bin/env python
import sys

from ryu.cmd import manager
from ryu.base.app_manager import AppManager

from configuration import CONTROLLER_PORT


def main():
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

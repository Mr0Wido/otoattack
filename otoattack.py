#!/usr/bin/env python3
import sys
import os


main_dir = os.path.dirname(os.path.abspath(__file__))
tool_dir = os.path.join(main_dir, "tools")
sys.path.append(tool_dir)


from tools.main import main 

if __name__ == '__main__':
    main()
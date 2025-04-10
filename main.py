from test_manager import TestManager
from test_cases import get_test_cases
from logger import Logger

logger = Logger()

def run_tests():
    test_manager = TestManager()
    for test_func, expected_output in get_test_cases():
        test_manager.add_test_case(test_func, expected_output)
    test_manager.run_tests()

def main():
    logger.log("###################################################################")
    logger.log("###################### START OF PROGRAM #############################")
    logger.log("###################################################################")

    run_tests()

    logger.log("###################################################################")
    logger.log("###################### END OF PROGRAM #############################")
    logger.log("###################################################################")

if __name__ == "__main__":
    main()
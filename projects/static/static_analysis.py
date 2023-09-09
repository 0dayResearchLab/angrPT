import r2pipe

class StaticAnalysis:
    """
    This class provides a static analysis interface.
    """

    def __init__(self, path):
        self.r = r2pipe.open(path)

    def get_function_parameters(self, addr):
        """
        Return a list of function's parameters.

        - args
        :addr: An address of the function.
        """

        self.r.cmd('s 0x%x' % addr)
        self.r.cmd('af')
        result = reversed(self.r.cmd('afv').strip().split('\n'))

        prototypes = []
        for line in result:
            if line.find('arg') >= 0:
                prototypes.append(line.split('@')[-1].strip())
            else:
                break

        return prototypes
import angr
import time
import threading 

CONSTRAINT_MODE = 'constraints'

class SwitchStateFinder(angr.ExplorationTechnique):
    """
    An exploration technique to get all states of the switch-case statement.
    """    
    def __init__(self, case):
        super(SwitchStateFinder, self).__init__()
        self._case = case
        self.switch_states = {}
        self.constraint_stashs = []
        
        ##added
        self.before_ioctl_number = None
        self.switch_block_addresses = {}
        ##yame
        self.dup = 0
        self.goodbye = 0

    def monitor_value(self, value, timeout):
        current_value = value
        def check_value():
            nonlocal current_value
            time.sleep(timeout)
            if value == current_value:
                print('IOCTL timeout')
                self.goodbye = 1
                return
        
        thread = threading.Thread(target=check_value)
        thread.start()

    def setup(self, simgr):
        self.monitor_value(self.dup, 10)
        if CONSTRAINT_MODE not in simgr.stashes:
            simgr.stashes[CONSTRAINT_MODE] = []

    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if stash == 'active' and len(simgr.stashes[stash]) > 1:
            saved_states = [] 
            for state in simgr.stashes[stash]:
                if self.dup > 30 or self.goodbye == 1:
                    break
                try:
                    io_code = state.solver.eval_one(self._case)
                    if io_code in self.switch_states: # duplicated codes
                        self.dup += 1
                        continue

                    self.switch_states[io_code] = state
                    self.switch_block_addresses[io_code] = state.solver.eval(state.regs.rip)                    
                    
                    self.switch_block_addresses = dict(sorted(self.switch_block_addresses.items(), key=lambda x : x[1]))
                    self.before_ioctl_number = io_code
                except:
                    saved_states.append(state)

            simgr.stashes[stash] = saved_states

        return simgr

    def get_states(self):
        return self.switch_states 

import re
import sys
import angr
import claripy
import archinfo
from pprint import pprint as pp

from .symbolic import explore_technique
from .symbolic import structures
from .static.static_analysis import StaticAnalysis

DispatchDeviceControl_OFFSET = 0xe0
DispatchCreate_OFFSET = 0x70

ARG_DEVICEOBJECT = 0xdead0000
ARG_DRIVEROBJECT = 0xdead1000
ARG_REGISTRYPATH = 0xdead2000

ARG_IRP = 0xdead3000
ARG_IOSTACKLOCATION = 0xdead4000

ERR_VALUE = 0x1000000

good_range = 0


hihi= False
def speculate_bvs_range(state, bvs):        
    # if not (first_sat_state-ERR_VALUE <= state.addr <= first_sat_state+ERR_VALUE):
    #     yield 'err-err'
    #     return    

    """
    Speculate a range of the symbolic variable.
    """
    inf = 0xffffffff
    minv = state.solver.min(bvs)
    maxv = state.solver.max(bvs)
    
    result = []
    if maxv == inf:  # when the max is infinite
        result.append('%d-inf' % minv)
        return result
    
    if maxv > 0x2000:
        maxv = 0x2000    
    
    i = start = minv
    while i <= maxv + 1:
        if not state.solver.satisfiable([bvs == i]):
            result.append('%d-%d' % (start, i - 1))

            # find next start
            while not state.solver.satisfiable([bvs == i]) and i <= maxv + 1:
                i += 1
            start = i
        i += 1
    
    if len(result)<1:
        result.append('%d-inf' % minv)
    return result

class WDMDriverFactory(angr.factory.AngrObjectFactory):
    """
    This class provides state presets of the Windows.
    """

    def __init__(self, *args, **kwargs):
        super(WDMDriverFactory, self).__init__(*args, **kwargs)

        # set the default calling convention
        if isinstance(self.project.arch, archinfo.ArchAMD64):
            self._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64(self.project.arch)
        else:
            raise ValueError('Unsupported architecture')

    def call_state(self, addr, *args, **kwargs):
        # Todo : little endian and big endian confliction.
        #kwargs['add_options'] = kwargs.pop('add_options', angr.options.unicorn)
        cc = kwargs.pop('cc', self._default_cc)
        kwargs['cc'] = cc

        return super(WDMDriverFactory, self).call_state(addr, *args, **kwargs)

class WDMDriverAnalysis(angr.Project):
    """
    This class provides an interface that analyzes WDM driver.
    """

    def __init__(self, *args, **kwargs):
        """
        - kwargs
        :skip_call_mode: Only functions with specific arguments are analyzed.
        """

        kwargs['auto_load_libs'] = kwargs.pop('auto_load_libs', False)
        kwargs['support_selfmodifying_code'] = True # for the skip mode
        #kwargs['use_sim_procedures'] = kwargs.pop('use_sim_procedures', False)
        
        self.driver_path = args[0]
        # Static binary analysis using radare2
        # self.static_analyzer = StaticAnalysis(self.driver_path)
        self.skip_call_mode = kwargs.pop('skip_call_mode', False)

        super(WDMDriverAnalysis, self).__init__(*args, **kwargs)
        self.factory = WDMDriverFactory(self)
        self.project = self.factory.project

        self.major_functions = {}
        self.global_variables = []

    def set_mode(self, mode, state, allowed_arguments=None):
        """
        Set a mode to respond to a variety of drivers.

        - mode
        :force_skip_call:               Don't analyze other functions.
        :skip_call:                     Only functions with specific arguments are analyzed.
        :symbolize_global_variables:    Set a Symbolic Value on every global variables.
        """
        if allowed_arguments is None:
            allowed_arguments = []

        if mode == 'force_skip_call':
            def force_skip_call(state):
                state.mem[state.regs.rip].uint8_t = 0xc3
                state.regs.rax = state.solver.BVS('ret', 64)

            state.inspect.b('call', action=force_skip_call)

        elif mode == 'skip_call':
            def skip_function_by_arguments(state):
                # Get parameters of the current function.
                parameters = []

                skip = True
                for arg_type in parameters:
                    if '+' not in arg_type:     # register
                        argument = getattr(state.regs, arg_type)
                    else:                       # stack value
                        offset = int(arg_type.split('+')[-1], 16)
                        argument = state.mem[getattr(state.regs, arg_type.split('+')[0]) + offset].uint64_t.resolved
                        
                    if argument.symbolic:
                        argument = str(argument)

                        for arg in allowed_arguments:
                            if isinstance(arg, str) and arg in argument:
                                skip = False
                    else:
                        argument = state.solver.eval(argument)

                        if argument in allowed_arguments:
                            skip = False

                    if skip == False:
                        break

                if skip:
                    state.mem[state.regs.rip].uint8_t = 0xc3
                    state.regs.rax = state.solver.BVS('ret', 64)

            state.inspect.b('call', action=skip_function_by_arguments)

        elif mode == 'symbolize_global_variables':
            self.global_variables = []

            def symbolize_global_variables(state):
                obj = self.project.loader.main_object
                mem_read_address = state.solver.eval(state.inspect.mem_read_address)
                section = obj.find_section_containing(mem_read_address)

                if mem_read_address not in self.global_variables and '.data' in str(section):
                    self.global_variables.append(mem_read_address)
                    setattr(state.mem[mem_read_address], 'uint64_t', state.solver.BVS('global_%x' % mem_read_address, 64))

            state.inspect.b('mem_read', condition=symbolize_global_variables)   

    def isWDM(self):
        """
        Return True if the driver is a WDM driver. 
        """

        return True if self.project.loader.find_symbol('IoCreateDevice') else False

    def find_device_name(self):
        """
        Return DeviceName of the driver. It searchs "DosDevices" statically.
        """

        DOS_DEVICES = "\\Device\\".encode('utf-16le')
        data = open(self.driver_path, 'rb').read()

        device_name_list = []
        cursor = 0

        while cursor < len(data):
            cursor = data.find(DOS_DEVICES, cursor)
            if cursor == -1:
                break

            terminate = data.find(b'\x00\x00', cursor)
            if ( terminate - cursor) % 2:
                terminate += 1

            match = data[cursor:terminate].decode('utf-16le')
            device_name_list.append(match)
            cursor += len(DOS_DEVICES)

        return set(device_name_list)

    def find_dispatcher(self, dispatcher_address):
        """
        Return an address of the function DispatchDeviceControl.

        - Set a breakpoint on DriverObject->MajorFunctions[MJ_DEVICE_CONTROL]
        """

        state = self.project.factory.call_state(self.project.entry, ARG_DRIVEROBJECT, ARG_REGISTRYPATH)
        if self.skip_call_mode:
            self.set_mode('skip_call', state, allowed_arguments=[ARG_DRIVEROBJECT])

        simgr = self.project.factory.simgr(state)

        # Set a breakpoint on DriverObject->MajorFuntion[MJ_DEVICE_CONTROL]
        def set_major_functions(state):
            self.major_functions['DispatchCreate'] = state.mem[ARG_DRIVEROBJECT + DispatchCreate_OFFSET].uint64_t.concrete
            self.major_functions['DispatchDeviceControl'] = state.solver.eval(state.inspect.mem_write_expr)

        state.inspect.b('mem_write',when=angr.BP_AFTER,
                        mem_write_address=ARG_DRIVEROBJECT + DispatchDeviceControl_OFFSET,
                        action=set_major_functions)

        if dispatcher_address != False:
            self.major_functions['DispatchDeviceControl'] = int(dispatcher_address, 16)
            return self.major_functions['DispatchDeviceControl']

        # DFS exploration
        simgr.use_technique(angr.exploration_techniques.dfs.DFS())
        simgr.run(until=lambda x: 'DispatchDeviceControl' in self.major_functions)

        # Second exploration
        # to skip default initialization.
        if self.major_functions['DispatchDeviceControl'] == self.major_functions['DispatchCreate']:
            for _ in range(50):
                simgr.step()

                if self.major_functions['DispatchDeviceControl'] != self.major_functions['DispatchCreate']:
                    break
        
        return self.major_functions['DispatchDeviceControl']   

    def recovery_ioctl_interface(self):
        """
        Return an IOCTL interface of the driver.

        - An IOCTL Interface contains IoControlCode, InputBufferLength and OutputBufferLength.
        """

        state = self.project.factory.call_state(self.major_functions['DispatchDeviceControl'], ARG_DRIVEROBJECT, ARG_IRP)
        self.set_mode('symbolize_global_variables', state)
        simgr = self.project.factory.simgr(state)

        io_stack_location = structures.IO_STACK_LOCATION(state, ARG_IOSTACKLOCATION)
        irp = structures.IRP(state, ARG_IRP)

        state.solver.add(irp.fields['Tail.Overlay.CurrentStackLocation'] == io_stack_location.address)
        state.solver.add(io_stack_location.fields['MajorFunction'] == 14)

        # Find all I/O control codes.
        state_finder = explore_technique.SwitchStateFinder(io_stack_location.fields['IoControlCode'])
        simgr.use_technique(state_finder)
        simgr.run(n=30)

        ioctl_interface = []

        switch_states = state_finder.get_states()
        
        for ioctl_code, case_state in switch_states.items():
            def get_constraint_states(st):
                self.set_mode('symbolize_global_variables', st)

                preconstraints = []
                for constraint in st.history.jump_guards:
                    if 'Buffer' in str(constraint):
                        preconstraints.append(str(constraint))

                simgr = self.project.factory.simgr(st)

                for _ in range(10):
                    simgr.step()
                    for state in simgr.active:
                        for constraint in state.history.jump_guards:
                            if 'BufferLength' in str(constraint) and \
                                str(constraint) not in preconstraints:
                                yield state
            constraint_states = get_constraint_states(case_state)

            print("analyze start "+hex(ioctl_code)+" addr is "+hex(case_state.addr))
            def is_there_constraint(st):
                self.set_mode('symbolize_global_variables', st)
                simgr = self.project.factory.simgr(st)
                for _ in range(10):
                    simgr.step()

                    for state in simgr.active:
                        for constraint in state.history.jump_guards:
                            if 'BufferLength' in str(constraint):
                                return True
                return False

            # Inspect what constraints are used.
            is_contraint = is_there_constraint(case_state)
           # return
            if is_contraint:
                def gogogo(st):
                    self.set_mode('symbolize_global_variables', st)
                    simgr = self.project.factory.simgr(st)
                    result = []
                    global hihi
                    hihi = False

                    def sat_state_bp(state):
                        ntstatus_value = state.solver.eval(state.inspect.mem_write_expr)
                        
                        if ntstatus_value <= 0xBFFFFFFF: 
                            global hihi
                            hihi = True
                            x= {'IoControlCode': hex(ioctl_code), 
                                'InBufferLength': list(speculate_bvs_range(state, 
                                                            io_stack_location.fields['InputBufferLength'])),
                                'OutBufferLength': list(speculate_bvs_range(state,
                                                            io_stack_location.fields['OutputBufferLength'])
                                )}
                            ioctl_interface.append(x)

                    st.inspect.b('mem_write', when=angr.BP_AFTER, 
                        mem_write_address = ARG_IRP + 0x30,action = sat_state_bp)
          
                    for _ in range(20):
                        if len(simgr.active)>0 and not hihi:
                            simgr.step()

                    founded = False
                    if hihi:
                        founded=True
                    else:    
                        for state in simgr.active:
                            symbolic_expr = state.mem[0xdead3030].int.resolved
                            concrete_value = state.solver.eval(symbolic_expr)

                        #   print("Io status is ",hex(concrete_value), state)

                            if concrete_value <0xBFFFFFFF:
                                founded = True
                                x= {'IoControlCode': hex(ioctl_code), 
                                    'InBufferLength': list(speculate_bvs_range(state, 
                                                                io_stack_location.fields['InputBufferLength'])),
                                    'OutBufferLength': list(speculate_bvs_range(state,
                                                                io_stack_location.fields['OutputBufferLength'])
                                    )}
                                ioctl_interface.append(x)
                                #print("simgr.active",x,"\n")
                                break

                    if not founded:

                        for state in simgr.deadended:
                            symbolic_expr = state.mem[0xdead3030].int.resolved
                            concrete_value = state.solver.eval(symbolic_expr)

                            #print("Io status is ",hex(concrete_value), state)

                            if concrete_value <0xBFFFFFFF:
                                founded = True
                                x= {'IoControlCode': hex(ioctl_code), 
                                    'InBufferLength': list(speculate_bvs_range(state, 
                                                                io_stack_location.fields['InputBufferLength'])),
                                    'OutBufferLength': list(speculate_bvs_range(state,
                                                                io_stack_location.fields['OutputBufferLength'])
                                    )}
                                ioctl_interface.append(x)
                                #print("simgr.deadended",x,"\n")
                                break

                    if not founded:                        
                        sat_state = next(constraint_states)
                        unsat_state = next(constraint_states)

                        self.set_mode('force_skip_call', sat_state)
                        self.set_mode('force_skip_call', unsat_state)
                        self.set_mode('symbolize_global_variables', sat_state)
                        self.set_mode('symbolize_global_variables', unsat_state)
                        simgr_sat = self.project.factory.simgr(sat_state)
                        simgr_unsat = self.project.factory.simgr(unsat_state)

                        def determine_unsat():
                            for _ in range(30):
                                simgr_sat.step()
                                simgr_unsat.step()
                                
                                if len(simgr_sat.active) == 0:
                                    yield False
                                elif len(simgr_unsat.active) == 0:
                                    yield True

                        if not next(determine_unsat()):
                            sat_state, unsat_state = unsat_state, sat_state

                        # Get valid constraints.
                        def get_valid_constraints(sat_state, unsat_state):
                            simgr = self.project.factory.simgr(sat_state)

                            for _ in range(10):
                                simgr.step()

                            for states in list(simgr.stashes.values()):
                                for state in states:
                                    if unsat_state.addr not in state.history.bbl_addrs:
                                        return state

                        sat_state = get_valid_constraints(sat_state, unsat_state)
                        if not sat_state:
                            sat_state = case_state
                        ioctl_interface.append({'IoControlCode': hex(ioctl_code), 
                                        'InBufferLength': list(speculate_bvs_range(sat_state, 
                                                                    io_stack_location.fields['InputBufferLength'])),
                                        'OutBufferLength': list(speculate_bvs_range(sat_state,
                                                                    io_stack_location.fields['OutputBufferLength'])
                                        )})

                gogogo(case_state)
                

            else:
               # print("no constraint")
                sat_state = case_state
                x= {'IoControlCode': hex(ioctl_code), 
                                        'InBufferLength': list(speculate_bvs_range(sat_state, 
                                                                    io_stack_location.fields['InputBufferLength'])),
                                        'OutBufferLength': list(speculate_bvs_range(sat_state,
                                                                    io_stack_location.fields['OutputBufferLength'])
                                        )}
                ioctl_interface.append(x)                
        
        ioctl_interface = sorted(ioctl_interface, key=lambda x:int(x['IoControlCode'], 16))

        switch_block_addresses_fixed = {}
        prev_key = None
        for key, value in state_finder.switch_block_addresses.items():
            if prev_key is not None:
                switch_block_addresses_fixed[prev_key] = {'start': state_finder.switch_block_addresses[prev_key], 'end': value - 1}
            prev_key = key
        
        try:
            average_diff = sum(switch_block_addresses_fixed[key]['end']- switch_block_addresses_fixed[key]['start'] for key, value in switch_block_addresses_fixed.items()) / (len(switch_block_addresses_fixed) - 1)
            if prev_key is not None:
                switch_block_addresses_fixed[prev_key] = {'start': state_finder.switch_block_addresses[prev_key], 'end': int(state_finder.switch_block_addresses[prev_key] + average_diff)}
        except:
            pass
        
        #print(state_finder.switch_block_addresses)
        #print(switch_block_addresses_fixed)
        
        switch_block_addresses_fixed = [
            {'IoControlCode': key, **value} for key, value in switch_block_addresses_fixed.items()
        ]        
        switch_block_addresses_fixed = sorted(switch_block_addresses_fixed, key=lambda x:x['IoControlCode'])

        return ioctl_interface, switch_block_addresses_fixed

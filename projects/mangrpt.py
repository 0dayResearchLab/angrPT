import os
import angr
import json
import pefile
import angrutils
import capstone

class angrPTObject():
    def __init__(self, driver_path, dispatcher_address, ioctl_infos):
        self.ioctl_called = None
        self.global_var_start = 0
        self.global_var_end = 0
        self.external_functions = []
        self.driver_path = driver_path
        self.ioctl_infos = ioctl_infos      
        self.dispatcher_address = dispatcher_address
        self.ioctl_xref = {}
    
    def analyzeXref(self):
        self.get_data_section()
        return self.get_function_table()

    """ PE section을 순회하면서 .data 영역을 가져오는 함수 for Global Variables"""
    def get_data_section(self):        
        pe = pefile.PE(self.driver_path)
        data_section = None
        for section in pe.sections:
            if section.Name.decode().strip('\x00') == ".data":
                data_section = section

        self.global_var_start = pe.OPTIONAL_HEADER.ImageBase + data_section.VirtualAddress
        self.global_var_end = self.global_var_start + data_section.SizeOfRawData
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for dll_import in entry.imports:
                if dll_import.name:
                    self.external_functions.append(dll_import.address)



    """함수 블록을 가져오고 안에 자세한 정보를 저장하는 함수 """
    def get_function_table(self):
        max_depth = 5
        proj = angr.Project(self.driver_path, auto_load_libs=False)#, main_opts={"custom_base_addr": start_address})
        cfg = proj.analyses.CFG()

        dispatcher_function = proj.kb.functions[self.dispatcher_address]
        dispatcher_start_addr = dispatcher_function.addr
        dispatcher_end_addr = dispatcher_start_addr + dispatcher_function.size

        #######################################
        callgraph = proj.kb.callgraph

        depth1_functions = {}
        callees = [dst for _, dst in callgraph.out_edges(dispatcher_start_addr)]
        for callee in callees:
            callee_func = proj.kb.functions.get(callee)

            call_sites = [addr for addr in dispatcher_function.get_call_sites() if dispatcher_function.get_call_target(addr) == callee]
            for ioctl_info in self.ioctl_infos:
                for call_site in call_sites:
                    if ioctl_info['start'] <= call_site <= ioctl_info['end']:
                       depth1_functions[ioctl_info['IoControlCode']] = callee
                       #print(f"[AngrPT] IoControlCode: {hex(ioctl_info['IoControlCode'])} calls {callee_func.name if callee_func else hex(callee)}({hex(callee)})")

        self.ioctl_called = {}
        for ioctl_code, depth1_func in depth1_functions.items():
            visited = set()
            called_functions = []
            stack = [(depth1_func, 1)]  # (함수 주소, 현재 깊이)

            while stack:
                func_addr, depth = stack.pop()
                if func_addr in visited or depth > max_depth:
                    continue
                visited.add(func_addr)
                func = proj.kb.functions.get(func_addr)
                called_functions.append(func_addr)

                if not func:
                    continue

                callees = [dst for _, dst in callgraph.out_edges(func_addr)]
                for callee in callees:
                    callee_func = proj.kb.functions.get(callee)
                    stack.append((callee, depth + 1))
            self.ioctl_called[ioctl_code] = called_functions

        for ioctl_code, funcs in self.ioctl_called.items():
            print( f"[AngrPT] IoControlCode: {hex(ioctl_code)} calls {[hex(f) for f in funcs]}")




        global_access_offset = list(proj.kb.xrefs.get_xrefs_by_dst_region(self.global_var_start, self.global_var_end))


        for global_access in global_access_offset:
            for ioctl_info in self.ioctl_infos:
                ioctl_code = ioctl_info['IoControlCode']
                self.ioctl_xref.setdefault(ioctl_code, [])

                if ioctl_info['start'] <= global_access.ins_addr <= ioctl_info['end']:
                    self.ioctl_xref[ioctl_code].append(global_access)
                    print(f'[AngrPT] {hex(ioctl_code)}: global variable access in depth = 0.')
                funcs = self.ioctl_called.get(ioctl_code)
                if funcs is not None:
                    for func in funcs:
                        angr_func = proj.kb.functions.get(func)
                        func_start = angr_func.addr
                        func_end = func_start + angr_func.size
                        is_external = angr_func.is_plt or angr_func.is_simprocedure # 단순 범위 검사라 외부함수 제외 안해도 괜찮지 않을까?ㄴ
                        if func_start <= global_access.ins_addr <= func_end:
                            self.ioctl_xref[ioctl_code].append(global_access)
                            print(f'[AngrPT] {hex(ioctl_code)}: global variable access in depth = n.')

        return self.ioctl2global(proj)
        
    def ioctl2global(self, proj):
        # offset recovery
        print(f'[AngrPT] Starting recovery xref mods ...')

        for xrefs in self.ioctl_xref.values():
            for xref in xrefs:
                block = proj.factory.block(xref.ins_addr)

                #  Xref가 발생한 주소가 속한 BasicBlock에서 0번째가 아닐수도 있잖음. target으로 수정.
                # for insn in block.capstone.insns:
                #     print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                target_insn = next((insn for insn in block.capstone.insns if insn.address == xref.ins_addr), None)
                print(f"Xref Instruction: 0x{target_insn.address:x}: {target_insn.mnemonic} {target_insn.op_str}")

                for op_index, op in enumerate(target_insn.operands):
                    if op.type == capstone.x86.X86_OP_MEM:
                        base_reg = target_insn.reg_name(op.mem.base)
                        index_reg = target_insn.reg_name(op.mem.index)
                        scale = op.mem.scale
                        disp = op.mem.disp
                        # segment = insn.reg_name(op.mem.segment)
                        # lmod = op.mem.lmod
                        size = op.size

                        #print(block)
                        #print(block_insn_op_str)
                        #print(block_insn_mnemonic)
                        # TODO: lea instruction 추가,
                        #       mov r11, qword ptr [rip + 0x7074] 같이 2번째 parameter가 xref인 경우도 처리 필요.
                        if base_reg == 'rip':
                            if target_insn.mnemonic == 'cmp':
                                xref.type = 1
                            elif target_insn.mnemonic in ['mov', 'movabs', 'movaps', 'and', 'or'] and op_index == 0:
                                xref.type = 2

                        print(f"  - Operand {op_index}: Memory Access")
                        print(f"    - Base Register: {base_reg if base_reg else 'None'}")
                        print(f"    - Index Register: {index_reg if index_reg else 'None'}")
                        print(f"    - Scale: {scale}")
                        print(f"    - Displacement: {disp:#x}")
                        print(f"    - Memory Size: {size} bytes" if size else "    - Memory Size: Unknown")
                        # print(f"    - Segment Register: {segment if segment else 'None'}")
                        # print(f"    - LMOD: {lmod}")

                        # QWORD PTR (64비트)인지 확인
                        if size == 8:
                            print("    - **QWORD PTR detected!**")
                        elif size == 4:
                            print("    - **DWORD PTR detected!**")
                        elif size == 2:
                            print("    - **WORD PTR detected!**")
                        elif size == 1:
                            print("    - **BYTE PTR detected!**")

                print(f"  - Xref Mode : {xref.type_string}")
                print('===============================================')

        ioctl_dependency = {}
        for ioctl_code, xrefs in self.ioctl_xref.items():
            if len(xrefs) > 0:
                ioctl_dependency[ioctl_code] = []
                for xref in xrefs:
                    ioctl_dependency[ioctl_code].append({
                                'addr' : xref.dst,
                                'mode' : xref.type_string
                            })


        #! 실험용 코드.. (read <-> write)
        # write_to_read_connections = {}
        # for ioctl_num, xref_values in ioctl_dependency.items():
        #     read_addrs = {value['addr'] for value in xref_values if value['mode'] == 'read'}
        #     write_addrs = {value['addr'] for value in xref_values if value['mode'] == 'write'}
        #     unknown_addrs = {value['addr'] for value in xref_values if value['mode'] == 'offset'}
            
        #     for write_addr in write_addrs:
        #         if write_addr not in write_to_read_connections:
        #             write_to_read_connections[write_addr] = set()
        #         for read_addr in read_addrs:
        #             write_to_read_connections[write_addr].add(read_addr)
            
        #print(ioctl_dependency)
        #print(write_to_read_connections)

        return ioctl_dependency
from typing import DefaultDict
from ..base import Edge, Transformer
from angr.knowledge_plugins.key_definitions.atoms import Register
from collections import defaultdict

class AngrRemovePathTerminator(Transformer):
    def __init__(self):
        pass
        
    def transform(self, graph):
        remove = []
        for n in graph.nodes:
            if hasattr(n.obj, 'is_simprocedure') and n.obj.is_simprocedure and n.obj.simprocedure_name == 'PathTerminator':
                remove.append(n)
        for r in remove:
            graph.remove_node(r)


class AngrRemoveSimProcedures(Transformer):
    def __init__(self):
        pass
        
    def transform(self, graph):
        remove = []
        for n in graph.nodes:
            if n.obj.is_simprocedure:
                remove.append(n)
                cs = []
                for e in graph.edges:
                    if e.dst == n:
                        cs.append(e.src)
                found = False
                for c in cs:
                    for e in graph.edges:
                        if e.src == c and e.dst != n:
                            found = True
                            break
                    if not found:
                        remove.append(c)
        for r in remove:
            graph.remove_node(r)


class AngrRemoveImports(Transformer):
    def __init__(self, project):
        self.project = project
        self.eaddrs = self.import_addrs(project)
        
    def import_addrs(self, project):
        eaddrs=[]
        for _ in project.loader.main_object.imports.values():
            if _.resolvedby != None:
                eaddrs.append(_.value)
        return set(eaddrs)

    def transform(self, graph):
        return
        remove = set()
        for n in graph.nodes:
            if n.obj.addr in self.eaddrs:
                remove.add(n)
                cs = []
                for e in graph.edges:
                    if e.dst == n:
                        cs.append(e.src)
                found = False
                for c in cs:
                    for e in graph.edges:
                        if e.src == c and e.dst != n:
                            found = True
                            break
                    if not found:
                        remove.add(c)
        #for r in remove:
        #    graph.remove_node(r)



class AngrRemoveFakeretEdges(Transformer):
    def __init__(self):
        pass
        
    def transform(self, graph):
        remove = []
        for e in graph.edges:
            if e.meta['jumpkind'] == 'Ijk_FakeRet':
                remove.append(e)
        for r in remove:
            graph.remove_edge(r)


class AngrRDARemoveGarbageNodes(Transformer):
    def __init__(self, project):
        super(AngrRDARemoveGarbageNodes, self).__init__()
        self.project = project        

    def transform(self, graph):

        offsets  = set()
        offsets.add(self.project.arch.registers['cc_op'][0])
        offsets.add(self.project.arch.registers['cc_ndep'][0])
        offsets.add(self.project.arch.registers['cc_dep1'][0])
        offsets.add(self.project.arch.registers['cc_dep2'][0])
        offsets.add(self.project.arch.registers['ip'][0])
        
        remove = []
        
        for node in graph.nodes:
            if node.obj.codeloc.sim_procedure != None:
                continue

            if type(node.obj.atom) is Register:
                if node.obj.atom.reg_offset in offsets:
                    remove.append(node)

        for r in remove:
            graph.remove_node(r)

class AngrRDAConnectCodelocations(Transformer):
    def __init__(self, project):
        super(AngrRDAConnectCodelocations, self).__init__()
        self.project = project

    def transform(self, graph):
        nodes_by_codeloc = defaultdict(list)        
        

        for node in graph.nodes:
            if node.obj.codeloc.ins_addr is not None:
                nodes_by_codeloc[node.obj.codeloc.ins_addr].append(node)
        
        for k,v in nodes_by_codeloc.items():
            if len(v) > 1:
                v = sorted(v, key=lambda x: x.obj.codeloc.stmt_idx if x.obj.codeloc.stmt_idx != -2 else 100000)
                for i in range(len(v)-1):
                    graph.add_edge(Edge(v[i], v[i+1], meta={ 'synthetic': True }))


class AngrDDGRemoveGarbageNodes(Transformer):
    def __init__(self, project):
        super(AngrDDGRemoveGarbageNodes, self).__init__()
        self.project = project        

    def transform(self, graph):

        offsets  = set()
        offsets.add(self.project.arch.registers['cc_op'][0])
        offsets.add(self.project.arch.registers['cc_ndep'][0])
        offsets.add(self.project.arch.registers['cc_dep1'][0])
        offsets.add(self.project.arch.registers['cc_dep2'][0])
        offsets.add(self.project.arch.registers['ip'][0])
        
        remove = []
        
        for node in graph.nodes:
            if node.obj.location.sim_procedure != None:
                continue

            vex = self.project.factory.block(addr=node.obj.location.block_addr).vex
            stmt = vex.statements[node.obj.location.stmt_idx]
            if stmt.tag == 'Ist_Put':
                if stmt.offset in offsets:
                    remove.append(node)

        for r in remove:
            graph.remove_node(r)

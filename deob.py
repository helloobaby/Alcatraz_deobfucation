#
#Backspace

# 
# binaryninja plugin 
# 有些时候需要多执行几次这个脚本，因为反编译器判断函数的边界有时候会错的，这样的话
# 需要Undefine current function,再次执行脚本
# 

from binaryninja import *
import os
import sys


# llil.operation == <LowLevelILOperation.LLIL_IF: 59>

# if (eax != 0x1ffdbaed) then 16 @ 0x1400124d5 else 25 @ 0x1400124e5
# llil.condition == binaryninja.lowlevelil.LowLevelILCmpNe
# if (eax == 0x46bab93) then 20 @ 0x1400124fa else 24 @ 0x1400124e3
# llil.condition == binaryninja.lowlevelil.LowLevelILCmpE


state_action={}
arch = Architecture['x86']
patch_task={}

# cmp eax,<value>
swVar='eax'

# 模式匹配特征块
def is_dispatch_bb(bb:LowLevelILBasicBlock):
    # example分发块
    # if (eax != 0xe) then 159 @ 0x1400b4076 else 160 @ 0x1400b4069
    if bb.length == 1 and bb[0].operation == LowLevelILOperation.LLIL_IF and isinstance(bb[0].operands[0].left,LowLevelILReg) and bb[0].operands[0].left.src.name == swVar:
        print('识别的分发块起始地址llil index -> '+ hex(bb.start))
        return True
        
def get_state_action(bb:LowLevelILBasicBlock):


    op1=bb[0].operands[0].operands[1].value
    state=0
    action=0
    
    # 分je\jne情况枚举
    if isinstance(bb[0].condition,LowLevelILCmpNe): # 
        if isinstance(op1,ConstantRegisterValue): 
            state=op1.value
            action=current_llil[bb[0].operands[2]].address
                
    if isinstance(bb[0].condition,LowLevelILCmpE):
        if isinstance(op1,ConstantRegisterValue):
            state=op1.value
            action=current_llil[bb[0].operands[1]].address
            
    print('Id(State) %#x-> Block(Action) %#x' %(state,action))
    state_action[state]=action
   

# 解析指令,收集所有更改状态的指令地址
# mov eax,<constant value>
def change_state(text_token_list:list):
    if (len(text_token_list) < 4 ):
        return None
    #print(text_token_list)
    if str(text_token_list[0]) == 'mov' and str(text_token_list[2]) == swVar and  text_token_list[4].type == InstructionTextTokenType.IntegerToken:
        # 返回state
        return text_token_list[4].value
    
    return None


# 获得这条指令在这个函数对应的basicblock
def get_addr_in_basicblock(addr:int) ->basicblock:
    for bb in current_function.basic_blocks:
        for text in bb.disassembly_text:
            if text.address==addr:
                return bb
        
    print('Error : %#x not in any block ? ' % addr)
    sys.exit(-1)
    return None
    
    
    
# 这条指令在这个basicblock里patch安全吗
# mov     rax, cs:__security_cookie
def is_safely_patched(addr:int,bb:BasicBlock):
    # 理论上来说这条指令后面应该要没有有效的指令
    # 无效指令包括(所有的jcc nop)
    
    for insn_text in bb.disassembly_text:
        if insn_text.address > addr:
            #print(hex(insn_text.address))
            if 'nop' != str(insn_text.tokens[0]) and 'jmp' != str(insn_text.tokens[0]): # 这条指令既不是nop 也不是jcc ,不安全
                return False
            
    return True
    

# 首先正确提取分发块和真实块
for bb in current_llil.basic_blocks:
    if(is_dispatch_bb(bb)):
        get_state_action(bb)

#sys.exit(0)


for bb in current_function.basic_blocks:
    
    # 统计这个basicblock的指令数，什么len length全是指令字节数
    instruction_count=len(bb.disassembly_text)
    
    for i in range(0,instruction_count):
        address=bb.disassembly_text[i].address
        
        state = change_state(bb[i][0])
        if state != None:
            print('识别到的更改状态的指令地址 ' + hex(address))
            
            #continue
            
            #print(get_addr_in_basicblock(address))
            
            
            if(is_safely_patched(address,get_addr_in_basicblock(address))):
                print('安全patch')
                
                # 获得状态
                jmp_dest_state=state
                
                # 获得状态对应的真实代码块
                
                # 有可能返回函数值的真实mov eax,<value>
                if jmp_dest_state not in state_action:
                    continue
                jmp_dest=state_action[jmp_dest_state]
                
                insnstr =  'jmp '+ hex(jmp_dest)
                print('地址 %#x patch后的指令字符串 %s' %(address,insnstr))
                
                # 最后再patchaddr in patch_task:
                patch_task[address]=insnstr
                
            else:
                print('Patch不了')
                

for address in patch_task:
    bv.write(address,arch.assemble(patch_task[address],addr=address))
    

# remove dead code
lpatch_addr=[]
for bb in current_function.basic_blocks:
    instruction_count=len(bb.disassembly_text)
    for i in range(0,instruction_count):
        if i+1 == instruction_count:
            break
        
        if (str(bb[i][0][0]) == 'push' and str(bb[i][0][2]) == 'rax' and str(bb[i+1][0][0]) == 'pushf') or (str(bb[i][0][0]) == 'popf' and str(bb[i+1][0][2]) == 'rax' and str(bb[i+1][0][0]) == 'pop'):
            # bv.convert_to_nop(bb.disassembly_text[i].address)
            # bv.convert_to_nop(bb.disassembly_text[i+1].address)
            lpatch_addr.append(bb.disassembly_text[i].address)
            lpatch_addr.append(bb.disassembly_text[i+1].address)
            
for patch_addr in lpatch_addr:
    bv.convert_to_nop(patch_addr)
    
//
//  YJStackDumper.m
//  CMSStackDumper
//
//  Created by symbio on 2021/10/11.
//

#import "YJStackDumper.h"
#import "YJStackDumperPublic.h"
#import "YJStackDumperTool.h"

#define PACStrippingMask_ARM64e 0x0000000fffffffff

typedef struct BSStackFrameEntry{
    const struct BSStackFrameEntry *const previous;
    const uintptr_t return_address;
} BSStackFrameEntry;

static NSMutableDictionary *_threadBinaryInfos = nil;
static dispatch_queue_t _stackDumperQueue = nil;

@implementation YJStackDumper

+ (YJStackDumperModel *)dumperWithContext:(_STRUCT_MCONTEXT)context {
    NSString *threadStack = [self getThreadStackTraceForMachineContext:context];
    if (threadStack.length <= 0) {
        return nil;
    }

    YJStackDumperModel *model = [[YJStackDumperModel alloc] init];
    model.threadStack = threadStack;
    model.binaryInfo         = [self getThreadBinaryInfo];
    model.erroruuidu         = [YJStackDumperTool getCurrentAppDSYMUUID];
    model.baseAddress        = [YJStackDumperTool getCurrentAppAddress];

    return model;
}

#pragma mark - public

+ (YJStackDumperModel *)dumperWithNSThread:(NSThread *)thread
{
    if (!(thread && [thread isKindOfClass:NSThread.class])) {
        NSLog(@"参数类型不匹配: %@", thread);
        return nil;
    }
    
    _STRUCT_MCONTEXT machineContext = [YJStackDumperTool getMachineContextForNSThread:thread];
    return [self dumperWithContext:machineContext];
}

+ (YJStackDumperModel *)dumperWithMainThread
{
    return [self dumperWithNSThread:[NSThread mainThread]];
}

+ (YJStackDumperModel *)dumperWithCurrentThread
{
    return [self dumperWithNSThread:[NSThread currentThread]];
}

+ (NSArray<YJStackDumperModel *> *)dumperWithAllThread
{
    NSMutableArray *allThreadModels = [NSMutableArray array];
    
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count = 0;
    const task_t this_task = mach_task_self();
    
    kern_return_t kr = task_threads(this_task, &threads, &thread_count);
    if(kr == KERN_SUCCESS) {
        
        for (int i = 0; i < thread_count; i ++) {
            
            _STRUCT_MCONTEXT machineContext = [YJStackDumperTool getMachineContextForMachThread:threads[i]];
            
            YJStackDumperModel *model = [self dumperWithContext:machineContext];
            if (model) {
                [allThreadModels addObject:model];
            }
        }
    }
    
    return [allThreadModels copy];
}

+ (NSString *)getThreadBinaryInfo
{
    NSMutableString *threadBinaryInfo = [NSMutableString string];
    
    dispatch_sync(_stackDumperQueue, ^{
        for (NSString *imageInfo in _threadBinaryInfos.allValues) {
            if (imageInfo) {
                [threadBinaryInfo appendString:[NSString stringWithFormat:@"%@\n", imageInfo]];
            }
        }
    });
    
    return [threadBinaryInfo copy];
}

#pragma -mark GenerateBacbsrackEnrty
static NSString* logBacktraceEntry(const int entryNum,
                            const uintptr_t address,
                            const Dl_info* const dlInfo) {
    char faddrBuff[20];
    
    const char* fname = lastPathEntry(dlInfo->dli_fname);
    if(fname == NULL) {
        sprintf(faddrBuff, POINTER_FMT, (uintptr_t)dlInfo->dli_fbase);
        fname = faddrBuff;
    }
    
    uintptr_t baseAddr = (uintptr_t)dlInfo->dli_fbase;
    uintptr_t offset = address - baseAddr;
    
    NSString *process = [NSString stringWithUTF8String:fname];
    return [NSString stringWithFormat:@"%-30@  0x%016" PRIxPTR " 0x%016" PRIxPTR " + %lu\n" ,process, (uintptr_t)address, (uintptr_t)baseAddr, offset];
}

static const char* lastPathEntry(const char* const path) {
    if(path == NULL) {
        return NULL;
    }
    
    char* lastFile = strrchr(path, '/');
    return (lastFile == NULL ? path : lastFile + 1);
}

#pragma mark - machineContext

static void getAllRegistersValues(_STRUCT_MCONTEXT *machineContext) {
    
#if defined(__arm64__)
    uint64_t register_x[29];
    uint64_t register_fp;
    uint64_t register_lr;
    uint64_t register_sp;
    uint64_t register_pc;
    uint32_t register_cpsr;
    for (int i = 0; i < 29; i ++) {
        register_x[i] = machineContext->__ss.__x[i];
    }
    register_fp = machineContext->__ss.__fp;
    register_lr = machineContext->__ss.__lr;
    register_sp = machineContext->__ss.__sp;
    register_pc = machineContext->__ss.__pc;
    register_cpsr = machineContext->__ss.__cpsr;
#elif defined(__arm__)
    uint32_t register_r[13];
    uint32_t register_lr;
    uint32_t register_sp;
    uint32_t register_pc;
    uint32_t register_cpsr;
    for (int i = 0; i < 13; i ++) {
        register_r[i] = machineContext->__ss.__r[i];
    }
    register_lr = machineContext->__ss.__lr;
    register_sp = machineContext->__ss.__sp;
    register_pc = machineContext->__ss.__pc;
    register_cpsr = machineContext->__ss.__cpsr;
#endif
}

static uintptr_t mach_framePointer(mcontext_t const machineContext){
    return machineContext->__ss.BS_FRAME_POINTER;
}

static uintptr_t mach_stackPointer(mcontext_t const machineContext){
    return machineContext->__ss.BS_STACK_POINTER;
}

static uintptr_t mach_instructionAddress(mcontext_t const machineContext){
    return machineContext->__ss.BS_INSTRUCTION_ADDRESS;
}

static uintptr_t mach_linkRegister(mcontext_t const machineContext){
#if defined(__i386__) || defined(__x86_64__)
    return 0;
#else
    return machineContext->__ss.__lr;
#endif
}

static kern_return_t mach_copyMem(const void *const src, void *const dst, const size_t numBytes){
    vm_size_t bytesCopied = 0;
    return vm_read_overwrite(mach_task_self(), (vm_address_t)src, (vm_size_t)numBytes, (vm_address_t)dst, &bytesCopied);
}

#pragma -mark Symbolicate
static void symbolicate(const uintptr_t* const backtraceBuffer,
                 Dl_info* const symbolsBuffer,
                 const int numEntries,
                 const int skippedEntries){
    int i = 0;
    
    if(!skippedEntries && i < numEntries) {
        _dladdr(backtraceBuffer[i], &symbolsBuffer[i]);
        i++;
    }
    
    for(; i < numEntries; i++) {
        _dladdr(CALL_INSTRUCTION_FROM_RETURN_ADDRESS(backtraceBuffer[i]), &symbolsBuffer[i]);
    }
}

static bool _dladdr(const uintptr_t address, Dl_info* const info) {
    info->dli_fname = NULL;
    info->dli_fbase = NULL;
    info->dli_sname = NULL;
    info->dli_saddr = NULL;
    
    const uint32_t idx = imageIndexContainingAddress(address);
    if(idx == UINT_MAX) {
        return false;
    }
    const struct mach_header* header = _dyld_get_image_header(idx);
    const uintptr_t imageVMAddrSlide = (uintptr_t)_dyld_get_image_vmaddr_slide(idx);
    const uintptr_t addressWithSlide = address - imageVMAddrSlide;
    const uintptr_t segmentBase = segmentBaseOfImageIndex(idx) + imageVMAddrSlide;
    if(segmentBase == 0) {
        return false;
    }
    
    info->dli_fname = _dyld_get_image_name(idx);
    info->dli_fbase = (void*)header;
    
    // Find symbol tables and get whichever symbol is closest to the address.
    const BS_NLIST* bestMatch = NULL;
    uintptr_t bestDistance = ULONG_MAX;
    uintptr_t cmdPtr = firstCmdAfterHeader(header);
    if(cmdPtr == 0) {
        return false;
    }
    for(uint32_t iCmd = 0; iCmd < header->ncmds; iCmd++) {
        const struct load_command* loadCmd = (struct load_command*)cmdPtr;
        if(loadCmd->cmd == LC_SYMTAB) {
            const struct symtab_command* symtabCmd = (struct symtab_command*)cmdPtr;
            const BS_NLIST* symbolTable = (BS_NLIST*)(segmentBase + symtabCmd->symoff);
            const uintptr_t stringTable = segmentBase + symtabCmd->stroff;
            
            for(uint32_t iSym = 0; iSym < symtabCmd->nsyms; iSym++) {
                // If n_value is 0, the symbol refers to an external object.
                if(symbolTable[iSym].n_value != 0) {
                    uintptr_t symbolBase = symbolTable[iSym].n_value;
                    uintptr_t currentDistance = addressWithSlide - symbolBase;
                    if((addressWithSlide >= symbolBase) &&
                       (currentDistance <= bestDistance)) {
                        bestMatch = symbolTable + iSym;
                        bestDistance = currentDistance;
                    }
                }
            }
            if(bestMatch != NULL) {
                info->dli_saddr = (void*)(bestMatch->n_value + imageVMAddrSlide);
                info->dli_sname = (char*)((intptr_t)stringTable + (intptr_t)bestMatch->n_un.n_strx);
                if(*info->dli_sname == '_') {
                    info->dli_sname++;
                }
                // This happens if all symbols have been stripped.
                if(info->dli_saddr == info->dli_fbase && bestMatch->n_type == 3) {
                    info->dli_sname = NULL;
                }
                break;
            }
        }
        cmdPtr += loadCmd->cmdsize;
    }
    
    
    //收集binaryInfo
    NSString *dyldFull = [NSString stringWithFormat:@"%s",_dyld_get_image_name(idx)];
    NSString *imageNameOrNil = [dyldFull lastPathComponent];
    NSString *imageName = imageNameOrNil ? imageNameOrNil : @"";
    
    NSString *binaryOrNil = [YJStackDumper getBinaryInfoByIndex:idx image:imageNameOrNil];
    
    dispatch_sync(_stackDumperQueue, ^{
        
        BOOL noCollected = ![_threadBinaryInfos objectForKey:imageName];
        if (binaryOrNil && noCollected) {
            [_threadBinaryInfos setObject:binaryOrNil forKey:imageName];
        }
    });
    
    return true;
}

static uintptr_t firstCmdAfterHeader(const struct mach_header* const header) {
    switch(header->magic) {
        case MH_MAGIC:
        case MH_CIGAM:
            return (uintptr_t)(header + 1);
        case MH_MAGIC_64:
        case MH_CIGAM_64:
            return (uintptr_t)(((struct mach_header_64*)header) + 1);
        default:
            return 0;  // Header is corrupt
    }
}

static uint32_t imageIndexContainingAddress(const uintptr_t address) {
    const uint32_t imageCount = _dyld_image_count();
    const struct mach_header* header = 0;
    
    for(uint32_t iImg = 0; iImg < imageCount; iImg++) {
        header = _dyld_get_image_header(iImg);
        if(header != NULL) {
            // Look for a segment command with this address within its range.
            uintptr_t addressWSlide = address - (uintptr_t)_dyld_get_image_vmaddr_slide(iImg);
            uintptr_t cmdPtr = firstCmdAfterHeader(header);
            if(cmdPtr == 0) {
                continue;
            }
            for(uint32_t iCmd = 0; iCmd < header->ncmds; iCmd++) {
                const struct load_command* loadCmd = (struct load_command*)cmdPtr;
                if(loadCmd->cmd == LC_SEGMENT) {
                    const struct segment_command* segCmd = (struct segment_command*)cmdPtr;
                    if(addressWSlide >= segCmd->vmaddr && addressWSlide < segCmd->vmaddr + segCmd->vmsize) {
                        return iImg;
                    }
                }
                else if(loadCmd->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64* segCmd = (struct segment_command_64*)cmdPtr;
                    if(addressWSlide >= segCmd->vmaddr && addressWSlide < segCmd->vmaddr + segCmd->vmsize) {
                        return iImg;
                    }
                }
                cmdPtr += loadCmd->cmdsize;
            }
        }
    }
    return UINT_MAX;
}

static uintptr_t segmentBaseOfImageIndex(const uint32_t idx) {
    const struct mach_header* header = _dyld_get_image_header(idx);
    
    // Look for a segment command and return the file image address.
    uintptr_t cmdPtr = firstCmdAfterHeader(header);
    if(cmdPtr == 0) {
        return 0;
    }
    for(uint32_t i = 0;i < header->ncmds; i++) {
        const struct load_command* loadCmd = (struct load_command*)cmdPtr;
        if(loadCmd->cmd == LC_SEGMENT) {
            const struct segment_command* segmentCmd = (struct segment_command*)cmdPtr;
            if(strcmp(segmentCmd->segname, SEG_LINKEDIT) == 0) {
                return segmentCmd->vmaddr - segmentCmd->fileoff;
            }
        }
        else if(loadCmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64* segmentCmd = (struct segment_command_64*)cmdPtr;
            if(strcmp(segmentCmd->segname, SEG_LINKEDIT) == 0) {
                return (uintptr_t)(segmentCmd->vmaddr - segmentCmd->fileoff);
            }
        }
        cmdPtr += loadCmd->cmdsize;
    }
    return 0;
}

#pragma mark - private

+ (NSString *)getThreadStackTraceForMachineContext:(_STRUCT_MCONTEXT)machineContext
{
    uintptr_t backtraceBuffer[MAX_THREAD_FRAMES];
    int i = 0;

    //获取寄存器的数值
    getAllRegistersValues(&machineContext);
    
    const uintptr_t instructionAddress = mach_instructionAddress(&machineContext);
    backtraceBuffer[i] = instructionAddress;
    
#if defined (__arm64__)
    backtraceBuffer[i] = instructionAddress & PACStrippingMask_ARM64e;
#endif
    ++i;
    
    uintptr_t linkRegister = mach_linkRegister(&machineContext);
    if (linkRegister) {
        backtraceBuffer[i] = linkRegister;
        
#if defined (__arm64__)
        backtraceBuffer[i] = linkRegister & PACStrippingMask_ARM64e;
#endif

        i++;
    }
    
    BSStackFrameEntry frame = {0};
    const uintptr_t framePtr = mach_framePointer(&machineContext);
    if(framePtr == 0 ||
       mach_copyMem((void *)framePtr, &frame, sizeof(frame)) != KERN_SUCCESS) {
        NSLog(@"获取入口栈帧失败");
        return nil;
    }
    
    for(; i < MAX_THREAD_FRAMES; i++) {
        // 记录每一个栈帧返回地址
        backtraceBuffer[i] = frame.return_address;
        
#if defined (__arm64__)
        backtraceBuffer[i] = frame.return_address & PACStrippingMask_ARM64e;
#endif
        
        if(backtraceBuffer[i] == 0 ||
           frame.previous == 0 ||
           mach_copyMem(frame.previous, &frame, sizeof(frame)) != KERN_SUCCESS) {
            break;
        }
    }
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _stackDumperQueue = dispatch_queue_create("stackDumperQueue", DISPATCH_QUEUE_SERIAL);
        _threadBinaryInfos = [NSMutableDictionary dictionary];
    });
    
    //清除之前的数据,一个线程对应一个符号化数据
    [_threadBinaryInfos removeAllObjects];
    
    int backtraceLength = i;
    NSString *stackLine = nil;
    NSMutableString *threadStack = [NSMutableString string];
    
    Dl_info symbolicated[backtraceLength];
    symbolicate(backtraceBuffer, symbolicated, backtraceLength, 0);
    
    for (int i = 0; i < backtraceLength; ++i) {
        
        stackLine = [NSString stringWithFormat:@"%-3d %@",i, logBacktraceEntry(i, backtraceBuffer[i], &symbolicated[i])];
        [threadStack appendString:stackLine];
    }
    
    return threadStack;
}

+ (NSString *)getBinaryInfoByIndex:(int)index image:(NSString *)imageName
{
    NSString *binaryInfo = nil;
    
    const struct mach_header *header = _dyld_get_image_header(index);
    intptr_t imageAddress = (intptr_t)header;
    NSString *uuidOrNil = [YJStackDumperTool getHeaderDSYMUUID:header];
    NSString *uuid = uuidOrNil ? uuidOrNil : @"";
    
    const NXArchInfo *info = NULL;
    if (info == NULL) {
        info = NXGetArchInfoFromCpuType(header->cputype, header->cpusubtype);
    }
    
    if (imageName && info->name != NULL && uuid.length > 0 && imageAddress > 0) {
        binaryInfo = [NSString stringWithFormat:@"%@:%s;%@;0x%016lx",imageName,info->name,uuid,imageAddress];
    }
    
    if (info != NULL) {
        NXFreeArchInfo(info);
        info = NULL;
    }
    
    return binaryInfo;
}

@end

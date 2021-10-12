//
//  YJStackDumperTool.m
//  CMSStackDumper
//
//  Created by symbio on 2021/10/11.
//

#import "YJStackDumperTool.h"

static const struct mach_header *_header = NULL;
static NSString *_uuid = nil;
static NSString *_baseAddress = nil;
static mach_port_t _main_thread_id;

@implementation YJStackDumperTool

#pragma mark - public API

+ (NSString *)getCurrentAppDSYMUUID
{
    if (_uuid) return [_uuid copy];
 
    const struct mach_header *appHeader = [YJStackDumperTool getMachHeader];
    
    if (!appHeader) return nil;
    
    _uuid = [YJStackDumperTool getHeaderDSYMUUID:appHeader];
    
    return [_uuid copy];
}

+ (NSString *)getHeaderDSYMUUID:(const struct mach_header *)header
{
    NSString *result = nil;
    BOOL is64bit = header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64;
    uintptr_t cursor = (uintptr_t)header + (is64bit ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    const struct segment_command *segmentCommand = NULL;
    for (uint32_t i = 0; i < header->ncmds; i++, cursor += segmentCommand->cmdsize)
    {
        segmentCommand = (struct segment_command *)cursor;
        if (segmentCommand->cmd == LC_UUID)
        {
            const struct uuid_command *uuidCommand = (const struct uuid_command *)segmentCommand;
            NSString *temp = [[[[NSUUID alloc] initWithUUIDBytes:uuidCommand->uuid] UUIDString] lowercaseString];
            
            result = [temp stringByReplacingOccurrencesOfString:@"-" withString:@""];
            break;
        }
    }
    return result;
}

+ (NSString *)getCurrentAppAddress
{
    if (_baseAddress) return [_baseAddress copy];
    
    _baseAddress = [NSString stringWithFormat:@"0x%016lx",(intptr_t)[YJStackDumperTool getMachHeader]];

    return [_baseAddress copy];
}

+ (_STRUCT_MCONTEXT)getMachineContextForNSThread:(NSThread *)thread
{
    thread_t threadt = intoMachThread(thread);
    
    return [YJStackDumperTool getMachineContextForMachThread:threadt];
}

+ (_STRUCT_MCONTEXT)getMachineContextForMachThread:(thread_t)threadt
{
    _STRUCT_MCONTEXT machineContext;
    
    if(!getMachineContext(threadt, &machineContext)) {
        NSLog(@"获取machineContext失败");
    }
    
    return machineContext;
}

#pragma mark - private

+ (void)load
{
    _main_thread_id = mach_thread_self();
}

+ (const struct mach_header *)getMachHeader
{
    if (_header) return _header;
    
    uint32_t count = _dyld_image_count();
    
    for(uint32_t i = 0; i < count; i++){
        const struct mach_header *tmpHeader = _dyld_get_image_header(i);
        if (tmpHeader->filetype == MH_EXECUTE) {
            _header = tmpHeader;
            break;
        }
    }
    
    return _header;
}

static thread_t intoMachThread(NSThread *nsthread)
{
    char name[256];
    mach_msg_type_number_t count;
    thread_act_array_t list;
    task_threads(mach_task_self(), &list, &count);
    
    NSTimeInterval currentTimestamp = [[NSDate date] timeIntervalSince1970];
    NSString *originName = [nsthread name];
    [nsthread setName:[NSString stringWithFormat:@"%f", currentTimestamp]];
    
    if ([nsthread isMainThread]) {
        return (thread_t)_main_thread_id;
    }
    
    for (int i = 0; i < count; ++i) {
        pthread_t pt = pthread_from_mach_thread_np(list[i]);
        if ([nsthread isMainThread]) {
            if (list[i] == _main_thread_id) {
                return list[i];
            }
        }
        if (pt) {
            name[0] = '\0';
            pthread_getname_np(pt, name, sizeof name);
            if (!strcmp(name, [nsthread name].UTF8String)) {
                [nsthread setName:originName];
                return list[i];
            }
        }
    }
    
    [nsthread setName:originName];
    
    return mach_thread_self();
}

static bool getMachineContext(thread_t thread, _STRUCT_MCONTEXT *machineContext) {
    mach_msg_type_number_t state_count = BS_THREAD_STATE_COUNT;
    kern_return_t kr = thread_get_state(thread, BS_THREAD_STATE, (thread_state_t)&machineContext->__ss, &state_count);
    return (kr == KERN_SUCCESS);
}

@end

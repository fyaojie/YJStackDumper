//
//  YJStackDumperTool.h
//  CMSStackDumper
//
//  Created by symbio on 2021/10/11.
//

#import <Foundation/Foundation.h>
#import "YJStackDumperPublic.h"

NS_ASSUME_NONNULL_BEGIN

@interface YJStackDumperTool : NSObject
/// 获取当前app符号化所需的uuid
+ (NSString *)getCurrentAppDSYMUUID;

/// 获取当前app的基地址
+ (NSString *)getCurrentAppAddress;

/// 获取当前镜像的uuid
+ (NSString *)getHeaderDSYMUUID:(const struct mach_header *)header;

+ (_STRUCT_MCONTEXT)getMachineContextForNSThread:(NSThread *)thread;

+ (_STRUCT_MCONTEXT)getMachineContextForMachThread:(thread_t)threadt;
@end

NS_ASSUME_NONNULL_END

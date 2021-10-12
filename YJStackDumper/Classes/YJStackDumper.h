//
//  YJStackDumper.h
//  CMSStackDumper
//
//  Created by symbio on 2021/10/11.
//

#import <Foundation/Foundation.h>
#import "YJStackDumperModel.h"
NS_ASSUME_NONNULL_BEGIN

@interface YJStackDumper : NSObject
+ (YJStackDumperModel *)dumperWithNSThread:(NSThread *)thread;
+ (YJStackDumperModel *)dumperWithMainThread;
+ (YJStackDumperModel *)dumperWithCurrentThread;
+ (NSArray<YJStackDumperModel *> *)dumperWithAllThread;
@end

NS_ASSUME_NONNULL_END

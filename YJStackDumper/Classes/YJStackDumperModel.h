//
//  YJStackDumperModel.h
//  CMSStackDumper
//
//  Created by symbio on 2021/10/11.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface YJStackDumperModel : NSObject

@property (nonatomic, copy)NSString *erroruuidu; //崩溃uuid
@property (nonatomic, copy)NSString *baseAddress; //基址
@property (nonatomic, copy)NSString *binaryInfo;  //binary infos 用于系统方法符号化

@property (nonatomic, copy) NSString *threadStack;

@end

NS_ASSUME_NONNULL_END

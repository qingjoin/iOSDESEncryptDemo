//
//  ViewController.h
//  DEScodeDemo
//
//  Created by qingyun on 9/30/13.
//  Copyright (c) 2013 qingyun. All rights reserved.
//

#import <UIKit/UIKit.h>
#define     LocalStr_None           @""
#define __BASE64( text )        [ViewController base64StringFromText:text]
#define __TEXT( base64 )        [ViewController textFromBase64String:base64]


@interface ViewController : UIViewController
- (IBAction)DESbtnPress:(id)sender;
@property (weak, nonatomic) IBOutlet UITextField *inputText;
- (IBAction)DESEncryptyBtnPress:(id)sender;
@property (weak, nonatomic) IBOutlet UILabel *DESEncryptString;

@property (weak, nonatomic) IBOutlet UILabel *DESDecryptString;
@end

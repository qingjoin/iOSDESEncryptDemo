//
//  ViewController.m
//  DEScodeDemo
//
//  Created by qingyun on 9/30/13.
//  Copyright (c) 2013 qingyun. All rights reserved.
//

#import "ViewController.h"

#import <CommonCrypto/CommonCryptor.h>

#import "DESEncryptFile.h"


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)DESbtnPress:(id)sender
{
    
    _DESDecryptString.text = [DESEncryptFile textFromBase64String:_DESEncryptString.text withKey:@"2013"];
     
    /*
    NSString *ttt  = [ViewController encryptUseDES:@"helloworld" key:@"abcdefgh"]; //94A3161CEFB5267501
    NSString *ttted  = [ViewController encryptUseDES:ttt key:@"abcdefgh"];
    NSLog(@"1:%@, %@",ttt,ttted);//A6ACA2DB5B58B831C0C69308   A6ACA2DB5B58B831
    */

    /*
    NSString *s = @"helloworld";
    NSData *aData  = [s dataUsingEncoding: NSUTF8StringEncoding];;
    NSData *aa = [ViewController DESEncrypt:aData WithKey:@"abcdefgh" ];
     
    NSString *bt64Str = [ViewController base64Encoding:aa];
    NSData *fbt64 = [ViewController dataWithBase64EncodedString:bt64Str];
    
    
    NSData *datas = [ViewController DESDecrypt:fbt64 WithKey:@"abcdefgh"];
    NSString *str = [[NSString alloc]initWithData:datas encoding:NSUTF8StringEncoding];
    NSLog(@"%@   %@        ",bt64Str, str  );
  
    */
    
}

- (IBAction)DESEncryptyBtnPress:(id)sender
{
    _DESEncryptString.text = [DESEncryptFile base64StringFromText:_inputText.text withKey:@"2013"];
    
}



static Byte iv[] = {1,2,3,4,5,6,7,8};
///******************************************************************************
//DES加密
 +(NSString *) encryptUseDES:(NSString *)plainText key:(NSString *)key
{
    
         NSString *ciphertext = nil;
         const char *textBytes = [plainText UTF8String];
         NSUInteger dataLength = [plainText length];
        unsigned char buffer[1024];
         memset(buffer, 0, sizeof(char));
         size_t numBytesEncrypted = 0;
         CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                               kCCOptionECBMode|kCCOptionPKCS7Padding,  //kCCOptionECBMode  kCCOptionPKCS7Padding
                                               [key UTF8String], kCCKeySizeDES,
                                               iv,
                                               textBytes, dataLength,
                                               buffer, 1024,
                                               &numBytesEncrypted);
            if (cryptStatus == kCCSuccess) {
                
                NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
                //ciphertext = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
                
                //NSLog(@"ssf:%s",buffer);
                ciphertext = [ViewController base64Encoding:data];
               // NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
                //        Byte* bb = (Byte*)[data bytes];
                //        ciphertext = [self parseByteArray2HexString:bb];
        
             }
         return ciphertext;
   
     
}



/******************************************************************************
 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
 函数描述 : 文本数据进行DES加密
 输入参数 : (NSData *)data
 (NSString *)key
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 : 此函数不可用于过长文本
 ******************************************************************************/
+ (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
{
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCBlockSizeDES,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer);
    return nil;
}

/******************************************************************************
 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
 函数描述 : 文本数据进行DES解密
 输入参数 : (NSData *)data
 (NSString *)key
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 : 此函数不可用于过长文本
 ******************************************************************************/
+ (NSData *)DESDecrypt:(NSData *)data WithKey:(NSString *)key
{
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr, kCCBlockSizeDES,
                                          NULL,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer);
    return nil;
}

/******************************************************************************
 函数名称 : + (NSData *)dataWithBase64EncodedString:(NSString *)string
 函数描述 : base64格式字符串转换为文本数据
 输入参数 : (NSString *)string
 输出参数 : N/A
 返回参数 : (NSData *)
 备注信息 :
 ******************************************************************************/
+ (NSData *)dataWithBase64EncodedString:(NSString *)string
{
	if (string == nil)
		[NSException raise:NSInvalidArgumentException format:nil];
	if ([string length] == 0)
		return [NSData data];
	
	static char *decodingTable = NULL;
	if (decodingTable == NULL)
	{
		decodingTable = malloc(256);
		if (decodingTable == NULL)
			return nil;
		memset(decodingTable, CHAR_MAX, 256);
		NSUInteger i;
		for (i = 0; i < 64; i++)
			decodingTable[(short)encodingTable[i]] = i;
	}
	
	const char *characters = [string cStringUsingEncoding:NSASCIIStringEncoding];
	if (characters == NULL)     //  Not an ASCII string!
		return nil;
	char *bytes = malloc((([string length] + 3) / 4) * 3);
	if (bytes == NULL)
		return nil;
	NSUInteger length = 0;
	
	NSUInteger i = 0;
	while (YES)
	{
		char buffer[4];
		short bufferLength;
		for (bufferLength = 0; bufferLength < 4; i++)
		{
			if (characters[i] == '\0')
				break;
			if (isspace(characters[i]) || characters[i] == '=')
				continue;
			buffer[bufferLength] = decodingTable[(short)characters[i]];
			if (buffer[bufferLength++] == CHAR_MAX)      //  Illegal character!
			{
				free(bytes);
				return nil;
			}
		}
		
		if (bufferLength == 0)
			break;
		if (bufferLength == 1)      //  At least two characters are needed to produce one byte!
		{
			free(bytes);
			return nil;
		}
		
		//  Decode the characters in the buffer to bytes.
		bytes[length++] = (buffer[0] << 2) | (buffer[1] >> 4);
		if (bufferLength > 2)
			bytes[length++] = (buffer[1] << 4) | (buffer[2] >> 2);
		if (bufferLength > 3)
			bytes[length++] = (buffer[2] << 6) | buffer[3];
	}
	
	bytes = realloc(bytes, length);
	return [NSData dataWithBytesNoCopy:bytes length:length];
}

/******************************************************************************
 函数名称 : + (NSString *)base64EncodedStringFrom:(NSData *)data
 函数描述 : 文本数据转换为base64格式字符串
 输入参数 : (NSData *)data
 输出参数 : N/A
 返回参数 : (NSString *)
 备注信息 :
 ******************************************************************************/
+ (NSString *)base64EncodedStringFrom:(NSData *)data
{
	if ([data length] == 0)
		return @"";
	
    char *characters = malloc((([data length] + 2) / 3) * 4);
	if (characters == NULL)
		return nil;
	NSUInteger length = 0;
	
	NSUInteger i = 0;
	while (i < [data length])
	{
		char buffer[3] = {0,0,0};
		short bufferLength = 0;
		while (bufferLength < 3 && i < [data length])
			buffer[bufferLength++] = ((char *)[data bytes])[i++];
		
		//  Encode the bytes in the buffer to four characters, including padding "=" characters if necessary.
		characters[length++] = encodingTable[(buffer[0] & 0xFC) >> 2];
		characters[length++] = encodingTable[((buffer[0] & 0x03) << 4) | ((buffer[1] & 0xF0) >> 4)];
		if (bufferLength > 1)
			characters[length++] = encodingTable[((buffer[1] & 0x0F) << 2) | ((buffer[2] & 0xC0) >> 6)];
		else characters[length++] = '=';
		if (bufferLength > 2)
			characters[length++] = encodingTable[buffer[2] & 0x3F];
		else characters[length++] = '=';
	}
	
	return [[NSString alloc] initWithBytesNoCopy:characters length:length encoding:NSASCIIStringEncoding freeWhenDone:YES];
}




//******************************************************************************
/*
//DES解密
+(NSString *) DecryptUseDES:(NSString *)plainText key:(NSString *)key
{
    NSString *ciphertext = nil;
    NSData *textData = [ViewController dataWithBase64EncodedString:plainText];
    const char *textBytes = [plainText UTF8String];
    NSUInteger dataLength = [plainText length];
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
                                          kCCOptionECBMode|kCCOptionPKCS7Padding,  //kCCOptionECBMode  kCCOptionPKCS7Padding
                                          [key UTF8String], kCCKeySizeDES,
                                          iv,
                                          textBytes, dataLength,
                                          buffer, 1024,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        //ciphertext = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        //NSLog(@"ssf:%s",buffer);
        //ciphertext = [ViewController base64Encoding:data];
        // NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        //        Byte* bb = (Byte*)[data bytes];
        //        ciphertext = [self parseByteArray2HexString:bb];
        
    }
    return ciphertext;
    
    
}
*/


/*
 DES加密
 */
/*
+(NSString *) encryptUseDES1:(NSString *)clearText key:(NSString *)key
{
    NSString *ciphertext = nil;
    NSData *textData = [clearText dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [clearText length];
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesEncrypted = 0;
    
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                          kCCOptionECBMode,
                                          [key UTF8String], kCCKeySizeDES,
                                          iv,
                                          [textData bytes]  , dataLength,
                                          buffer, 1024,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSLog(@"DES加密成功");
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        Byte* bb = (Byte*)[data bytes];
        ciphertext = [ViewController parseByteArray2HexString:bb];//16 进制
        //ciphertext = [ViewController base64Encoding:data];
    }else{
        NSLog(@"DES加密失败");
    }
    return ciphertext;
}
*/

/**
 DES解密
 */

/*
+(NSString *) decryptUseDES1:(NSString *)plainText key:(NSString *)key
{
    NSString *cleartext = nil;
    //NSData *textData = [ViewController dataWithBase64EncodedString:plainText];
    NSData *textData = [ViewController parseHexToByteArray:plainText];//16 进制
    NSUInteger dataLength = [textData length];
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesEncrypted = 0;
    
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
                                          kCCOptionECBMode,
                                          [key UTF8String], kCCKeySizeDES,
                                          iv,
                                          [textData bytes]  , dataLength,
                                          buffer, 1024,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSLog(@"DES解密成功");
        
        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        cleartext = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }else{
        NSLog(@"DES解密失败");
    }
    return cleartext;
}

+ (id)dataWithBase64EncodedString:(NSString *)string;
{
    
    if (string == nil)
        [NSException raise:NSInvalidArgumentException format:@""];
    if ([string length] == 0)
        return [NSData data];
    static char *decodingTable = NULL;
    if (decodingTable == NULL)
    {
        decodingTable = malloc(256);
        if (decodingTable == NULL)
            return nil;
        memset(decodingTable, CHAR_MAX, 256);
        NSUInteger i;
        for (i = 0; i < 64; i++)
            decodingTable[(short)encodingTable[i]] = i;
    }
    const char *characters = [string cStringUsingEncoding:NSASCIIStringEncoding];
    if (characters == NULL)     //  Not an ASCII string!
        return nil;
    char *bytes = malloc((([string length] + 3) / 4) * 3);
    if (bytes == NULL)
        return nil;
    NSUInteger length = 0;
    NSUInteger i = 0;
    while (YES)
    {
        char buffer[4];
        short bufferLength;
        for (bufferLength = 0; bufferLength < 4; i++)
        {
            if (characters[i] == '\0')
                break;
            if (isspace(characters[i]) || characters[i] == '=')
                continue;
            buffer[bufferLength] = decodingTable[(short)characters[i]];
            if (buffer[bufferLength++] == CHAR_MAX)      //  Illegal character!
            {
                free(bytes);
                return nil;
            }
        }
        if (bufferLength == 0)
            break;
        if (bufferLength == 1)      //  At least two characters are needed to produce one byte!
        {
            free(bytes);
            return nil;
        }
        //  Decode the characters in the buffer to bytes.
        bytes[length++] = (buffer[0] << 2) | (buffer[1] >> 4);
        if (bufferLength > 2)
            bytes[length++] = (buffer[1] << 4) | (buffer[2] >> 2);
        if (bufferLength > 3)
            bytes[length++] = (buffer[2] << 6) | buffer[3];
    }
    realloc(bytes, length);
    return [NSData dataWithBytesNoCopy:bytes length:length];
}

*/
/**
 字节数组转化16进制数
 */
+(NSString *) parseByteArray2HexString:(Byte[]) bytes
{
    NSMutableString *hexStr = [[NSMutableString alloc]init];
    int i = 0;
    if(bytes)
    {
        while (bytes[i] != '\0')
        {
            NSString *hexByte = [NSString stringWithFormat:@"%x",bytes[i] & 0xff];///16进制数
            if([hexByte length]==1)
                [hexStr appendFormat:@"0%@", hexByte];
            else
                [hexStr appendFormat:@"%@", hexByte];

            i++;
        }
    }
    NSLog(@"bytes 的16进制数为:%@",hexStr);
    return [hexStr uppercaseString];
}

/*
 将16进制数据转化成NSData 数组
 */
+(NSData*) parseHexToByteArray:(NSString*) hexString
{
    int j=0;
    Byte bytes[hexString.length];
    for(int i=0;i<[hexString length];i++)
    {
        int int_ch;  /// 两位16进制数转化后的10进制数
        unichar hex_char1 = [hexString characterAtIndex:i]; ////两位16进制数中的第一位(高位*16)
        int int_ch1;
        if(hex_char1 >= '0' && hex_char1 <='9')
            int_ch1 = (hex_char1-48)*16;   //// 0 的Ascll - 48
        else if(hex_char1 >= 'A' && hex_char1 <='F')
            int_ch1 = (hex_char1-55)*16; //// A 的Ascll - 65
        else
            int_ch1 = (hex_char1-87)*16; //// a 的Ascll - 97
        i++;
        unichar hex_char2 = [hexString characterAtIndex:i]; ///两位16进制数中的第二位(低位)
        int int_ch2;
        if(hex_char2 >= '0' && hex_char2 <='9')
            int_ch2 = (hex_char2-48); //// 0 的Ascll - 48
        else if(hex_char2 >= 'A' && hex_char1 <='F')
            int_ch2 = hex_char2-55; //// A 的Ascll - 65
        else
            int_ch2 = hex_char2-87; //// a 的Ascll - 97
        
        int_ch = int_ch1+int_ch2;
        bytes[j] = int_ch;  ///将转化后的数放入Byte数组里
        j++;
    }
    
    NSData *newData = [[NSData alloc] initWithBytes:bytes length:hexString.length/2];
    NSLog(@"newData=%@",newData);
    return newData;
}



///******************************************************************************
// 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
// 函数描述 : 文本数据进行DES解密
// 输入参数 : (NSData *)data
// (NSString *)key
// 输出参数 : N/A
// 返回参数 : (NSData *)
// 备注信息 : 此函数不可用于过长文本
// ******************************************************************************/
// DES解密
// */
/*
+(NSString *) decryptUseDES:(NSString *)plainText key:(NSString *)key
{
    NSString *cleartext = nil;
      NSData *textData = [self parseHexToByteArray:plainText];
        NSUInteger dataLength = [textData length];
        unsigned char buffer[1024];
       memset(buffer, 0, sizeof(char));
       size_t numBytesEncrypted = 0;
    
   
       CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
                                             kCCOptionECBMode,
                                             [key UTF8String], kCCKeySizeDES,
                                             iv,
                                            [textData bytes]  , dataLength,
                                             buffer, 1024,
                                              &numBytesEncrypted);
        if (cryptStatus == kCCSuccess) {
            NSLog(@"DES解密成功");
    
            NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
            cleartext = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        }else{
           NSLog(@"DES解密失败");
        }
        return cleartext;
}
*/



 static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


+(NSString *)base64Encoding:(NSData*) text
{
    if (text.length == 0)
        return @"";
    
    char *characters = malloc(text.length*3/2);
    
    if (characters == NULL)
        return @"";
    
    int end = text.length - 3;
    int index = 0;
    int charCount = 0;
    int n = 0;
    
    while (index <= end) {
        int d = (((int)(((char *)[text bytes])[index]) & 0x0ff) << 16)
        | (((int)(((char *)[text bytes])[index + 1]) & 0x0ff) << 8)
        | ((int)(((char *)[text bytes])[index + 2]) & 0x0ff);
        
        characters[charCount++] = encodingTable[(d >> 18) & 63];
        characters[charCount++] = encodingTable[(d >> 12) & 63];
        characters[charCount++] = encodingTable[(d >> 6) & 63];
        characters[charCount++] = encodingTable[d & 63];
        
        index += 3;
        
        if(n++ >= 14)
        {
            n = 0;
            characters[charCount++] = ' ';
        }
    }
    
    if(index == text.length - 2)
    {
        int d = (((int)(((char *)[text bytes])[index]) & 0x0ff) << 16)
        | (((int)(((char *)[text bytes])[index + 1]) & 255) << 8);
        characters[charCount++] = encodingTable[(d >> 18) & 63];
        characters[charCount++] = encodingTable[(d >> 12) & 63];
        characters[charCount++] = encodingTable[(d >> 6) & 63];
        characters[charCount++] = '=';
    }
    else if(index == text.length - 1)
    {
        int d = ((int)(((char *)[text bytes])[index]) & 0x0ff) << 16;
        characters[charCount++] = encodingTable[(d >> 18) & 63];
        characters[charCount++] = encodingTable[(d >> 12) & 63];
        characters[charCount++] = '=';
        characters[charCount++] = '=';
    }
    NSString * rtnStr = [[NSString alloc] initWithBytesNoCopy:characters length:charCount encoding:NSUTF8StringEncoding freeWhenDone:YES];
    return rtnStr;
}

/*
+(NSString *)base64Encoding:(NSData*) text
{
    if (text.length == 0)
        return @"";

    char *characters = malloc(text.length*3/2);

    if (characters == NULL)
        return @"";

    int end = text.length - 3;
    int index = 0;
    int charCount = 0;
    int n = 0;

    while (index <= end) {
        int d = (((int)(((char *)[text bytes])[index]) & 0x0ff) << 16)
        | (((int)(((char *)[text bytes])[index + 1]) & 0x0ff) << 8)
        | ((int)(((char *)[text bytes])[index + 2]) & 0x0ff);

        characters[charCount++] = encodingTable[(d >> 18) & 63];
        characters[charCount++] = encodingTable[(d >> 12) & 63];
        characters[charCount++] = encodingTable[(d >> 6) & 63];
        characters[charCount++] = encodingTable[d & 63];

        index += 3;

        if(n++ >= 14)
        {
            n = 0;
            characters[charCount++] = ' ';
        }
    }

    if(index == text.length - 2)
    {
        int d = (((int)(((char *)[text bytes])[index]) & 0x0ff) << 16)
        | (((int)(((char *)[text bytes])[index + 1]) & 255) << 8);
        characters[charCount++] = encodingTable[(d >> 18) & 63];
        characters[charCount++] = encodingTable[(d >> 12) & 63];
        characters[charCount++] = encodingTable[(d >> 6) & 63];
        characters[charCount++] = '=';
    }
    else if(index == text.length - 1)
    {
        int d = ((int)(((char *)[text bytes])[index]) & 0x0ff) << 16;
        characters[charCount++] = encodingTable[(d >> 18) & 63];
        characters[charCount++] = encodingTable[(d >> 12) & 63];
        characters[charCount++] = '=';
        characters[charCount++] = '=';
    }
    NSString * rtnStr = [[NSString alloc] initWithBytesNoCopy:characters length:charCount encoding:NSUTF8StringEncoding freeWhenDone:YES];
    return rtnStr;
}

*/


 
 



//
//static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//+ (NSData *)dataWithBase64EncodedString:(NSString *)string
//{
//    if (string == nil)
//        [NSException raise:NSInvalidArgumentException format:nil];
//    if ([string length] == 0)
//        return [NSData data];
//
//    static char *decodingTable = NULL;
//    if (decodingTable == NULL)
//    {
//        decodingTable = malloc(256);
//        if (decodingTable == NULL)
//            return nil;
//        memset(decodingTable, CHAR_MAX, 256);
//        NSUInteger i;
//        for (i = 0; i < 64; i++)
//            decodingTable[(short)encodingTable[i]] = i;
//    }
//
//    const char *characters = [string cStringUsingEncoding:NSASCIIStringEncoding];
//    if (characters == NULL)     //  Not an ASCII string!
//        return nil;
//    char *bytes = malloc((([string length] + 3) / 4) * 3);
//    if (bytes == NULL)
//        return nil;
//    NSUInteger length = 0;
//
//    NSUInteger i = 0;
//    while (YES)
//    {
//        char buffer[4];
//        short bufferLength;
//        for (bufferLength = 0; bufferLength < 4; i++)
//        {
//            if (characters[i] == '\0')
//                break;
//            if (isspace(characters[i]) || characters[i] == '=')
//                continue;
//            buffer[bufferLength] = decodingTable[(short)characters[i]];
//            if (buffer[bufferLength++] == CHAR_MAX)      //  Illegal character!
//            {
//                free(bytes);
//                return nil;
//            }
//        }
//
//        if (bufferLength == 0)
//            break;
//        if (bufferLength == 1)      //  At least two characters are needed to produce one byte!
//        {
//            free(bytes);
//            return nil;
//        }
//        
//        //  Decode the characters in the buffer to bytes.
//        bytes[length++] = (buffer[0] << 2) | (buffer[1] >> 4);
//        if (bufferLength > 2)
//            bytes[length++] = (buffer[1] << 4) | (buffer[2] >> 2);
//        if (bufferLength > 3)
//            bytes[length++] = (buffer[2] << 6) | buffer[3];
//    }
//    
//    bytes = realloc(bytes, length);
//    return [NSData dataWithBytesNoCopy:bytes length:length];
//}
//
//
//
///******************************************************************************
// 函数名称 : + (NSString *)base64EncodedStringFrom:(NSData *)data
// 函数描述 : 文本数据转换为base64格式字符串
// 输入参数 : (NSData *)data
// 输出参数 : N/A
// 返回参数 : (NSString *)
// 备注信息 :
// ******************************************************************************/
//+ (NSString *)base64EncodedStringFrom:(NSData *)data
//{
//    if ([data length] == 0)
//        return @"";
//    
//    char *characters = malloc((([data length] + 2) / 3) * 4);
//    if (characters == NULL)
//        return nil;
//    NSUInteger length = 0;
//    
//    NSUInteger i = 0;
//    while (i < [data length])
//    {
//        char buffer[3] = {0,0,0};
//        short bufferLength = 0;
//        while (bufferLength < 3 && i < [data length])
//            buffer[bufferLength++] = ((char *)[data bytes])[i++];
//        
//        //  Encode the bytes in the buffer to four characters, including padding "=" characters if necessary.
//        characters[length++] = encodingTable[(buffer[0] & 0xFC) >> 2];
//        characters[length++] = encodingTable[((buffer[0] & 0x03) << 4) | ((buffer[1] & 0xF0) >> 4)];
//        if (bufferLength > 1)
//            characters[length++] = encodingTable[((buffer[1] & 0x0F) << 2) | ((buffer[2] & 0xC0) >> 6)];
//        else characters[length++] = '=';
//        if (bufferLength > 2)
//            characters[length++] = encodingTable[buffer[2] & 0x3F];
//        else characters[length++] = '=';
//    }
//    
//    return [[NSString alloc] initWithBytesNoCopy:characters length:length encoding:NSASCIIStringEncoding freeWhenDone:YES];
//}
//
//
//
///******************************************************************************
// 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
// 函数描述 : 文本数据进行DES加密
// 输入参数 : (NSData *)data
// (NSString *)key
// 输出参数 : N/A
// 返回参数 : (NSData *)
// 备注信息 : 此函数不可用于过长文本
// ******************************************************************************/
//+ (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
//{
//    char keyPtr[kCCKeySizeAES256+1];
//    bzero(keyPtr, sizeof(keyPtr));
//    
//    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
//    
//    NSUInteger dataLength = [data length];
//    
//    size_t bufferSize = dataLength + kCCBlockSizeAES128;
//    void *buffer = malloc(bufferSize);
//    
//    size_t numBytesEncrypted = 0;
//    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
//                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
//                                          keyPtr, kCCBlockSizeDES,
//                                          NULL,
//                                          [data bytes], dataLength,
//                                          buffer, bufferSize,
//                                          &numBytesEncrypted);
//    if (cryptStatus == kCCSuccess) {
//        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
//    }
//    
//    free(buffer);
//    return nil;
//}
//
//
//
//
///******************************************************************************
// 函数名称 : + (NSData *)DESEncrypt:(NSData *)data WithKey:(NSString *)key
// 函数描述 : 文本数据进行DES解密
// 输入参数 : (NSData *)data
// (NSString *)key
// 输出参数 : N/A
// 返回参数 : (NSData *)
// 备注信息 : 此函数不可用于过长文本
// ******************************************************************************/
//+ (NSData *)DESDecrypt:(NSData *)data WithKey:(NSString *)key
//{
//    char keyPtr[kCCKeySizeAES256+1];
//    bzero(keyPtr, sizeof(keyPtr));
//    
//    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
//    
//    NSUInteger dataLength = [data length];
//    
//    size_t bufferSize = dataLength + kCCBlockSizeAES128;
//    void *buffer = malloc(bufferSize);
//    
//    size_t numBytesDecrypted = 0;
//    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
//                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
//                                          keyPtr, kCCBlockSizeDES,
//                                          NULL,
//                                          [data bytes], dataLength,
//                                          buffer, bufferSize,
//                                          &numBytesDecrypted);
//    
//    if (cryptStatus == kCCSuccess) {
//        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
//    }
//    
//    free(buffer);
//    return nil;
//}
//
//
//
//+ (NSString *)base64StringFromText:(NSString *)text
//{
//    if (text && ![text isEqualToString:LocalStr_None]) {
//        //取项目的bundleIdentifier作为KEY
//        NSString *key = [[NSBundle mainBundle] bundleIdentifier];
//        NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
//        //IOS 自带DES加密 Begin
//        data = [self DESEncrypt:data WithKey:key];
//        //IOS 自带DES加密 End
//        return [self base64EncodedStringFrom:data];
//    }
//    else {
//        return LocalStr_None;
//    }
//}
//
//+ (NSString *)textFromBase64String:(NSString *)base64
//{
//    if (base64 && ![base64 isEqualToString:LocalStr_None]) {
//        //取项目的bundleIdentifier作为KEY
//        NSString *key = [[NSBundle mainBundle] bundleIdentifier];
//        NSData *data = [self dataWithBase64EncodedString:base64];
//        //IOS 自带DES解密 Begin
//        data = [self DESDecrypt:data WithKey:key];
//        //IOS 自带DES加密 End
//        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
//    }
//    else {
//        return LocalStr_None;
//    }
//}





///////////////////////////////////////////////////////////////////////////


//static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//static Byte iv[] = {1,2,3,4,5,6,7,8};
///*
// DES加密
// */
//+(NSString *) encryptUseDES:(NSString *)clearText key:(NSString *)key
//{
//    
//    NSString *ciphertext = nil;
//   NSData *textData = [clearText dataUsingEncoding:NSUTF8StringEncoding];
//    NSUInteger dataLength = [clearText length];
//    unsigned char buffer[1024];
//    memset(buffer, 0, sizeof(char));
//      size_t numBytesEncrypted = 0;
//    
//  
//    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
//                                                                                        kCCOptionECBMode,
//                                                                                         [key UTF8String], kCCKeySizeDES,
//                                                                                         iv,
//                                                                                         [textData bytes]  , dataLength,
//                                                                                          buffer, 1024,
//                                                                                          &numBytesEncrypted);
//   if (cryptStatus == kCCSuccess) {
//                NSLog(@"DES加密成功");
//                NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
//                Byte* bb = (Byte*)[data bytes];
//                ciphertext = [ViewController parseByteArray2HexString:bb];
//           }else{
//                   NSLog(@"DES加密失败");
//               }
//    return ciphertext;
//    /*
//    NSString *ciphertext = nil;
//    NSData *textData = [clearText dataUsingEncoding:NSUTF8StringEncoding];
//    NSUInteger dataLength = [clearText length];
//    unsigned char buffer[1024];
//    memset(buffer, 0, sizeof(char));
//    size_t numBytesEncrypted = 0;
//    
//    
//    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
//                                          kCCOptionECBMode,
//                                          [key UTF8String], kCCKeySizeDES,
//                                          iv,
//                                          [textData bytes]  , dataLength,
//                                          buffer, 1024,
//                                          &numBytesEncrypted);
//    if (cryptStatus == kCCSuccess) {
//        NSLog(@"DES加密成功");
//        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
//        Byte* bb = (Byte*)[data bytes];
//        ciphertext = [self parseByteArray2HexString:bb];
//    }else{
//        NSLog(@"DES加密失败");
//    }
//    return ciphertext;
//     */
//}
//
///**
// DES解密
// */
//+(NSString *) decryptUseDES:(NSString *)plainText key:(NSString *)key
//{
//    NSString *cleartext = nil;
//    NSData *textData = [self parseHexToByteArray:plainText];
//    NSUInteger dataLength = [textData length];
//    unsigned char buffer[1024];
//    memset(buffer, 0, sizeof(char));
//    size_t numBytesEncrypted = 0;
//    
//    
//    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
//                                          kCCOptionECBMode,
//                                          [key UTF8String], kCCKeySizeDES,
//                                          iv,
//                                          [textData bytes]  , dataLength,
//                                          buffer, 1024,
//                                          &numBytesEncrypted);
//    if (cryptStatus == kCCSuccess) {
//        NSLog(@"DES解密成功");
//        
//        NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
//        cleartext = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
//    }else{
//        NSLog(@"DES解密失败");
//    }
//    return cleartext;
//}
//
//
//
//
//+(NSString *)base64Encoding:(NSData*) text
//{
//    if (text.length == 0)
//        return @"";
//    
//    char *characters = malloc(text.length*3/2);
//    
//    if (characters == NULL)
//        return @"";
//    
//    int end = text.length - 3;
//    int index = 0;
//    int charCount = 0;
//    int n = 0;
//    
//    while (index <= end) {
//        int d = (((int)(((char *)[text bytes])[index]) & 0x0ff) << 16)
//        | (((int)(((char *)[text bytes])[index + 1]) & 0x0ff) << 8)
//        | ((int)(((char *)[text bytes])[index + 2]) & 0x0ff);
//        
//        characters[charCount++] = encodingTable[(d >> 18) & 63];
//        characters[charCount++] = encodingTable[(d >> 12) & 63];
//        characters[charCount++] = encodingTable[(d >> 6) & 63];
//        characters[charCount++] = encodingTable[d & 63];
//        
//        index += 3;
//        
//        if(n++ >= 14)
//        {
//            n = 0;
//            characters[charCount++] = ' ';
//        }
//    }
//    
//    if(index == text.length - 2)
//    {
//        int d = (((int)(((char *)[text bytes])[index]) & 0x0ff) << 16)
//        | (((int)(((char *)[text bytes])[index + 1]) & 255) << 8);
//        characters[charCount++] = encodingTable[(d >> 18) & 63];
//        characters[charCount++] = encodingTable[(d >> 12) & 63];
//        characters[charCount++] = encodingTable[(d >> 6) & 63];
//        characters[charCount++] = '=';
//    }
//    else if(index == text.length - 1)
//    {
//        int d = ((int)(((char *)[text bytes])[index]) & 0x0ff) << 16;
//        characters[charCount++] = encodingTable[(d >> 18) & 63];
//        characters[charCount++] = encodingTable[(d >> 12) & 63];
//        characters[charCount++] = '=';
//        characters[charCount++] = '=';
//    }
//    NSString * rtnStr = [[NSString alloc] initWithBytesNoCopy:characters length:charCount encoding:NSUTF8StringEncoding freeWhenDone:YES];
//    return rtnStr;
//}
//
///**
// 字节转化为16进制数
// */
//+(NSString *) parseByte2HexString:(Byte *) bytes
//{
//    NSMutableString *hexStr = [[NSMutableString alloc]init];
//    int i = 0;
//    if(bytes)
//    {
//        while (bytes[i] != '\0')
//        {
//            NSString *hexByte = [NSString stringWithFormat:@"%x",bytes[i] & 0xff];///16进制数
//            if([hexByte length]==1)
//                [hexStr appendFormat:@"0%@", hexByte];
//            else
//                [hexStr appendFormat:@"%@", hexByte];
//            
//            i++;
//        }
//    }
//    
//    NSLog(@"bytes 的16进制数为:%@",hexStr);
//    return hexStr;
//}
//
//
///**
// 字节数组转化16进制数
// */
//+(NSString *) parseByteArray2HexString:(Byte[]) bytes
//{
//    NSMutableString *hexStr = [[NSMutableString alloc]init];
//    int i = 0;
//    if(bytes)
//    {
//        while (bytes[i] != '\0')
//        {
//            NSString *hexByte = [NSString stringWithFormat:@"%x",bytes[i] & 0xff];///16进制数
//            if([hexByte length]==1)
//                [hexStr appendFormat:@"0%@", hexByte];
//            else
//                [hexStr appendFormat:@"%@", hexByte];
//            
//            i++;
//        }
//    }
//    NSLog(@"bytes 的16进制数为:%@",hexStr);
//    return [hexStr uppercaseString];
//}
//
///*
// 将16进制数据转化成NSData 数组
// */
//+(NSData*) parseHexToByteArray:(NSString*) hexString
//{
//    int j=0;
//    Byte bytes[hexString.length];
//    for(int i=0;i<[hexString length];i++)
//    {
//        int int_ch;  /// 两位16进制数转化后的10进制数
//        unichar hex_char1 = [hexString characterAtIndex:i]; ////两位16进制数中的第一位(高位*16)
//        int int_ch1;
//        if(hex_char1 >= '0' && hex_char1 <='9')
//            int_ch1 = (hex_char1-48)*16;   //// 0 的Ascll - 48
//        else if(hex_char1 >= 'A' && hex_char1 <='F')
//            int_ch1 = (hex_char1-55)*16; //// A 的Ascll - 65
//        else
//            int_ch1 = (hex_char1-87)*16; //// a 的Ascll - 97
//        i++;
//        unichar hex_char2 = [hexString characterAtIndex:i]; ///两位16进制数中的第二位(低位)
//        int int_ch2;
//        if(hex_char2 >= '0' && hex_char2 <='9')
//            int_ch2 = (hex_char2-48); //// 0 的Ascll - 48
//        else if(hex_char2 >= 'A' && hex_char1 <='F')
//            int_ch2 = hex_char2-55; //// A 的Ascll - 65
//        else
//            int_ch2 = hex_char2-87; //// a 的Ascll - 97
//        
//        int_ch = int_ch1+int_ch2;
//        bytes[j] = int_ch;  ///将转化后的数放入Byte数组里
//        j++;
//    }
//    
//    NSData *newData = [[NSData alloc] initWithBytes:bytes length:hexString.length/2];
//    NSLog(@"newData=%@",newData);
//    return newData;
//}







@end

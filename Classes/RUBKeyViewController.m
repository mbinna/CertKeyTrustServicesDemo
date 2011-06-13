//
//  RUBKeyViewController.m
//  RUBCertKeyTrustDemo
//
//  Created by Manuel Binna on 03.02.11.
//  Copyright 2011 Manuel Binna. All rights reserved.
//

#import "RUBKeyViewController.h"

#define kPrivateKeyTag  @"de.rub.emma.CertKeyTrustDemo.PrivateKey"
#define kPublicKeyTag   @"de.rub.emma.CertKeyTrustDemo.PublicKey"

#define kRSAKeyLength   (2048)


#pragma mark -

@interface RUBKeyViewController ()

// Key generation
- (void)generateAsymmetricKeyPair;
- (SecKeyRef)publicKey;
- (void)setPublicKey:(SecKeyRef)theNewPublicKey;
- (SecKeyRef)privateKey;
- (void)setPrivateKey:(SecKeyRef)theNewPrivateKey;

// Asymmetric encryption
- (NSData *)encryptData:(NSData *)dataToEncrypt withPublicKey:(SecKeyRef)aPublicKey;
- (NSData *)decryptData:(NSData *)dataToDecrypt withPrivateKey:(SecKeyRef)aPrivateKey;

// Digital signature
- (NSData *)signData:(NSData *)dataToSign withPrivateKey:(SecKeyRef)aPrivateKey;
- (void)verifySignature:(NSData *)signature forData:(NSData *)dataToVerify withPublicKey:(SecKeyRef)aPublicKey;

// Helpers
@property(nonatomic, retain) NSData *testData;
- (NSData *)SHA1DigestFromData:(NSData *)data;
- (void)logMessage:(NSString *)message withHeadline:(NSString *)headline;

@end


#pragma mark -

@implementation RUBKeyViewController

#pragma mark Properties

// Public properties
@synthesize textView;
@synthesize activityIndicatorView;
@synthesize encryptAndDecryptButton;
@synthesize signAndVerifyButton;

// Private properteis
@synthesize testData;

#pragma mark NSObject

- (void)dealloc 
{
    [textView release];
    [activityIndicatorView release];
    [encryptAndDecryptButton release];
    [signAndVerifyButton release];
    
    [testData release];
    
    if (publicKey)
        CFRelease(publicKey);
    if (privateKey)
        CFRelease(privateKey);
    
    [super dealloc];
}

#pragma mark UIViewController

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil 
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self != nil) 
    {
        NSString *filePath = [[NSBundle mainBundle] pathForResource:@"SecretText" ofType:@"txt"];
        testData = [[NSData alloc] initWithContentsOfFile:filePath];
    }
    return self;
}

- (void)viewDidLoad 
{
    [super viewDidLoad];
    
    // Set up UI 
    [[self textView] setText:@""];
    [[self textView] setFont:[UIFont fontWithName:@"Helvetica" size:15.0f]];
    [[self navigationItem] setTitle:@"Key"];
    
    [self generateAsymmetricKeyPair];   
    // Returns asynchronously
}

- (void)viewDidUnload 
{
    [super viewDidUnload];
    
    [self setTextView:nil];
    [self setActivityIndicatorView:nil];
    [self setEncryptAndDecryptButton:nil];
    [self setSignAndVerifyButton:nil];
}

#pragma mark RUBKeyViewController

- (IBAction)encryptAndDecryptButtonTapped:(id)sender
{
    [[self activityIndicatorView] startAnimating];
    [[self encryptAndDecryptButton] setEnabled:NO];
    
    // Encrypt and decrypt asynchronously
    __block __typeof__(self) blockSelf = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *encryptedTestData = [blockSelf encryptData:[blockSelf testData] withPublicKey:[blockSelf publicKey]];
        NSData *decryptedTestData = [blockSelf decryptData:encryptedTestData withPrivateKey:[blockSelf privateKey]];
        
        // Update UI
        dispatch_async(dispatch_get_main_queue(), ^{
            if ([decryptedTestData isEqual:[blockSelf testData]]) {
                [blockSelf logMessage:@"Encryption and decryption successful" withHeadline:@"Encryption/decryption"];
            } else {
                [blockSelf logMessage:@"Error in encryption/decryption" withHeadline:@"Encryption/decryption"];
            }
            
            [[blockSelf activityIndicatorView] stopAnimating];
            [[blockSelf encryptAndDecryptButton] setEnabled:YES];
        });
    });
}

- (IBAction)signAndVerifyButtonTapped:(id)sender
{
    NSData *signature = [self signData:[self testData] withPrivateKey:[self privateKey]];
    [self verifySignature:signature forData:[self testData] withPublicKey:[self publicKey]];
}

#pragma mark RUBKeyViewController ()

- (void)generateAsymmetricKeyPair 
{
    [[self activityIndicatorView] startAnimating];
    [[self signAndVerifyButton] setEnabled:NO];
    
    // Generate key pair asynchronously
    __block __typeof__(self) blockSelf = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Configure the public key
        NSMutableDictionary *publicKeyAttributes = [[NSMutableDictionary alloc] init];
        NSData *publicKeyTagData = [kPublicKeyTag dataUsingEncoding:NSUTF8StringEncoding];
        [publicKeyAttributes setObject:publicKeyTagData forKey:(id)kSecAttrApplicationTag];
        [publicKeyAttributes setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecAttrIsPermanent];
        
        // Configure private key
        NSMutableDictionary *privateKeyAttributes = [[NSMutableDictionary alloc] init];
        NSData *privateKeyTagData = [kPrivateKeyTag dataUsingEncoding:NSUTF8StringEncoding];
        [privateKeyAttributes setObject:privateKeyTagData forKey:(id)kSecAttrApplicationTag];
        [privateKeyAttributes setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecAttrIsPermanent];
        
        // Configure key pair
        NSMutableDictionary *keyPairAttributes = [[NSMutableDictionary alloc] init];
        [keyPairAttributes setObject:(id)kSecAttrKeyTypeRSA forKey:(id)kSecAttrKeyType];
        [keyPairAttributes setObject:[NSNumber numberWithInteger:kRSAKeyLength] forKey:(id)kSecAttrKeySizeInBits];
        [keyPairAttributes setObject:publicKeyAttributes forKey:(id)kSecPublicKeyAttrs];
        [keyPairAttributes setObject:privateKeyAttributes forKey:(id)kSecPrivateKeyAttrs];
        [publicKeyAttributes release];
        [privateKeyAttributes release];
        
        // Generate key pair
        SecKeyRef thePublicKey = NULL;
        SecKeyRef thePrivateKey = NULL;
        OSStatus generatePairStatus = SecKeyGeneratePair((CFDictionaryRef)keyPairAttributes, 
                                                         &thePublicKey, 
                                                         &thePrivateKey);
        if (generatePairStatus == errSecSuccess) 
        {
            [blockSelf setPublicKey:thePublicKey];
            [blockSelf setPrivateKey:thePrivateKey];
        }
        [keyPairAttributes release];
        
        // Cleanup
        if (thePublicKey) 
            CFRelease(thePublicKey);
        if (thePrivateKey)
            CFRelease(thePrivateKey);
        
        // Update UI
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *message = [NSString stringWithFormat:@"RSA key pair with key length of %d was created", 
                                 kRSAKeyLength];
            [blockSelf logMessage:message withHeadline:@"Key Genernation Complete"];
            [[blockSelf activityIndicatorView] stopAnimating];
            [[blockSelf signAndVerifyButton] setEnabled:YES];
        });
    });
}

- (NSData *)signData:(NSData *)dataToSign withPrivateKey:(SecKeyRef)aPrivateKey
{
    NSData *digest = [self SHA1DigestFromData:dataToSign];
    
    // Sign digest
    size_t signatureLength = SecKeyGetBlockSize(aPrivateKey);
    NSMutableData *signature = [[[NSMutableData alloc] initWithLength:signatureLength] autorelease];
    OSStatus signatureStatus = SecKeyRawSign(aPrivateKey, 
                                             kSecPaddingPKCS1SHA1, 
                                             [digest bytes], 
                                             [digest length], 
                                             [signature mutableBytes], 
                                             &signatureLength);
    [signature setLength:signatureLength];  // Just in case SecKeyRawSign() modifies that value internally
    
    // Return signature or nil
    if (signatureStatus != errSecSuccess) 
    {
        [self logMessage:@"Could not create signature." withHeadline:@"Error"];
        return nil;
    }
    return [[signature copy] autorelease];  // Return immutable copy
}

- (void)verifySignature:(NSData *)signature forData:(NSData *)dataToVerify withPublicKey:(SecKeyRef)aPublicKey;
{
    NSData *digestOfDataToVerify = [self SHA1DigestFromData:dataToVerify];
    
    OSStatus verificationStatus = SecKeyRawVerify(aPublicKey, 
                                                  kSecPaddingPKCS1SHA1, 
                                                  [digestOfDataToVerify bytes], 
                                                  [digestOfDataToVerify length], 
                                                  [signature bytes], 
                                                  [signature length]);
    if (verificationStatus != errSecSuccess) 
    {
        [self logMessage:@"Invalid signature!" withHeadline:@"Signature Verification"];
    }
    else
    {
        [self logMessage:@"Signature is valid." withHeadline:@"Signature Verification"];
    }
}

- (NSData *)encryptData:(NSData *)dataToEncrypt withPublicKey:(SecKeyRef)aPublicKey 
{
    // PKCS #1 padding. Can only encrypt SecKeyGetBlockSize() - 11 bytes.
    if ([dataToEncrypt length] > (SecKeyGetBlockSize(aPublicKey) - 11)) 
    {
        return nil;
    }
    
    // Encrypt data with public key
    size_t encryptedDataLength = SecKeyGetBlockSize(aPublicKey);
    NSMutableData *encryptedData = [[[NSMutableData alloc] initWithLength:encryptedDataLength] autorelease];
    OSStatus encryptStatus = SecKeyEncrypt(aPublicKey, 
                                           kSecPaddingPKCS1,
                                           [dataToEncrypt bytes], 
                                           [dataToEncrypt length], 
                                           [encryptedData mutableBytes], 
                                           &encryptedDataLength);
    [encryptedData setLength:encryptedDataLength];  // Adjust length to actual length of encrypted data
    
    // Return encrypted data or nil
    if (encryptStatus != errSecSuccess) 
    {
        [self logMessage:@"Could not encrypt data" withHeadline:@"Error"];
        return nil;
    }
    return [[encryptedData copy] autorelease];    // Return immutable copy
}

- (NSData *)decryptData:(NSData *)dataToDecrypt withPrivateKey:(SecKeyRef)aPrivateKey
{
    size_t decryptedDataLength = SecKeyGetBlockSize(aPrivateKey);
    NSMutableData *decryptedData = [[[NSMutableData alloc] initWithLength:decryptedDataLength] autorelease];
    OSStatus decryptStatus = SecKeyDecrypt(aPrivateKey, 
                                           kSecPaddingPKCS1, 
                                           [dataToDecrypt bytes], 
                                           [dataToDecrypt length], 
                                           [decryptedData mutableBytes], 
                                           &decryptedDataLength);
    [decryptedData setLength:decryptedDataLength];  // Adjust length to actual length of decrypted data
    
    // Return decrypted data or nil
    if (decryptStatus != errSecSuccess) 
    {
        [self logMessage:@"Could not decrypt data" withHeadline:@"Error"];
        return nil;
    }
    return [[decryptedData copy] autorelease];  // Return immutable copy
}

- (NSData *)SHA1DigestFromData:(NSData *)data
{
    // Compute SHA1 digest
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([data bytes], [data length], digest);
    
    NSData *theDigest = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    return theDigest;
}

- (void)logMessage:(NSString *)message withHeadline:(NSString *)headline
{
    NSLog(@"%@: %@", headline, message);
    NSString *output = [[NSMutableString alloc] initWithFormat:@"%@%@:\n%@\n\n", 
                        [[self textView] text], 
                        headline, 
                        message];
    [[self textView] setText:output];
    [output release];
    
    // Scroll to bottm
    NSRange rangeOfLastCharacter = NSMakeRange([[[self textView] text] length] - 1, 0);
    [[self textView] setSelectedRange:rangeOfLastCharacter] ;
}

- (SecKeyRef)publicKey
{
    return publicKey;
}

- (void)setPublicKey:(SecKeyRef)theNewPublicKey
{
    if (publicKey != theNewPublicKey)
    {
        if (publicKey)
            CFRelease(publicKey);
        
        publicKey = (SecKeyRef) CFRetain(theNewPublicKey);
    }
}

- (SecKeyRef)privateKey
{
    return privateKey;
}

- (void)setPrivateKey:(SecKeyRef)theNewPrivateKey
{
    if (privateKey != theNewPrivateKey)
    {
        if (privateKey)
            CFRelease(privateKey);
        
        privateKey = (SecKeyRef) CFRetain(theNewPrivateKey);
    }
}

@end

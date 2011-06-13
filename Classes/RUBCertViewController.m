//
//  RUBCertViewController.m
//  RUBCertKeyTrustDemo
//
//  Created by Manuel Binna on 01.02.11.
//  Copyright Manuel Binna 2011. All rights reserved.
//

#import "RUBCertViewController.h"

#define kImportExportPassword   @"emma"


#pragma mark -

@interface RUBCertViewController ()

@property (nonatomic, retain) NSMutableArray *identities;
@property (nonatomic, retain) NSMutableArray *persistentKeychainReferences;

// Extracting PKCS#12 data
- (void)extractPKCS12File;
- (OSStatus)extractIdentity:(SecIdentityRef *)identity 
                   andTrust:(SecTrustRef *)trust 
             fromPKCS12Data:(NSData *)PKCS12Data;

// Logging
- (void)logSubjectSummariesOfIdentities:(NSArray *)theIdentities;
- (void)logAttributesOfPersistentKeychainReferences:(NSArray *)thePersistentKeychainReferences;
- (void)addLogEntryWithTitle:(NSString *)headline andMessage:(NSString *)message;

// Keychain
- (NSData *)persistentKeychainReferenceForIdentity:(SecIdentityRef)identity;
- (SecIdentityRef)identityForPersistentKeychainReference:(NSData *)persistentKeychainReference;
- (NSDictionary *)keychainItemForPersistentKeychainReference:(NSData *)persistentKeychainReference;
- (void)clearKeychainItems;

- (void)listAllIdentities;

@end


#pragma mark -

@implementation RUBCertViewController

#pragma mark Properties

@synthesize identities;
@synthesize persistentKeychainReferences;
@synthesize textView;

#pragma mark NSObject

- (void)dealloc 
{
    [identities release];
    [persistentKeychainReferences release];
    [textView release];
    
    [super dealloc];
}

#pragma mark UIViewController

- (id)initWithNibName:(NSString *)theNibName bundle:(NSBundle *)theNibBundle
{
    self = [super initWithNibName:theNibName bundle:theNibBundle];
    if (self != nil)
    {
        identities = [[NSMutableArray alloc] init];
        persistentKeychainReferences = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void)viewDidLoad 
{
    [super viewDidLoad];
    
    [[self textView] setText:@""];
    [[self textView] setFont:[UIFont fontWithName:@"Helvetica" size:15.0f]];
    [[self navigationItem] setTitle:@"Certificate"];
    
    [self clearKeychainItems];
    
    [self extractPKCS12File];
    [self listAllIdentities];
    [self logAttributesOfPersistentKeychainReferences:[self persistentKeychainReferences]];
}

- (void)viewDidUnload 
{
	[super viewDidUnload];
    
    [self setTextView:nil];
}

#pragma mark RUBCertViewController

#pragma mark RUBCertViewController ()

- (void)extractPKCS12File
{
    NSString *thePath = [[NSBundle mainBundle] pathForResource:@"SelfSignedSSLServerCert" ofType:@"p12"];
    NSData *PKCS12Data = [[NSData alloc] initWithContentsOfFile:thePath];
    SecIdentityRef identity;
    SecTrustRef trust;
    OSStatus identityAndTrustExtractionStatus = [self extractIdentity:&identity 
                                                             andTrust:&trust 
                                                       fromPKCS12Data:PKCS12Data];
    [PKCS12Data release];
    
    if (identityAndTrustExtractionStatus != errSecSuccess)
    {
        return;
    }
    
    [[self identities] addObject:(id)identity];
    
    // The trust object, containing the policy and other information needed to determine whether the certificate is 
    // trusted, is included in the PKCS data.
    SecTrustResultType trustEvaluationResult = kSecTrustResultInvalid;
    OSStatus trustEvaluationStatus = SecTrustEvaluate(trust, &trustEvaluationResult);
    if (trustEvaluationStatus != errSecSuccess)
    {
        NSLog(@"Could not evaluate trust. Error %lu", trustEvaluationStatus);
        return;
    }
    
    NSString *logTitle = @"Trust evaluation";
    NSString *logMessage = nil;
    switch (trustEvaluationResult)
    {
        case kSecTrustResultConfirm:
            logMessage = @"Confirmation from the user is required before proceeding.";
            break;
            
        case kSecTrustResultRecoverableTrustFailure:    // It might be able to recover from the failure.
            logMessage = @"Recoverable Trust Failure detected.";
            logMessage = [logMessage stringByAppendingString:@"\nSetting exceptions..."];
            CFDataRef cookie = SecTrustCopyExceptions(trust);
            if (SecTrustSetExceptions(trust, cookie))
            {
                logMessage = [logMessage stringByAppendingString:@"\nSuccessfully set exceptions."];
                
                SecTrustResultType trustReevaluationResult = kSecTrustResultInvalid;
                OSStatus trustReevaluationStatus = SecTrustEvaluate(trust, &trustReevaluationResult);
                if (trustReevaluationStatus == errSecSuccess)
                {
                    if ((trustReevaluationResult == kSecTrustResultProceed) || 
                        (trustReevaluationResult == kSecTrustResultUnspecified))
                    {
                        logMessage = [logMessage stringByAppendingString:@"\nTrust evaluation successfull."];
                        NSData *persistentRef = [self persistentKeychainReferenceForIdentity:identity];
                        [[self persistentKeychainReferences] addObject:persistentRef];
                    }
                }
                else
                {
                    logMessage = [logMessage stringByAppendingString:@"\nTrust evaluation not successfull."];
                }
            }
            else
            {
                logMessage = [logMessage stringByAppendingString:@"\nCould no set exceptions. Aborting"];
            }
            CFRelease(cookie);

            break;
            
        case kSecTrustResultProceed:
            logMessage = @"The user indicated that the certificate may be trusted for the purposes designated in the "
                         @"specified policies";
            break;
            
        case kSecTrustResultDeny:
            logMessage = @"The user specified that the certificate should not be trusted.";
            break;
            
        case kSecTrustResultInvalid:
            logMessage = @"Invalid setting or result. Usually, this result indicates that the SecTrustEvaluate "
                         @"function did not complete successfully.";
            break;
            
        case kSecTrustResultFatalTrustFailure:
            logMessage = @"Trust denied; no simple fix is available.";
            break;
            
        case kSecTrustResultOtherError:
            logMessage = @"A failure other than that of trust evaluation; for example, an internal failure of the "
                         @"SecTrustEvaluate function.";
            break;
            
        default:
            break;
    }
    [self addLogEntryWithTitle:logTitle andMessage:logMessage];
}

- (OSStatus)extractIdentity:(SecIdentityRef *)identity andTrust:(SecTrustRef *)trust fromPKCS12Data:(NSData *)PKCS12Data
{   
    // The password is needed to decrypt the information in the PKCS#12 data
    NSDictionary *options = [NSDictionary dictionaryWithObject:kImportExportPassword 
                                                        forKey:(id)kSecImportExportPassphrase];
    
    NSArray *items = nil;
    OSStatus importStatus = SecPKCS12Import((CFDataRef)PKCS12Data, (CFDictionaryRef)options, (CFArrayRef *)&items);
    if (importStatus == errSecSuccess) 
    {
        // SecPKCS12Import() returns one dictionary for each item (identity or certificate) in the PKCS#12 data.
        NSDictionary *identityAndTrust = [items objectAtIndex:0];
        *identity = (SecIdentityRef)[identityAndTrust objectForKey:(id)kSecImportItemIdentity];
        *trust = (SecTrustRef)[identityAndTrust objectForKey:(id)kSecImportItemTrust];
    }
    
    return importStatus;
}

- (void)logSubjectSummariesOfIdentities:(NSArray *)theIdentities
{
    __block __typeof__(self) blockSelf = self;
    [theIdentities enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        SecIdentityRef identity = (SecIdentityRef)obj;
        SecCertificateRef certificate = NULL;
        
        OSStatus certificateStatus = SecIdentityCopyCertificate(identity, &certificate);
        if (certificateStatus == errSecSuccess)
        {
            // Output properties of certificate
            NSString *certificateSubjectSummary = (NSString *)SecCertificateCopySubjectSummary(certificate);
            [blockSelf addLogEntryWithTitle:@"Certificate subject summary" andMessage:certificateSubjectSummary];
            [certificateSubjectSummary release];
        }
    }];
}

- (void)logAttributesOfPersistentKeychainReferences:(NSArray *)thePersistentKeychainReferences
{
    __block __typeof__(self) blockSelf = self;
    [thePersistentKeychainReferences enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        NSString *logTitle = @"Keychain Item (Identity)";
        NSMutableString *message = [NSMutableString string];
        NSDictionary *keychainItem = [blockSelf keychainItemForPersistentKeychainReference:(NSData *)obj];
        if (keychainItem != nil) {
            // Log available fields of the identity
            [message appendFormat:@"kSecAttrAccessible: %@\n", [keychainItem objectForKey:(id)kSecAttrAccessible]];
            [message appendFormat:@"kSecAttrAccessGroup: %@\n", [keychainItem objectForKey:(id)kSecAttrAccessGroup]];
            [message appendFormat:@"kSecAttrKeyClass: %@\n", [keychainItem objectForKey:(id)kSecAttrKeyClass]];
            [message appendFormat:@"kSecAttrLabel: %@\n", [keychainItem objectForKey:(id)kSecAttrLabel]];
            [message appendFormat:@"kSecAttrApplicationLabel: %@\n", 
             [keychainItem objectForKey:(id)kSecAttrApplicationLabel]];
            [message appendFormat:@"kSecAttrIsPermanent: %@\n", [keychainItem objectForKey:(id)kSecAttrIsPermanent]];
            [message appendFormat:@"kSecAttrApplicationTag: %@\n", [keychainItem objectForKey:(id)kSecAttrApplicationTag]];
            [message appendFormat:@"kSecAttrKeyType: %@\n", [keychainItem objectForKey:(id)kSecAttrKeyType]];
            [message appendFormat:@"kSecAttrKeySizeInBits: %@\n", [keychainItem objectForKey:(id)kSecAttrKeySizeInBits]];
            [message appendFormat:@"kSecAttrEffectiveKeySize: %@\n", 
             [keychainItem objectForKey:(id)kSecAttrEffectiveKeySize]];
            [message appendFormat:@"kSecAttrCanEncrypt: %@\n", [keychainItem objectForKey:(id)kSecAttrCanEncrypt]];
            [message appendFormat:@"kSecAttrCanDecrypt: %@\n", [keychainItem objectForKey:(id)kSecAttrCanDecrypt]];
            [message appendFormat:@"kSecAttrCanDerive: %@\n", [keychainItem objectForKey:(id)kSecAttrCanDerive]];
            [message appendFormat:@"kSecAttrCanSign: %@\n", [keychainItem objectForKey:(id)kSecAttrCanSign]];
            [message appendFormat:@"kSecAttrCanVerify: %@\n", [keychainItem objectForKey:(id)kSecAttrCanVerify]];
            [message appendFormat:@"kSecAttrCanWrap: %@\n", [keychainItem objectForKey:(id)kSecAttrCanWrap]];
            [message appendFormat:@"kSecAttrCanUnwrap: %@\n", [keychainItem objectForKey:(id)kSecAttrCanUnwrap]];  
        }
        
        NSString *logMessage = [[message copy] autorelease];
        [blockSelf addLogEntryWithTitle:logTitle andMessage:logMessage];
    }];
}

- (void)addLogEntryWithTitle:(NSString *)headline andMessage:(NSString *)message
{
    NSLog(@"%@: %@", headline, message);
    
    NSString *output = [[NSMutableString alloc] initWithFormat:@"%@%@:\n%@\n\n", 
                        [[self textView] text], 
                        headline, 
                        message];
    [[self textView] setText:output];
    [output release];
}

- (NSData *)persistentKeychainReferenceForIdentity:(SecIdentityRef)identity
{
    NSData *persistentRef = nil;
    NSDictionary *attributes = [NSDictionary dictionaryWithObjectsAndKeys:
                                (id)identity, kSecValueRef, 
                                (id)kCFBooleanTrue, kSecReturnPersistentRef, 
                                nil];
    OSStatus itemAddStatus = SecItemAdd((CFDictionaryRef)attributes, (CFTypeRef *)&persistentRef);
    if (itemAddStatus != errSecSuccess)
    {
        return nil;
    }
    
    return persistentRef;
}

- (SecIdentityRef)identityForPersistentKeychainReference:(NSData *)persistentKeychainReference
{
    SecIdentityRef identity = NULL;
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (id)persistentKeychainReference, kSecValuePersistentRef,
                           (id)kCFBooleanTrue, kSecReturnRef, 
                           nil];
    OSStatus itemCopyMatchingStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&identity);
    if (itemCopyMatchingStatus != errSecSuccess)
    {
        return NULL;
    }
    
    return identity;
}

- (void)listAllIdentities
{
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (id)kSecClassIdentity, kSecClass,
                           (id)kCFBooleanTrue, kSecReturnRef,
                           (id)kSecMatchLimitAll, kSecMatchLimit,
                           nil];
    NSArray *allIdentities = nil;
    OSStatus itemCopyMatchingStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&allIdentities);
    if (itemCopyMatchingStatus != errSecSuccess)
    {
        return;
    }
    
    [self logSubjectSummariesOfIdentities:allIdentities];
}

- (NSDictionary *)keychainItemForPersistentKeychainReference:(NSData *)persistentKeychainReference
{
    NSDictionary *keychainItem = nil;
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (id)persistentKeychainReference, kSecValuePersistentRef,
                           (id)kCFBooleanTrue, kSecReturnAttributes,
                           (id)kCFBooleanTrue, kSecReturnData,
                           nil];
    OSStatus itemCopyMatchingStatus = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&keychainItem);
    if (itemCopyMatchingStatus != errSecSuccess)
    {
        return NULL;
    }
    
    return [keychainItem autorelease];
}

- (void)clearKeychainItems
{
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (id)kSecClassIdentity, kSecClass,
                           nil];
    SecItemDelete((CFDictionaryRef)query);
}

@end

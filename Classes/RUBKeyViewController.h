//
//  RUBKeyViewController.h
//  RUBCertKeyTrustDemo
//
//  Created by Manuel Binna on 03.02.11.
//  Copyright 2011 Manuel Binna. All rights reserved.
//

@interface RUBKeyViewController : UIViewController 
{
    @private
    
    UITextView *textView;
    UIActivityIndicatorView *activityIndicatorView;
    UIButton *encryptAndDecryptButton;
    UIButton *signAndVerifyButton;
    
    NSData *testData;
    
    SecKeyRef publicKey;
    SecKeyRef privateKey;
}

@property (nonatomic, retain) IBOutlet UITextView *textView;
@property (nonatomic, retain) IBOutlet UIActivityIndicatorView *activityIndicatorView;
@property (nonatomic, retain) IBOutlet UIButton *encryptAndDecryptButton;
@property (nonatomic, retain) IBOutlet UIButton *signAndVerifyButton;

- (IBAction)encryptAndDecryptButtonTapped:(id)sender;
- (IBAction)signAndVerifyButtonTapped:(id)sender;

@end

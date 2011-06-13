//
//  RUBCertViewController.h
//  RUBCertKeyTrustDemo
//
//  Created by Manuel Binna on 01.02.11.
//  Copyright Manuel Binna 2011. All rights reserved.
//

@interface RUBCertViewController : UIViewController 
{
    @private
    
    NSMutableArray *identities;
    NSMutableArray *persistentKeychainReferences;
    UITextView *textView;
}

@property (nonatomic, retain) IBOutlet UITextView *textView;

@end
